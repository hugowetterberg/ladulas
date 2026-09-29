package agent_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/hugowetterberg/ladulas/pkg/agent"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The keys programs park in the agent (§10, decision AU): accepted through
// Add, listed beside the store's, signed with after the same decision as any
// other key, and gone on Remove, RemoveAll, expiry and seal.

func freshKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	return priv
}

func publicOf(t *testing.T, priv ed25519.PrivateKey) ssh.PublicKey {
	t.Helper()

	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	return pub
}

func TestAgentParksAKeyAndSignsWithIt(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)
	client := a.client(t)

	priv := freshKey(t)

	if err := client.Add(sshagent.AddedKey{
		PrivateKey: priv,
		Comment:    "tsh-prod",
	}); err != nil {
		t.Fatalf("add: %v", err)
	}

	keys, err := client.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	// After the store's key, with the comment it was parked under.
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(keys))
	}

	if keys[1].Comment != "tsh-prod" {
		t.Errorf("parked key comment: %q", keys[1].Comment)
	}

	pub := publicOf(t, priv)

	if string(keys[1].Marshal()) != string(pub.Marshal()) {
		t.Error("the listed key is not the parked key")
	}

	digest := sha512.Sum512([]byte("a commit object"))
	payload := sshsigBlob("git", "sha512", digest[:])

	sig, err := client.Sign(pub, payload)
	if err != nil {
		t.Fatalf("sign with the parked key: %v", err)
	}

	if err := pub.Verify(payload, sig); err != nil {
		t.Errorf("the signature does not verify: %v", err)
	}

	// The request said what the key is, and who parked it: this process.
	req := a.approver.last()

	parked := req.GetLocalKey()
	if parked == nil {
		t.Fatal("the request did not say the key was parked")
	}

	if parked.GetAddedBy().GetPid() != int32(os.Getpid()) { //nolint:gosec // a pid fits
		t.Errorf("parked by pid %d, want this process", parked.GetAddedBy().GetPid())
	}

	if req.GetKey().GetLabel() != "tsh-prod" {
		t.Errorf("request key label: %q", req.GetKey().GetLabel())
	}

	listed := a.parked.List()
	if len(listed) != 1 {
		t.Fatalf("the parked set lists %d keys", len(listed))
	}

	if listed[0].GetKeyFingerprint() != ssh.FingerprintSHA256(pub) {
		t.Errorf("parked key fingerprint: %s", listed[0].GetKeyFingerprint())
	}

	if listed[0].GetExpiresAt() != nil {
		t.Error("a key parked without a lifetime has an expiry")
	}

	if kinds := a.events.kinds(); len(kinds) != 1 || kinds[0] != agent.LocalKeyAdded {
		t.Errorf("events: %v", kinds)
	}
}

// tsh parks its certificate, so the agent lists the certificate and signs
// under it — and the certificate's own validity is the key's lifetime.
func TestAgentParksACertificate(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)
	client := a.client(t)

	priv := freshKey(t)
	pub := publicOf(t, priv)

	caSigner, err := ssh.NewSignerFromKey(freshKey(t))
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}

	validBefore := time.Now().Add(time.Hour).Truncate(time.Second)

	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "hugo",
		ValidPrincipals: []string{"hugo"},
		ValidAfter:      0,
		ValidBefore:     uint64(validBefore.Unix()), //nolint:gosec // in range
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("sign cert: %v", err)
	}

	if err := client.Add(sshagent.AddedKey{
		PrivateKey:  priv,
		Certificate: cert,
		Comment:     "teleport:hugo",
	}); err != nil {
		t.Fatalf("add: %v", err)
	}

	keys, err := client.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(keys))
	}

	if keys[1].Format != ssh.CertAlgoED25519v01 {
		t.Errorf("listed as %s, want the certificate type", keys[1].Format)
	}

	payload := authBlob([]byte("session"), "hugo", "ssh-connection", cert)

	sig, err := client.Sign(cert, payload)
	if err != nil {
		t.Fatalf("sign under the certificate: %v", err)
	}

	if err := pub.Verify(payload, sig); err != nil {
		t.Errorf("the signature does not verify against the key: %v", err)
	}

	listed := a.parked.List()
	if len(listed) != 1 {
		t.Fatalf("the parked set lists %d keys", len(listed))
	}

	if !listed[0].GetCertificate() {
		t.Error("the parked key does not say it is a certificate")
	}

	if listed[0].GetAlgorithm() != ssh.KeyAlgoED25519 {
		t.Errorf("underlying algorithm: %s", listed[0].GetAlgorithm())
	}

	if got := listed[0].GetExpiresAt().AsTime(); !got.Equal(validBefore) {
		t.Errorf("expires %v, want the certificate's %v", got, validBefore)
	}
}

// Remove drops a parked key and refuses a managed one; RemoveAll drops every
// parked key and leaves the store's standing, reporting success because the
// wire has no other byte.
func TestAgentRemovesParkedKeysOnly(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)
	client := a.client(t)

	first, second := freshKey(t), freshKey(t)

	for _, priv := range []ed25519.PrivateKey{first, second} {
		if err := client.Add(sshagent.AddedKey{PrivateKey: priv}); err != nil {
			t.Fatalf("add: %v", err)
		}
	}

	if err := client.Remove(a.publicKey); err == nil {
		t.Error("the agent removed a managed key")
	}

	if err := client.Remove(publicOf(t, first)); err != nil {
		t.Errorf("remove a parked key: %v", err)
	}

	if err := client.Remove(publicOf(t, first)); err == nil {
		t.Error("removing a key twice succeeded")
	}

	keys, err := client.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(keys) != 2 {
		t.Fatalf("after one removal: %d keys", len(keys))
	}

	if err := client.RemoveAll(); err != nil {
		t.Fatalf("remove all: %v", err)
	}

	keys, err = client.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(keys) != 1 || string(keys[0].Marshal()) != string(a.publicKey.Marshal()) {
		t.Errorf("after RemoveAll the agent lists %d keys, and the managed one "+
			"should be the one left", len(keys))
	}

	want := []agent.LocalKeyEventKind{
		agent.LocalKeyAdded, agent.LocalKeyAdded,
		agent.LocalKeyForgotten, agent.LocalKeyForgotten,
	}

	if got := a.events.kinds(); len(got) != len(want) {
		t.Errorf("events: %v, want %v", got, want)
	}
}

// Adding a key the store holds is a success that parks nothing: the agent has
// the key, which is what was asked, and a second copy would list it twice.
func TestAgentAddingAManagedKeyParksNothing(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)
	client := a.client(t)

	raw, err := ssh.ParseRawPrivateKey(a.vault.Keys()[0].GetPrivateKey())
	if err != nil {
		t.Fatalf("parse the store's key: %v", err)
	}

	if err := client.Add(sshagent.AddedKey{PrivateKey: raw}); err != nil {
		t.Fatalf("add a managed key: %v", err)
	}

	keys, err := client.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("the agent lists %d keys", len(keys))
	}

	if a.parked.Len() != 0 {
		t.Error("the managed key was parked as well")
	}
}

// A sealed instance parks nothing, and says so through the gate.
func TestAgentRefusesToParkWhileTheGateIsShut(t *testing.T) {
	events := &eventLog{}

	var shut atomic.Bool

	a := newTestAgentWith(t, ladulasv1.Decision_DECISION_APPROVE, events,
		agent.NewLocalKeys(agent.LocalKeysOptions{
			OnEvent: events.record,
			Accept: func() error {
				if shut.Load() {
					return errors.New("sealed")
				}

				return nil
			},
		}))
	client := a.client(t)

	shut.Store(true)

	if err := client.Add(sshagent.AddedKey{PrivateKey: freshKey(t)}); err == nil {
		t.Fatal("a key was parked through a shut gate")
	}

	shut.Store(false)

	if err := client.Add(sshagent.AddedKey{PrivateKey: freshKey(t)}); err != nil {
		t.Fatalf("add through an open gate: %v", err)
	}
}

// The set is bounded, and a full one refuses rather than growing.
func TestParkedKeysAreCapped(t *testing.T) {
	events := &eventLog{}
	parked := agent.NewLocalKeys(agent.LocalKeysOptions{
		Limit:   1,
		OnEvent: events.record,
	})

	if err := parked.Add(sshagent.AddedKey{PrivateKey: freshKey(t)}, nil); err != nil {
		t.Fatalf("first add: %v", err)
	}

	err := parked.Add(sshagent.AddedKey{PrivateKey: freshKey(t)}, nil)
	if !errors.Is(err, agent.ErrLocalKeysFull) {
		t.Fatalf("second add: %v, want %v", err, agent.ErrLocalKeysFull)
	}

	if parked.Len() != 1 {
		t.Errorf("%d keys parked past the limit", parked.Len())
	}
}

// A lifetime constraint is honoured: the key is gone when it passes, reported
// once, whether the timer or a reader noticed first.
func TestParkedKeyExpires(t *testing.T) {
	events := &eventLog{}

	var now atomic.Pointer[time.Time]

	start := time.Now()
	now.Store(&start)

	parked := agent.NewLocalKeys(agent.LocalKeysOptions{
		OnEvent: events.record,
		Now: func() time.Time {
			return *now.Load()
		},
	})

	if err := parked.Add(sshagent.AddedKey{
		PrivateKey:   freshKey(t),
		LifetimeSecs: 3600,
	}, nil); err != nil {
		t.Fatalf("add: %v", err)
	}

	listed := parked.List()
	if len(listed) != 1 || listed[0].GetExpiresAt() == nil {
		t.Fatalf("the parked key has no expiry: %v", listed)
	}

	later := start.Add(2 * time.Hour)
	now.Store(&later)

	if parked.Len() != 0 {
		t.Error("the key outlived its lifetime")
	}

	// The timer fires an hour from now on the real clock, and finds nothing:
	// one expiry, one event.
	want := []agent.LocalKeyEventKind{agent.LocalKeyAdded, agent.LocalKeyExpired}

	if got := events.kinds(); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("events: %v, want %v", got, want)
	}
}

// Forgetting by label drops everything under it — tsh parks a certificate and
// the bare key under one comment — and promotion takes them together, handing
// back the one private half they share.
func TestParkedKeysAreNamedByLabel(t *testing.T) {
	events := &eventLog{}
	parked := agent.NewLocalKeys(agent.LocalKeysOptions{OnEvent: events.record})

	priv := freshKey(t)
	pub := publicOf(t, priv)

	caSigner, err := ssh.NewSignerFromKey(freshKey(t))
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}

	cert := &ssh.Certificate{
		Key:         pub,
		CertType:    ssh.UserCert,
		ValidBefore: ssh.CertTimeInfinity,
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("sign cert: %v", err)
	}

	other := freshKey(t)

	adds := []sshagent.AddedKey{
		{PrivateKey: priv, Certificate: cert, Comment: "teleport:hugo"},
		{PrivateKey: priv, Comment: "teleport:hugo"},
		{PrivateKey: other, Comment: "teleport:hugo"},
	}

	for _, add := range adds {
		if err := parked.Add(add, nil); err != nil {
			t.Fatalf("add: %v", err)
		}
	}

	// Three entries under one label and two different keys: nothing to
	// promote by that name.
	if _, _, err := parked.Take("teleport:hugo"); !errors.Is(err, agent.ErrAmbiguousLocalKey) {
		t.Fatalf("take by an ambiguous label: %v", err)
	}

	if parked.Len() != 3 {
		t.Fatalf("a refused take dropped keys: %d left", parked.Len())
	}

	// By the key's own fingerprint, the certificate over it comes too.
	taken, infos, err := parked.Take(ssh.FingerprintSHA256(pub))
	if err != nil {
		t.Fatalf("take: %v", err)
	}

	if len(infos) != 2 {
		t.Fatalf("took %d entries, want the key and its certificate", len(infos))
	}

	if got, ok := taken.(ed25519.PrivateKey); !ok || !got.Equal(priv) {
		t.Error("the private half handed back is not the parked one")
	}

	if parked.Len() != 1 {
		t.Errorf("%d keys left, want the other one", parked.Len())
	}

	dropped, err := parked.Forget("TELEPORT:HUGO")
	if err != nil {
		t.Fatalf("forget by label: %v", err)
	}

	if len(dropped) != 1 || parked.Len() != 0 {
		t.Errorf("forget dropped %d, %d left", len(dropped), parked.Len())
	}

	if _, err := parked.Forget("teleport:hugo"); !errors.Is(err, agent.ErrNoSuchLocalKey) {
		t.Errorf("forgetting nothing: %v", err)
	}

	var promoted, forgotten int

	for _, kind := range events.kinds() {
		switch kind {
		case agent.LocalKeyPromoted:
			promoted++
		case agent.LocalKeyForgotten:
			forgotten++
		case agent.LocalKeyAdded, agent.LocalKeyExpired:
		}
	}

	if promoted != 2 || forgotten != 1 {
		t.Errorf("%d promoted and %d forgotten events", promoted, forgotten)
	}
}

// Wipe is the seal: everything goes, for the reason given.
func TestParkedKeysGoWithTheSeal(t *testing.T) {
	events := &eventLog{}
	parked := agent.NewLocalKeys(agent.LocalKeysOptions{OnEvent: events.record})

	for range 3 {
		if err := parked.Add(sshagent.AddedKey{PrivateKey: freshKey(t)}, nil); err != nil {
			t.Fatalf("add: %v", err)
		}
	}

	if n := parked.Wipe("dropped with the seal"); n != 3 {
		t.Errorf("wiped %d", n)
	}

	if parked.Len() != 0 {
		t.Error("keys survived the wipe")
	}

	events.mu.Lock()
	defer events.mu.Unlock()

	for _, event := range events.events[3:] {
		if event.Kind != agent.LocalKeyForgotten ||
			!strings.Contains(event.Reason, "seal") {
			t.Errorf("event after the wipe: %v %q", event.Kind, event.Reason)
		}
	}
}
