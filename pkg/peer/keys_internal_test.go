package peer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/gitctx"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// memoryKeys is a key store for the tests. Where the keys are kept is the
// keystore package's business; what these tests are about is which of them a
// peer is allowed to borrow and what the holder does with the request.
type memoryKeys struct {
	mu   sync.Mutex
	keys map[string]ssh.Signer
	refs []*ladulasv1.KeyRef
}

func (m *memoryKeys) KeyRefs() []*ladulasv1.KeyRef {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]*ladulasv1.KeyRef(nil), m.refs...)
}

func (m *memoryKeys) Signer(
	fingerprint string,
) (ssh.Signer, *storepb.StoredKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	signer, ok := m.keys[fingerprint]
	if !ok {
		return nil, nil, trust.ErrNoSuchPeer
	}

	return signer, nil, nil
}

// generate adds a key and returns how the protocol refers to it.
func (m *memoryKeys) generate(t *testing.T, label string) *ladulasv1.KeyRef {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, label)
	if err != nil {
		t.Fatalf("marshal a key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(pem.EncodeToMemory(block))
	if err != nil {
		t.Fatalf("parse a key: %v", err)
	}

	ref := &ladulasv1.KeyRef{
		Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		Algorithm:   signer.PublicKey().Type(),
		PublicKey:   signer.PublicKey().Marshal(),
		Label:       label,
		Comment:     label + "@example.test",
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.keys == nil {
		m.keys = map[string]ssh.Signer{}
	}

	m.keys[ref.GetFingerprint()] = signer
	m.refs = append(m.refs, ref)

	return ref
}

// hold adds the public half of a key the instance is to be treated as holding,
// which is what accepting a handover leaves behind (decision S). No signer comes
// with it: what it is used to ask is which key set a reference lands in.
func (m *memoryKeys) hold(ref *ladulasv1.KeyRef) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.refs = append(m.refs, ref)
}

// allowKey grants a peer the right to sign with a key, which pairing on its own
// never does (§7).
func (i *instance) allowKey(t *testing.T, peer string, keys ...string) {
	t.Helper()

	record, ok := i.store.Peer(peer)
	if !ok {
		t.Fatalf("%s has no record of %s", i.identity.Name(), peer)
	}

	_, err := i.store.SetPeerDirections(peer, trust.Directions{
		MayApprove:  record.GetMayApprove(),
		MayRequest:  record.GetMayRequest(),
		AllowedKeys: keys,
	})
	if err != nil {
		t.Fatalf("allow keys: %v", err)
	}
}

// waitForOfferedKey blocks until the link has learned what the holder offers,
// which happens when the presence stream comes up rather than when a key is
// wanted — an agent answering ssh cannot wait for a round trip.
func waitForOfferedKey(t *testing.T, requester *instance, fingerprint string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		for _, ref := range requester.node.RemoteKeyRefs() {
			if ref.GetFingerprint() == fingerprint {
				return
			}
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("%s never learned that a peer offers %s",
		requester.identity.Name(), fingerprint)
}

// waitForLink blocks until the requester's link to a peer is up, which is what
// makes "the peer offers nothing" distinguishable from "nobody has asked yet".
func waitForLink(t *testing.T, requester *instance, fingerprint string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		if l := requester.node.link(fingerprint); l != nil {
			if online, _, _ := l.State(); online {
				return
			}
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("%s never linked to %s", requester.identity.Name(), fingerprint)
}

func readAudit(t *testing.T, path string) []*ladulasv1.AuditEntry {
	t.Helper()

	entries, err := approval.ReadAuditLog(path, 0)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}

	return entries
}

// askToSign goes straight to the holder's RPC, the way a compromised requester
// would: past the offered-key index, which is only ever this side's cache of
// what it was told.
func askToSign(
	ctx context.Context,
	requester, holder *instance,
	req *ladulasv1.ApprovalRequest,
	payload []byte,
) error {
	l := requester.node.link(holder.identity.Fingerprint())
	if l == nil {
		return trust.ErrNoSuchPeer
	}

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(req)
	if err != nil {
		return err
	}

	client := ladulasv1connect.NewKeyServiceClient(
		l.client.HTTP(), l.client.URL(l.addresses()[0]))

	_, err = client.RemoteSign(ctx, connect.NewRequest(&ladulasv1.RemoteSignRequest{
		Request:    body,
		Payload:    payload,
		WrapSshsig: true,
	}))

	return err
}

// commitObject is a git commit object of the shape ladulas-sign submits: the
// whole thing, unhashed, so the approver can see what it is signing.
func commitObject(subject string) []byte {
	return []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author Test Author <author@example.test> 1754700000 +0200\n" +
		"committer Test Author <author@example.test> 1754700000 +0200\n" +
		"\n" + subject + "\n")
}

// signRequest is what a keyless requester builds before handing the payload to
// a holder: the same shape the local signing socket builds (§5).
func signRequest(key *ladulasv1.KeyRef, object []byte) *ladulasv1.ApprovalRequest {
	digest, _ := sshsig.Hash(sshsig.DefaultHash, object)

	return &ladulasv1.ApprovalRequest{
		RequestId: identity.NewRequestID(),
		Kind:      ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
		Key:       key,
		Timeout:   durationpb.New(10 * time.Second),
		Operation: &ladulasv1.ApprovalRequest_Sshsig{
			Sshsig: &ladulasv1.SshsigRequest{
				Namespace:     sshsig.GitNamespace,
				HashAlgorithm: sshsig.DefaultHash,
				MessageDigest: digest,
				GitContext: &ladulasv1.GitContext{
					RepositoryPath: "/srv/build/ladulas",
					Branch:         "main",
					Object:         object,
				},
			},
		},
	}
}

// TestKeylessRequesterBorrowsASignature is M4's headline: a machine that holds
// no private key gets a commit signed by the machine that does.
func TestKeylessRequesterBorrowsASignature(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)

	// The headless box has nobody at it and no key of its own.
	headless.drop()

	key := desktop.keys.generate(t, "work")
	desktop.allowKey(t, headless.identity.Fingerprint(), key.GetFingerprint())

	waitForOfferedKey(t, headless, key.GetFingerprint())

	desktop.human.set(approveAnswer("approved at the desktop"), nil)

	object := commitObject("tighten the socket permissions")
	req := signRequest(key, object)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := headless.node.RemoteSign(ctx, req, object, true)
	if err != nil {
		t.Fatalf("remote sign: %v", err)
	}

	if len(resp.GetSignature()) == 0 {
		t.Fatal("the holder approved without signing")
	}

	// The signature is over the SSHSIG wrapper the holder built, and it verifies
	// under the key the holder offered — which is the whole of what a borrowed
	// signature has to be.
	pub, err := ssh.ParsePublicKey(key.GetPublicKey())
	if err != nil {
		t.Fatalf("parse the key: %v", err)
	}

	blob, err := sshsig.SigningBlobFor(sshsig.GitNamespace, sshsig.DefaultHash, object)
	if err != nil {
		t.Fatalf("build the blob: %v", err)
	}

	var sig ssh.Signature

	if err := ssh.Unmarshal(resp.GetSignature(), &sig); err != nil {
		t.Fatalf("parse the signature: %v", err)
	}

	if err := pub.Verify(blob, &sig); err != nil {
		t.Errorf("the borrowed signature does not verify: %v", err)
	}

	// The desktop was shown the commit, from a named machine, and checked for
	// itself that the object it displayed is the one being signed (§5).
	shown := desktop.human.last()
	if shown == nil {
		t.Fatal("the desktop was never asked")
	}

	if shown.Msg.GetRequester().GetInstanceId() != headless.identity.Fingerprint() {
		t.Errorf("the desktop was shown %q as the requester",
			shown.Msg.GetRequester().GetInstanceId())
	}

	git := shown.Msg.GetSshsig().GetGitContext()

	if !git.GetVerifiedAgainstPayload() {
		t.Errorf("the holder did not verify the commit: %s",
			git.GetVerificationError())
	}

	if got := git.GetParsed().GetSubject(); got != "tighten the socket permissions" {
		t.Errorf("the desktop was shown the subject %q", got)
	}

	// And the requester's own log holds the holder's signature over the answer,
	// not merely its own account of it (§18).
	requireSignedDecision(t, headless.audit, true)
	requireSignedDecision(t, desktop.audit, false)
}

// TestAKeyHeldHereIsNoLongerBorrowed: the same key in two stores is what a
// handover leaves behind on purpose (decision S), and from then on the copy here
// is the one that gets used.
//
// It leaves the remote key set, because that is the set everything reaches into
// a peer for — the agent's identity list and both sign paths — and a signature
// made here can be covered by a standing delegation while one made on the holder
// is the holder's decision every time (decision P). The row stays, saying the
// key is held in both places, which is what a listing is for.
func TestAKeyHeldHereIsNoLongerBorrowed(t *testing.T) {
	desktop := newInstance(t, "desktop")
	laptop := newInstance(t, "laptop")

	pair(t, desktop, laptop)

	key := desktop.keys.generate(t, "old")
	desktop.allowKey(t, laptop.identity.Fingerprint(), key.GetFingerprint())

	waitForOfferedKey(t, laptop, key.GetFingerprint())

	// The copy arrives, which is all `keys accept` leaves behind that matters
	// here: a key of that fingerprint in the store.
	laptop.keys.hold(key)

	if refs := laptop.node.RemoteKeyRefs(); len(refs) != 0 {
		t.Errorf("the laptop still borrows %d keys it holds itself", len(refs))
	}

	borrowed := laptop.node.BorrowedKeys()
	if len(borrowed) != 1 {
		t.Fatalf("the laptop lists %d borrowed keys", len(borrowed))
	}

	if !borrowed[0].GetHeldHere() {
		t.Error("the row does not say the key is held here as well")
	}

	if borrowed[0].GetPeer() != "desktop" {
		t.Errorf("the row no longer says whose copy it is: %q",
			borrowed[0].GetPeer())
	}
}

// TestBorrowingNeedsTheKeyToBeGranted: pairing grants directions, never keys,
// so an unmodified M3 pairing borrows nothing.
func TestBorrowingNeedsTheKeyToBeGranted(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	key := desktop.keys.generate(t, "work")

	// The link is up, and offers nothing.
	waitForLink(t, headless, desktop.identity.Fingerprint())

	if refs := headless.node.RemoteKeyRefs(); len(refs) != 0 {
		t.Fatalf("a freshly paired peer already offers %d keys", len(refs))
	}

	// Asking anyway is refused, and refused without anyone being prompted:
	// a request that could not produce a signature should not put a commit on
	// somebody's screen.
	before := desktop.human.count()

	object := commitObject("a commit nobody granted a key for")
	req := signRequest(key, object)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// With nothing offered there is no holder to reach at all.
	if _, err := headless.node.RemoteSign(ctx, req, object, true); err == nil {
		t.Fatal("a key nobody offered was borrowed anyway")
	}

	// And going straight to the holder's RPC, as a compromised requester would,
	// is refused there.
	if err := askToSign(ctx, headless, desktop, req, object); err == nil {
		t.Fatal("the holder signed with a key it never granted")
	} else if !strings.Contains(err.Error(), "may not sign") &&
		!strings.Contains(err.Error(), "no key") {
		t.Errorf("the refusal reads %q", err.Error())
	}

	if asked := desktop.human.count() - before; asked != 0 {
		t.Errorf("the desktop was prompted %d times for a key it never granted", asked)
	}
}

// TestTheHolderShowsThePayloadNotTheClaim is the M2 invariant in the form the
// remote path gives it (§5, §16).
//
// When the holder builds the wrapper it also takes the object from the payload,
// so a requester that describes one commit and hands over another does not get
// caught — it gets ignored. The prompt shows the commit that is about to be
// signed because there is nowhere else for the prompt to have got it from.
func TestTheHolderShowsThePayloadNotTheClaim(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	key := desktop.keys.generate(t, "work")
	desktop.allowKey(t, headless.identity.Fingerprint(), key.GetFingerprint())
	waitForOfferedKey(t, headless, key.GetFingerprint())

	desktop.human.set(approveAnswer("approved at the desktop"), nil)

	innocuous := commitObject("fix a typo in the README")
	actual := commitObject("ship the keys to an attacker")

	// The request describes the innocuous commit; the payload is the other one.
	req := signRequest(key, innocuous)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if _, err := headless.node.RemoteSign(ctx, req, actual, true); err != nil {
		t.Fatalf("remote sign: %v", err)
	}

	shown := desktop.human.last()
	if shown == nil {
		t.Fatal("the desktop never saw the request at all")
	}

	git := shown.Msg.GetSshsig().GetGitContext()

	if !git.GetVerifiedAgainstPayload() {
		t.Errorf("the holder did not verify the commit: %s",
			git.GetVerificationError())
	}

	if got := git.GetParsed().GetSubject(); got != "ship the keys to an attacker" {
		t.Errorf("the desktop was shown %q rather than the commit being signed", got)
	}

	// And the digest the prompt is built around is the payload's, not the one
	// the request arrived with.
	digest, err := sshsig.Hash(sshsig.DefaultHash, actual)
	if err != nil {
		t.Fatalf("hash the payload: %v", err)
	}

	if got := shown.Msg.GetSshsig().GetMessageDigest(); string(got) != string(digest) {
		t.Error("the prompt was built around the digest the requester claimed")
	}
}

// TestAMismatchedObjectIsDenied covers the other half: when the requester hands
// over an already-wrapped blob — the agent path, where there is only a digest —
// the object it sends alongside is checked against that digest and a mismatch
// is a hard denial rather than a prompt that lies (§5, §9).
func TestAMismatchedObjectIsDenied(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	key := desktop.keys.generate(t, "work")
	desktop.allowKey(t, headless.identity.Fingerprint(), key.GetFingerprint())
	waitForOfferedKey(t, headless, key.GetFingerprint())

	desktop.human.set(approveAnswer("the human would have said yes"), nil)

	innocuous := commitObject("fix a typo in the README")
	actual := commitObject("ship the keys to an attacker")

	blob, err := sshsig.SigningBlobFor(
		sshsig.GitNamespace, sshsig.DefaultHash, actual)
	if err != nil {
		t.Fatalf("build the blob: %v", err)
	}

	req := signRequest(key, innocuous)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := headless.node.RemoteSign(ctx, req, blob, false)
	if err != nil {
		t.Fatalf("remote sign: %v", err)
	}

	decision, _, err := identity.VerifyApproval(resp.GetApproval())
	if err != nil {
		t.Fatalf("verify the answer: %v", err)
	}

	if decision.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Fatal("a request whose context describes a different commit was approved")
	}

	if decision.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_HARD_RULE {
		t.Errorf("the refusal came from %v rather than a hard rule",
			decision.GetSource())
	}

	if len(resp.GetSignature()) != 0 {
		t.Error("a denied request came back with a signature")
	}

	// The object the holder weighed is the one the requester sent — it has no
	// other — and it did not parse to the digest inside the blob.
	object, err := gitctx.ParseObject(innocuous)
	if err != nil {
		t.Fatalf("the test's own object does not parse: %v", err)
	}

	if object.GetSubject() != "fix a typo in the README" {
		t.Fatalf("the test's own object says %q", object.GetSubject())
	}
}

// TestAnOpaquePayloadIsDeniedWhateverItIsCalled: the holder classifies the
// bytes, so a request dressed up as a git signature over something that is
// neither an SSHSIG blob nor a login is still hard-denied (§9).
func TestAnOpaquePayloadIsDeniedWhateverItIsCalled(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	key := desktop.keys.generate(t, "work")
	desktop.allowKey(t, headless.identity.Fingerprint(), key.GetFingerprint())
	waitForOfferedKey(t, headless, key.GetFingerprint())

	desktop.human.set(approveAnswer("the human would have said yes"), nil)

	junk := []byte("this is not a signing payload at all")

	req := signRequest(key, junk)
	req.GetSshsig().GetGitContext().Object = nil

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// wrapSSHSIG false: the payload claims to be the exact blob to sign.
	resp, err := headless.node.RemoteSign(ctx, req, junk, false)
	if err != nil {
		t.Fatalf("remote sign: %v", err)
	}

	decision, _, err := identity.VerifyApproval(resp.GetApproval())
	if err != nil {
		t.Fatalf("verify the answer: %v", err)
	}

	if decision.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Fatal("an unclassifiable payload was signed")
	}

	if decision.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_HARD_RULE {
		t.Errorf("the refusal came from %v rather than a hard rule",
			decision.GetSource())
	}
}

// TestABorrowedDenialIsFinal: the holder's refusal comes back as an answer with
// a reason on it, and nothing tries anywhere else.
func TestABorrowedDenialIsFinal(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	key := desktop.keys.generate(t, "work")
	desktop.allowKey(t, headless.identity.Fingerprint(), key.GetFingerprint())
	waitForOfferedKey(t, headless, key.GetFingerprint())

	desktop.human.set(denyAnswer("I did not make that commit"), nil)

	object := commitObject("a commit nobody wants")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := headless.node.RemoteSign(
		ctx, signRequest(key, object), object, true)
	if err != nil {
		t.Fatalf("remote sign: %v", err)
	}

	if len(resp.GetSignature()) != 0 {
		t.Fatal("a refusal came back with a signature")
	}

	decision, _, err := identity.VerifyApproval(resp.GetApproval())
	if err != nil {
		t.Fatalf("verify the answer: %v", err)
	}

	if decision.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Fatalf("the answer says %v", decision.GetDecision())
	}

	if !strings.Contains(decision.GetReason(), "I did not make that commit") {
		t.Errorf("the requester was not told why: %q", decision.GetReason())
	}

	// The requester's log records the refusal with the holder's signature on it.
	entries := readAudit(t, headless.audit)

	var found bool

	for _, entry := range entries {
		if entry.GetResponse().GetDecision() == ladulasv1.Decision_DECISION_DENY &&
			entry.GetRemoteApproval() != nil {
			found = true
		}
	}

	if !found {
		t.Error("the refusal is not in the requester's log as the holder's answer")
	}
}

// TestConcurrentBorrowedSignatures runs the borrowing path under the race
// detector: several sign requests at once share the link, its key cache and the
// engine's fan-out, and none of them may see another's answer.
func TestConcurrentBorrowedSignatures(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	key := desktop.keys.generate(t, "work")
	desktop.allowKey(t, headless.identity.Fingerprint(), key.GetFingerprint())
	waitForOfferedKey(t, headless, key.GetFingerprint())

	desktop.human.set(approveAnswer("approved at the desktop"), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const requests = 8

	type outcome struct {
		object    []byte
		signature []byte
		err       error
	}

	results := make(chan outcome, requests)

	var wg sync.WaitGroup

	for i := range requests {
		wg.Add(1)

		go func() {
			defer wg.Done()

			object := commitObject("commit number " + string(rune('a'+i)))

			resp, err := headless.node.RemoteSign(
				ctx, signRequest(key, object), object, true)
			if err != nil {
				results <- outcome{err: err}

				return
			}

			results <- outcome{object: object, signature: resp.GetSignature()}
		}()
	}

	wg.Wait()
	close(results)

	pub, err := ssh.ParsePublicKey(key.GetPublicKey())
	if err != nil {
		t.Fatalf("parse the key: %v", err)
	}

	var seen int

	for result := range results {
		if result.err != nil {
			t.Errorf("remote sign: %v", result.err)

			continue
		}

		seen++

		// Each answer has to be the signature over that request's own commit,
		// and not over one of the others.
		blob, err := sshsig.SigningBlobFor(
			sshsig.GitNamespace, sshsig.DefaultHash, result.object)
		if err != nil {
			t.Fatalf("build the blob: %v", err)
		}

		var sig ssh.Signature

		if err := ssh.Unmarshal(result.signature, &sig); err != nil {
			t.Fatalf("parse a signature: %v", err)
		}

		if err := pub.Verify(blob, &sig); err != nil {
			t.Errorf("a signature covers a different commit: %v", err)
		}
	}

	if seen != requests {
		t.Errorf("%d of %d requests came back", seen, requests)
	}
}
