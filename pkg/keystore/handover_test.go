package keystore_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/pkg/keystore"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// A portable key handed to a peer is the one thing that moves key material
// (decision S), so these tests are as much about what does not happen as about
// what does: nothing usable appears before an acceptance, a refusal leaves
// nothing behind, and a hardware key is refused rather than quietly skipped.

const peerFingerprint = "SHA256:iAmAPeerAndThisIsMyFingerprint00000000000000"

func portablePEM(t *testing.T, comment string) []byte {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		t.Fatalf("marshal the key: %v", err)
	}

	return pem.EncodeToMemory(block)
}

func offerKey(t *testing.T, v *keystore.Vault, label string) *storepb.PendingKeyOffer {
	t.Helper()

	offer, err := v.AddKeyOffer(peerFingerprint, "phone", label, "", "",
		portablePEM(t, "hugo@phone"), time.Now())
	if err != nil {
		t.Fatalf("add the key offer: %v", err)
	}

	return offer
}

func TestKeyOfferIsNotAKeyUntilAccepted(t *testing.T) {
	v, opts := newVault(t)

	offer := offerKey(t, v, "from the phone")

	if len(v.Keys()) != 0 {
		t.Fatalf("an unanswered offer became a key: %d keys", len(v.Keys()))
	}

	if len(v.KeyRefs()) != 0 {
		t.Errorf("an unanswered offer is offered by the agent")
	}

	if _, _, err := v.Signer(offer.GetFingerprint()); err == nil {
		t.Errorf("an unanswered offer can sign")
	}

	pending := v.PendingKeyOffers()
	if len(pending) != 1 {
		t.Fatalf("the offer is not waiting: %d offers", len(pending))
	}

	if pending[0].GetPeerName() != "phone" {
		t.Errorf("the offer forgot who sent it: %q", pending[0].GetPeerName())
	}

	// It survives a restart, which is the whole reason it is in the store: the
	// side that sent it is typically a phone that cannot be dialled back.
	reopened, err := keystore.Open(opts)
	if err != nil {
		t.Fatalf("reopen the store: %v", err)
	}

	if len(reopened.PendingKeyOffers()) != 1 {
		t.Fatalf("the offer did not survive a restart")
	}

	key, err := reopened.AcceptKeyOffer(offer.GetId(), "")
	if err != nil {
		t.Fatalf("accept the offer: %v", err)
	}

	if key.GetOrigin() != storepb.KeyOrigin_KEY_ORIGIN_RECEIVED {
		t.Errorf("an accepted key does not say where it came from: %s",
			key.GetOrigin())
	}

	if key.GetReceivedFrom().GetPeerFingerprint() != peerFingerprint {
		t.Errorf("an accepted key does not name the peer that sent it")
	}

	if key.GetLabel() != "from the phone" {
		t.Errorf("the sender's label was not kept: %q", key.GetLabel())
	}

	if len(reopened.PendingKeyOffers()) != 0 {
		t.Errorf("an accepted offer is still waiting to be answered")
	}

	if _, _, err := reopened.Signer(key.GetFingerprint()); err != nil {
		t.Errorf("an accepted key cannot sign: %v", err)
	}
}

func TestAcceptKeyOfferRenames(t *testing.T) {
	v, _ := newVault(t)

	if _, err := v.GenerateKey("work", ""); err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	offer := offerKey(t, v, "work")

	// The sender's label collides, which is an ordinary thing for two stores to
	// disagree about and not a reason to lose the key.
	_, err := v.AcceptKeyOffer(offer.GetId(), "")
	if err == nil {
		t.Fatalf("a colliding label was accepted")
	}

	if len(v.PendingKeyOffers()) != 1 {
		t.Fatalf("a failed acceptance dropped the offer")
	}

	key, err := v.AcceptKeyOffer(offer.GetId(), "work-phone")
	if err != nil {
		t.Fatalf("accept under another label: %v", err)
	}

	if key.GetLabel() != "work-phone" {
		t.Errorf("the new label was not used: %q", key.GetLabel())
	}
}

func TestRefuseKeyOfferKeepsNothing(t *testing.T) {
	v, _ := newVault(t)

	offer := offerKey(t, v, "unwanted")

	if err := v.RefuseKeyOffer(offer.GetId()); err != nil {
		t.Fatalf("refuse the offer: %v", err)
	}

	if len(v.PendingKeyOffers()) != 0 || len(v.Keys()) != 0 {
		t.Errorf("a refusal left something behind")
	}

	if err := v.RefuseKeyOffer(offer.GetId()); !errors.Is(err, keystore.ErrNoSuchOffer) {
		t.Errorf("refusing twice: %v", err)
	}
}

func TestKeyOffersAreBounded(t *testing.T) {
	v, _ := newVault(t)

	for i := range keystore.MaxPendingKeyOffers {
		_, err := v.AddKeyOffer(peerFingerprint, "phone", "", "", "",
			portablePEM(t, "hugo@phone"), time.Now())
		if err != nil {
			t.Fatalf("offer %d: %v", i, err)
		}
	}

	_, err := v.AddKeyOffer(peerFingerprint, "phone", "", "", "",
		portablePEM(t, "hugo@phone"), time.Now())
	if !errors.Is(err, keystore.ErrTooManyOffers) {
		t.Errorf("a peer can fill the store with offers: %v", err)
	}
}

func TestResendReplacesTheOffer(t *testing.T) {
	v, _ := newVault(t)

	keyPEM := portablePEM(t, "hugo@phone")

	first, err := v.AddKeyOffer(
		peerFingerprint, "phone", "same", "", "", keyPEM, time.Now())
	if err != nil {
		t.Fatalf("first offer: %v", err)
	}

	second, err := v.AddKeyOffer(
		peerFingerprint, "phone", "same", "", "", keyPEM, time.Now())
	if err != nil {
		t.Fatalf("second offer: %v", err)
	}

	pending := v.PendingKeyOffers()
	if len(pending) != 1 {
		t.Fatalf("a resend piled up: %d offers", len(pending))
	}

	if pending[0].GetId() != second.GetId() {
		t.Errorf("the resend did not replace the first offer")
	}

	if err := v.RefuseKeyOffer(first.GetId()); !errors.Is(err, keystore.ErrNoSuchOffer) {
		t.Errorf("the replaced offer is still answerable: %v", err)
	}
}

func TestOfferOfAKeyAlreadyHeld(t *testing.T) {
	v, _ := newVault(t)

	keyPEM := portablePEM(t, "hugo@phone")

	if _, err := v.ImportKey(keyPEM, "", "mine"); err != nil {
		t.Fatalf("import the key: %v", err)
	}

	_, err := v.AddKeyOffer(
		peerFingerprint, "phone", "theirs", "", "", keyPEM, time.Now())
	if !errors.Is(err, keystore.ErrDuplicateKey) {
		t.Errorf("a key already held was offered again: %v", err)
	}
}

func TestPortableKeyAndHandoverRecord(t *testing.T) {
	v, _ := newVault(t)

	key, err := v.GenerateKey("work", "")
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	sendable, err := v.PortableKey("work")
	if err != nil {
		t.Fatalf("resolve the key by label: %v", err)
	}

	if len(sendable.GetPrivateKey()) == 0 {
		t.Errorf("a portable key came back without its private half")
	}

	at := time.Now().Truncate(time.Second)

	// Sending the same key to the same peer twice is one fact, not two.
	for range 2 {
		queued, err := v.QueueHandover(peerFingerprint, "phone", sendable, at)
		if err != nil {
			t.Fatalf("queue the handover: %v", err)
		}

		if err := v.CompleteHandover(queued.GetId(), at); err != nil {
			t.Fatalf("complete the handover: %v", err)
		}
	}

	if len(v.QueuedHandovers()) != 0 {
		t.Errorf("a delivered handover is still queued")
	}

	var stored *storepb.StoredKey

	for _, k := range v.Keys() {
		if k.GetFingerprint() == key.GetFingerprint() {
			stored = k
		}
	}

	if len(stored.GetHandedTo()) != 1 {
		t.Fatalf("the handover record: %d entries", len(stored.GetHandedTo()))
	}

	if stored.GetHandedTo()[0].GetPeerName() != "phone" {
		t.Errorf("the handover does not say who has it")
	}

	if !stored.GetHandedTo()[0].GetAt().AsTime().Equal(at.UTC()) {
		t.Errorf("the handover does not say when")
	}
}

func TestPortableKeyRefusesAHardwareKey(t *testing.T) {
	v, _, _ := newHardwareVault(t)

	if _, err := v.GenerateHardwareKey("enclave", ""); err != nil {
		t.Fatalf("generate a hardware key: %v", err)
	}

	_, err := v.PortableKey("enclave")
	if !errors.Is(err, keystore.ErrHardwareKey) {
		t.Errorf("a hardware key was offered up for sending: %v", err)
	}

	if _, err := v.PortableKey("nothing"); !errors.Is(err, keystore.ErrNoSuchKey) {
		t.Errorf("an unknown key: %v", err)
	}
}

func TestDropPeerKeyOffers(t *testing.T) {
	v, _ := newVault(t)

	offerKey(t, v, "from the phone")

	if err := v.DropPeerKeyOffers("SHA256:somebodyelse"); err != nil {
		t.Fatalf("drop another peer's offers: %v", err)
	}

	if len(v.PendingKeyOffers()) != 1 {
		t.Fatalf("another peer's revocation dropped this offer")
	}

	if err := v.DropPeerKeyOffers(peerFingerprint); err != nil {
		t.Fatalf("drop the peer's offers: %v", err)
	}

	if len(v.PendingKeyOffers()) != 0 {
		t.Errorf("revoking a peer left its key offer behind")
	}
}

// refusingGate stands in for a dismissed Face ID sheet.
type refusingGate struct {
	reasons []string
	refuse  bool
}

func (g *refusingGate) Authorize(reason string) error {
	g.reasons = append(g.reasons, reason)

	if g.refuse {
		return keystore.ErrSignatureRefused
	}

	return nil
}

func TestSignGateGuardsPortableKeys(t *testing.T) {
	gate := &refusingGate{}

	opts := keystore.Options{
		Dir:              t.TempDir(),
		Keyring:          &keystore.MemoryKeyring{},
		Passphrase:       staticPassphrase(testPassphrase),
		InstanceName:     "test-phone",
		ScryptWorkFactor: 10,
		SignGate:         gate,
	}

	v, err := keystore.Create(opts)
	if err != nil {
		t.Fatalf("create the store: %v", err)
	}

	key, err := v.GenerateKey("portable", "")
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	signer, _, err := v.Signer(key.GetFingerprint())
	if err != nil {
		t.Fatalf("get a signer: %v", err)
	}

	if len(gate.reasons) != 0 {
		t.Errorf("the gate was asked before a signature was wanted")
	}

	if _, err := signer.Sign(rand.Reader, []byte("something")); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if len(gate.reasons) != 1 {
		t.Fatalf("the gate was not asked: %d prompts", len(gate.reasons))
	}

	if !strings.Contains(gate.reasons[0], "portable") {
		t.Errorf("the prompt does not name the key: %q", gate.reasons[0])
	}

	gate.refuse = true

	_, err = signer.Sign(rand.Reader, []byte("something else"))
	if !errors.Is(err, keystore.ErrSignatureRefused) {
		t.Errorf("a refused prompt still signed: %v", err)
	}
}
