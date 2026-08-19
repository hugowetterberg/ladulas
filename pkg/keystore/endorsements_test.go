package keystore_test

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// The store's half of decision AG: whether a promise may be acted on here, and
// what a retraction takes with it.

func endorsedVault(t *testing.T) (*keystore.Vault, *storepb.StoredKey) {
	t.Helper()

	v, _ := newVault(t)

	key, err := v.GenerateKey("work", "hugo@guppy")
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	return v, key
}

// endorsementFor builds a promise about a key, signed the way one arrives.
func endorsementFor(
	t *testing.T, v *keystore.Vault, key *storepb.StoredKey,
	id, issuer, requester string, ttl time.Duration,
) (*ladulasv1.SignedEndorsement, *ladulasv1.Endorsement) {
	t.Helper()

	signer, err := v.PortableSigner(key.GetFingerprint())
	if err != nil {
		t.Fatalf("portable signer: %v", err)
	}

	now := time.Now()

	e := &ladulasv1.Endorsement{
		EndorsementId: id,
		Scope: &ladulasv1.GrantScope{
			KeyFingerprint:      key.GetFingerprint(),
			Kind:                ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
			RequesterInstanceId: requester,
		},
		CreatedAt:            timestamppb.New(now),
		ExpiresAt:            timestamppb.New(now.Add(ttl)),
		IssuerFingerprint:    issuer,
		IssuerName:           "iPhone",
		RequesterFingerprint: requester,
		RequesterName:        "pietro",
		KeyFingerprint:       key.GetFingerprint(),
	}

	signed, err := v.Identity().SignEndorsement(e, signer)
	if err != nil {
		t.Fatalf("sign the endorsement: %v", err)
	}

	return signed, e
}

func pairApprover(t *testing.T, v *keystore.Vault, fingerprint string) {
	t.Helper()

	if err := v.PutPeer(&storepb.TrustRecord{
		Fingerprint:   fingerprint,
		Name:          "iPhone",
		MayApprove:    true,
		MayUseAllKeys: true,
	}); err != nil {
		t.Fatalf("pair: %v", err)
	}
}

// Both halves of the narrow rule: the key has to be here, and the issuer has to
// be somebody this instance would have taken a live approval from. Each closes
// a hole the other does not.
func TestAnEndorsementIsUsableOnlyFromAPairedApproverOfAKeyHeldHere(t *testing.T) {
	v, key := endorsedVault(t)

	signed, e := endorsementFor(
		t, v, key, "grant-1", "SHA256:iphone", "SHA256:pietro", time.Hour)

	if err := v.AddEndorsement(signed, e, true); err != nil {
		t.Fatalf("add: %v", err)
	}

	// The key is here and the issuer is a stranger.
	usable, err := v.UsableEndorsements()
	if err != nil {
		t.Fatalf("usable: %v", err)
	}

	if len(usable) != 0 {
		t.Fatal("a promise from an unpaired machine was usable")
	}

	if got := v.InertBecause(e); got == "" {
		t.Error("an unusable promise gave no reason")
	}

	// Pair the issuer as an approver and it becomes usable.
	pairApprover(t, v, "SHA256:iphone")

	usable, err = v.UsableEndorsements()
	if err != nil {
		t.Fatalf("usable: %v", err)
	}

	if len(usable) != 1 {
		t.Fatalf("a promise from a paired approver was not usable: %d", len(usable))
	}

	if got := v.InertBecause(e); got != "" {
		t.Errorf("a usable promise says it is inert: %q", got)
	}

	// A promise about a key this instance does not hold is carried, not acted
	// on — which is the ordinary state of the requester's own copy.
	elsewhere, key2 := endorsedVault(t)
	other, otherE := endorsementFor(
		t, elsewhere, key2, "grant-2", "SHA256:iphone", "SHA256:pietro", time.Hour)

	if err := v.AddEndorsement(other, otherE, false); err != nil {
		t.Fatalf("add: %v", err)
	}

	usable, err = v.UsableEndorsements()
	if err != nil {
		t.Fatalf("usable: %v", err)
	}

	if len(usable) != 1 {
		t.Errorf("a promise about a key held elsewhere was usable: %d", len(usable))
	}
}

// A retraction takes the promise with it, and outlives it: the endorsement is
// carried by the requester, so one that arrives after the retraction has to be
// refused rather than honoured.
func TestARetractionDropsAndKeepsRefusing(t *testing.T) {
	v, key := endorsedVault(t)

	pairApprover(t, v, "SHA256:iphone")

	signed, e := endorsementFor(
		t, v, key, "grant-1", "SHA256:iphone", "SHA256:pietro", time.Hour)

	if err := v.AddEndorsement(signed, e, true); err != nil {
		t.Fatalf("add: %v", err)
	}

	signer, err := v.PortableSigner(key.GetFingerprint())
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	r := &ladulasv1.Retraction{
		RetractionId:      "r1",
		KeyFingerprint:    key.GetFingerprint(),
		EndorsementId:     "grant-1",
		IssuedAt:          timestamppb.Now(),
		RememberUntil:     timestamppb.New(time.Now().Add(2 * time.Hour)),
		IssuerFingerprint: ssh.FingerprintSHA256(v.Identity().PublicKey()),
		IssuerName:        "guppy",
	}

	signedR, err := v.Identity().SignRetraction(r, signer)
	if err != nil {
		t.Fatalf("sign the retraction: %v", err)
	}

	fresh, err := v.AddRetraction(signedR, r)
	if err != nil {
		t.Fatalf("retract: %v", err)
	}

	if !fresh {
		t.Error("a retraction nothing had heard of was not news")
	}

	held, err := v.Endorsements()
	if err != nil {
		t.Fatalf("endorsements: %v", err)
	}

	if len(held) != 0 {
		t.Fatalf("the retracted promise is still held: %d", len(held))
	}

	// The one that matters: the requester still has its copy and will present
	// it. Taking it back has to keep meaning something after the artifact comes
	// round again.
	if err := v.AddEndorsement(signed, e, false); err == nil {
		t.Fatal("a retracted promise was accepted again")
	}

	// And the same retraction arriving twice is not news, which is what stops
	// gossip bouncing one between two holders for as long as it is remembered.
	again, err := v.AddRetraction(signedR, r)
	if err != nil {
		t.Fatalf("retract again: %v", err)
	}

	if again {
		t.Error("a retraction already held was reported as news")
	}
}

// Retracting by time takes back every promise made up to that moment, which is
// what somebody reaches for when a key may have leaked.
func TestARetractionByTimeTakesBackEverythingOlder(t *testing.T) {
	v, key := endorsedVault(t)

	pairApprover(t, v, "SHA256:iphone")

	signed, e := endorsementFor(
		t, v, key, "grant-1", "SHA256:iphone", "SHA256:pietro", time.Hour)

	if err := v.AddEndorsement(signed, e, true); err != nil {
		t.Fatalf("add: %v", err)
	}

	signer, err := v.PortableSigner(key.GetFingerprint())
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	r := &ladulasv1.Retraction{
		RetractionId:      "r-all",
		KeyFingerprint:    key.GetFingerprint(),
		IssuedBefore:      timestamppb.New(time.Now().Add(time.Minute)),
		IssuedAt:          timestamppb.Now(),
		RememberUntil:     timestamppb.New(time.Now().Add(9 * time.Hour)),
		IssuerFingerprint: ssh.FingerprintSHA256(v.Identity().PublicKey()),
		IssuerName:        "guppy",
		Reason:            "the key may have leaked",
	}

	signedR, err := v.Identity().SignRetraction(r, signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := v.AddRetraction(signedR, r); err != nil {
		t.Fatalf("retract: %v", err)
	}

	held, err := v.Endorsements()
	if err != nil {
		t.Fatalf("endorsements: %v", err)
	}

	if len(held) != 0 {
		t.Fatalf("a promise older than the retraction survived: %d", len(held))
	}
}

// A retraction is about one key, and a holder of one key must not be able to
// take back a promise about another — which is why the key is matched as well
// as the identifier.
func TestARetractionDoesNotReachAnotherKey(t *testing.T) {
	v, key := endorsedVault(t)

	pairApprover(t, v, "SHA256:iphone")

	signed, e := endorsementFor(
		t, v, key, "grant-1", "SHA256:iphone", "SHA256:pietro", time.Hour)

	if err := v.AddEndorsement(signed, e, true); err != nil {
		t.Fatalf("add: %v", err)
	}

	second, err := v.GenerateKey("other", "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	signer, err := v.PortableSigner(second.GetFingerprint())
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	// Same identifier, different key.
	r := &ladulasv1.Retraction{
		RetractionId:      "r2",
		KeyFingerprint:    second.GetFingerprint(),
		EndorsementId:     "grant-1",
		IssuedAt:          timestamppb.Now(),
		RememberUntil:     timestamppb.New(time.Now().Add(2 * time.Hour)),
		IssuerFingerprint: ssh.FingerprintSHA256(v.Identity().PublicKey()),
	}

	signedR, err := v.Identity().SignRetraction(r, signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := v.AddRetraction(signedR, r); err != nil {
		t.Fatalf("retract: %v", err)
	}

	held, err := v.Endorsements()
	if err != nil {
		t.Fatalf("endorsements: %v", err)
	}

	if len(held) != 1 {
		t.Fatalf("a retraction about another key took the promise: %d", len(held))
	}
}
