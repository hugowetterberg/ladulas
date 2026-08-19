package identity_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
)

// signingKey is a portable key of the kind decision S lets travel, which is the
// only kind an endorsement is ever about.
func signingKey(t *testing.T) ssh.Signer {
	t.Helper()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	signer, err := ssh.NewSignerFromSigner(private)
	if err != nil {
		t.Fatalf("wrap the key: %v", err)
	}

	return signer
}

func testEndorsement(key ssh.Signer, issuer, requester string) *ladulasv1.Endorsement {
	fingerprint := ssh.FingerprintSHA256(key.PublicKey())

	return &ladulasv1.Endorsement{
		EndorsementId: "grant-1",
		Scope: &ladulasv1.GrantScope{
			KeyFingerprint:      fingerprint,
			Kind:                ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
			RequesterInstanceId: requester,
		},
		CreatedAt:            timestamppb.New(time.Unix(1786209283, 0)),
		ExpiresAt:            timestamppb.New(time.Unix(1786212883, 0)),
		Description:          "sign in ladulas for an hour",
		IssuerFingerprint:    issuer,
		IssuerName:           "iPhone",
		RequesterFingerprint: requester,
		RequesterName:        "pietro",
		KeyFingerprint:       fingerprint,
	}
}

func TestEndorsementCarriesBothSignatures(t *testing.T) {
	t.Parallel()

	id, _, err := identity.Generate("iPhone")
	if err != nil {
		t.Fatalf("generate the identity: %v", err)
	}

	key := signingKey(t)
	e := testEndorsement(key, id.Fingerprint(), "SHA256:pietro")

	signed, err := id.SignEndorsement(e, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	got, err := identity.VerifyEndorsement(signed)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if got.GetEndorsementId() != "grant-1" ||
		got.GetRequesterFingerprint() != "SHA256:pietro" {
		t.Errorf("the endorsement came back as %+v", got)
	}

	// The key signature is an SSHSIG under a namespace of its own, which is
	// what keeps it from being replayable as a git signature (§5).
	sig, err := sshsig.ParseBinary(signed.GetKeySignature())
	if err != nil {
		t.Fatalf("parse the key signature: %v", err)
	}

	if sig.Namespace != identity.EndorsementNamespace {
		t.Errorf("the key signature namespace is %q", sig.Namespace)
	}

	if err := sig.Verify(sshsig.GitNamespace, signed.GetEndorsement()); err == nil {
		t.Error("the key signature verifies as a git signature")
	}
}

// The identity half says who, and without that check a holder could issue in
// another holder's name — which matters, because the receiving side decides
// whether to honour an endorsement by looking the issuer up in its own trust
// records.
func TestEndorsementIssuerCannotBeForged(t *testing.T) {
	t.Parallel()

	honest, _, err := identity.Generate("iPhone")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	liar, _, err := identity.Generate("laptop")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	key := signingKey(t)

	// The liar holds the key and signs an endorsement claiming to be the phone.
	e := testEndorsement(key, honest.Fingerprint(), "SHA256:pietro")

	signed, err := liar.SignEndorsement(e, key)
	if err == nil {
		if _, err := identity.VerifyEndorsement(signed); err == nil {
			t.Fatal("an endorsement naming one issuer and signed by another verified")
		}

		return
	}

	// Signing may equally refuse it up front; either is a pass, and this is
	// the assertion that the two do not disagree about what is wrong.
	if !strings.Contains(err.Error(), "issuer") &&
		!strings.Contains(err.Error(), "signed by") {
		t.Fatalf("sign refused for the wrong reason: %v", err)
	}
}

// The key half says the issuer held the key, and it is what makes the whole
// mechanism safe: an approver that holds no copy must not be able to write a
// standing cheque on somebody else's key.
func TestEndorsementMustBeSignedByTheKeyItIsAbout(t *testing.T) {
	t.Parallel()

	id, _, err := identity.Generate("iPhone")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	key := signingKey(t)
	other := signingKey(t)

	e := testEndorsement(key, id.Fingerprint(), "SHA256:pietro")

	if _, err := id.SignEndorsement(e, other); err == nil {
		t.Fatal("an endorsement about one key was signed with another")
	}

	// And the same thing assembled by hand, which is what an attacker would
	// actually do: a real endorsement about `key`, with a key signature made
	// over it by a key that is not `key`.
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	honest, err := id.SignEndorsement(
		testEndorsement(other, id.Fingerprint(), "SHA256:pietro"), other)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	forged := proto.CloneOf(honest)
	forged.Endorsement = body

	if _, err := identity.VerifyEndorsement(forged); err == nil {
		t.Fatal("an endorsement verified against a signature over other bytes")
	}
}

func TestEndorsementDetectsTampering(t *testing.T) {
	t.Parallel()

	id, _, err := identity.Generate("iPhone")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	key := signingKey(t)

	signed, err := id.SignEndorsement(
		testEndorsement(key, id.Fingerprint(), "SHA256:pietro"), key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Lengthening the promise is the edit worth naming: the artifact is the
	// only thing a holder has to go on about how long it runs.
	longer := testEndorsement(key, id.Fingerprint(), "SHA256:pietro")
	longer.ExpiresAt = timestamppb.New(time.Unix(1786299283, 0))

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(longer)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	tampered := proto.CloneOf(signed)
	tampered.Endorsement = body

	if _, err := identity.VerifyEndorsement(tampered); err == nil {
		t.Fatal("an endorsement with a lengthened expiry verified")
	}
}

func TestRetractionNamesOneTarget(t *testing.T) {
	t.Parallel()

	id, _, err := identity.Generate("guppy")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	key := signingKey(t)
	fingerprint := ssh.FingerprintSHA256(key.PublicKey())

	for _, tc := range []struct {
		name string
		r    *ladulasv1.Retraction
		ok   bool
	}{
		{
			name: "one endorsement",
			r: &ladulasv1.Retraction{
				RetractionId: "r1", KeyFingerprint: fingerprint,
				EndorsementId:     "grant-1",
				IssuerFingerprint: id.Fingerprint(),
				RememberUntil:     timestamppb.New(time.Unix(1786299283, 0)),
			},
			ok: true,
		},
		{
			name: "everything up to a moment",
			r: &ladulasv1.Retraction{
				RetractionId: "r2", KeyFingerprint: fingerprint,
				IssuedBefore:      timestamppb.New(time.Unix(1786212883, 0)),
				IssuerFingerprint: id.Fingerprint(),
				RememberUntil:     timestamppb.New(time.Unix(1786299283, 0)),
			},
			ok: true,
		},
		{
			name: "both",
			r: &ladulasv1.Retraction{
				RetractionId: "r3", KeyFingerprint: fingerprint,
				EndorsementId:     "grant-1",
				IssuedBefore:      timestamppb.New(time.Unix(1786212883, 0)),
				IssuerFingerprint: id.Fingerprint(),
				RememberUntil:     timestamppb.New(time.Unix(1786299283, 0)),
			},
		},
		{
			name: "neither",
			r: &ladulasv1.Retraction{
				RetractionId: "r4", KeyFingerprint: fingerprint,
				IssuerFingerprint: id.Fingerprint(),
				RememberUntil:     timestamppb.New(time.Unix(1786299283, 0)),
			},
		},
	} {
		signed, err := id.SignRetraction(tc.r, key)
		if err != nil {
			t.Fatalf("%s: sign: %v", tc.name, err)
		}

		_, err = identity.VerifyRetraction(signed)

		if tc.ok && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}

		if !tc.ok && err == nil {
			t.Errorf("%s: verified", tc.name)
		}
	}
}
