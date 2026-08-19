package identity_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

func testIdentity(t *testing.T) *identity.Identity {
	t.Helper()

	id, keyPEM, err := identity.Generate("test-instance")
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	if !bytes.Contains(keyPEM, []byte("OPENSSH PRIVATE KEY")) {
		t.Fatalf("identity key is not in OpenSSH format: %q", keyPEM)
	}

	return id
}

func TestGenerateRoundTrip(t *testing.T) {
	id, keyPEM, err := identity.Generate("first")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	reloaded, err := identity.FromPEM(keyPEM, "first")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	if id.Fingerprint() != reloaded.Fingerprint() {
		t.Errorf("fingerprint changed across reload: %s != %s",
			id.Fingerprint(), reloaded.Fingerprint())
	}

	if id.PublicKey().Type() != "ssh-ed25519" {
		t.Errorf("want an ed25519 identity, got %s", id.PublicKey().Type())
	}
}

func TestSignAndVerifyApproval(t *testing.T) {
	id := testIdentity(t)

	resp := &ladulasv1.ApprovalResponse{
		RequestId:     "req-1",
		RequestDigest: identity.Digest([]byte("the request")),
		Decision:      ladulasv1.Decision_DECISION_APPROVE,
		Source:        ladulasv1.DecisionSource_DECISION_SOURCE_USER,
		Approver:      id.ApproverInfo(true),
		Reason:        "user approved",
	}

	signed, err := id.SignApproval(resp)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if signed.GetApproverFingerprint() != id.Fingerprint() {
		t.Errorf("artifact names the wrong approver")
	}

	got, pub, err := identity.VerifyApproval(signed)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if pub.Type() != "ssh-ed25519" {
		t.Errorf("unexpected key type %s", pub.Type())
	}

	if !proto.Equal(resp, got) {
		t.Errorf("response did not survive the round trip:\n want %v\n  got %v", resp, got)
	}
}

func TestVerifyApprovalRejectsTamperedResponse(t *testing.T) {
	id := testIdentity(t)

	signed, err := id.SignApproval(&ladulasv1.ApprovalResponse{
		RequestId: "req-1",
		Decision:  ladulasv1.Decision_DECISION_DENY,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Swap the denial for an approval, keeping the signature.
	tampered := &ladulasv1.ApprovalResponse{
		RequestId: "req-1",
		Decision:  ladulasv1.Decision_DECISION_APPROVE,
	}

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	signed.Response = body

	if _, _, err := identity.VerifyApproval(signed); err == nil {
		t.Fatal("verification accepted a tampered response")
	}
}

func TestVerifyApprovalRejectsSubstitutedKey(t *testing.T) {
	id := testIdentity(t)
	other := testIdentity(t)

	signed, err := id.SignApproval(&ladulasv1.ApprovalResponse{RequestId: "req-1"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	signed.ApproverPublicKey = other.PublicKey().Marshal()

	if _, _, err := identity.VerifyApproval(signed); err == nil {
		t.Fatal("verification accepted a substituted approver key")
	}
}

// A signature the identity key made over something that is not domain
// separated as an approval must not verify as one. This is what stops a
// signature harvested from any other use of the identity key — a peer
// handshake, say — from being presented as an approval.
func TestVerifyApprovalRejectsUndomainedSignature(t *testing.T) {
	id, keyPEM, err := identity.Generate("test-instance")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(
		&ladulasv1.ApprovalResponse{
			RequestId: "req-1",
			Decision:  ladulasv1.Decision_DECISION_APPROVE,
		})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	sig, err := signer.Sign(rand.Reader, body)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	forged := &ladulasv1.SignedApproval{
		Response:            body,
		ApproverPublicKey:   id.PublicKey().Marshal(),
		ApproverFingerprint: id.Fingerprint(),
		SignatureAlgorithm:  sig.Format,
		Signature:           ssh.Marshal(sig),
	}

	if _, _, err := identity.VerifyApproval(forged); err == nil {
		t.Fatal("verification accepted a signature made outside the approval domain")
	}
}
