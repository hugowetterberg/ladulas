package identity_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

func newIdentity(t *testing.T, name string) *identity.Identity {
	t.Helper()

	id, _, err := identity.Generate(name)
	if err != nil {
		t.Fatalf("generate an identity: %v", err)
	}

	return id
}

func delegation(approver, requester string) *ladulasv1.Delegation {
	return &ladulasv1.Delegation{
		DelegationId: "del-1",
		Scope: &ladulasv1.GrantScope{
			KeyFingerprint: "SHA256:key",
			Kind:           ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
			Repository:     "/home/hugo/foo",
		},
		CreatedAt:            timestamppb.New(time.Unix(1_700_000_000, 0)),
		ExpiresAt:            timestamppb.New(time.Unix(1_700_003_600, 0)),
		Description:          "git signing in /home/hugo/foo, for 1 hour",
		ApproverFingerprint:  approver,
		ApproverName:         "phone",
		RequesterFingerprint: requester,
	}
}

func TestDelegationRoundTrips(t *testing.T) {
	approver := newIdentity(t, "phone")

	signed, err := approver.SignDelegation(
		delegation(approver.Fingerprint(), "SHA256:desktop"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	got, key, err := identity.VerifyDelegation(signed)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if got.GetDelegationId() != "del-1" {
		t.Errorf("the delegation came back as %q", got.GetDelegationId())
	}

	if got.GetRequesterFingerprint() != "SHA256:desktop" {
		t.Errorf("it names %q", got.GetRequesterFingerprint())
	}

	if key == nil {
		t.Error("no key came back")
	}
}

// A delegation and an approval of one specific request must never be
// confusable as bytes, which is what the separate domain separator buys. The
// test is worth having because the two artifacts are otherwise the same shape,
// and a shared prefix would be an easy thing to reach for.
func TestDelegationIsNotAnApproval(t *testing.T) {
	approver := newIdentity(t, "phone")

	d := delegation(approver.Fingerprint(), "SHA256:desktop")

	signed, err := approver.SignDelegation(d)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// The same bytes, offered as an approval.
	asApproval := &ladulasv1.SignedApproval{
		Response:            signed.GetDelegation(),
		ApproverPublicKey:   signed.GetApproverPublicKey(),
		ApproverFingerprint: signed.GetApproverFingerprint(),
		SignatureAlgorithm:  signed.GetSignatureAlgorithm(),
		Signature:           signed.GetSignature(),
	}

	if _, _, err := identity.VerifyApproval(asApproval); err == nil {
		t.Fatal("a delegation verified as an approval")
	}

	// And the other way round.
	resp := &ladulasv1.ApprovalResponse{
		RequestId: "req-1",
		Decision:  ladulasv1.Decision_DECISION_APPROVE,
	}

	approval, err := approver.SignApproval(resp)
	if err != nil {
		t.Fatalf("sign approval: %v", err)
	}

	asDelegation := &ladulasv1.SignedDelegation{
		Delegation:          approval.GetResponse(),
		ApproverPublicKey:   approval.GetApproverPublicKey(),
		ApproverFingerprint: approval.GetApproverFingerprint(),
		SignatureAlgorithm:  approval.GetSignatureAlgorithm(),
		Signature:           approval.GetSignature(),
	}

	if _, _, err := identity.VerifyDelegation(asDelegation); err == nil {
		t.Fatal("an approval verified as a delegation")
	}
}

// The artifact says who signed it and the delegation inside says who granted
// it. A delegation naming one approver and signed by another is not a
// delegation from either of them.
func TestDelegationApproverMustAgreeWithItsSignature(t *testing.T) {
	approver := newIdentity(t, "phone")

	signed, err := approver.SignDelegation(
		delegation("SHA256:somebody-else", "SHA256:desktop"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	_, _, err = identity.VerifyDelegation(signed)
	if err == nil {
		t.Fatal("a delegation naming another approver verified")
	}

	if !strings.Contains(err.Error(), "names approver") {
		t.Errorf("the error does not say what was wrong: %v", err)
	}
}

// Changing anything inside the delegation invalidates it — including the
// instance it is for, which is what stops one being replayed at a third
// machine that happens to hold the same key.
func TestDelegationCannotBeReaddressed(t *testing.T) {
	approver := newIdentity(t, "phone")

	signed, err := approver.SignDelegation(
		delegation(approver.Fingerprint(), "SHA256:desktop"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tampered := delegation(approver.Fingerprint(), "SHA256:someone-elses-laptop")

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	signed.Delegation = body

	if _, _, err := identity.VerifyDelegation(signed); err == nil {
		t.Fatal("a re-addressed delegation verified")
	}
}
