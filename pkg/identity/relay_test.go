package identity_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

func TestARelayCallVerifies(t *testing.T) {
	id, _, err := identity.Generate("phone")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	call := identity.NewRelayCall("abcdef")
	call.Operation = &ladulasv1.RelayCall_Wake{
		Wake: &ladulasv1.Wake{Style: ladulasv1.WakeStyle_WAKE_STYLE_ALERT},
	}

	signed, err := id.SignRelayCall(call)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	got, key, err := identity.VerifyRelayCall(signed)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if got.GetInstanceId() != "abcdef" {
		t.Fatalf("the call named %q", got.GetInstanceId())
	}

	if key.Type() != id.PublicKey().Type() {
		t.Fatalf("the key came back as %s", key.Type())
	}

	if got.GetNonce() == "" || got.GetIssuedAt() == nil {
		t.Fatal("the call was not stamped")
	}
}

func TestARelayCallDoesNotVerifyOnceItHasBeenTouched(t *testing.T) {
	id, _, err := identity.Generate("phone")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	signed, err := id.SignRelayCall(identity.NewRelayCall("abcdef"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Repointing the call at another instance is the whole of what an attacker
	// would want out of one, so it is the thing to break.
	var call ladulasv1.RelayCall

	if err := proto.Unmarshal(signed.GetCall(), &call); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	call.InstanceId = "somebody-else"

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&call)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	signed.Call = body

	if _, _, err := identity.VerifyRelayCall(signed); err == nil {
		t.Fatal("a rewritten relay call verified")
	}
}

// The relay is the only party an instance signs for that it does not trust, so
// the separator that keeps its signatures out of the approval world is worth a
// test of its own (§11, decision P's reasoning applied one step further).
func TestARelayCallIsNotAnApproval(t *testing.T) {
	id, _, err := identity.Generate("phone")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	signed, err := id.SignRelayCall(identity.NewRelayCall("abcdef"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// The same bytes and the same signature, presented as the other artifact.
	_, _, err = identity.VerifyApproval(&ladulasv1.SignedApproval{
		Response:            signed.GetCall(),
		ApproverPublicKey:   signed.GetPublicKey(),
		ApproverFingerprint: id.Fingerprint(),
		SignatureAlgorithm:  signed.GetSignatureAlgorithm(),
		Signature:           signed.GetSignature(),
	})
	if err == nil {
		t.Fatal("a relay call verified as an approval")
	}
}
