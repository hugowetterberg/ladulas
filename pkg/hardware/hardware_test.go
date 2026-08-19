package hardware_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/pkg/hardware"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The whole of what the seam has to be true for: a key nobody can read still
// produces SSH signatures that verify against its public half.
func TestAHardwareKeySignsSSHSignatures(t *testing.T) {
	t.Parallel()

	backend := hardware.NewMemory()

	key, err := hardware.Generate(backend, "ssh-1", "Sign with work-p256", true)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if got := key.SSHPublicKey().Type(); got != ssh.KeyAlgoECDSA256 {
		t.Fatalf("the key is %s, not %s", got, ssh.KeyAlgoECDSA256)
	}

	signer, err := key.Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	payload := []byte("a commit object, more or less")

	signature, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := key.SSHPublicKey().Verify(payload, signature); err != nil {
		t.Fatalf("the signature does not verify: %v", err)
	}

	// A biometric key was used behind a prompt, and the prompt said what for.
	prompts := backend.Prompts()
	if len(prompts) != 1 || !strings.Contains(prompts[0], "work-p256") {
		t.Errorf("the platform was asked to display %q", prompts)
	}
}

// The identity key is the same key in a different job: it authenticates the
// channel and signs approval artifacts, and neither may notice where it lives.
func TestAHardwareIdentitySignsApprovals(t *testing.T) {
	t.Parallel()

	backend := hardware.NewMemory()

	key, err := hardware.Generate(backend, "identity", "", false)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	id, err := identity.FromSigner("phone", key)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	if id.Fingerprint() != key.Fingerprint() {
		t.Errorf("the identity fingerprint %q is not the key's %q",
			id.Fingerprint(), key.Fingerprint())
	}

	if _, ok := id.CryptoSigner().Public().(*ecdsa.PublicKey); !ok {
		t.Errorf("the identity's crypto signer is not a P-256 key, "+
			"so it could not be put in a certificate: %T",
			id.CryptoSigner().Public())
	}

	signed, err := id.SignApproval(&ladulasv1.ApprovalResponse{
		RequestId: "req-1",
		Decision:  ladulasv1.Decision_DECISION_APPROVE,
	})
	if err != nil {
		t.Fatalf("sign an approval: %v", err)
	}

	resp, pub, err := identity.VerifyApproval(signed)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if resp.GetRequestId() != "req-1" {
		t.Errorf("the artifact covers %q", resp.GetRequestId())
	}

	if ssh.FingerprintSHA256(pub) != id.Fingerprint() {
		t.Errorf("the artifact was signed by %s, not %s",
			ssh.FingerprintSHA256(pub), id.Fingerprint())
	}
}

// A key reopened from what the store recorded is the same key, and opening it
// does not need the platform.
func TestOpenUsesTheRecordedPublicKey(t *testing.T) {
	t.Parallel()

	backend := hardware.NewMemory()

	generated, err := hardware.Generate(backend, "ssh-1", "reason", false)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	reopened, err := hardware.Open(
		backend, "ssh-1", "reason", generated.SSHPublicKey().Marshal())
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if reopened.Fingerprint() != generated.Fingerprint() {
		t.Errorf("the reopened key is %s, not %s",
			reopened.Fingerprint(), generated.Fingerprint())
	}
}

// A refused signature is an ordinary outcome — the user dismissed Face ID — and
// has to arrive as an error rather than as a signature nobody produced.
func TestARefusedSignatureIsAnError(t *testing.T) {
	t.Parallel()

	backend := hardware.NewMemory()
	backend.Fail = errors.New("the user cancelled")

	key, err := hardware.Generate(backend, "ssh-1", "reason", true)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	signer, err := key.Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	if _, err := signer.Sign(rand.Reader, []byte("payload")); err == nil {
		t.Fatal("a cancelled prompt produced a signature")
	}
}

// crypto.Signer is a contract, and the parts of it a secure element cannot
// honour are the parts worth refusing outright rather than passing on.
func TestOnlySHA256DigestsAreSigned(t *testing.T) {
	t.Parallel()

	key, err := hardware.Generate(hardware.NewMemory(), "ssh-1", "reason", false)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	digest := make([]byte, crypto.SHA256.Size())

	if _, err := key.Sign(rand.Reader, digest, crypto.SHA512); err == nil {
		t.Error("a SHA-512 signature was accepted")
	}

	if _, err := key.Sign(rand.Reader, digest[:8], crypto.SHA256); err == nil {
		t.Error("a truncated digest was accepted")
	}
}

func TestABackendlessKeyIsRefused(t *testing.T) {
	t.Parallel()

	if _, err := hardware.Generate(nil, "ssh-1", "", false); !errors.Is(err, hardware.ErrNoBackend) {
		t.Errorf("generating without a backend gave %v", err)
	}

	if _, err := hardware.Open(nil, "ssh-1", "", nil); !errors.Is(err, hardware.ErrNoBackend) {
		t.Errorf("opening without a backend gave %v", err)
	}
}
