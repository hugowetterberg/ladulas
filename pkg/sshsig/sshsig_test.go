package sshsig_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/internal/testutil"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
)

func TestSignAndVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	signer := newEd25519Signer(t)
	message := []byte("tree deadbeef\n\ncommit message\n")

	sig, err := sshsig.Sign(signer, sshsig.GitNamespace, "", message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if sig.HashAlgorithm != sshsig.HashSHA512 {
		t.Errorf("hash algorithm is %q, want sha512", sig.HashAlgorithm)
	}

	if err := sig.Verify(sshsig.GitNamespace, message); err != nil {
		t.Errorf("verify: %v", err)
	}

	if err := sig.Verify(sshsig.GitNamespace, []byte("something else")); err == nil {
		t.Error("a signature verified against a different message")
	}

	if err := sig.Verify("file", message); err == nil {
		t.Error("a signature verified under a different namespace")
	}
}

func TestArmourRoundTrip(t *testing.T) {
	t.Parallel()

	signer := newEd25519Signer(t)

	sig, err := sshsig.Sign(signer, sshsig.GitNamespace, "", []byte("hello"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	armoured := sig.Armored()

	if !strings.HasPrefix(armoured, "-----BEGIN SSH SIGNATURE-----\n") {
		t.Errorf("armour does not start with the begin marker:\n%s", armoured)
	}

	if !strings.HasSuffix(armoured, "-----END SSH SIGNATURE-----\n") {
		t.Errorf("armour does not end with the end marker:\n%s", armoured)
	}

	// ssh-keygen wraps the body at 70 columns and git reproduces the file
	// verbatim in the gpgsig header, so the width is part of the format in
	// practice even though nothing enforces it.
	lines := strings.Split(strings.TrimSuffix(armoured, "\n"), "\n")
	for _, line := range lines[1 : len(lines)-1] {
		if len(line) > 70 {
			t.Errorf("armour line is %d characters, want at most 70", len(line))
		}
	}

	parsed, err := sshsig.Parse(armoured)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := parsed.Verify(sshsig.GitNamespace, []byte("hello")); err != nil {
		t.Errorf("verify the reparsed signature: %v", err)
	}

	if got := parsed.PublicKey.Type(); got != ssh.KeyAlgoED25519 {
		t.Errorf("public key type %q, want %q", got, ssh.KeyAlgoED25519)
	}
}

func TestSigningBlobIsWhatTheAgentSees(t *testing.T) {
	t.Parallel()

	digest, err := sshsig.Hash(sshsig.HashSHA512, []byte("message"))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	blob := sshsig.SigningBlob("git", "sha512", digest)

	if string(blob[:6]) != "SSHSIG" {
		t.Fatalf("blob does not start with the magic preamble: %q", blob[:6])
	}

	// The blob the signer receives carries no version field — that only exists
	// in the signature file — so the bytes after the preamble are the namespace
	// string. Getting this wrong produces signatures nothing can verify.
	if got := string(blob[6:10]); got != "\x00\x00\x00\x03" {
		t.Fatalf("expected a 3-byte namespace length after the preamble, got %q", got)
	}

	if got := string(blob[10:13]); got != "git" {
		t.Fatalf("namespace is %q, want git", got)
	}
}

func TestRSASignsWithSHA2(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	sig, err := sshsig.Sign(signer, sshsig.GitNamespace, "", []byte("hello"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if sig.Signature.Format != ssh.KeyAlgoRSASHA512 {
		t.Errorf("signature format is %q, want %q",
			sig.Signature.Format, ssh.KeyAlgoRSASHA512)
	}

	if err := sig.Verify(sshsig.GitNamespace, []byte("hello")); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestSHA256Hash(t *testing.T) {
	t.Parallel()

	signer := newEd25519Signer(t)

	sig, err := sshsig.Sign(signer, "file", sshsig.HashSHA256, []byte("hello"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := sig.Verify("file", []byte("hello")); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestRejectsUnknownHash(t *testing.T) {
	t.Parallel()

	if _, err := sshsig.Hash("md5", []byte("x")); err == nil {
		t.Error("md5 was accepted as a hash algorithm")
	}
}

// TestSshKeygenVerifiesOurSignature is the one that matters: a signature this
// package produces has to be readable by the tool git actually shells out to
// when it verifies. Everything else in here could be self-consistently wrong.
func TestSshKeygenVerifiesOurSignature(t *testing.T) {
	t.Parallel()

	keygen := testutil.RequireTool(t, "ssh-keygen")

	dir := t.TempDir()
	signer := newEd25519Signer(t)
	message := []byte("the message that is signed\n")

	sig, err := sshsig.Sign(signer, sshsig.GitNamespace, "", message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	messagePath := filepath.Join(dir, "message")
	if err := os.WriteFile(messagePath, message, 0o600); err != nil {
		t.Fatalf("write message: %v", err)
	}

	sigPath := messagePath + ".sig"
	if err := os.WriteFile(sigPath, []byte(sig.Armored()), 0o600); err != nil {
		t.Fatalf("write signature: %v", err)
	}

	authorized := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	allowed := filepath.Join(dir, "allowed_signers")

	err = os.WriteFile(allowed,
		[]byte("signer@example.test "+authorized), 0o600)
	if err != nil {
		t.Fatalf("write allowed signers: %v", err)
	}

	cmd := exec.Command(keygen,
		"-Y", "verify",
		"-n", "git",
		"-f", allowed,
		"-I", "signer@example.test",
		"-s", sigPath)
	cmd.Dir = dir
	cmd.Env = testutil.Env()

	stdin, err := os.Open(messagePath) //nolint:gosec // a path this test wrote
	if err != nil {
		t.Fatalf("open message: %v", err)
	}

	defer func() {
		_ = stdin.Close()
	}()

	cmd.Stdin = stdin

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -Y verify rejected our signature: %v\n%s", err, out)
	}
}

// TestParsesSshKeygenSignature is the same check in the other direction.
func TestParsesSshKeygenSignature(t *testing.T) {
	t.Parallel()

	keygen := testutil.RequireTool(t, "ssh-keygen")

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id")

	testutil.Run(t, dir, keygen,
		"-t", "ed25519", "-N", "", "-C", "test", "-q", "-f", keyPath)

	message := []byte("a message ssh-keygen signs\n")

	messagePath := filepath.Join(dir, "message")
	if err := os.WriteFile(messagePath, message, 0o600); err != nil {
		t.Fatalf("write message: %v", err)
	}

	testutil.Run(t, dir, keygen,
		"-Y", "sign", "-n", "git", "-f", keyPath, messagePath)

	armoured, err := os.ReadFile(messagePath + ".sig")
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}

	sig, err := sshsig.Parse(string(armoured))
	if err != nil {
		t.Fatalf("parse ssh-keygen's signature: %v", err)
	}

	if err := sig.Verify(sshsig.GitNamespace, message); err != nil {
		t.Errorf("verify ssh-keygen's signature: %v", err)
	}
}

func newEd25519Signer(t *testing.T) ssh.Signer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(pem.EncodeToMemory(block))
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	return signer
}
