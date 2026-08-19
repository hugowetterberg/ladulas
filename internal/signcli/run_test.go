package signcli_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/internal/signcli"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

const commitObject = "tree e95bc8444bcd06692c882451e807e45dfe27b5ba\n" +
	"parent 937fa9137d03e1ca64111b86264e78dc907127e7\n" +
	"author A U Thor <author@example.test> 1786209283 +0200\n" +
	"committer A U Thor <author@example.test> 1786209283 +0200\n" +
	"\n" +
	"a commit worth approving\n"

type keyStore struct {
	signer ssh.Signer
}

func (k *keyStore) KeyRefs() []*ladulasv1.KeyRef {
	return []*ladulasv1.KeyRef{{
		Fingerprint: ssh.FingerprintSHA256(k.signer.PublicKey()),
		Algorithm:   k.signer.PublicKey().Type(),
		PublicKey:   k.signer.PublicKey().Marshal(),
		Label:       "work",
	}}
}

func (k *keyStore) Signer(string) (ssh.Signer, *storepb.StoredKey, error) {
	return k.signer, &storepb.StoredKey{Label: "work"}, nil
}

type approver struct {
	decision ladulasv1.Decision
	requests []*ladulasv1.ApprovalRequest
}

func (a *approver) SubmitSigned(
	_ context.Context, req *ladulasv1.ApprovalRequest,
) (*ladulasv1.ApprovalResponse, *ladulasv1.SignedApproval, error) {
	a.requests = append(a.requests, req)

	return &ladulasv1.ApprovalResponse{
		Decision: a.decision,
		Source:   ladulasv1.DecisionSource_DECISION_SOURCE_POLICY,
		Reason:   "the test decided",
	}, &ladulasv1.SignedApproval{ApproverFingerprint: "SHA256:test"}, nil
}

type run struct {
	status   int
	stderr   string
	stdout   string
	handedTo []string
	approver *approver
	keys     *keyStore
	dir      string
}

// runSign drives Run exactly as git would, against an instance that answers
// with the given decision. A nil decision means no instance is listening.
func runSign(
	t *testing.T, dir string, decision *ladulasv1.Decision,
	args func(key string) []string,
) *run {
	t.Helper()

	keys := &keyStore{signer: newSigner(t)}
	app := &approver{}

	result := &run{approver: app, keys: keys, dir: dir}

	socket := filepath.Join(shortDir(t), "control.sock")

	if decision != nil {
		app.decision = *decision

		server, err := localapi.New(localapi.Options{
			SocketPath: socket,
			Keys:       keys,
			Approver:   app,
		})
		if err != nil {
			t.Fatalf("server: %v", err)
		}

		if err := server.Listen(); err != nil {
			t.Fatalf("listen: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)

		go func() {
			done <- server.Serve(ctx)
		}()

		t.Cleanup(func() {
			cancel()

			if err := <-done; err != nil {
				t.Errorf("serve: %v", err)
			}
		})
	}

	keyFile := filepath.Join(dir, "signing.pub")

	err := os.WriteFile(keyFile,
		ssh.MarshalAuthorizedKey(keys.signer.PublicKey()), 0o600)
	if err != nil {
		t.Fatalf("write key file: %v", err)
	}

	var stdout, stderr bytes.Buffer

	result.status = signcli.Run(context.Background(), args(keyFile), signcli.Options{
		Stdout:     &stdout,
		Stderr:     &stderr,
		SocketPath: socket,
		SSHKeygen:  "/usr/bin/ssh-keygen",
		Dir:        dir,
		NoDiff:     true,
		Exec: func(_ string, argv []string) error {
			result.handedTo = argv

			return nil
		},
	})

	result.stdout = stdout.String()
	result.stderr = stderr.String()

	return result
}

// shortDir is a temporary directory outside the test tree, because a unix
// socket address is capped at about 100 characters.
func shortDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "ladulas")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}

	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})

	return dir
}

func writePayload(t *testing.T, dir, name, body string) string {
	t.Helper()

	path := filepath.Join(dir, name)

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	return path
}

func TestSignsThroughTheInstance(t *testing.T) {
	approve := ladulasv1.Decision_DECISION_APPROVE

	dir := t.TempDir()

	result := runSign(t, dir, &approve, func(key string) []string {
		payload := writePayload(t, dir, "buffer", commitObject)

		return []string{"-Y", "sign", "-n", "git", "-f", key, "-U", payload}
	})

	if result.status != 0 {
		t.Fatalf("status %d, stderr:\n%s", result.status, result.stderr)
	}

	if result.handedTo != nil {
		t.Fatalf("the invocation was handed to ssh-keygen: %v", result.handedTo)
	}

	armoured, err := os.ReadFile(filepath.Join(dir, "buffer.sig"))
	if err != nil {
		t.Fatalf("read the signature: %v", err)
	}

	sig, err := sshsig.Parse(string(armoured))
	if err != nil {
		t.Fatalf("parse the signature: %v", err)
	}

	if err := sig.Verify("git", []byte(commitObject)); err != nil {
		t.Errorf("the signature does not cover the payload: %v", err)
	}

	if len(result.approver.requests) != 1 {
		t.Fatalf("the approver saw %d requests", len(result.approver.requests))
	}

	git := result.approver.requests[0].GetSshsig().GetGitContext()

	if string(git.GetObject()) != commitObject {
		t.Error("the whole commit object did not reach the approver")
	}

	if git.GetOperation() != "commit" {
		t.Errorf("operation is %q", git.GetOperation())
	}
}

// The signature file has to land where ssh-keygen would have put it, because
// that is the only part of the contract git looks at.
func TestSignatureFileIsNextToThePayload(t *testing.T) {
	approve := ladulasv1.Decision_DECISION_APPROVE

	dir := t.TempDir()

	result := runSign(t, dir, &approve, func(key string) []string {
		payload := writePayload(t, dir, "some.buffer", commitObject)

		return []string{"-Y", "sign", "-n", "git", "-f", key, payload}
	})

	if result.status != 0 {
		t.Fatalf("status %d: %s", result.status, result.stderr)
	}

	if _, err := os.Stat(filepath.Join(dir, "some.buffer.sig")); err != nil {
		t.Errorf("no signature next to the payload: %v", err)
	}
}

// A denial is an answer. Retrying it through ssh-keygen would let the same
// request past an approver who has just said no.
func TestDenialIsNotRetriedThroughSshKeygen(t *testing.T) {
	deny := ladulasv1.Decision_DECISION_DENY

	dir := t.TempDir()

	result := runSign(t, dir, &deny, func(key string) []string {
		payload := writePayload(t, dir, "buffer", commitObject)

		return []string{"-Y", "sign", "-n", "git", "-f", key, "-U", payload}
	})

	if result.status == 0 {
		t.Fatal("a denied signature exited successfully")
	}

	if result.handedTo != nil {
		t.Errorf("a denial was handed to ssh-keygen: %v", result.handedTo)
	}

	if _, err := os.Stat(filepath.Join(dir, "buffer.sig")); !os.IsNotExist(err) {
		t.Error("a denied signature still wrote a signature file")
	}

	if !strings.Contains(result.stderr, "refused") {
		t.Errorf("stderr does not say what happened:\n%s", result.stderr)
	}
}

// With nothing listening, git still has to be able to commit through the plain
// agent — that is the fallback §5 promises.
func TestFallsBackWhenNoInstanceIsListening(t *testing.T) {
	dir := t.TempDir()

	result := runSign(t, dir, nil, func(key string) []string {
		payload := writePayload(t, dir, "buffer", commitObject)

		return []string{"-Y", "sign", "-n", "git", "-f", key, "-U", payload}
	})

	if result.handedTo == nil {
		t.Fatalf("nothing was handed to ssh-keygen; stderr:\n%s", result.stderr)
	}

	// The command line has to arrive intact, -U and all, or the agent is never
	// consulted.
	joined := strings.Join(result.handedTo, " ")

	for _, want := range []string{"-Y sign", "-n git", "-U", "buffer"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the handed-over command line lost %q: %v", want, result.handedTo)
		}
	}
}

func TestFallsBackForAKeyTheInstanceDoesNotHold(t *testing.T) {
	approve := ladulasv1.Decision_DECISION_APPROVE

	dir := t.TempDir()
	other := newSigner(t)

	result := runSign(t, dir, &approve, func(string) []string {
		payload := writePayload(t, dir, "buffer", commitObject)
		keyFile := filepath.Join(dir, "other.pub")

		err := os.WriteFile(keyFile,
			ssh.MarshalAuthorizedKey(other.PublicKey()), 0o600)
		if err != nil {
			t.Fatalf("write key: %v", err)
		}

		return []string{"-Y", "sign", "-n", "git", "-f", keyFile, "-U", payload}
	})

	if result.handedTo == nil {
		t.Fatalf("an unknown key was not handed over; stderr:\n%s", result.stderr)
	}
}

// git runs the same program to verify, and that must not become this program's
// problem.
func TestVerificationIsHandedOver(t *testing.T) {
	approve := ladulasv1.Decision_DECISION_APPROVE

	dir := t.TempDir()

	result := runSign(t, dir, &approve, func(string) []string {
		return []string{
			"-Y", "verify", "-n", "git",
			"-f", filepath.Join(dir, "allowed_signers"),
			"-I", "hugo@example.test",
			"-s", filepath.Join(dir, "sig"),
			"-Overify-time=20260808191413",
		}
	})

	if result.handedTo == nil {
		t.Fatalf("verification was not handed over; stderr:\n%s", result.stderr)
	}

	if !strings.Contains(strings.Join(result.handedTo, " "), "-Y verify") {
		t.Errorf("the handed-over command line is %v", result.handedTo)
	}

	if len(result.approver.requests) != 0 {
		t.Error("verification reached the approval engine")
	}
}

// A private key file names a key just as well as a public one, and Ladulås
// never reads the private half — it only needs to know which key is meant.
func TestPrivateKeyFileIdentifiesTheKey(t *testing.T) {
	approve := ladulasv1.Decision_DECISION_APPROVE

	dir := t.TempDir()

	result := runSign(t, dir, &approve, func(string) []string {
		payload := writePayload(t, dir, "buffer", commitObject)

		return []string{"-Y", "sign", "-n", "git", "-f",
			asPrivateKeyFile(t, dir), payload}
	})

	if result.status != 0 {
		t.Fatalf("status %d: %s", result.status, result.stderr)
	}

	if result.handedTo != nil {
		t.Errorf("handed over: %v", result.handedTo)
	}
}

// asPrivateKeyFile turns the fixture's public key file into the shape a private
// key has on disk: an unreadable private half next to a .pub. That is the case
// git produces when user.signingkey is a path, and the key still has to be
// identified from the public half alone.
func asPrivateKeyFile(t *testing.T, dir string) string {
	t.Helper()

	path := filepath.Join(dir, "id_ed25519")

	if err := os.WriteFile(path, []byte("not something we may read\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	if err := os.Rename(filepath.Join(dir, "signing.pub"), path+".pub"); err != nil {
		t.Fatalf("rename: %v", err)
	}

	return path
}

func TestUnknownNamespaceCarriesNoContext(t *testing.T) {
	approve := ladulasv1.Decision_DECISION_APPROVE

	dir := t.TempDir()

	result := runSign(t, dir, &approve, func(key string) []string {
		payload := writePayload(t, dir, "buffer", "some file contents\n")

		return []string{"-Y", "sign", "-n", "file", "-f", key, payload}
	})

	if result.status != 0 {
		t.Fatalf("status %d: %s", result.status, result.stderr)
	}

	req := result.approver.requests[0]

	if req.GetSshsig().GetGitContext() != nil {
		t.Error("a file signature arrived with a git context")
	}
}

// Without an ssh-keygen to fall back to there is nothing sensible to do, and
// saying so beats silently succeeding.
func TestNoSshKeygenToFallBackTo(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	var stderr bytes.Buffer

	status := signcli.Run(context.Background(),
		[]string{"-Y", "verify", "-s", "/tmp/sig"}, signcli.Options{
			Stderr:     &stderr,
			SocketPath: filepath.Join(t.TempDir(), "nothing.sock"),
			Exec: func(string, []string) error {
				return errors.New("nothing should have been run")
			},
		})

	if status == 0 {
		t.Error("exited successfully with no signing program available")
	}

	if !strings.Contains(stderr.String(), "ssh-keygen") {
		t.Errorf("stderr does not mention the missing tool:\n%s", stderr.String())
	}
}

func newSigner(t *testing.T) ssh.Signer {
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
