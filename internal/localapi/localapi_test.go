package localapi_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/internal/testutil"
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

// keyStore is one key and nothing else.
type keyStore struct {
	signer ssh.Signer
}

func (k *keyStore) KeyRefs() []*ladulasv1.KeyRef {
	return []*ladulasv1.KeyRef{{
		Fingerprint: ssh.FingerprintSHA256(k.signer.PublicKey()),
		Algorithm:   k.signer.PublicKey().Type(),
		PublicKey:   k.signer.PublicKey().Marshal(),
		Label:       "work",
		Comment:     "work@example.test",
	}}
}

func (k *keyStore) Signer(fingerprint string) (ssh.Signer, *storepb.StoredKey, error) {
	if fingerprint != ssh.FingerprintSHA256(k.signer.PublicKey()) {
		return nil, nil, errors.New("no such key")
	}

	return k.signer, &storepb.StoredKey{Label: "work"}, nil
}

// approver answers with a fixed decision and records what it was asked.
type approver struct {
	decision ladulasv1.Decision
	requests []*ladulasv1.ApprovalRequest
}

func (a *approver) SubmitSigned(
	_ context.Context, req *ladulasv1.ApprovalRequest,
) (*ladulasv1.ApprovalResponse, *ladulasv1.SignedApproval, error) {
	a.requests = append(a.requests, req)

	// Named rather than returned as three literals on one statement. The
	// indentation gofmt wants for a composite literal inside a multi-value
	// return has changed between Go versions, and CI's linter carries a gofmt
	// of its own — so the shape that is formatted the same way by every one of
	// them is the shape that does not have the construct in it.
	resp := &ladulasv1.ApprovalResponse{
		Decision: a.decision,
		Source:   ladulasv1.DecisionSource_DECISION_SOURCE_POLICY,
		Reason:   "the test said so",
	}

	signed := &ladulasv1.SignedApproval{
		ApproverFingerprint: "SHA256:test",
	}

	return resp, signed, nil
}

type fixture struct {
	client   *localapi.Client
	approver *approver
	keys     *keyStore
}

func newFixture(t *testing.T, decision ladulasv1.Decision) *fixture {
	t.Helper()

	keys := &keyStore{signer: newSigner(t)}
	app := &approver{decision: decision}

	// A short path: a unix socket address is capped at about 100 characters and
	// the test temporary directory can be long.
	dir, err := os.MkdirTemp("", "ladulas")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}

	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})

	socket := filepath.Join(dir, "control.sock")

	server, err := localapi.New(localapi.Options{
		SocketPath: socket,
		Keys:       keys,
		Approver:   app,
		Identity: func() *ladulasv1.RequesterInfo {
			return &ladulasv1.RequesterInfo{
				InstanceId: "SHA256:instance", Name: "test", Local: true,
			}
		},
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

	return &fixture{
		client:   localapi.NewClient(socket),
		approver: app,
		keys:     keys,
	}
}

func TestSignPayloadRoundTrip(t *testing.T) {
	f := newFixture(t, ladulasv1.Decision_DECISION_APPROVE)

	resp, err := f.client.SignPayload(context.Background(), &ladulasv1.SignPayloadRequest{
		PublicKey: f.keys.signer.PublicKey().Marshal(),
		Payload:   []byte(commitObject),
		Namespace: "git",
		Timeout:   durationpb.New(30 * time.Second),
		GitContext: &ladulasv1.GitContext{
			RepositoryPath: "/home/hugo/Projects/ladulas",
			Branch:         "main",
			Operation:      "commit",
		},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !resp.GetApproved() {
		t.Fatalf("not approved: %s", resp.GetReason())
	}

	sig, err := sshsig.Parse(resp.GetArmoredSignature())
	if err != nil {
		t.Fatalf("parse the signature: %v", err)
	}

	if err := sig.Verify("git", []byte(commitObject)); err != nil {
		t.Errorf("the signature does not cover the payload: %v", err)
	}

	if resp.GetApproval().GetApproverFingerprint() == "" {
		t.Error("the response carries no approval artifact")
	}

	// The request the approver saw is a git signing request with the object in
	// it, which is the whole point of the socket.
	if len(f.approver.requests) != 1 {
		t.Fatalf("the approver saw %d requests", len(f.approver.requests))
	}

	req := f.approver.requests[0]

	if req.GetKind() != ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN {
		t.Errorf("kind is %v", req.GetKind())
	}

	git := req.GetSshsig().GetGitContext()

	if string(git.GetObject()) != commitObject {
		t.Error("the object in the context is not the payload")
	}

	if git.GetBranch() != "main" {
		t.Errorf("branch is %q", git.GetBranch())
	}

	digest, err := sshsig.Hash("sha512", []byte(commitObject))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if string(req.GetSshsig().GetMessageDigest()) != string(digest) {
		t.Error("the digest in the request is not the digest of the payload")
	}
}

// A caller that sends an object different from its payload gets the payload
// used anyway: the server never takes the caller's word for what is being
// signed (§5).
func TestSubmittedObjectIsReplacedByThePayload(t *testing.T) {
	f := newFixture(t, ladulasv1.Decision_DECISION_APPROVE)

	_, err := f.client.SignPayload(context.Background(), &ladulasv1.SignPayloadRequest{
		PublicKey: f.keys.signer.PublicKey().Marshal(),
		Payload:   []byte(commitObject),
		Namespace: "git",
		GitContext: &ladulasv1.GitContext{
			Object: []byte("tree aaaa\n\nsomething else entirely\n"),
			Parsed: &ladulasv1.GitObject{Subject: "a lie"},
		},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	git := f.approver.requests[0].GetSshsig().GetGitContext()

	if string(git.GetObject()) != commitObject {
		t.Errorf("the submitted object survived: %q", git.GetObject())
	}
}

func TestDenialReturnsNoSignature(t *testing.T) {
	f := newFixture(t, ladulasv1.Decision_DECISION_DENY)

	resp, err := f.client.SignPayload(context.Background(), &ladulasv1.SignPayloadRequest{
		PublicKey: f.keys.signer.PublicKey().Marshal(),
		Payload:   []byte(commitObject),
		Namespace: "git",
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if resp.GetApproved() {
		t.Fatal("a denied request was approved")
	}

	if resp.GetArmoredSignature() != "" {
		t.Error("a denied request came back with a signature")
	}

	if resp.GetReason() != "the test said so" {
		t.Errorf("reason is %q", resp.GetReason())
	}
}

func TestUnknownKeyIsRefused(t *testing.T) {
	f := newFixture(t, ladulasv1.Decision_DECISION_APPROVE)

	other := newSigner(t)

	_, err := f.client.SignPayload(context.Background(), &ladulasv1.SignPayloadRequest{
		PublicKey: other.PublicKey().Marshal(),
		Payload:   []byte(commitObject),
		Namespace: "git",
	})
	if err == nil {
		t.Fatal("a key the instance does not hold was accepted")
	}

	if !strings.Contains(err.Error(), "no key") {
		t.Errorf("error is %v", err)
	}
}

// A signature in another namespace is not a commit and must not arrive dressed
// as one.
func TestNonGitNamespaceCarriesNoGitContext(t *testing.T) {
	f := newFixture(t, ladulasv1.Decision_DECISION_APPROVE)

	_, err := f.client.SignPayload(context.Background(), &ladulasv1.SignPayloadRequest{
		PublicKey:  f.keys.signer.PublicKey().Marshal(),
		Payload:    []byte("some file contents"),
		Namespace:  "file",
		GitContext: &ladulasv1.GitContext{RepositoryPath: "/somewhere"},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	req := f.approver.requests[0]

	if req.GetKind() != ladulasv1.RequestKind_REQUEST_KIND_SSHSIG {
		t.Errorf("kind is %v, want a plain SSHSIG request", req.GetKind())
	}

	if req.GetSshsig().GetGitContext() != nil {
		t.Error("a non-git namespace arrived with a git context")
	}
}

func TestEmptyPayloadIsRefused(t *testing.T) {
	f := newFixture(t, ladulasv1.Decision_DECISION_APPROVE)

	_, err := f.client.SignPayload(context.Background(), &ladulasv1.SignPayloadRequest{
		PublicKey: f.keys.signer.PublicKey().Marshal(),
		Namespace: "git",
	})
	if err == nil {
		t.Fatal("an empty payload was accepted")
	}
}

func TestNoInstanceListening(t *testing.T) {
	t.Parallel()

	client := localapi.NewClient(filepath.Join(t.TempDir(), "nothing.sock"))

	_, err := client.SignPayload(context.Background(), &ladulasv1.SignPayloadRequest{
		PublicKey: []byte("key"),
		Payload:   []byte("payload"),
		Namespace: "git",
	})
	if !errors.Is(err, localapi.ErrNoInstance) {
		t.Fatalf("error is %v, want ErrNoInstance", err)
	}
}

// The signature the socket produces has to satisfy the tool git verifies with.
func TestSshKeygenVerifiesTheSocketSignature(t *testing.T) {
	keygen := testutil.RequireTool(t, "ssh-keygen")

	f := newFixture(t, ladulasv1.Decision_DECISION_APPROVE)

	resp, err := f.client.SignPayload(context.Background(), &ladulasv1.SignPayloadRequest{
		PublicKey: f.keys.signer.PublicKey().Marshal(),
		Payload:   []byte(commitObject),
		Namespace: "git",
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	dir := t.TempDir()

	messagePath := filepath.Join(dir, "message")
	if err := os.WriteFile(messagePath, []byte(commitObject), 0o600); err != nil {
		t.Fatalf("write message: %v", err)
	}

	sigPath := messagePath + ".sig"

	err = os.WriteFile(sigPath, []byte(resp.GetArmoredSignature()), 0o600)
	if err != nil {
		t.Fatalf("write signature: %v", err)
	}

	allowed := filepath.Join(dir, "allowed_signers")
	authorized := string(ssh.MarshalAuthorizedKey(f.keys.signer.PublicKey()))

	if err := os.WriteFile(allowed, []byte("work@example.test "+authorized), 0o600); err != nil {
		t.Fatalf("write allowed signers: %v", err)
	}

	stdin, err := os.Open(messagePath) //nolint:gosec // a path this test wrote
	if err != nil {
		t.Fatalf("open message: %v", err)
	}

	defer func() {
		_ = stdin.Close()
	}()

	cmd := exec.Command(keygen, "-Y", "verify", "-n", "git",
		"-f", allowed, "-I", "work@example.test", "-s", sigPath)
	cmd.Dir = dir
	cmd.Env = testutil.Env()
	cmd.Stdin = stdin

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen rejected the signature: %v\n%s", err, out)
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
