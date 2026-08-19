package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/agent"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// stubApprover records what it is asked and answers with a fixed decision.
type stubApprover struct {
	decision ladulasv1.Decision

	mu       sync.Mutex
	requests []*ladulasv1.ApprovalRequest
}

func (s *stubApprover) Submit(
	_ context.Context, req *ladulasv1.ApprovalRequest,
) (*ladulasv1.ApprovalResponse, error) {
	s.mu.Lock()
	s.requests = append(s.requests, proto.CloneOf(req))
	s.mu.Unlock()

	return &ladulasv1.ApprovalResponse{
		RequestId: req.GetRequestId(),
		Decision:  s.decision,
		Source:    ladulasv1.DecisionSource_DECISION_SOURCE_POLICY,
		DecidedAt: timestamppb.Now(),
		Reason:    "test policy",
	}, nil
}

func (s *stubApprover) last() *ladulasv1.ApprovalRequest {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.requests) == 0 {
		return nil
	}

	return s.requests[len(s.requests)-1]
}

func (s *stubApprover) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.requests)
}

type testAgent struct {
	socket     string
	vault      *keystore.Vault
	approver   *stubApprover
	keyRef     *ladulasv1.KeyRef
	publicKey  ssh.PublicKey
	knownHosts string
}

// socketDir keeps the socket path well inside the ~107 byte sun_path limit,
// which t.TempDir() paths can exceed for long test names.
func socketDir(t *testing.T) string {
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

// testPassphrase is what a test store is wrapped with: since decision I a
// store has no other way in.
func testPassphrase(string, bool) ([]byte, error) {
	return []byte("test passphrase"), nil
}

func newTestAgent(t *testing.T, decision ladulasv1.Decision) *testAgent {
	t.Helper()

	vault, err := keystore.Create(keystore.Options{
		Dir:              t.TempDir(),
		Keyring:          &keystore.MemoryKeyring{},
		Passphrase:       testPassphrase,
		InstanceName:     "test-desktop",
		ScryptWorkFactor: 10,
	})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	stored, err := vault.GenerateKey("work", "hugo@example.com")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pub, err := ssh.ParsePublicKey(stored.GetPublicKey())
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	approver := &stubApprover{decision: decision}
	socket := filepath.Join(socketDir(t), "agent.sock")

	server, err := agent.New(agent.Options{
		SocketPath: socket,
		Keys:       vault,
		Approver:   approver,
		KnownHosts: agent.NewKnownHosts(knownHosts),
		Identity: func() *ladulasv1.RequesterInfo {
			return vault.Identity().RequesterInfo(true)
		},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	if err := server.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})

	go func() {
		defer close(done)

		if err := server.Serve(ctx); err != nil {
			t.Errorf("serve: %v", err)
		}
	}()

	t.Cleanup(func() {
		cancel()

		if err := server.Close(); err != nil {
			t.Errorf("close: %v", err)
		}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})

	return &testAgent{
		socket:     socket,
		vault:      vault,
		approver:   approver,
		keyRef:     keystore.KeyRef(stored),
		publicKey:  pub,
		knownHosts: knownHosts,
	}
}

func (a *testAgent) client(t *testing.T) sshagent.ExtendedAgent {
	t.Helper()

	conn, err := net.Dial("unix", a.socket)
	if err != nil {
		t.Fatalf("dial agent: %v", err)
	}

	t.Cleanup(func() {
		_ = conn.Close()
	})

	return sshagent.NewClient(conn)
}

func TestAgentListsKeys(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	keys, err := a.client(t).List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(keys))
	}

	if keys[0].Comment != "hugo@example.com" {
		t.Errorf("comment: %q", keys[0].Comment)
	}

	if string(keys[0].Marshal()) != string(a.publicKey.Marshal()) {
		t.Error("the listed key is not the stored key")
	}
}

// A key its holder keeps out of identity lists is not handed to ssh, and signs
// as soon as something names it (decision T).
//
// The two halves are the whole of the setting. ssh tries every identity it is
// given, so a key that is only ever named — by user.signingkey, or by a peer
// asking for that key — has no business being one of them; and taking it out of
// the list must not be a way of switching the key off, because there is already
// one of those.
func TestAgentLeavesOutAKeyItsHolderHid(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	if _, err := a.vault.SetKeyAgentUse("work", false); err != nil {
		t.Fatalf("hide the key: %v", err)
	}

	client := a.client(t)

	keys, err := client.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(keys) != 0 {
		t.Fatalf("the agent offers %d hidden keys", len(keys))
	}

	digest := sha512.Sum512([]byte("a commit object"))
	payload := sshsigBlob("git", "sha512", digest[:])

	signature, err := client.Sign(a.publicKey, payload)
	if err != nil {
		t.Fatalf("sign with a hidden key: %v", err)
	}

	if err := a.publicKey.Verify(payload, signature); err != nil {
		t.Errorf("the signature does not verify: %v", err)
	}
}

func TestAgentSignsWhenApproved(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	digest := sha512.Sum512([]byte("a commit object"))
	payload := sshsigBlob("git", "sha512", digest[:])

	sig, err := a.client(t).Sign(a.publicKey, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := a.publicKey.Verify(payload, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	req := a.approver.last()

	if req.GetKind() != ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN {
		t.Errorf("kind: %v", req.GetKind())
	}

	if req.GetKey().GetFingerprint() != a.keyRef.GetFingerprint() {
		t.Errorf("wrong key in the request")
	}

	if req.GetRequester().GetProcess().GetPid() == 0 {
		t.Error("no peer process credentials on a local request")
	}

	if !strings.Contains(req.GetRequester().GetProcess().GetExecutable(), "agent.test") {
		t.Errorf("unexpected peer executable %q",
			req.GetRequester().GetProcess().GetExecutable())
	}
}

func TestAgentRefusesWhenDenied(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_DENY)

	_, err := a.client(t).Sign(a.publicKey, sshsigBlob("git", "sha512", []byte("d")))
	if err == nil {
		t.Fatal("the agent signed a denied request")
	}

	if a.approver.count() != 1 {
		t.Errorf("the approver was asked %d times", a.approver.count())
	}
}

// Key management goes through Ladulås itself (§4), so every mutation request
// has to fail.
func TestAgentRefusesMutation(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)
	client := a.client(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if err := client.Add(sshagent.AddedKey{PrivateKey: &priv}); err == nil {
		t.Error("Add succeeded")
	}

	if err := client.Remove(a.publicKey); err == nil {
		t.Error("Remove succeeded")
	}

	if err := client.RemoveAll(); err == nil {
		t.Error("RemoveAll succeeded")
	}

	if err := client.Lock([]byte("x")); err == nil {
		t.Error("Lock succeeded")
	}

	if err := client.Unlock([]byte("x")); err == nil {
		t.Error("Unlock succeeded")
	}

	// The key set is unchanged.
	keys, err := client.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("key set changed: %d keys", len(keys))
	}
}

func TestAgentSessionBindGivesDestinationContext(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	host := newTestHostKey(t)
	sessionID := []byte("the session identifier")

	writeKnownHosts(t, a.knownHosts, "bastion.example.net", host.PublicKey())

	client := a.client(t)

	if _, err := client.Extension(
		agent.SessionBindExtension,
		sessionBindPayload(t, host, sessionID, false),
	); err != nil {
		t.Fatalf("session-bind: %v", err)
	}

	payload := authBlob(sessionID, "hugo", "ssh-connection", a.publicKey)

	if _, err := client.Sign(a.publicKey, payload); err != nil {
		t.Fatalf("sign: %v", err)
	}

	auth := a.approver.last().GetSshAuth()

	if !auth.GetBound() {
		t.Fatal("the request was not correlated against the binding")
	}

	if auth.GetForwarded() {
		t.Error("a direct connection was reported as forwarded")
	}

	if auth.GetDestinationLabel() != "bastion.example.net" {
		t.Errorf("destination label %q, want the known_hosts name",
			auth.GetDestinationLabel())
	}

	if !auth.GetDestination().GetKnown() {
		t.Error("the host key was not matched against known_hosts")
	}

	if got := auth.GetDestination().GetFingerprint(); got !=
		ssh.FingerprintSHA256(host.PublicKey()) {
		t.Errorf("host key fingerprint %q", got)
	}

	if len(auth.GetBindingChain()) != 1 {
		t.Errorf("binding chain has %d entries", len(auth.GetBindingChain()))
	}
}

func TestAgentReportsForwardedRequests(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	outer := newTestHostKey(t)
	inner := newTestHostKey(t)

	client := a.client(t)

	// A forwarded agent socket: the ssh client that forwarded us binds with
	// is_forwarding set, and the client on the far side then binds its own hop.
	for _, bind := range []struct {
		host    ssh.Signer
		session string
		forward bool
	}{
		{host: outer, session: "outer-session", forward: true},
		{host: inner, session: "inner-session", forward: false},
	} {
		if _, err := client.Extension(
			agent.SessionBindExtension,
			sessionBindPayload(t, bind.host, []byte(bind.session), bind.forward),
		); err != nil {
			t.Fatalf("session-bind: %v", err)
		}
	}

	payload := authBlob([]byte("inner-session"), "hugo", "ssh-connection", a.publicKey)

	if _, err := client.Sign(a.publicKey, payload); err != nil {
		t.Fatalf("sign: %v", err)
	}

	auth := a.approver.last().GetSshAuth()

	if !auth.GetForwarded() {
		t.Error("a forwarded request was not flagged as forwarded")
	}

	if auth.GetForwardedHops() != 1 {
		t.Errorf("forwarded hops = %d, want 1", auth.GetForwardedHops())
	}

	if len(auth.GetBindingChain()) != 2 {
		t.Errorf("binding chain has %d entries, want 2", len(auth.GetBindingChain()))
	}
}

func TestAgentReportsUnboundRequests(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	payload := authBlob([]byte("nobody bound this"), "hugo", "ssh-connection", a.publicKey)

	if _, err := a.client(t).Sign(a.publicKey, payload); err != nil {
		t.Fatalf("sign: %v", err)
	}

	auth := a.approver.last().GetSshAuth()

	if auth.GetBound() {
		t.Error("an unbound request was reported as bound")
	}

	if auth.GetDestinationLabel() != "unknown destination" {
		t.Errorf("destination label %q", auth.GetDestinationLabel())
	}
}

func TestAgentRejectsUnverifiableSessionBind(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	host := newTestHostKey(t)
	payload := sessionBindPayload(t, host, []byte("session"), false)

	// Flip a bit in the signature.
	payload[len(payload)-2] ^= 0xff

	if _, err := a.client(t).Extension(agent.SessionBindExtension, payload); err == nil {
		t.Fatal("the agent accepted an unverifiable session binding")
	}
}

func TestAgentIgnoresUnknownExtensions(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	_, err := a.client(t).Extension("nonsense@example.com", nil)
	if !errors.Is(err, sshagent.ErrExtensionUnsupported) {
		t.Fatalf("want ErrExtensionUnsupported, got %v", err)
	}
}

// Sessions are per connection, so a binding on one connection must not leak
// into another.
func TestAgentBindingsAreScopedToTheConnection(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	host := newTestHostKey(t)
	sessionID := []byte("session")

	first := a.client(t)

	if _, err := first.Extension(
		agent.SessionBindExtension, sessionBindPayload(t, host, sessionID, false),
	); err != nil {
		t.Fatalf("session-bind: %v", err)
	}

	second := a.client(t)

	payload := authBlob(sessionID, "hugo", "ssh-connection", a.publicKey)

	if _, err := second.Sign(a.publicKey, payload); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if a.approver.last().GetSshAuth().GetBound() {
		t.Error("a binding leaked between connections")
	}
}

func TestAgentDeniesOpaquePayloadsAtThePolicyLayer(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	// The agent itself does not deny; it classifies honestly and lets the
	// engine apply the hard rule. What matters here is that the classification
	// reaches the approver as opaque.
	if _, err := a.client(t).Sign(a.publicKey, []byte("sign this please")); err != nil {
		t.Fatalf("sign: %v", err)
	}

	req := a.approver.last()

	if req.GetKind() != ladulasv1.RequestKind_REQUEST_KIND_OPAQUE_SIGN {
		t.Fatalf("kind: %v", req.GetKind())
	}

	if req.GetOpaqueSign().GetReason() == "" {
		t.Error("no reason recorded for the opaque classification")
	}
}

// The gold standard: real ssh-keygen, signing a real payload through the real
// socket, verified by real ssh-keygen. If this passes, git commit signing works.
func TestSSHKeygenSignAndVerifyThroughTheAgent(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not available")
	}

	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	dir := t.TempDir()
	pubPath := filepath.Join(dir, "id.pub")
	payloadPath := filepath.Join(dir, "payload")
	allowedSigners := filepath.Join(dir, "allowed_signers")

	pubLine := string(ssh.MarshalAuthorizedKey(a.publicKey))

	writeFile(t, pubPath, pubLine)
	writeFile(t, payloadPath, "tree deadbeef\nauthor Hugo <hugo@example.com>\n\nA commit.\n")
	writeFile(t, allowedSigners, "hugo@example.com "+pubLine)

	sign := exec.Command(keygen, "-Y", "sign", "-f", pubPath, "-n", "git", "-U", payloadPath)
	sign.Env = append(os.Environ(), "SSH_AUTH_SOCK="+a.socket)

	if out, err := sign.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y sign: %v: %s", err, out)
	}

	req := a.approver.last()

	if req.GetKind() != ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN {
		t.Fatalf("ssh-keygen's payload did not classify as a git signature: %v (%s)",
			req.GetKind(), req.GetOpaqueSign().GetReason())
	}

	if req.GetSshsig().GetNamespace() != "git" {
		t.Errorf("namespace %q", req.GetSshsig().GetNamespace())
	}

	if len(req.GetSshsig().GetMessageDigest()) == 0 {
		t.Error("no message digest in the request")
	}

	payload, err := os.Open(payloadPath)
	if err != nil {
		t.Fatalf("open payload: %v", err)
	}

	defer func() {
		_ = payload.Close()
	}()

	verify := exec.Command(keygen,
		"-Y", "verify",
		"-f", allowedSigners,
		"-I", "hugo@example.com",
		"-n", "git",
		"-s", payloadPath+".sig")
	verify.Stdin = payload

	if out, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y verify: %v: %s", err, out)
	}
}

func TestSSHKeygenSignIsRefusedWhenDenied(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not available")
	}

	a := newTestAgent(t, ladulasv1.Decision_DECISION_DENY)

	dir := t.TempDir()
	pubPath := filepath.Join(dir, "id.pub")
	payloadPath := filepath.Join(dir, "payload")

	writeFile(t, pubPath, string(ssh.MarshalAuthorizedKey(a.publicKey)))
	writeFile(t, payloadPath, "a commit object")

	sign := exec.Command(keygen, "-Y", "sign", "-f", pubPath, "-n", "git", "-U", payloadPath)
	sign.Env = append(os.Environ(), "SSH_AUTH_SOCK="+a.socket)

	if out, err := sign.CombinedOutput(); err == nil {
		t.Fatalf("ssh-keygen signed a denied request: %s", out)
	}

	if _, err := os.Stat(payloadPath + ".sig"); err == nil {
		t.Error("a signature file was written for a denied request")
	}
}

func TestListenRefusesToHijackALiveAgent(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	second, err := agent.New(agent.Options{
		SocketPath: a.socket,
		Keys:       a.vault,
		Approver:   a.approver,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	if err := second.Listen(); err == nil {
		t.Fatal("a second agent took over a live socket")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeKnownHosts(t *testing.T, path, host string, pub ssh.PublicKey) {
	t.Helper()

	line := fmt.Sprintf("%s %s", host,
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))))

	writeFile(t, path, line+"\n")
}

func newTestHostKey(t *testing.T) ssh.Signer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	return signer
}

func sessionBindPayload(
	t *testing.T, host ssh.Signer, sessionID []byte, forwarding bool,
) []byte {
	t.Helper()

	sig, err := host.Sign(rand.Reader, sessionID)
	if err != nil {
		t.Fatalf("sign session id: %v", err)
	}

	var out []byte

	out = append(out, blob(host.PublicKey().Marshal())...)
	out = append(out, blob(sessionID)...)
	out = append(out, blob(ssh.Marshal(sig))...)

	if forwarding {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}

	return out
}

// A short-lived CLI command constructs a Server it never listens on. Closing
// that one must not take the running daemon's socket away.
func TestCloseWithoutListenLeavesTheSocketAlone(t *testing.T) {
	a := newTestAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	bystander, err := agent.New(agent.Options{
		SocketPath: a.socket,
		Keys:       a.vault,
		Approver:   a.approver,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	if err := bystander.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := os.Stat(a.socket); err != nil {
		t.Fatalf("the socket was removed by a server that never listened: %v", err)
	}

	if _, err := a.client(t).List(); err != nil {
		t.Errorf("the running agent stopped answering: %v", err)
	}
}
