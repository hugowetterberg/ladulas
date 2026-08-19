package agent_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/agent"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// A keyless instance's agent is the M4 shape of §3: it lists keys that live on
// paired holders and forwards sign requests to them, and ssh cannot tell the
// difference. What is stubbed here is the channel; what is tested is that the
// agent asks the right side of it and reports the answer honestly.

// holder stands in for a paired key holder: it offers one key, signs with it,
// and answers with a signed approval artifact the way a real one does.
type holder struct {
	identity *identity.Identity
	signer   ssh.Signer
	ref      *ladulasv1.KeyRef

	mu       sync.Mutex
	decision ladulasv1.Decision
	asked    []*ladulasv1.ApprovalRequest
	payloads [][]byte
	wrapped  []bool
}

func newHolder(t *testing.T, decision ladulasv1.Decision) *holder {
	t.Helper()

	id, _, err := identity.Generate("desktop")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	vault, err := keystore.Create(keystore.Options{
		Dir:              t.TempDir(),
		Keyring:          &keystore.MemoryKeyring{},
		Passphrase:       testPassphrase,
		InstanceName:     "desktop",
		ScryptWorkFactor: 10,
	})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	stored, err := vault.GenerateKey("work", "hugo@example.com")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	signer, _, err := vault.Signer(stored.GetFingerprint())
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	return &holder{
		identity: id,
		signer:   signer,
		ref:      keystore.KeyRef(stored),
		decision: decision,
	}
}

func (h *holder) RemoteKeyRefs() []*ladulasv1.KeyRef {
	h.mu.Lock()
	defer h.mu.Unlock()

	return []*ladulasv1.KeyRef{h.ref}
}

// RefreshKeys is a no-op here: what a stub offers does not change.
func (h *holder) RefreshKeys(context.Context) {}

// BorrowedKey remembers exactly what the stub offers, since a stub is never
// unreachable.
func (h *holder) BorrowedKey(blob []byte) (*ladulasv1.KeyRef, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !bytes.Equal(h.ref.GetPublicKey(), blob) {
		return nil, false
	}

	return h.ref, true
}

func (h *holder) RemoteSign(
	_ context.Context,
	req *ladulasv1.ApprovalRequest,
	payload []byte,
	wrapSSHSIG bool,
) (*ladulasv1.RemoteSignResponse, error) {
	h.mu.Lock()
	h.asked = append(h.asked, proto.CloneOf(req))
	h.payloads = append(h.payloads, payload)
	h.wrapped = append(h.wrapped, wrapSSHSIG)
	decision := h.decision
	h.mu.Unlock()

	signed, err := h.identity.SignApproval(&ladulasv1.ApprovalResponse{
		RequestId: req.GetRequestId(),
		Decision:  decision,
		Source:    ladulasv1.DecisionSource_DECISION_SOURCE_USER,
		DecidedAt: timestamppb.Now(),
		Reason:    "answered at the desktop",
		Approver:  h.identity.ApproverInfo(false),
	})
	if err != nil {
		return nil, err
	}

	out := &ladulasv1.RemoteSignResponse{Approval: signed}

	if decision != ladulasv1.Decision_DECISION_APPROVE {
		return out, nil
	}

	sig, err := h.signer.Sign(rand.Reader, payload)
	if err != nil {
		return nil, err
	}

	out.Signature = ssh.Marshal(sig)

	return out, nil
}

// lends makes the stub offer a key that lives in somebody else's store as well.
//
// It cannot sign with that one, and nothing in the cases that use it is supposed
// to ask: the whole point is that the instance holding the copy answers for
// itself.
func (h *holder) lends(ref *ladulasv1.KeyRef) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.ref = ref
}

func (h *holder) last() (*ladulasv1.ApprovalRequest, []byte, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.asked) == 0 {
		return nil, nil, false
	}

	return h.asked[len(h.asked)-1],
		h.payloads[len(h.payloads)-1],
		h.wrapped[len(h.wrapped)-1]
}

// keylessAgent is an agent over a store with no keys in it at all.
type keylessAgent struct {
	socket   string
	approver *stubApprover
	holder   *holder
}

func newKeylessAgent(t *testing.T, decision ladulasv1.Decision) *keylessAgent {
	t.Helper()

	return newRemoteAgent(t, newVault(t, "headless"), newHolder(t, decision))
}

// newVault is a store of its own, so that a case can decide what is in it.
func newVault(t *testing.T, name string) *keystore.Vault {
	t.Helper()

	vault, err := keystore.Create(keystore.Options{
		Dir:              t.TempDir(),
		Keyring:          &keystore.MemoryKeyring{},
		Passphrase:       testPassphrase,
		InstanceName:     name,
		ScryptWorkFactor: 10,
	})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	return vault
}

// newRemoteAgent serves an agent over a store and a paired holder, whatever
// each of them holds.
func newRemoteAgent(
	t *testing.T, vault *keystore.Vault, remote *holder,
) *keylessAgent {
	t.Helper()

	// The local approver would approve anything. It is here to fail the test if
	// the agent ever asks it about a key that lives somewhere else: a borrowed
	// signature is decided by the holder and by nobody here (§8).
	approver := &stubApprover{decision: ladulasv1.Decision_DECISION_APPROVE}
	socket := filepath.Join(socketDir(t), "agent.sock")

	server, err := agent.New(agent.Options{
		SocketPath: socket,
		Keys:       vault,
		Approver:   approver,
		Remote:     remote,
		KnownHosts: agent.NewKnownHosts(filepath.Join(t.TempDir(), "known_hosts")),
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

	return &keylessAgent{socket: socket, approver: approver, holder: remote}
}

func (a *keylessAgent) client(t *testing.T) sshagent.ExtendedAgent {
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

// TestAKeylessAgentListsThePeersKeys: ssh asks for identities and is given the
// holder's, with nothing to say they are not local.
func TestAKeylessAgentListsThePeersKeys(t *testing.T) {
	a := newKeylessAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	keys, err := a.client(t).List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("the keyless agent listed %d keys", len(keys))
	}

	if string(keys[0].Blob) != string(a.holder.ref.GetPublicKey()) {
		t.Error("the listed key is not the one the holder offers")
	}
}

// TestAKeylessAgentBorrowsTheSignature: the signature comes from the holder,
// verifies under the holder's key, and this instance's own approver is never
// asked — asking twice would put one operation in front of two people.
func TestAKeylessAgentBorrowsTheSignature(t *testing.T) {
	a := newKeylessAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	pub, err := ssh.ParsePublicKey(a.holder.ref.GetPublicKey())
	if err != nil {
		t.Fatalf("parse the key: %v", err)
	}

	digest := sha512.Sum512([]byte("a commit object"))
	payload := sshsigBlob("git", "sha512", digest[:])

	sig, err := a.client(t).Sign(pub, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := pub.Verify(payload, sig); err != nil {
		t.Errorf("the borrowed signature does not verify: %v", err)
	}

	if a.approver.count() != 0 {
		t.Errorf("the keyless instance asked its own approver %d times",
			a.approver.count())
	}

	// The holder was handed the exact blob the agent was given, not a rewrapped
	// one: an agent payload is already the thing to sign.
	asked, sent, wrapped := a.holder.last()
	if asked == nil {
		t.Fatal("the holder was never asked")
	}

	if wrapped {
		t.Error("the agent asked the holder to wrap a payload that is already a blob")
	}

	if string(sent) != string(payload) {
		t.Error("the holder was sent something other than the payload")
	}

	if asked.GetKind() != ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN {
		t.Errorf("the request went out as %v", asked.GetKind())
	}
}

// TestABorrowedRefusalIsARefusal: a denial by the holder is final here. Nothing
// falls back to the local approver, which would have said yes.
//
// The reason does not reach ssh — the agent protocol has no room for one, which
// is a limitation of SSH_AGENT_FAILURE and not of this path — so what is
// asserted is that the operation failed and that nobody else was asked. The
// reason does reach a user through ladulas-sign, which has a response type with
// somewhere to put it (§5).
func TestABorrowedRefusalIsARefusal(t *testing.T) {
	a := newKeylessAgent(t, ladulasv1.Decision_DECISION_DENY)

	pub, err := ssh.ParsePublicKey(a.holder.ref.GetPublicKey())
	if err != nil {
		t.Fatalf("parse the key: %v", err)
	}

	digest := sha512.Sum512([]byte("a commit object"))

	_, err = a.client(t).Sign(pub, sshsigBlob("git", "sha512", digest[:]))
	if err == nil {
		t.Fatal("a refused signature came back anyway")
	}

	if a.approver.count() != 0 {
		t.Errorf("a refusal by the holder was taken to the local approver %d times",
			a.approver.count())
	}
}

// TestAKeyHeldHereIsSignedHere is decision S meeting decision N: the same
// portable key is in this store and on the holder that handed it over, and the
// copy here is what answers.
//
// Both halves are asserted because both are wrong in a different way. Two
// entries of one fingerprint in the identity list would have ssh try the same
// key twice against a server that allows six attempts; and asking the holder for
// a signature this instance can make itself would wake a phone for nothing and
// throw away the delegation that covers the local key (decision P).
func TestAKeyHeldHereIsSignedHere(t *testing.T) {
	vault := newVault(t, "laptop")

	stored, err := vault.GenerateKey("old", "hugo@example.com")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	remote := newHolder(t, ladulasv1.Decision_DECISION_APPROVE)
	remote.lends(keystore.KeyRef(stored))

	a := newRemoteAgent(t, vault, remote)

	keys, err := a.client(t).List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("the agent offered %d identities for one key", len(keys))
	}

	pub, err := ssh.ParsePublicKey(stored.GetPublicKey())
	if err != nil {
		t.Fatalf("parse the key: %v", err)
	}

	digest := sha512.Sum512([]byte("a commit object"))
	payload := sshsigBlob("git", "sha512", digest[:])

	sig, err := a.client(t).Sign(pub, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := pub.Verify(payload, sig); err != nil {
		t.Errorf("the local signature does not verify: %v", err)
	}

	if a.approver.count() != 1 {
		t.Errorf("the local approver was asked %d times", a.approver.count())
	}

	if asked, _, _ := a.holder.last(); asked != nil {
		t.Error("the holder was asked for a signature this instance could make")
	}
}

// TestAKeyNobodyHoldsIsNotOffered: a key that is neither here nor on a paired
// holder is refused, which is what makes ladulas-sign's fall back to ssh-keygen
// reachable.
func TestAKeyNobodyHoldsIsNotOffered(t *testing.T) {
	a := newKeylessAgent(t, ladulasv1.Decision_DECISION_APPROVE)

	stranger := newHolder(t, ladulasv1.Decision_DECISION_APPROVE)

	pub, err := ssh.ParsePublicKey(stranger.ref.GetPublicKey())
	if err != nil {
		t.Fatalf("parse the key: %v", err)
	}

	digest := sha512.Sum512([]byte("a commit object"))

	_, err = a.client(t).Sign(pub, sshsigBlob("git", "sha512", digest[:]))
	if err == nil {
		t.Fatal("a key nobody holds was signed with")
	}
}
