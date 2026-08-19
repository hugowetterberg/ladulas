package localapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// ladulas-sign on a keyless box is the other half of §3: the key is somewhere
// else, the payload goes there whole, and what comes back is an armoured
// signature git can write to a commit. What is stubbed here is the channel.

// remoteHolder stands in for a paired key holder reached over the peer channel.
type remoteHolder struct {
	identity *identity.Identity
	signer   ssh.Signer
	decision ladulasv1.Decision

	asked   []*ladulasv1.ApprovalRequest
	payload []byte
	wrapped bool
}

func (r *remoteHolder) ref() *ladulasv1.KeyRef {
	return &ladulasv1.KeyRef{
		Fingerprint: ssh.FingerprintSHA256(r.signer.PublicKey()),
		Algorithm:   r.signer.PublicKey().Type(),
		PublicKey:   r.signer.PublicKey().Marshal(),
		Label:       "desktop-work",
		Comment:     "work@desktop.example.test",
	}
}

func (r *remoteHolder) RemoteKeyRefs() []*ladulasv1.KeyRef {
	return []*ladulasv1.KeyRef{r.ref()}
}

// RefreshKeys is a no-op here: what a stub offers does not change.
func (r *remoteHolder) RefreshKeys(context.Context) {}

// BorrowedKey remembers exactly what the stub offers, since a stub is never
// unreachable.
func (r *remoteHolder) BorrowedKey(blob []byte) (*ladulasv1.KeyRef, bool) {
	ref := r.ref()

	if !bytes.Equal(ref.GetPublicKey(), blob) {
		return nil, false
	}

	return ref, true
}

func (r *remoteHolder) RemoteSign(
	_ context.Context,
	req *ladulasv1.ApprovalRequest,
	payload []byte,
	wrapSSHSIG bool,
) (*ladulasv1.RemoteSignResponse, error) {
	r.asked = append(r.asked, req)
	r.payload = payload
	r.wrapped = wrapSSHSIG

	signed, err := r.identity.SignApproval(&ladulasv1.ApprovalResponse{
		RequestId: req.GetRequestId(),
		Decision:  r.decision,
		Source:    ladulasv1.DecisionSource_DECISION_SOURCE_USER,
		Reason:    "answered at the desktop",
		Approver:  r.identity.ApproverInfo(false),
	})
	if err != nil {
		return nil, err
	}

	out := &ladulasv1.RemoteSignResponse{Approval: signed}

	if r.decision != ladulasv1.Decision_DECISION_APPROVE {
		return out, nil
	}

	// The holder builds the wrapper itself; that is what wrapSSHSIG asks for.
	blob, err := sshsig.SigningBlobFor(
		req.GetSshsig().GetNamespace(),
		req.GetSshsig().GetHashAlgorithm(), payload)
	if err != nil {
		return nil, err
	}

	sig, err := r.signer.Sign(rand.Reader, blob)
	if err != nil {
		return nil, err
	}

	out.Signature = ssh.Marshal(sig)

	return out, nil
}

// keylessFixture is a signing socket over a store with no keys in it.
type keylessFixture struct {
	client   *localapi.Client
	approver *approver
	holder   *remoteHolder
}

// emptyKeys is a store that holds nothing, which is what a keyless instance is.
type emptyKeys struct{}

var errNoKeys = errors.New("this instance holds no keys")

func (emptyKeys) KeyRefs() []*ladulasv1.KeyRef {
	return nil
}

func (emptyKeys) Signer(string) (ssh.Signer, *storepb.StoredKey, error) {
	return nil, nil, errNoKeys
}

func newKeylessFixture(t *testing.T, decision ladulasv1.Decision) *keylessFixture {
	t.Helper()

	id, _, err := identity.Generate("desktop")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	holder := &remoteHolder{
		identity: id,
		signer:   newSigner(t),
		decision: decision,
	}

	// The local approver would approve anything, and is here to fail the test if
	// it is ever consulted about a key that lives elsewhere (§8).
	app := &approver{decision: ladulasv1.Decision_DECISION_APPROVE}

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
		Keys:       emptyKeys{},
		Approver:   app,
		Remote:     holder,
		Identity: func() *ladulasv1.RequesterInfo {
			return &ladulasv1.RequesterInfo{
				InstanceId: "SHA256:headless", Name: "headless", Local: true,
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

	return &keylessFixture{
		client:   localapi.NewClient(socket),
		approver: app,
		holder:   holder,
	}
}

// TestSignPayloadBorrowsAKey: the whole commit goes to the holder unhashed and
// unwrapped, and the armour that comes back is a signature over it.
func TestSignPayloadBorrowsAKey(t *testing.T) {
	f := newKeylessFixture(t, ladulasv1.Decision_DECISION_APPROVE)

	resp, err := f.client.SignPayload(context.Background(),
		&ladulasv1.SignPayloadRequest{
			PublicKey: f.holder.ref().GetPublicKey(),
			Payload:   []byte(commitObject),
			Namespace: "git",
			Timeout:   durationpb.New(30 * time.Second),
			GitContext: &ladulasv1.GitContext{
				RepositoryPath: "/srv/build/ladulas",
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
		t.Errorf("the borrowed signature does not cover the payload: %v", err)
	}

	// The holder was sent the raw commit and asked to wrap it, which is what
	// puts the object rather than a digest in front of the approver (§5).
	if !f.holder.wrapped {
		t.Error("the payload went out already wrapped")
	}

	if string(f.holder.payload) != commitObject {
		t.Error("the holder was sent something other than the commit object")
	}

	if len(f.approver.requests) != 0 {
		t.Errorf("the keyless instance asked its own approver %d times",
			len(f.approver.requests))
	}

	if resp.GetApproval().GetApproverFingerprint() !=
		f.holder.identity.Fingerprint() {
		t.Error("the response does not carry the holder's own artifact")
	}
}

// TestABorrowedRefusalCarriesTheReason: a denial is an answer, and it is the
// answer git prints — nothing falls back to ssh-keygen on a refusal (§5).
func TestABorrowedRefusalCarriesTheReason(t *testing.T) {
	f := newKeylessFixture(t, ladulasv1.Decision_DECISION_DENY)

	resp, err := f.client.SignPayload(context.Background(),
		&ladulasv1.SignPayloadRequest{
			PublicKey: f.holder.ref().GetPublicKey(),
			Payload:   []byte(commitObject),
			Namespace: "git",
		})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if resp.GetApproved() {
		t.Fatal("a refused signature came back approved")
	}

	if !strings.Contains(resp.GetReason(), "answered at the desktop") {
		t.Errorf("the caller was told %q", resp.GetReason())
	}

	if resp.GetArmoredSignature() != "" {
		t.Error("a refusal came back with a signature")
	}
}
