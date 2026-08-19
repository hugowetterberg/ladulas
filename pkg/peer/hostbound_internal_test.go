package peer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/pkg/agent"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The holder's half of a hostbound login (§4, §15).
//
// A key holder is asked to sign an authentication blob by a machine it does not
// trust — that is the whole premise of remote signing — and the blob names the
// server the login is for. So the holder takes the destination from the bytes
// and refuses a request that describes a different one, rather than showing
// somebody a prompt that says github.com over a signature for somewhere else.

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	return sshPub
}

func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)

	return out
}

func hostboundPayload(
	sessionID []byte, username string, pub, hostKey ssh.PublicKey,
) []byte {
	var out []byte

	out = append(out, sshString(sessionID)...)
	out = append(out, 50)
	out = append(out, sshString([]byte(username))...)
	out = append(out, sshString([]byte("ssh-connection"))...)
	out = append(out, sshString([]byte(agent.MethodHostbound))...)
	out = append(out, 1)
	out = append(out, sshString([]byte(pub.Type()))...)
	out = append(out, sshString(pub.Marshal())...)
	out = append(out, sshString(hostKey.Marshal())...)

	return out
}

func TestAHostboundLoginTakesItsDestinationFromThePayload(t *testing.T) {
	pub := testKey(t)
	hostKey := testKey(t)

	payload := hostboundPayload([]byte("session"), "hugo", pub, hostKey)

	// What a requester sends: its own parse of the payload, and the known_hosts
	// name only it can produce.
	msg := &ladulasv1.ApprovalRequest{
		Operation: &ladulasv1.ApprovalRequest_SshAuth{
			SshAuth: &ladulasv1.SshAuthRequest{
				SessionId:        []byte("session"),
				Bound:            true,
				Destination:      hostKeyMessage(hostKey, "github.com"),
				DestinationLabel: "github.com",
			},
		},
	}

	if err := rebuildOperation(msg, payload, false); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	auth := msg.GetSshAuth()

	if msg.GetKind() != ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH {
		t.Fatalf("the payload classified as %v", msg.GetKind())
	}

	if auth.GetPayloadDestination().GetFingerprint() !=
		ssh.FingerprintSHA256(hostKey) {
		t.Errorf("the destination in the payload is %q",
			auth.GetPayloadDestination().GetFingerprint())
	}

	// The label the requester sent survives, because it is about the same host
	// key and it is the only place a name could come from.
	if auth.GetDestinationLabel() != "github.com" {
		t.Errorf("the destination is shown as %q", auth.GetDestinationLabel())
	}
}

// The §15 attack in its authentication form: a compromised requester asking for
// a signature for one server while telling the approver it is another.
func TestADestinationThatIsNotTheSignedOneIsRefused(t *testing.T) {
	pub := testKey(t)
	hostKey := testKey(t)
	elsewhere := testKey(t)

	payload := hostboundPayload([]byte("session"), "hugo", pub, hostKey)

	msg := &ladulasv1.ApprovalRequest{
		Operation: &ladulasv1.ApprovalRequest_SshAuth{
			SshAuth: &ladulasv1.SshAuthRequest{
				SessionId:        []byte("session"),
				Bound:            true,
				Destination:      hostKeyMessage(elsewhere, "github.com"),
				DestinationLabel: "github.com",
			},
		},
	}

	err := rebuildOperation(msg, payload, false)
	if err == nil {
		t.Fatal("a request naming the wrong destination was accepted")
	}

	if !strings.Contains(err.Error(), "different destination") {
		t.Errorf("the refusal does not say what was wrong: %v", err)
	}
}

// A holder with no known_hosts is the ordinary case — a phone — and it has to
// end up with something to show rather than an empty line.
func TestAHolderWithoutKnownHostsNamesTheFingerprint(t *testing.T) {
	pub := testKey(t)
	hostKey := testKey(t)

	payload := hostboundPayload([]byte("session"), "hugo", pub, hostKey)

	msg := &ladulasv1.ApprovalRequest{
		Operation: &ladulasv1.ApprovalRequest_SshAuth{
			SshAuth: &ladulasv1.SshAuthRequest{SessionId: []byte("session")},
		},
	}

	if err := rebuildOperation(msg, payload, false); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	if msg.GetSshAuth().GetDestinationLabel() != ssh.FingerprintSHA256(hostKey) {
		t.Errorf("the destination is shown as %q",
			msg.GetSshAuth().GetDestinationLabel())
	}
}

func hostKeyMessage(pub ssh.PublicKey, name string) *ladulasv1.HostKey {
	return &ladulasv1.HostKey{
		Blob:            pub.Marshal(),
		Algorithm:       pub.Type(),
		Fingerprint:     ssh.FingerprintSHA256(pub),
		KnownHostsNames: []string{name},
		Known:           true,
	}
}
