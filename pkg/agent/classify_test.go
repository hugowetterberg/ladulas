package agent_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/pkg/agent"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

func str(s string) []byte {
	return blob([]byte(s))
}

func blob(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)

	return out
}

// sshsigBlob builds what ssh-keygen -Y sign hands the agent.
func sshsigBlob(namespace, hashAlgorithm string, digest []byte) []byte {
	var out []byte

	out = append(out, "SSHSIG"...)
	out = append(out, str(namespace)...)
	out = append(out, str("")...)
	out = append(out, str(hashAlgorithm)...)
	out = append(out, blob(digest)...)

	return out
}

// authBlob builds an RFC 4252 §7 public key authentication blob.
func authBlob(sessionID []byte, username, service string, pub ssh.PublicKey) []byte {
	var out []byte

	out = append(out, blob(sessionID)...)
	out = append(out, 50)
	out = append(out, str(username)...)
	out = append(out, str(service)...)
	out = append(out, str("publickey")...)
	out = append(out, 1)
	out = append(out, str(pub.Type())...)
	out = append(out, blob(pub.Marshal())...)

	return out
}

// hostboundBlob is what ssh actually sends to nearly every server it logs in
// to: the same blob with the method OpenSSH negotiated since 8.9 and the
// server's host key on the end.
func hostboundBlob(
	sessionID []byte, username string, pub, hostKey ssh.PublicKey,
) []byte {
	var out []byte

	out = append(out, blob(sessionID)...)
	out = append(out, 50)
	out = append(out, str(username)...)
	out = append(out, str("ssh-connection")...)
	out = append(out, str(agent.MethodHostbound)...)
	out = append(out, 1)
	out = append(out, str(pub.Type())...)
	out = append(out, blob(pub.Marshal())...)
	out = append(out, blob(hostKey.Marshal())...)

	return out
}

func testPublicKey(t *testing.T) ssh.PublicKey {
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

func TestClassifyGitSignature(t *testing.T) {
	digest := sha512.Sum512([]byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n"))

	got := agent.Classify(sshsigBlob("git", "sha512", digest[:]))

	if got.Kind != ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN {
		t.Fatalf("want GIT_SIGN, got %v (%s)", got.Kind, opaqueReason(got))
	}

	if got.Sshsig.GetNamespace() != "git" {
		t.Errorf("namespace: %q", got.Sshsig.GetNamespace())
	}

	if got.Sshsig.GetHashAlgorithm() != "sha512" {
		t.Errorf("hash algorithm: %q", got.Sshsig.GetHashAlgorithm())
	}

	if string(got.Sshsig.GetMessageDigest()) != string(digest[:]) {
		t.Error("digest did not survive parsing")
	}
}

// A non-git namespace is still a legitimate SSHSIG request, just not a commit.
func TestClassifyOtherNamespaceSignature(t *testing.T) {
	got := agent.Classify(sshsigBlob("file", "sha512", []byte("digest")))

	if got.Kind != ladulasv1.RequestKind_REQUEST_KIND_SSHSIG {
		t.Fatalf("want SSHSIG, got %v", got.Kind)
	}
}

func TestClassifySSHAuth(t *testing.T) {
	pub := testPublicKey(t)
	sessionID := []byte("session-identifier")

	got := agent.Classify(authBlob(sessionID, "hugo", "ssh-connection", pub))

	if got.Kind != ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH {
		t.Fatalf("want SSH_AUTH, got %v (%s)", got.Kind, opaqueReason(got))
	}

	if got.SSHAuth.GetUsername() != "hugo" {
		t.Errorf("username: %q", got.SSHAuth.GetUsername())
	}

	if got.SSHAuth.GetService() != "ssh-connection" {
		t.Errorf("service: %q", got.SSHAuth.GetService())
	}

	if string(got.SSHAuth.GetSessionId()) != string(sessionID) {
		t.Error("session identifier did not survive parsing")
	}
}

// The method ssh really uses (§4). It went unhandled until an ssh to GitHub
// failed with "agent refused operation", and the honest form of the lesson is
// this test: an authentication blob this does not recognise is a login that
// cannot happen at all.
func TestClassifyHostboundSSHAuth(t *testing.T) {
	pub := testPublicKey(t)
	hostKey := testPublicKey(t)
	sessionID := []byte("session-identifier")

	got := agent.Classify(hostboundBlob(sessionID, "hugo", pub, hostKey))

	if got.Kind != ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH {
		t.Fatalf("want SSH_AUTH, got %v (%s)", got.Kind, opaqueReason(got))
	}

	if got.SSHAuth.GetMethod() != agent.MethodHostbound {
		t.Errorf("method: %q", got.SSHAuth.GetMethod())
	}

	if got.SSHAuth.GetUsername() != "hugo" {
		t.Errorf("username: %q", got.SSHAuth.GetUsername())
	}

	// The host key inside the payload is the point of the method, and the thing
	// an approver somewhere else can trust without trusting the machine that
	// asked (§15).
	named := got.SSHAuth.GetPayloadDestination()

	if named.GetFingerprint() != ssh.FingerprintSHA256(hostKey) {
		t.Errorf("the payload's host key is %q", named.GetFingerprint())
	}

	if string(named.GetBlob()) != string(hostKey.Marshal()) {
		t.Error("the host key blob did not survive parsing")
	}

	// And the plain method carries none, rather than an empty one.
	plain := agent.Classify(authBlob(sessionID, "hugo", "ssh-connection", pub))
	if plain.SSHAuth.GetPayloadDestination() != nil {
		t.Error("a plain publickey blob named a destination")
	}
}

// Everything that is neither is denied by default, so everything that is
// neither has to classify as opaque rather than being forced into one of the
// two shapes.
func TestClassifyOpaque(t *testing.T) {
	pub := testPublicKey(t)

	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{name: "empty", payload: nil},
		{name: "random", payload: []byte("just some bytes to sign, please")},
		{
			name:    "sshsig truncated",
			payload: sshsigBlob("git", "sha512", []byte("d"))[:10],
		},
		{
			name: "sshsig with trailing bytes",
			payload: append(
				sshsigBlob("git", "sha512", []byte("digest")), 'x'),
		},
		{
			name:    "sshsig with empty namespace",
			payload: sshsigBlob("", "sha512", []byte("digest")),
		},
		{
			name: "auth blob with trailing bytes",
			payload: append(
				authBlob([]byte("sid"), "hugo", "ssh-connection", pub), 'x'),
		},
		{
			name:    "auth blob truncated",
			payload: authBlob([]byte("sid"), "hugo", "ssh-connection", pub)[:20],
		},
		{
			name:    "auth blob with wrong method",
			payload: wrongMethodAuthBlob([]byte("sid"), pub),
		},
		{
			// The strictness the hostbound method must not lose: a host key that
			// is not one is not a destination, and a signature over it would be a
			// signature over something nobody parsed.
			name: "hostbound blob with an unreadable host key",
			payload: func() []byte {
				b := hostboundBlob([]byte("sid"), "hugo", pub, pub)
				b = b[:len(b)-4-len(pub.Marshal())]

				return append(b, blob([]byte("not a public key"))...)
			}(),
		},
		{
			name: "hostbound blob with no host key",
			payload: func() []byte {
				b := hostboundBlob([]byte("sid"), "hugo", pub, pub)

				return b[:len(b)-4-len(pub.Marshal())]
			}(),
		},
		{
			name: "auth blob with wrong message type",
			payload: func() []byte {
				b := authBlob([]byte("sid"), "hugo", "ssh-connection", pub)
				b[4+3] = 51

				return b
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := agent.Classify(tc.payload)

			if got.Kind != ladulasv1.RequestKind_REQUEST_KIND_OPAQUE_SIGN {
				t.Fatalf("want OPAQUE_SIGN, got %v", got.Kind)
			}

			if got.Opaque.GetReason() == "" {
				t.Error("opaque classification carries no reason")
			}

			if got.Opaque.GetPayloadLength() != uint32(len(tc.payload)) {
				t.Errorf("payload length %d, want %d",
					got.Opaque.GetPayloadLength(), len(tc.payload))
			}
		})
	}
}

func wrongMethodAuthBlob(sessionID []byte, pub ssh.PublicKey) []byte {
	var out []byte

	out = append(out, blob(sessionID)...)
	out = append(out, 50)
	out = append(out, str("hugo")...)
	out = append(out, str("ssh-connection")...)
	out = append(out, str("password")...)
	out = append(out, 1)
	out = append(out, str(pub.Type())...)
	out = append(out, blob(pub.Marshal())...)

	return out
}

func opaqueReason(c agent.Classification) string {
	if c.Opaque == nil {
		return ""
	}

	return c.Opaque.GetReason()
}
