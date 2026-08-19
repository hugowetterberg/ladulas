package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/ssh"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

func marshalString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)

	return out
}

func newHostKey(t *testing.T) ssh.Signer {
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

func bindPayload(t *testing.T, host ssh.Signer, sessionID []byte, forwarding bool) []byte {
	t.Helper()

	sig, err := host.Sign(rand.Reader, sessionID)
	if err != nil {
		t.Fatalf("sign session id: %v", err)
	}

	var out []byte

	out = append(out, marshalString(host.PublicKey().Marshal())...)
	out = append(out, marshalString(sessionID)...)
	out = append(out, marshalString(ssh.Marshal(sig))...)

	if forwarding {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}

	return out
}

func TestParseSessionBind(t *testing.T) {
	host := newHostKey(t)
	sessionID := []byte("a session identifier")

	pub, gotSessionID, forwarding, err := parseSessionBind(
		bindPayload(t, host, sessionID, true))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if string(pub.Marshal()) != string(host.PublicKey().Marshal()) {
		t.Error("host key did not survive parsing")
	}

	if string(gotSessionID) != string(sessionID) {
		t.Error("session identifier did not survive parsing")
	}

	if !forwarding {
		t.Error("is_forwarding was lost")
	}
}

// The signature is what makes the destination in a prompt evidence rather than
// a claim, so a binding whose signature does not verify has to be rejected.
func TestParseSessionBindRejectsBadSignature(t *testing.T) {
	host := newHostKey(t)
	other := newHostKey(t)
	sessionID := []byte("a session identifier")

	t.Run("wrong signer", func(t *testing.T) {
		payload := bindPayload(t, other, sessionID, false)

		// Swap in a different host key, keeping the signature.
		var out []byte

		out = append(out, marshalString(host.PublicKey().Marshal())...)
		out = append(out, payload[4+len(other.PublicKey().Marshal()):]...)

		if _, _, _, err := parseSessionBind(out); err == nil {
			t.Fatal("accepted a binding signed by a different key")
		}
	})

	t.Run("different session id", func(t *testing.T) {
		sig, err := host.Sign(rand.Reader, []byte("some other session"))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}

		var out []byte

		out = append(out, marshalString(host.PublicKey().Marshal())...)
		out = append(out, marshalString(sessionID)...)
		out = append(out, marshalString(ssh.Marshal(sig))...)
		out = append(out, 0)

		if _, _, _, err := parseSessionBind(out); err == nil {
			t.Fatal("accepted a signature over a different session identifier")
		}
	})

	t.Run("trailing bytes", func(t *testing.T) {
		payload := append(bindPayload(t, host, sessionID, false), 'x')

		if _, _, _, err := parseSessionBind(payload); err == nil {
			t.Fatal("accepted a payload with trailing bytes")
		}
	})

	t.Run("empty session id", func(t *testing.T) {
		payload := bindPayload(t, host, []byte{}, false)

		if _, _, _, err := parseSessionBind(payload); err == nil {
			t.Fatal("accepted an empty session identifier")
		}
	})
}

func binding(sessionID string, forwarding bool) *ladulasv1.SessionBinding {
	return &ladulasv1.SessionBinding{
		SessionId:    []byte(sessionID),
		IsForwarding: forwarding,
		HostKey:      &ladulasv1.HostKey{Fingerprint: "SHA256:" + sessionID},
	}
}

// The binding list doubles as the hop chain: entry 0 is the connection this
// socket belongs to, and OpenSSH marks it is_forwarding when the socket is
// itself forwarded.
func TestBindingsContext(t *testing.T) {
	for _, tc := range []struct {
		name          string
		list          []*ladulasv1.SessionBinding
		sessionID     string
		wantMatch     string
		wantForwarded bool
		wantHops      int32
	}{
		{
			name:      "direct connection",
			list:      []*ladulasv1.SessionBinding{binding("bastion", false)},
			sessionID: "bastion",
			wantMatch: "bastion",
		},
		{
			name: "forwarded socket, first hop",
			list: []*ladulasv1.SessionBinding{
				binding("bastion", true),
			},
			sessionID:     "bastion",
			wantMatch:     "bastion",
			wantForwarded: true,
			wantHops:      1,
		},
		{
			name: "forwarded socket, second hop",
			list: []*ladulasv1.SessionBinding{
				binding("bastion", true),
				binding("inner", false),
			},
			sessionID:     "inner",
			wantMatch:     "inner",
			wantForwarded: true,
			wantHops:      1,
		},
		{
			name: "two forwarding hops",
			list: []*ladulasv1.SessionBinding{
				binding("bastion", true),
				binding("middle", true),
				binding("inner", false),
			},
			sessionID:     "inner",
			wantMatch:     "inner",
			wantForwarded: true,
			wantHops:      2,
		},
		{
			name: "unmatched session on a forwarded socket",
			list: []*ladulasv1.SessionBinding{
				binding("bastion", true),
			},
			sessionID:     "somewhere-else",
			wantForwarded: true,
			wantHops:      1,
		},
		{
			name:      "no bindings at all",
			sessionID: "anything",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bindings

			for _, entry := range tc.list {
				if err := b.add(entry); err != nil {
					t.Fatalf("add: %v", err)
				}
			}

			got := b.context([]byte(tc.sessionID))

			switch {
			case tc.wantMatch == "" && got.binding != nil:
				t.Errorf("matched %q, wanted no match",
					got.binding.GetSessionId())
			case tc.wantMatch != "" && got.binding == nil:
				t.Errorf("no match, wanted %q", tc.wantMatch)
			case tc.wantMatch != "" && string(got.binding.GetSessionId()) != tc.wantMatch:
				t.Errorf("matched %q, want %q",
					got.binding.GetSessionId(), tc.wantMatch)
			}

			if got.forwarded != tc.wantForwarded {
				t.Errorf("forwarded = %v, want %v", got.forwarded, tc.wantForwarded)
			}

			if got.hops != tc.wantHops {
				t.Errorf("hops = %d, want %d", got.hops, tc.wantHops)
			}

			if len(got.chain) != len(tc.list) {
				t.Errorf("chain has %d entries, want %d", len(got.chain), len(tc.list))
			}
		})
	}
}

func TestBindingsAreCapped(t *testing.T) {
	var b bindings

	for i := range maxBindings {
		if err := b.add(binding(string(rune('a'+i)), false)); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}

	if err := b.add(binding("one too many", false)); err == nil {
		t.Fatal("the binding list grew without bound")
	}
}
