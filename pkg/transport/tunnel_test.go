package transport_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// TestHandshakeNegotiatesHybridKeyExchange holds §8's post-quantum claim to
// something. The tunnel's own pre-shared key is not relied on for
// confidentiality against a future quantum adversary; the pinned TLS inside it
// is, and Go negotiates X25519MLKEM768 by default only for as long as nobody
// sets CurvePreferences, GODEBUG=tlsmlkem=0, or a FIPS build. A peer that drops
// the hybrid falls back to plain X25519 without any error, so the only place
// this can be noticed is a test (decision AX).
func TestHandshakeNegotiatesHybridKeyExchange(t *testing.T) {
	serverID := newIdentity(t, "desktop")
	clientID := newIdentity(t, "laptop")

	var reached bool

	_, address := serve(t, transport.ServerOptions{
		Identity: serverID,
		Handler:  echoHandler(&reached),
	})

	client, err := transport.NewClient(transport.ClientOptions{
		Identity: clientID,
		Expect:   serverID.PublicKey(),
	})
	if err != nil {
		t.Fatalf("create the client: %v", err)
	}

	resp, err := client.HTTP().Get(client.URL(address) + "/")
	if err != nil {
		t.Fatalf("call the peer: %v", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.TLS == nil {
		t.Fatal("the response carries no TLS state")
	}

	if resp.TLS.CurveID != tls.X25519MLKEM768 {
		t.Errorf("the handshake used %v, want X25519MLKEM768", resp.TLS.CurveID)
	}
}

// tunnelGate is a TunnelGate a test can program.
type tunnelGate struct {
	admit  func(fingerprint string, key []byte) error
	permit func(fingerprint, procedure string) error
}

func (g tunnelGate) Admit(fingerprint string, key []byte) error {
	return g.admit(fingerprint, key)
}

func (g tunnelGate) Permit(fingerprint, procedure string) error {
	return g.permit(fingerprint, procedure)
}

// fakeTunnel is a tunnel made of a loopback socket: every connection it
// accepts claims to have come over a direct tunnel path from one client key.
// It stands in for tailcat, which needs a DERP region to start at all.
type fakeTunnel struct {
	listener net.Listener
	key      []byte
	path     string
}

func (f *fakeTunnel) Accept() (transport.TunnelConn, error) {
	conn, err := f.listener.Accept()
	if err != nil {
		return nil, err
	}

	return &fakeTunnelConn{Conn: conn, key: f.key, path: f.path}, nil
}

func (f *fakeTunnel) Close() error {
	return f.listener.Close()
}

type fakeTunnelConn struct {
	net.Conn

	key  []byte
	path string
}

func (c *fakeTunnelConn) SetDeadline(n int64) error {
	return c.Conn.SetDeadline(deadline(n))
}

func (c *fakeTunnelConn) SetReadDeadline(n int64) error {
	return c.Conn.SetReadDeadline(deadline(n))
}

func (c *fakeTunnelConn) SetWriteDeadline(n int64) error {
	return c.Conn.SetWriteDeadline(deadline(n))
}

func (c *fakeTunnelConn) Path() string      { return c.path }
func (c *fakeTunnelConn) ClientKey() []byte { return c.key }

func deadline(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}

	return time.Unix(0, n)
}

// serveTunnel starts a server with no bound listener and serves it through a
// fake tunnel, returning the address the tunnel's socket is on.
func serveTunnel(
	t *testing.T, server *transport.Server, gate transport.TunnelGate, key []byte,
) string {
	t.Helper()

	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	tunnel := &fakeTunnel{listener: socket, key: key, path: "tunnel, direct"}
	done := make(chan error, 1)

	go func() {
		done <- server.ServeTunnel(tunnel, gate)
	}()

	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close: %v", err)
		}

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve the tunnel: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the tunnel server did not stop")
		}
	})

	return socket.Addr().String()
}

// TestTunnelAdmitsOnlyTheOfferedClientKey is the tunnel listener's gate: the
// identity has to be one the caller admits, with the client key that identity
// offered, and what the handler is told about where the call came from is the
// path rather than an in-netstack address (decision AX).
func TestTunnelAdmitsOnlyTheOfferedClientKey(t *testing.T) {
	serverID := newIdentity(t, "desktop")
	clientID := newIdentity(t, "laptop")
	offered := bytes.Repeat([]byte{7}, 32)

	var remote string

	for _, tc := range []struct {
		name  string
		key   []byte
		admit bool
	}{
		{"the offered key", offered, true},
		{"another key", bytes.Repeat([]byte{8}, 32), false},
		{"no key at all", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			remote = ""

			server, err := transport.NewServer(transport.ServerOptions{
				Identity: serverID,
				Listen:   transport.ListenNone,
				Handler:  pathHandler(&remote),
			})
			if err != nil {
				t.Fatalf("create the server: %v", err)
			}

			address := serveTunnel(t, server, tunnelGate{
				admit: func(fingerprint string, key []byte) error {
					if fingerprint != clientID.Fingerprint() {
						return errors.New("not paired")
					}

					if len(key) == 0 || !bytes.Equal(key, offered) {
						return errors.New("not the key it offered")
					}

					return nil
				},
				permit: func(string, string) error { return nil },
			}, tc.key)

			client, err := transport.NewClient(transport.ClientOptions{
				Identity: clientID,
				Expect:   serverID.PublicKey(),
			})
			if err != nil {
				t.Fatalf("create the client: %v", err)
			}

			_, err = get(client, address)

			switch {
			case tc.admit && err != nil:
				t.Fatalf("an admitted key was refused: %v", err)
			case !tc.admit && err == nil:
				t.Fatal("a key the peer never offered got through the tunnel gate")
			case tc.admit && remote != "tunnel, direct":
				t.Errorf("the handler saw the caller at %q, want the path", remote)
			}
		})
	}
}

// pathHandler records what the handler is told about where a call came from.
func pathHandler(remote *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer := transport.PeerFrom(r.Context())

		*remote = peer.RemoteAddr
		if !peer.Tunnelled {
			// The path without the flag would let a phone's tunnelled calls
			// read as direct ones on the far side (decision BA).
			*remote += " (not marked tunnelled)"
		}
		fmt.Fprint(w, "reached")
	})
}

// TestTunnelRefusesWhatTheGateDoesNotPermit is the per-request half: an
// admitted identity still calls only what Permit allows, which is how the
// long-lived tunnel listener refuses the pairing RPCs (decision AX).
func TestTunnelRefusesWhatTheGateDoesNotPermit(t *testing.T) {
	serverID := newIdentity(t, "desktop")
	clientID := newIdentity(t, "laptop")
	key := bytes.Repeat([]byte{7}, 32)

	var remote string

	server, err := transport.NewServer(transport.ServerOptions{
		Identity: serverID,
		Listen:   transport.ListenNone,
		Handler:  pathHandler(&remote),
	})
	if err != nil {
		t.Fatalf("create the server: %v", err)
	}

	address := serveTunnel(t, server, tunnelGate{
		admit: func(string, []byte) error { return nil },
		permit: func(_ string, procedure string) error {
			if strings.HasPrefix(procedure, "/ladulas.v1.PairingService/") {
				return errors.New("the tunnel does not pair")
			}

			return nil
		},
	}, key)

	client, err := transport.NewClient(transport.ClientOptions{
		Identity: clientID,
		Expect:   serverID.PublicKey(),
	})
	if err != nil {
		t.Fatalf("create the client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for path, want := range map[string]int{
		"/ladulas.v1.PresenceService/Ping":     http.StatusOK,
		"/ladulas.v1.PairingService/PairStart": http.StatusForbidden,
	} {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			client.URL(address)+path, nil)
		if err != nil {
			t.Fatalf("build a request: %v", err)
		}

		resp, err := client.HTTP().Do(req)
		if err != nil {
			t.Fatalf("call %s: %v", path, err)
		}

		_ = resp.Body.Close()

		if resp.StatusCode != want {
			t.Errorf("%s answered %d, want %d", path, resp.StatusCode, want)
		}
	}
}
