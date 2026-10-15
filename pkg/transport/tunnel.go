package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// The tunnel listener: the same pinned TLS, served through a NAT traversal
// layer instead of a bound socket (§8, decision AX).
//
// Nothing about the channel changes on the way through. A connection that
// arrives over the tunnel runs the same TLS 1.3 handshake as one that arrives
// on a bound address, each side pinning the other's SubjectPublicKeyInfo, with
// connect-go above it; the tunnel is judged only as a way of reaching that
// handshake, never as a way of knowing who is on the other end of it. What is
// different is the door in front of the handshake, and what the far end is
// called while it is talking:
//
//   - The gate is the caller's own, and narrower than the bound listener's. A
//     tunnel is reachable from anywhere a DERP region is, so an identity that is
//     not already paired gets nothing through it — not even while a pairing
//     window is open, which is the bound listener's and the pairing server's
//     business — and the tailcat client key a connection arrived with has to be
//     the one that identity offered (TunnelGate.Admit).
//   - What a connection may call is checked per request as well
//     (TunnelGate.Permit), so that the long-lived tunnel listener refuses the
//     pairing RPCs altogether, and a pending identity reaches SettlePairing and
//     nothing else.
//   - RemoteAddr is the path, not an address. Through the tunnel the far end
//     has an in-netstack address that looks like a tailnet one, and every
//     prompt and pairing card shows RemoteAddr; "tunnel, direct" or "tunnel,
//     relayed via DERP <region>" is what it honestly is.
//
// The types are interfaces of strings, byte slices, integers and errors,
// because that is all gomobile binds (§21) and because the tunnel itself
// lives behind an internal package that the phone build never links: a phone
// does not listen, and a desktop's tailcat stays out of pkg/ entirely.

// TunnelConn is one connection a tunnel accepted, as the TLS server needs it.
type TunnelConn interface {
	Read(b []byte) (int, error)
	Write(b []byte) (int, error)
	Close() error
	// The deadlines are Unix nanoseconds, zero for none: time.Time is not a
	// type gomobile binds.
	SetDeadline(unixNano int64) error
	SetReadDeadline(unixNano int64) error
	SetWriteDeadline(unixNano int64) error
	// Path is what the connection came over, in the words a prompt shows:
	// "tunnel, direct" or "tunnel, relayed via DERP <region>".
	Path() string
	// ClientKey is the tunnel client key the connection came from — the key
	// the tunnel's own allowlist admitted — raw, 32 bytes. Empty when the
	// tunnel cannot say, which the gate refuses.
	ClientKey() []byte
}

// TunnelListener hands out the connections a tunnel accepted. Accept returns
// net.ErrClosed once Close has been called.
type TunnelListener interface {
	Accept() (TunnelConn, error)
	Close() error
}

// TunnelGate is the tunnel listener's own door (§8, §16).
type TunnelGate interface {
	// Admit decides, during the handshake, whether an identity arriving with a
	// tunnel client key gets to speak at all. It is the bound listener's Gate
	// with the connection's client key beside the identity.
	Admit(fingerprint string, clientKey []byte) error
	// Permit decides whether an admitted identity may call one procedure, by
	// its connect path ("/ladulas.v1.PairingService/SettlePairing").
	Permit(fingerprint, procedure string) error
}

// ErrTunnelClosed is what ServeTunnel returns for a server that has already
// been closed.
var ErrTunnelClosed = errors.New("transport: the peer channel is closed")

// ServeTunnel serves the peer handler on a tunnel's listener until the
// listener or the server is closed.
//
// It is a second http.Server beside the bound listeners' rather than another
// listener handed to the same one, because its TLS configuration differs: the
// gate is consulted per connection with that connection's client key, which a
// single shared VerifyPeerCertificate cannot see. Its connections are tracked
// in the same registry, so Disconnect drops a forgotten peer's tunnel
// connections along with its direct ones.
func (s *Server) ServeTunnel(listener TunnelListener, gate TunnelGate) error {
	if listener == nil || gate == nil {
		return errors.New("transport: a tunnel needs a listener and a gate")
	}

	server := &http.Server{
		Handler:   s.withPeerIdentity(permitted(gate, s.handler)),
		TLSConfig: s.tunnelTLSConfig(gate),
		// The same deadline on the same unauthenticated surface (§15).
		ReadHeaderTimeout: 15 * time.Second,
		ConnContext:       withConn,
		ErrorLog:          nil,
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()

		return ErrTunnelClosed
	}

	s.tunnels = append(s.tunnels, server)
	s.mu.Unlock()

	s.log.Info("peer channel serving through the tunnel",
		"identity", s.identity.Fingerprint())

	// ServeTLS rather than a pre-wrapped listener, for the reason Serve gives:
	// it is what arranges the ALPN advertisement for HTTP/2.
	err := server.ServeTLS(&trackingListener{
		Listener: &tunnelNetListener{listener: listener},
		registry: s.registry,
	}, "", "")

	if err == nil ||
		errors.Is(err, http.ErrServerClosed) ||
		errors.Is(err, net.ErrClosed) {
		return nil
	}

	return fmt.Errorf("transport: serve the peer channel through the tunnel: %w", err)
}

// tunnelTLSConfig is the bound listener's TLS configuration with the gate
// moved to where the connection is visible.
//
// GetConfigForClient runs once per connection with the connection in hand,
// which is what lets the verification callback it returns see the client key
// the tunnel admitted. Everything else — TLS 1.3 only, any client certificate,
// no session tickets, h2 — is the bound listener's, taken from the same
// function so the two cannot drift.
func (s *Server) tunnelTLSConfig(gate TunnelGate) *tls.Config {
	base := s.tlsConfig()
	base.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error {
		// Never reached: GetConfigForClient always answers. It refuses rather
		// than admits, so that a change to the standard library that skipped
		// GetConfigForClient would close this door rather than open it.
		return errors.New("transport: a tunnel connection reached the wrong gate")
	}

	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		key := tunnelClientKey(hello.Conn)

		config := s.tlsConfig()
		config.VerifyPeerCertificate = func(
			rawCerts [][]byte, _ [][]*x509.Certificate,
		) error {
			cert, err := leafFrom(rawCerts)
			if err != nil {
				return err
			}

			peer, err := identityFromCert(cert, "")
			if err != nil {
				return err
			}

			if err := gate.Admit(peer.Fingerprint, key); err != nil {
				s.log.Warn("refused a peer connection through the tunnel",
					"identity", peer.Fingerprint, "error", err.Error())

				return err
			}

			return nil
		}

		return config, nil
	}

	return base
}

// permitted refuses a request the gate does not allow, after withPeerIdentity
// has put the authenticated identity in the context.
func permitted(gate TunnelGate, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer := PeerFrom(r.Context())
		if peer == nil {
			http.Error(w, "no peer identity", http.StatusForbidden)

			return
		}

		if err := gate.Permit(peer.Fingerprint, r.URL.Path); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)

			return
		}

		next.ServeHTTP(w, r)
	})
}

// tunnelClientKey digs the client key out of a connection the tunnel listener
// handed out, from under the tracking wrapper.
func tunnelClientKey(conn net.Conn) []byte {
	if addr, ok := conn.RemoteAddr().(tunnelAddr); ok {
		return addr.key
	}

	return nil
}

// tunnelAddr is the remote address of a tunnel connection: the path it came
// over, and the client key it came from. Its String is the path, which is what
// a request's RemoteAddr — and so every prompt and pairing card — shows.
type tunnelAddr struct {
	path string
	key  []byte
}

// Network implements net.Addr.
func (a tunnelAddr) Network() string { return "tunnel" }

// String implements net.Addr: the path, never an address.
func (a tunnelAddr) String() string { return a.path }

// tunnelNetListener is a TunnelListener as net/http needs one.
type tunnelNetListener struct {
	listener TunnelListener
}

func (l *tunnelNetListener) Accept() (net.Conn, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err // http.Server inspects this error
	}

	return &tunnelNetConn{
		conn:   conn,
		remote: tunnelAddr{path: conn.Path(), key: conn.ClientKey()},
	}, nil
}

func (l *tunnelNetListener) Close() error {
	return l.listener.Close() // http.Server inspects this error
}

func (l *tunnelNetListener) Addr() net.Addr {
	return tunnelAddr{path: "tunnel"}
}

// tunnelNetConn is a TunnelConn as net/http needs one.
type tunnelNetConn struct {
	conn   TunnelConn
	remote tunnelAddr
}

func (c *tunnelNetConn) Read(b []byte) (int, error) {
	return c.conn.Read(b) // io.Reader's contract: the error as it is
}

func (c *tunnelNetConn) Write(b []byte) (int, error) {
	return c.conn.Write(b) // io.Writer's contract: the error as it is
}

func (c *tunnelNetConn) Close() error {
	return c.conn.Close() // net/http inspects this error
}

func (c *tunnelNetConn) LocalAddr() net.Addr {
	return tunnelAddr{path: "tunnel"}
}

func (c *tunnelNetConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *tunnelNetConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(unixNano(t)) // net/http inspects this error
}

func (c *tunnelNetConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(unixNano(t)) // net/http inspects this error
}

func (c *tunnelNetConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(unixNano(t)) // net/http inspects this error
}

// unixNano is a deadline as TunnelConn takes it, zero for none.
func unixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}

	return t.UnixNano()
}
