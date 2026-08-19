package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/identity"
)

// Gate decides, during the handshake, whether an identity gets to speak at all.
//
// It is the outer door of §15: an unpaired identity should not reach the RPC
// layer merely to be turned away there, and while no pairing is in progress it
// does not get past the handshake. Returning an error refuses the connection;
// a nil Gate lets everyone in, which is only useful in tests.
//
// It is also where §7's optional tailnet hardening goes when it is built: with
// a local tailscaled, a LocalAPI WhoIs on the peer's address can restrict
// incoming connections to the same tailnet user's devices, Taildrop's rule,
// before any protocol bytes are read. Nothing in the design depends on it —
// a compromised Tailscale control plane can produce a node that WhoIs vouches
// for, which is exactly the attack the identity key survives — so it stays an
// outer layer, and the node name it yields is recorded as a corroborating
// attribute on a trust record and never as an authorization. IsTailnetIP is
// what tells the difference between a tailnet address and any other private
// one; the rest is a dependency this milestone did not need to take on.
type Gate func(*PeerIdentity) error

// ServerOptions configures a peer listener.
type ServerOptions struct {
	// Identity is this instance's identity key. Required.
	Identity *identity.Identity
	// Listen is the bind specification; see ResolveBindAddresses. Empty means
	// the default port on every private and tailnet address.
	Listen string
	// AllowPublic opts in to binding addresses reachable from outside the local
	// network (decision H).
	AllowPublic bool
	// Handler serves the peer RPCs. Required.
	Handler http.Handler
	// Gate refuses unknown identities at handshake time.
	Gate Gate
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Server is the peer listener.
type Server struct {
	identity    *identity.Identity
	listenSpec  string
	allowPublic bool
	handler     http.Handler
	gate        Gate
	log         *slog.Logger

	certificate tls.Certificate
	registry    *connRegistry

	mu        sync.Mutex
	listeners []net.Listener
	addresses []string
	http      *http.Server

	closeOnce sync.Once
}

// NewServer creates a listener. It does not bind; call Listen.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Identity == nil {
		return nil, errors.New("transport: no instance identity")
	}

	if opts.Handler == nil {
		return nil, errors.New("transport: no handler to serve")
	}

	certificate, err := selfSigned(opts.Identity)
	if err != nil {
		return nil, err
	}

	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	return &Server{
		identity:    opts.Identity,
		listenSpec:  opts.Listen,
		allowPublic: opts.AllowPublic,
		handler:     opts.Handler,
		gate:        opts.Gate,
		log:         log,
		certificate: certificate,
		registry:    newConnRegistry(),
	}, nil
}

// Listen binds every address the policy resolves to.
//
// Binding them one at a time rather than a wildcard is the point: decision H
// says the open internet should never be listened on by accident, and a socket
// that was never opened is a stronger statement of that than one that opens and
// then refuses.
func (s *Server) Listen() error {
	addresses, err := ResolveBindAddresses(s.listenSpec, s.allowPublic)
	if err != nil {
		return err
	}

	var (
		listeners []net.Listener
		bound     []string
		problems  []error
	)

	for _, address := range addresses {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			problems = append(problems, err)

			s.log.Warn("could not bind a peer address",
				"address", address, "error", err.Error())

			continue
		}

		listeners = append(listeners, listener)
		bound = append(bound, listener.Addr().String())
	}

	if len(listeners) == 0 && len(addresses) > 0 {
		return fmt.Errorf("transport: could not bind any peer address: %w",
			errors.Join(problems...))
	}

	s.mu.Lock()
	s.listeners = listeners
	s.addresses = bound
	s.mu.Unlock()

	return nil
}

// Addresses returns what the listener bound, which is also what pairing
// advertises to a peer as the addresses to dial back on.
func (s *Server) Addresses() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.addresses...)
}

// Serve accepts connections until the context is done or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	// An instance that never listens has nothing to accept and everything else
	// to do: it dials, it pairs, it approves. Serving it is waiting.
	if strings.TrimSpace(s.listenSpec) == ListenNone {
		<-ctx.Done()

		return nil
	}

	s.mu.Lock()
	listeners := append([]net.Listener(nil), s.listeners...)
	s.mu.Unlock()

	if len(listeners) == 0 {
		if err := s.Listen(); err != nil {
			return err
		}

		s.mu.Lock()
		listeners = append([]net.Listener(nil), s.listeners...)
		s.mu.Unlock()
	}

	server := &http.Server{
		Handler:   s.withPeerIdentity(s.handler),
		TLSConfig: s.tlsConfig(),
		// The handshake is the whole of the unauthenticated surface (§15), so
		// it is the thing with a deadline on it. What happens afterwards is an
		// approval, which is a human, and gets minutes.
		ReadHeaderTimeout: 15 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return withConn(ctx, conn)
		},
		ErrorLog: nil,
	}

	s.mu.Lock()
	s.http = server
	s.mu.Unlock()

	stop := context.AfterFunc(ctx, func() {
		_ = s.Close()
	})
	defer stop()

	s.log.Info("peer channel listening",
		"addresses", s.Addresses(), "identity", s.identity.Fingerprint())

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)

	for _, listener := range listeners {
		wg.Add(1)

		go func() {
			defer wg.Done()

			// ServeTLS wraps the listener itself, which is what arranges the
			// ALPN advertisement for HTTP/2; handing it an already-wrapped
			// tls.Listener would leave the connection on HTTP/1.1.
			err := server.ServeTLS(&trackingListener{
				Listener: listener,
				registry: s.registry,
			}, "", "")

			if err == nil ||
				errors.Is(err, http.ErrServerClosed) ||
				errors.Is(err, net.ErrClosed) {
				return
			}

			mu.Lock()

			if first == nil {
				first = err
			}

			mu.Unlock()
		}()
	}

	wg.Wait()

	if first != nil {
		return fmt.Errorf("transport: serve the peer channel: %w", first)
	}

	return nil
}

// Close stops serving and drops every live connection.
func (s *Server) Close() error {
	var err error

	s.closeOnce.Do(func() {
		s.mu.Lock()
		server := s.http
		listeners := append([]net.Listener(nil), s.listeners...)
		s.mu.Unlock()

		if server != nil {
			err = server.Close()

			return
		}

		for _, listener := range listeners {
			if closeErr := listener.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
		}
	})

	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("transport: close the peer channel: %w", err)
	}

	return nil
}

// Disconnect drops every live connection from an identity and reports how many
// there were.
//
// This is what makes forgetting a peer mean something immediately. The
// authorization checks would refuse the peer's next call anyway, but a
// revocation that left the connection up would leave a peer that had been
// forgotten still holding a door open, and "revoked" should not be a thing that
// takes effect at the peer's convenience.
func (s *Server) Disconnect(fingerprint string) int {
	return s.registry.closeMatching(fingerprint)
}

func (s *Server) tlsConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{s.certificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   alpn,
		// Any certificate, because a certificate authority has no part in this.
		// The identity is the key inside it, and VerifyPeerCertificate is where
		// that gets decided.
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: s.verifyPeer,
		// The gate lives in VerifyPeerCertificate, and the stdlib does not run
		// that callback on a resumed TLS 1.3 connection — it restores the client
		// cert from the ticket and admits it. A ticket lasts up to a week, so a
		// resumption would let an identity that connected once during a pairing
		// window, or one disconnected by a revocation, re-enter past the gate
		// long after. Nothing this side dials ever resumes (the client sets no
		// session cache), so turning tickets off costs nothing and closes that
		// door; per-RPC authorization held regardless, but the gate is meant to
		// be the outer one (§8, §15).
		SessionTicketsDisabled: true,
	}
}

func (s *Server) verifyPeer(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	cert, err := leafFrom(rawCerts)
	if err != nil {
		return err
	}

	peer, err := identityFromCert(cert, "")
	if err != nil {
		return err
	}

	if s.gate == nil {
		return nil
	}

	if err := s.gate(peer); err != nil {
		s.log.Warn("refused a peer connection",
			"identity", peer.Fingerprint, "error", err.Error())

		return err
	}

	return nil
}

// withPeerIdentity puts the authenticated identity into the request context and
// records it against the connection, so that revoking a peer can find the
// connection to drop.
func (s *Server) withPeerIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := r.TLS

		if state == nil || len(state.PeerCertificates) == 0 {
			http.Error(w, "no peer certificate", http.StatusForbidden)

			return
		}

		peer, err := identityFromCert(state.PeerCertificates[0], r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)

			return
		}

		if tracked := connFrom(r.Context()); tracked != nil {
			tracked.setPeer(peer)
		}

		next.ServeHTTP(w, r.WithContext(WithPeer(r.Context(), peer)))
	})
}
