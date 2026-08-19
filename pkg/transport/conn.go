package transport

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
)

// peerContextKey carries the authenticated identity of the caller.
type peerContextKey struct{}

// WithPeer puts an authenticated peer identity into a context. Exported because
// a test — and an embedder serving the peer handler some other way — needs to
// be able to say who is calling.
func WithPeer(ctx context.Context, peer *PeerIdentity) context.Context {
	return context.WithValue(ctx, peerContextKey{}, peer)
}

// PeerFrom returns the authenticated identity of the caller, or nil.
//
// This is the only thing an RPC handler should authorize on. A message field
// naming an instance is the caller's word for it; this is the channel's.
func PeerFrom(ctx context.Context) *PeerIdentity {
	peer, _ := ctx.Value(peerContextKey{}).(*PeerIdentity)

	return peer
}

// connContextKey carries the tracked connection a request arrived on.
type connContextKey struct{}

func withConn(ctx context.Context, conn net.Conn) context.Context {
	tracked := trackedFrom(conn)
	if tracked == nil {
		return ctx
	}

	return context.WithValue(ctx, connContextKey{}, tracked)
}

func connFrom(ctx context.Context) *trackedConn {
	tracked, _ := ctx.Value(connContextKey{}).(*trackedConn)

	return tracked
}

// trackedFrom digs the tracked connection out from under the TLS wrapper that
// http.Server hands to ConnContext.
func trackedFrom(conn net.Conn) *trackedConn {
	for {
		switch c := conn.(type) {
		case *trackedConn:
			return c
		case *tls.Conn:
			conn = c.NetConn()
		default:
			return nil
		}
	}
}

// trackingListener hands out connections the server can find again.
type trackingListener struct {
	net.Listener

	registry *connRegistry
}

func (l *trackingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err // http.Server inspects this error
	}

	tracked := &trackedConn{Conn: conn, registry: l.registry}
	l.registry.add(tracked)

	return tracked, nil
}

// trackedConn is a live peer connection, labelled with who turned out to be on
// the other end of it once the handshake and the first request said so.
type trackedConn struct {
	net.Conn

	registry *connRegistry

	mu   sync.Mutex
	peer *PeerIdentity
}

func (c *trackedConn) setPeer(peer *PeerIdentity) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.peer = peer
}

func (c *trackedConn) fingerprint() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.peer == nil {
		return ""
	}

	return c.peer.Fingerprint
}

func (c *trackedConn) Close() error {
	c.registry.remove(c)

	return c.Conn.Close() // net/http inspects this error
}

// connRegistry is the set of live connections, so that forgetting a peer can
// drop the ones it is holding.
type connRegistry struct {
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
}

func newConnRegistry() *connRegistry {
	return &connRegistry{conns: map[*trackedConn]struct{}{}}
}

func (r *connRegistry) add(conn *trackedConn) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.conns[conn] = struct{}{}
}

func (r *connRegistry) remove(conn *trackedConn) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.conns, conn)
}

func (r *connRegistry) closeMatching(fingerprint string) int {
	if fingerprint == "" {
		return 0
	}

	r.mu.Lock()

	var matched []*trackedConn

	for conn := range r.conns {
		if conn.fingerprint() == fingerprint {
			matched = append(matched, conn)
		}
	}

	r.mu.Unlock()

	// Closing outside the lock, because Close removes the connection from this
	// very registry.
	for _, conn := range matched {
		_ = conn.Close()
	}

	return len(matched)
}
