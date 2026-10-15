package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fabric stands in for DERP and the punched paths between fake tunnels: a
// client raised against a server address reaches that server's listener over
// an in-memory pipe, carrying its client key, and the real pinned TLS and the
// real tunnel gate run over it. The tests can break it, mend it, make it
// relayed, and hold raises back.
type fabric struct {
	mu        sync.Mutex
	servers   map[string]*fabricListener
	connected map[string]map[string]bool
	conns     []net.Conn
	broken    bool
	relayed   bool
	raises    int
	// gate holds every raise until it is closed, when it is not nil.
	gate chan struct{}
}

func newFabric() *fabric {
	return &fabric{
		servers:   map[string]*fabricListener{},
		connected: map[string]map[string]bool{},
	}
}

// tunnel is a fake tunnel on this fabric.
func (f *fabric) tunnel(address string, client byte) *fakeTunnel {
	tunnel := newFakeTunnel(address, client)
	tunnel.fabric = f

	return tunnel
}

func (f *fabric) listen(server *fakeTunnel) *fabricListener {
	f.mu.Lock()
	defer f.mu.Unlock()

	listener := &fabricListener{
		server: server,
		accept: make(chan transport.TunnelConn),
		closed: make(chan struct{}),
	}
	f.servers[server.address] = listener

	return listener
}

func (f *fabric) clientPath(server string, key []byte) string {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.connected[server][string(key)] {
		return ""
	}

	if f.relayed {
		return ClientPathRelayed + " test"
	}

	return ClientPathDirect
}

// setBroken breaks every tunnel at once, the way DERP going away does, or
// mends them.
func (f *fabric) setBroken(broken bool) {
	f.mu.Lock()
	f.broken = broken

	var conns []net.Conn

	if broken {
		conns = f.conns
		f.conns = nil
		f.connected = map[string]map[string]bool{}
	}
	f.mu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (f *fabric) setRelayed(relayed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.relayed = relayed
}

func (f *fabric) raiseCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.raises
}

type fabricListener struct {
	server *fakeTunnel
	accept chan transport.TunnelConn
	closed chan struct{}
	once   sync.Once
}

func (l *fabricListener) Accept() (transport.TunnelConn, error) {
	select {
	case conn := <-l.accept:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *fabricListener) Close() error {
	l.once.Do(func() { close(l.closed) })

	return nil
}

// fabricClient is a raised client on the fabric.
type fabricClient struct {
	fabric  *fabric
	address string
	key     []byte
}

func (c *fabricClient) server() (*fabricListener, error) {
	f := c.fabric

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.broken {
		return nil, errors.New("DERP is unreachable")
	}

	server := f.servers[c.address]
	if server == nil {
		return nil, fmt.Errorf("no tunnel server at %s", c.address)
	}

	// The server's own allowlist, which the node keeps (decision AX).
	if !server.server.admits(c.key) {
		return nil, errors.New("the server does not admit this client key")
	}

	return server, nil
}

func (c *fabricClient) Ping(int64) error {
	c.fabric.mu.Lock()
	gate := c.fabric.gate
	c.fabric.raises++
	c.fabric.mu.Unlock()

	if gate != nil {
		<-gate
	}

	if _, err := c.server(); err != nil {
		return err
	}

	c.fabric.mu.Lock()
	defer c.fabric.mu.Unlock()

	if c.fabric.connected[c.address] == nil {
		c.fabric.connected[c.address] = map[string]bool{}
	}

	c.fabric.connected[c.address][string(c.key)] = true

	return nil
}

func (c *fabricClient) Dial(int64) (transport.TunnelConn, error) {
	server, err := c.server()
	if err != nil {
		return nil, err
	}

	near, far := net.Pipe()

	c.fabric.mu.Lock()
	c.fabric.conns = append(c.fabric.conns, near, far)
	c.fabric.mu.Unlock()

	path := server.server.path
	if path == "" {
		path = "tunnel, direct"
	}

	select {
	case server.accept <- &pipeConn{Conn: far, path: path, key: c.key}:
	case <-server.closed:
		return nil, net.ErrClosed
	}

	return &pipeConn{Conn: near, path: "tunnel"}, nil
}

func (c *fabricClient) Close() error { return nil }

// pipeConn is one end of a fabric connection as a TunnelConn.
type pipeConn struct {
	net.Conn

	path string
	key  []byte
}

func (c *pipeConn) SetDeadline(unixNano int64) error {
	return c.Conn.SetDeadline(fromUnixNano(unixNano))
}

func (c *pipeConn) SetReadDeadline(unixNano int64) error {
	return c.Conn.SetReadDeadline(fromUnixNano(unixNano))
}

func (c *pipeConn) SetWriteDeadline(unixNano int64) error {
	return c.Conn.SetWriteDeadline(fromUnixNano(unixNano))
}

func (c *pipeConn) Path() string      { return c.path }
func (c *pipeConn) ClientKey() []byte { return c.key }

func fromUnixNano(unixNano int64) time.Time {
	if unixNano == 0 {
		return time.Time{}
	}

	return time.Unix(0, unixNano)
}

// pingFn is a call that proves a path: the pinned Ping.
func pingFn(ctx context.Context, client *http.Client, baseURL string) error {
	_, err := ladulasv1connect.NewPresenceServiceClient(client, baseURL).
		Ping(ctx, connect.NewRequest(&ladulasv1.PingRequest{}))

	return err
}

// lan stands in for the direct path, so that the precedence between the two
// paths can be exercised in memory: a node's direct client dials the peer's
// LAN listener over a pipe whatever address it was given, and the probe the
// race runs answers while the LAN is up. Behind it is the node's real handler
// and its real gate, as on a bound listener.
type lan struct {
	mu        sync.Mutex
	broken    bool
	listeners map[string]*fabricListener
	conns     []net.Conn
}

func newLAN() *lan {
	return &lan{listeners: map[string]*fabricListener{}}
}

// setBroken takes the LAN away, dropping what is open across it, or brings it
// back.
func (l *lan) setBroken(broken bool) {
	l.mu.Lock()
	l.broken = broken

	var conns []net.Conn

	if broken {
		conns, l.conns = l.conns, nil
	}
	l.mu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (l *lan) up() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	return !l.broken
}

func (l *lan) probe(_ context.Context, addresses []string) string {
	if !l.up() || len(addresses) == 0 {
		return ""
	}

	return addresses[0]
}

// serve puts an instance on the LAN, behind the bound listener's gate.
func (l *lan) serve(t *testing.T, side *instance) {
	t.Helper()

	listener := &fabricListener{
		accept: make(chan transport.TunnelConn),
		closed: make(chan struct{}),
	}

	l.mu.Lock()
	l.listeners[side.identity.Fingerprint()] = listener
	l.mu.Unlock()

	go func() {
		_ = side.node.server.ServeTunnel(listener, lanGate{node: side.node})
	}()

	t.Cleanup(func() { _ = listener.Close() })
}

// client is a node's direct client: pinned exactly as a real one, dialling
// the peer it expects over the LAN.
func (l *lan) client(opts transport.ClientOptions) (*transport.Client, error) {
	return transport.NewTunnelClient(opts, &lanDialer{
		lan: l, fingerprint: ssh.FingerprintSHA256(opts.Expect),
	})
}

type lanDialer struct {
	lan         *lan
	fingerprint string
}

func (d *lanDialer) Dial(int64) (transport.TunnelConn, error) {
	d.lan.mu.Lock()
	broken := d.lan.broken
	listener := d.lan.listeners[d.fingerprint]
	d.lan.mu.Unlock()

	if broken || listener == nil {
		return nil, fmt.Errorf("dial tcp: %w", syscall.EHOSTUNREACH)
	}

	near, far := net.Pipe()

	d.lan.mu.Lock()
	d.lan.conns = append(d.lan.conns, near, far)
	d.lan.mu.Unlock()

	select {
	case listener.accept <- &pipeConn{Conn: far, path: "lan"}:
	case <-listener.closed:
		return nil, net.ErrClosed
	}

	return &pipeConn{Conn: near, path: "lan"}, nil
}

// lanGate is the bound listener's gate on the LAN listener.
type lanGate struct {
	node *Node
}

func (g lanGate) Admit(fingerprint string, _ []byte) error {
	return g.node.gate(&transport.PeerIdentity{Fingerprint: fingerprint})
}

func (g lanGate) Permit(string, string) error { return nil }

// tunnelled is a requester and an approver that are paired, both with the
// tunnel on over one fabric, and both on one LAN unless told otherwise; the
// requester links the approver. Every test of the dialling half starts here.
type tunnelled struct {
	approver, requester *instance
	tunnels             *fabric
	lan                 *lan
	// linked counts the requester's links coming up, each of which pushes
	// grant activity and logs "linked".
	linked atomic.Int32
	// key is the key the approver offers the requester.
	key *ladulasv1.KeyRef
}

// shape is what is different about one test's two machines.
type shape struct {
	// approverOffLAN and requesterOffLAN leave that side's address out of the
	// other's record: a peer reachable through its tunnel only.
	approverOffLAN, requesterOffLAN bool
	// relayed is a fabric that never punches.
	relayed bool
}

func newTunnelled(t *testing.T, want shape) *tunnelled {
	t.Helper()

	approverOnLAN, requesterOnLAN := !want.approverOffLAN, !want.requesterOffLAN

	h := &tunnelled{
		approver:  newInstanceOn(t, "desk", transport.ListenNone),
		requester: newInstanceOn(t, "laptop", transport.ListenNone),
		tunnels:   newFabric(),
		lan:       newLAN(),
	}

	h.tunnels.setRelayed(want.relayed)

	for _, side := range []*instance{h.approver, h.requester} {
		side.node.directClient = h.lan.client
		side.node.probe = h.lan.probe
		h.lan.serve(t, side)
	}

	addresses := func(on bool, address string) []string {
		if !on {
			return nil
		}

		return []string{address}
	}

	put := func(side *instance, record *storepb.TrustRecord) {
		if err := side.store.PutPeer(record); err != nil {
			t.Fatalf("put peer: %v", err)
		}
	}

	put(h.requester, &storepb.TrustRecord{
		Fingerprint:       h.approver.identity.Fingerprint(),
		Name:              "desk",
		IdentityPublicKey: h.approver.identity.PublicKey().Marshal(),
		Addresses:         addresses(approverOnLAN, "192.0.2.10:7373"),
		MayApprove:        true,
		Tunnel:            offerFrom("tcdesk", 1),
		TunnelUpdatedAt:   timestamppb.Now(),
	})
	put(h.approver, &storepb.TrustRecord{
		Fingerprint:       h.requester.identity.Fingerprint(),
		Name:              "laptop",
		IdentityPublicKey: h.requester.identity.PublicKey().Marshal(),
		Addresses:         addresses(requesterOnLAN, "192.0.2.20:7373"),
		MayRequest:        true,
		Tunnel:            offerFrom("tclaptop", 2),
		TunnelUpdatedAt:   timestamppb.Now(),
	})

	// The approver offers the requester a key, so that a path change that
	// blanked the agent's key list would show (watchPresence).
	h.key = h.approver.keys.generate(t, "desk")
	h.approver.allowKey(t, h.requester.identity.Fingerprint(), h.key.GetFingerprint())

	h.requester.node.linked = func(string) { h.linked.Add(1) }

	// Turning the tunnel on reconciles, which is what links the requester to
	// its approver now that there is a record to link.
	h.approver.node.SetTunnel(h.tunnels.tunnel("tcdesk", 1))
	h.requester.node.SetTunnel(h.tunnels.tunnel("tclaptop", 2))
	waitOffer(t, h.approver.node)
	waitOffer(t, h.requester.node)

	return h
}

// link is the requester's link to the approver, once it is up and has
// learned the key the approver offers.
func (h *tunnelled) link(t *testing.T) *link {
	t.Helper()

	waitLinked(t, h.requester, h.approver.identity.Fingerprint())

	l := h.requester.node.link(h.approver.identity.Fingerprint())

	waitUntil(t, "the link to learn the offered key", func() bool {
		return len(l.offeredKeys()) > 0
	})

	return l
}

// waitUntil polls a condition for up to ten seconds.
func waitUntil(t *testing.T, what string, done func() bool) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		if done() {
			return
		}

		time.Sleep(5 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %s", what)
}

// watchPresence samples a link from now on and reports whether anything a
// presence change does happened to it: the link seen down, its offered keys
// emptied — the agent's key list blanking — or the link coming up again, which
// pushes grant activity and logs "linked". A path change routed through
// failed() would do all three (decision AY).
func (h *tunnelled) watchPresence(l *link) (stop func() (dropped string)) {
	var (
		dropped atomic.Value
		done    = make(chan struct{})
		stopped = make(chan struct{})
		before  = h.linked.Load()
	)

	go func() {
		defer close(stopped)

		for {
			select {
			case <-done:
				return
			default:
			}

			if online, _, _ := l.State(); !online {
				dropped.CompareAndSwap(nil, "went down")
			} else if len(l.offeredKeys()) == 0 {
				dropped.CompareAndSwap(nil, "listed no keys")
			}

			time.Sleep(time.Millisecond)
		}
	}()

	return func() string {
		close(done)
		<-stopped

		if why, ok := dropped.Load().(string); ok {
			return why
		}

		if pushed := h.linked.Load() - before; pushed != 0 {
			return fmt.Sprintf("came up %d more times, pushing grant activity", pushed)
		}

		return ""
	}
}

// The headline rule of decision AY: a link moves from direct TCP to a punched
// tunnel make-before-break, and the move is not a presence change — the link
// never goes down, and a call afterwards goes through the tunnel, past the
// real pinned TLS and the real tunnel gate.
func TestALinkMovesToThePunchedTunnelWithoutAPresenceChange(t *testing.T) {
	h := newTunnelled(t, shape{})
	approver, requester := h.approver, h.requester
	l := h.link(t)

	stop := h.watchPresence(l)

	waitUntil(t, "the link to move to the tunnel", func() bool {
		return l.currentPath() == pathTunnel
	})

	if why := stop(); why != "" {
		t.Errorf("while the link changed path it %s", why)
	}

	status := requester.node.peerStatus(l.Record())

	if status.GetPath() != trust.PathTunnelDirect {
		t.Errorf("the peer's path reads %q", status.GetPath())
	}

	if status.GetTunnel() != trust.PathTunnelDirect {
		t.Errorf("the peer's tunnel reads %q", status.GetTunnel())
	}

	if state := trust.DescribeStatus(status, time.Now()); state != "connected, tunnel direct" {
		t.Errorf("the pill reads %q", state)
	}

	// A call takes the established path, which is the tunnel.
	used, err := requester.node.callOver(context.Background(), l.targets(context.Background()),
		pingFn)
	if err != nil || used.kind != pathTunnel {
		t.Errorf("a call went %v (%v), want through the tunnel", used.kind, err)
	}

	// And the listening side sees the client.
	inbound := approver.node.InboundTunnels()
	if len(inbound) != 1 || inbound[0].GetPath() != trust.PathTunnelDirect {
		t.Errorf("the approver sees inbound tunnels %v", inbound)
	}

	// The address machinery was left alone: a path is not an address.
	record, _ := requester.store.Peer(approver.identity.Fingerprint())
	for _, address := range record.GetAddresses() {
		if !trust.IsDirectAddress(address) {
			t.Errorf("the record gained %q", address)
		}
	}
}

// When the tunnel breaks under a link, the link falls back to the direct path
// at once and stays up; when the tunnel comes back it is not preferred again
// until it has held for the dwell (decision AY).
func TestAFailedTunnelFallsBackToDirectAndWaitsOutTheDwell(t *testing.T) {
	h := newTunnelled(t, shape{})

	const dwell = 400 * time.Millisecond

	h.requester.node.tunnelDwell = dwell

	l := h.link(t)

	waitUntil(t, "the link to move to the tunnel", func() bool {
		return l.currentPath() == pathTunnel
	})

	stop := h.watchPresence(l)

	h.tunnels.setBroken(true)

	waitUntil(t, "the link to fall back to direct", func() bool {
		return l.currentPath() == pathDirect
	})

	if why := stop(); why != "" {
		t.Errorf("when its tunnel broke the link %s", why)
	}

	status := h.requester.node.peerStatus(l.Record())
	if word := status.GetTunnel(); !strings.HasPrefix(word, "fallback to direct, because") &&
		!strings.HasPrefix(word, "tunnel in backoff until") {
		t.Errorf("after the fallback the tunnel reads %q", word)
	}

	h.tunnels.setBroken(false)

	waitUntil(t, "the tunnel to be raised again", func() bool {
		return l.tunnel.snapshot().up
	})

	up := time.Now()

	waitUntil(t, "the link to go back to the tunnel", func() bool {
		return l.currentPath() == pathTunnel
	})

	if held := time.Since(up); held < dwell-100*time.Millisecond {
		t.Errorf("the link went back to the tunnel after %v, inside the %v dwell",
			held, dwell)
	}
}

// A relayed tunnel yields to direct TCP that works: it is raised, and the link
// stays on the direct path beside it (decision AY).
func TestARelayedTunnelYieldsToDirectTCP(t *testing.T) {
	h := newTunnelled(t, shape{relayed: true})

	requester := h.requester
	l := h.link(t)

	waitUntil(t, "the tunnel to be raised", func() bool {
		return l.tunnel.snapshot().up
	})

	// Several beats, any of which would have moved it.
	time.Sleep(20 * requester.node.heartbeat)

	if path := l.currentPath(); path != pathDirect {
		t.Errorf("with a relayed tunnel and a working direct path the link is on %v", path)
	}

	if word := requester.node.peerStatus(l.Record()).GetTunnel(); !strings.HasPrefix(word, "direct ") {
		t.Errorf("the tunnel reads %q, want the direct address", word)
	}

	// Punched now: the next beat that says so moves the link.
	h.tunnels.setRelayed(false)

	waitUntil(t, "the link to move to the punched tunnel", func() bool {
		return l.currentPath() == pathTunnel
	})
}

// arrangeNode is a node with a tunnel and a record that offers one, for the
// race without a network.
func arrangeNode(t *testing.T, probe probeFunc) (*Node, *tunnelPath) {
	t.Helper()

	record := &storepb.TrustRecord{
		Fingerprint: "SHA256:desk",
		Addresses:   []string{"192.168.1.10:7373"},
		Tunnel:      offerFrom("tcdesk", 1),
	}
	store := &memoryStore{records: []*storepb.TrustRecord{record}}

	n := tunnelNode(store, newFakeTunnel("tcours", 9))
	n.probe = probe
	n.floor, n.ceiling = 10*time.Millisecond, 50*time.Millisecond
	n.tunnelSeen[record.GetFingerprint()] = time.Now()

	tunnel := &tunnelPath{node: n, fingerprint: record.GetFingerprint(), relayed: true}
	tunnel.address = "tcdesk"

	return n, tunnel
}

// raising puts a tunnel in the middle of a raise the test finishes.
func raising(tunnel *tunnelPath) chan struct{} {
	tunnel.mu.Lock()
	defer tunnel.mu.Unlock()

	tunnel.raising = true
	tunnel.finished = make(chan struct{})

	return tunnel.finished
}

func finish(tunnel *tunnelPath, finished chan struct{}, up, relayed bool) {
	tunnel.mu.Lock()
	tunnel.raising = false

	if up {
		tunnel.established = time.Now()
		tunnel.client = &transport.Client{}
		tunnel.relayed = relayed
	}
	tunnel.mu.Unlock()

	close(finished)
}

func firstKind(targets []target) pathKind {
	if len(targets) == 0 {
		return pathNone
	}

	return targets[0].via.kind
}

// A call made with no established path races the raise against the direct
// probe, and waits on neither longer than it takes the other to win (decision
// AY). Each case is one shape of the race.
func TestACallRacesTheRaiseAgainstTheDirectProbe(t *testing.T) {
	t.Parallel()

	answering := func(context.Context, []string) string { return "192.168.1.10:7373" }

	t.Run("a direct address that answers wins without waiting for the raise", func(t *testing.T) {
		t.Parallel()

		n, tunnel := arrangeNode(t, answering)
		raising(tunnel) // and never finished

		start := time.Now()
		got := n.arrange(context.Background(), tunnel,
			directTargets(&transport.Client{}, []string{"192.168.1.10:7373"}))

		if firstKind(got) != pathDirect || len(got) != 2 || got[1].via.kind != pathTunnel {
			t.Errorf("arranged %v", got)
		}

		if waited := time.Since(start); waited > time.Second {
			t.Errorf("waited %v on a raise that a direct answer beat", waited)
		}
	})

	t.Run("a punched raise wins without waiting for the probe", func(t *testing.T) {
		t.Parallel()

		slow := make(chan struct{})
		defer close(slow)

		n, tunnel := arrangeNode(t, func(ctx context.Context, _ []string) string {
			select {
			case <-slow:
			case <-ctx.Done():
			}

			return ""
		})
		finished := raising(tunnel)

		go func() {
			time.Sleep(20 * time.Millisecond)
			finish(tunnel, finished, true, false)
		}()

		start := time.Now()
		got := n.arrange(context.Background(), tunnel,
			directTargets(&transport.Client{}, []string{"192.168.1.10:7373"}))

		if firstKind(got) != pathTunnel {
			t.Errorf("arranged %v, want the tunnel first", got)
		}

		if waited := time.Since(start); waited > time.Second {
			t.Errorf("waited %v on a probe a punched tunnel beat", waited)
		}
	})

	t.Run("a relayed raise waits for the probe, and direct TCP outranks it", func(t *testing.T) {
		t.Parallel()

		n, tunnel := arrangeNode(t, func(context.Context, []string) string {
			time.Sleep(50 * time.Millisecond)

			return "192.168.1.10:7373"
		})
		finished := raising(tunnel)
		finish(tunnel, finished, true, true)

		got := n.arrange(context.Background(), tunnel,
			directTargets(&transport.Client{}, []string{"192.168.1.10:7373"}))

		if firstKind(got) != pathDirect {
			t.Errorf("arranged %v, want direct before a relayed tunnel", got)
		}
	})

	t.Run("a relayed tunnel carries the call when nothing direct answers", func(t *testing.T) {
		t.Parallel()

		n, tunnel := arrangeNode(t, func(context.Context, []string) string { return "" })
		finished := raising(tunnel)
		finish(tunnel, finished, true, true)

		got := n.arrange(context.Background(), tunnel,
			directTargets(&transport.Client{}, []string{"192.168.1.10:7373"}))

		if firstKind(got) != pathTunnel {
			t.Errorf("arranged %v, want the relayed tunnel when direct is dead", got)
		}
	})

	t.Run("a tunnel on probation does not outrank a direct answer", func(t *testing.T) {
		t.Parallel()

		n, tunnel := arrangeNode(t, answering)
		finished := raising(tunnel)
		finish(tunnel, finished, true, false)

		tunnel.mu.Lock()
		tunnel.tainted = time.Now()
		tunnel.mu.Unlock()

		got := n.arrange(context.Background(), tunnel,
			directTargets(&transport.Client{}, []string{"192.168.1.10:7373"}))

		if firstKind(got) != pathDirect {
			t.Errorf("arranged %v, want direct while the tunnel is inside its dwell", got)
		}
	})
}

// The precedence while a path is established, with nothing raced (decision
// AY).
func TestThePrecedenceOnAnEstablishedPath(t *testing.T) {
	t.Parallel()

	direct := directTargets(&transport.Client{}, []string{"192.168.1.10:7373"})

	for _, tc := range []struct {
		name    string
		current pathKind
		up      bool
		relayed bool
		want    pathKind
	}{
		{"punched outranks direct TCP", pathDirect, true, false, pathTunnel},
		{"direct TCP outranks relayed", pathDirect, true, true, pathDirect},
		{"a tunnel not up waits behind direct", pathDirect, false, false, pathDirect},
		{"on the tunnel, the tunnel first", pathTunnel, true, true, pathTunnel},
	} {
		_, tunnel := arrangeNode(t, nil)

		if tc.up {
			finish(tunnel, raising(tunnel), true, tc.relayed)
		}

		got := onPath(tc.current, tunnel, direct)

		if firstKind(got) != tc.want {
			t.Errorf("%s: first is %v, want %v", tc.name, firstKind(got), tc.want)
		}

		if len(got) != 2 {
			t.Errorf("%s: %d targets, want the other path kept behind", tc.name, len(got))
		}
	}
}

// A tunnel that was never reached outranks an address that refused, so the
// report names the path that was expected to work (decision AY); one that got
// an answer ranks as the answer.
func TestATunnelFailureHasARankOfItsOwn(t *testing.T) {
	t.Parallel()

	refused := fmt.Errorf("dial: %w", syscall.ECONNREFUSED)
	timedOut := &transport.TunnelError{Err: context.DeadlineExceeded}
	wrongPeer := &transport.TunnelError{Err: transport.ErrUnknownPeer}

	if failureRank(timedOut) <= failureRank(refused) {
		t.Errorf("a tunnel timing out ranks %d, not above a refusal at %d",
			failureRank(timedOut), failureRank(refused))
	}

	if failureRank(wrongPeer) <= failureRank(timedOut) {
		t.Error("a tunnel that reached the wrong identity does not outrank one that timed out")
	}

	n := &Node{}

	_, err := n.callOver(context.Background(), []target{
		{client: &transport.Client{}, via: direct("192.168.1.10:7373")},
		{via: tunnelRoute, tunnel: &tunnelPath{node: n, address: "tcdesk"}},
	}, func(context.Context, *http.Client, string) error { return refused })

	if err == nil || !strings.Contains(err.Error(), "192.168.1.10") {
		t.Errorf("a tunnel that was not up was reported over the address: %v", err)
	}
}

// A peer reachable only through its tunnel is a machine that listens, not a
// phone: it gets a link, and the link comes up over the tunnel with nothing to
// race against (decision AY).
func TestATunnelOnlyPeerIsLinkedOverItsTunnel(t *testing.T) {
	h := newTunnelled(t, shape{approverOffLAN: true})
	l := h.link(t)

	if path := l.currentPath(); path != pathTunnel {
		t.Errorf("a tunnel-only peer's link is on %v", path)
	}

	if h.tunnels.raiseCount() == 0 {
		t.Error("the link is up and nothing was raised")
	}

	h.requester.node.mu.Lock()
	_, inbox := h.requester.node.inboxes[h.approver.identity.Fingerprint()]
	h.requester.node.mu.Unlock()

	if inbox {
		t.Error("a tunnel-only peer was given an inbox as well")
	}

	if !h.requester.node.peerStatus(l.Record()).GetDialable() {
		t.Error("a tunnel-only peer is not reported dialable")
	}
}

// When the LAN goes away under a link on direct TCP, the link falls to an
// established tunnel without going down — the other direction of the same
// rule (decision AY).
func TestALostDirectPathFallsToTheTunnel(t *testing.T) {
	h := newTunnelled(t, shape{relayed: true})
	l := h.link(t)

	waitUntil(t, "the tunnel to be raised", func() bool {
		return l.tunnel.snapshot().up
	})

	if path := l.currentPath(); path != pathDirect {
		t.Fatalf("with a relayed tunnel the link is on %v", path)
	}

	stop := h.watchPresence(l)

	h.lan.setBroken(true)

	waitUntil(t, "the link to be on the relayed tunnel", func() bool {
		return l.currentPath() == pathTunnel
	})

	if why := stop(); why != "" {
		t.Errorf("when its direct path broke the link %s", why)
	}

	if word := h.requester.node.peerStatus(l.Record()).GetPath(); word != "tunnel relayed test" {
		t.Errorf("the path reads %q", word)
	}
}

// The dial-back raises a tunnel of its own on demand, for a peer whose offer
// names a server, and the reaper closes it when nothing has used it (decision
// AY): documentation is the one large flow, and it goes from an approver to a
// requester it has no link to.
func TestTheDialBackRaisesItsOwnTunnelAndReapsIt(t *testing.T) {
	h := newTunnelled(t, shape{requesterOffLAN: true})

	record, ok := h.approver.store.Peer(h.requester.identity.Fingerprint())
	if !ok {
		t.Fatal("the approver has no record of the requester")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := h.approver.node.call(ctx, record, pingFn); err != nil {
		t.Fatalf("a dial-back to a tunnel-only requester: %v", err)
	}

	status := h.approver.node.peerStatus(record)
	if !status.GetOnline() || !trust.IsTunnelPath(status.GetPath()) {
		t.Errorf("after the dial-back the requester reads online=%v path=%q",
			status.GetOnline(), status.GetPath())
	}

	h.approver.node.dialMu.Lock()
	held := h.approver.node.dialers[h.requester.identity.Fingerprint()]
	h.approver.node.dialMu.Unlock()

	tunnel := held.tunnelPath()
	if !tunnel.snapshot().up {
		t.Fatal("the dial-back's tunnel is not up after a call through it")
	}

	// Idle past the reap age, the reaper closes it.
	tunnel.mu.Lock()
	tunnel.lastUsed = time.Now().Add(-time.Hour)
	tunnel.mu.Unlock()

	go h.approver.node.reapOnce(DefaultTunnelIdle)

	waitUntil(t, "the idle tunnel to be reaped", func() bool {
		return !tunnel.snapshot().up
	})
}

// breakTunnelOnly breaks the fabric under a tunnel-only peer's link and waits
// for the link's tunnel to be down: a desktop off the LAN gone to sleep.
func (h *tunnelled) breakTunnelOnly(t *testing.T) *link {
	t.Helper()

	l := h.link(t)

	h.tunnels.setBroken(true)

	waitUntil(t, "the tunnel to be down", func() bool {
		return !l.tunnel.snapshot().up
	})

	return l
}

// A tunnel-only approver whose tunnel is down has not answered, and must not
// read as an answer: the engine takes a nil error as a final word, and before
// this was an error it denied the whole request the instant it was asked and
// dropped every other approver's prompt with it.
func TestADownTunnelOnlyApproverDoesNotDenyTheRequest(t *testing.T) {
	h := newTunnelled(t, shape{approverOffLAN: true})
	l := h.breakTunnelOnly(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	answer, err := (&RemoteApprover{link: l}).Decide(ctx, &approval.Request{Msg: gitRequest()})
	if err == nil {
		t.Fatalf("a down tunnel-only approver answered %v with no error", answer)
	}

	// And the request as a whole: the requester's own human answers, a little
	// after the remote approver has had every chance to settle it first.
	h.requester.human.set(approveAnswer("approved here"), nil)
	h.requester.human.setDelay(200 * time.Millisecond)

	resp, err := h.requester.engine.Submit(ctx, gitRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Errorf("decision %v: %s", resp.GetDecision(), resp.GetReason())
	}
}

// A holder whose only path is a tunnel that is not up is an unreachable
// holder, which decision AT falls through to the next one. Returned as no
// error, it stopped RemoteSign at a nil response.
func TestADownTunnelOnlyHolderIsUnreachable(t *testing.T) {
	h := newTunnelled(t, shape{approverOffLAN: true})
	l := h.breakTunnelOnly(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	object := commitObject("sign through a sleeping desktop")

	resp, err := h.requester.node.signOverLink(ctx, l, signRequest(h.key, object), object, true)
	if !errors.Is(err, ErrHolderUnreachable) {
		t.Errorf("signing over a down tunnel gave %v, %v; want ErrHolderUnreachable", resp, err)
	}
}

// A call that outlives its own deadline through the tunnel says nothing
// against the tunnel: before callOver checked, a slow diff fetch over a relay
// tore down the tunnel the link's presence stream was riding on.
func TestACallersDeadlineLeavesTheTunnelUp(t *testing.T) {
	h := newTunnelled(t, shape{approverOffLAN: true})
	l := h.link(t)

	stop := h.watchPresence(l)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	slow := func(ctx context.Context, client *http.Client, baseURL string) error {
		<-ctx.Done()

		return connect.NewError(connect.CodeDeadlineExceeded, ctx.Err())
	}

	if _, err := h.requester.node.callOver(ctx, tunnelTarget(l.tunnel), slow); err == nil {
		t.Fatal("a call past its deadline succeeded")
	}

	if !l.tunnel.snapshot().up {
		t.Error("the caller's deadline tore the tunnel down")
	}

	if why := stop(); why != "" {
		t.Errorf("after a caller's deadline the link %s", why)
	}
}

// The dial-back has no stream to be told on, so once a heartbeat it asks again
// through the tunnel: a tunnel that has punched since the raise — which is
// nearly every one, since the raise's Ping runs before hole-punching — reads
// punched, and keeps the call (decision AY).
func TestTheDialBackHearsItsTunnelPunch(t *testing.T) {
	h := newTunnelled(t, shape{requesterOffLAN: true, relayed: true})

	record, ok := h.approver.store.Peer(h.requester.identity.Fingerprint())
	if !ok {
		t.Fatal("the approver has no record of the requester")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := h.approver.node.call(ctx, record, pingFn); err != nil {
		t.Fatalf("a dial-back to a tunnel-only requester: %v", err)
	}

	if word := h.approver.node.peerStatus(record).GetPath(); word != "tunnel relayed test" {
		t.Fatalf("after the raise the path reads %q", word)
	}

	h.tunnels.setRelayed(false)

	h.approver.node.dialMu.Lock()
	held := h.approver.node.dialers[h.requester.identity.Fingerprint()]
	h.approver.node.dialMu.Unlock()

	// A heartbeat on.
	held.mu.Lock()
	held.checked = time.Time{}
	held.mu.Unlock()

	if err := h.approver.node.call(ctx, record, pingFn); err != nil {
		t.Fatalf("the second dial-back: %v", err)
	}

	if word := h.approver.node.peerStatus(record).GetPath(); word != trust.PathTunnelDirect {
		t.Errorf("after the tunnel punched the path reads %q", word)
	}
}

// Turning the tunnel off ends the dialer's raised clients at once, rather than
// at their next call or five idle minutes later: the upgrade is a public
// exposure, and switching it off ends it (decision AX).
func TestTurningTheTunnelOffClosesTheDialBacksClients(t *testing.T) {
	h := newTunnelled(t, shape{requesterOffLAN: true})

	record, ok := h.approver.store.Peer(h.requester.identity.Fingerprint())
	if !ok {
		t.Fatal("the approver has no record of the requester")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := h.approver.node.call(ctx, record, pingFn); err != nil {
		t.Fatalf("a dial-back to a tunnel-only requester: %v", err)
	}

	h.approver.node.dialMu.Lock()
	tunnel := h.approver.node.dialers[h.requester.identity.Fingerprint()].tunnelPath()
	h.approver.node.dialMu.Unlock()

	if !tunnel.snapshot().up {
		t.Fatal("the dial-back's tunnel is not up after a call through it")
	}

	h.approver.node.SetTunnel(nil)

	if tunnel.snapshot().up {
		t.Error("the dial-back's tunnel is still up with the tunnel off")
	}
}
