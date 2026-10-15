package peer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// The pairing server: off-network pairing for a full code (§7, decision AZ).
//
// The full code cannot carry the long-lived server's address. The displaying
// side does not know the joiner's client key until the joiner's MEOW arrives,
// so the long-lived server would have to admit anybody for the length of the
// window, and its address — which outlives the window by as long as the
// instance keeps its keys — would then be a bearer capability. So a code
// displayed while the long-lived server is up starts a second, short-lived
// tailcat server for that window alone: fresh keys, any client key admitted up
// to a small cap, and a mux that serves the PIN exchange and nothing else. Its
// address goes into the full code, and the joiner never writes it down; what a
// pairing records is the long-lived offer the exchange carries, which both
// sides admit when the code is spent (pendingOffer).
//
// Three moments, kept apart because the obvious implementation runs them
// together:
//
//   - Spent. The code has produced its pairing, or used its attempts up. Every
//     new exchange is refused from then on, on every listener, by the window
//     itself — that is not the pairing server's to enforce.
//   - Answered. The exchange that spent it has written its last message: the
//     PIN exchange's second round and the listener's confirmation in it.
//   - Closed. A short grace after that, so the response leaves the tunnel
//     before the tunnel does, bounded by the window's own five minutes.
//
// Closing on spend tears down the connection carrying the response. The
// displayer would then hold a pending pairing the joiner never heard about,
// and nothing times a pending pairing out (decision M).

// Pairing server limits.
const (
	// PairingServerClients is how many distinct client keys a pairing server
	// admits before it refuses every further one. Each is a WireGuard peer in
	// the process that also signs, and a window that a real joiner uses needs
	// one, or two if it retried from a reinstalled build; eight leaves room
	// for a person trying twice from two machines and keeps somebody holding
	// the code from filling the process with peers.
	PairingServerClients = 8

	// pairingServerStart bounds starting one, which is how long the code can
	// wait for it before it is shown without the address. The region pick has
	// a few seconds of this, and the DERP connection the rest. It is spent
	// before the PIN is on screen, so it is short: a pairing server that has
	// not come up by then is reported, and the direct addresses still work.
	pairingServerStart = 8 * time.Second

	// pairingServerGrace is how long a pairing server stays up after the
	// exchange that spent the code has returned, so that its response is
	// read before the tunnel under it goes.
	pairingServerGrace = 5 * time.Second
)

// Errors the joining side reports when the code's pairing server cannot be
// used (decision AZ).
var (
	// ErrTunnelNeeded is a joiner with the upgrade off holding a code whose
	// direct addresses did not answer. Joining through the pairing server
	// would make a pair with no tunnel and no direct path, which could never
	// settle, so it is refused.
	ErrTunnelNeeded = errors.New(
		"none of the other machine's addresses answered from here; " +
			"turn on the tunnel to pair across networks")
)

// pairingServe is a running pairing server and what its runner needs.
type pairingServe struct {
	window *pairingWindow
	server PairingServer

	mu sync.Mutex
	// inflight is pairing calls being served right now, and finished is told
	// each time one ends, so the runner can wait for the exchange that spent
	// the code to have written its answer.
	inflight int
	finished chan struct{}
	closed   chan struct{}
	once     sync.Once
}

func (p *pairingServe) begin() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.inflight++
}

func (p *pairingServe) end() {
	p.mu.Lock()
	p.inflight--
	p.mu.Unlock()

	select {
	case p.finished <- struct{}{}:
	default:
	}
}

func (p *pairingServe) busy() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.inflight > 0
}

// close tears the server down, once.
func (p *pairingServe) close() error {
	var err error

	p.once.Do(func() {
		close(p.closed)

		err = p.server.Close()
	})

	return err
}

// offNetwork is the sentence a code is shown with about the pairing server,
// and the address and version that go into the code when there is one.
type offNetwork struct {
	address  string
	version  int32
	sentence string
}

// unavailable is the screen's sentence for a code without the address.
func unavailable(reason string) offNetwork {
	return offNetwork{sentence: "Off-network pairing unavailable: " + reason}
}

// openPairingServer starts the pairing server for a window, when this instance
// can run one, and says what the code can then carry.
//
// Only when the long-lived server is up. Otherwise a joiner could complete the
// exchange through the pairing server and have nowhere to settle: the
// pairing's own offer would carry no address, and the long-lived listener is
// the only place SettlePairing is answered through the tunnel.
func (n *Node) openPairingServer(window *pairingWindow) offNetwork {
	n.tunnelMu.Lock()
	tunnel := n.tunnel
	up := n.tunnelAddress != ""
	detail := n.tunnelDetail
	closed := n.tunnelClosed
	n.tunnelMu.Unlock()

	switch {
	case closed:
		return unavailable("this instance is closing")
	case tunnel == nil:
		return unavailable("the tunnel is off on this machine")
	case !up && detail != "":
		return unavailable("the tunnel server is not up (" + detail + ")")
	case !up:
		return unavailable("the tunnel server is still starting")
	}

	server, err := startPairing(tunnel)
	if err != nil {
		n.log.Warn("the pairing server did not start", "error", err.Error())
		n.observedTunnel("pairing_server_failed")

		return unavailable("the pairing server did not start (" + err.Error() + ")")
	}

	serve := &pairingServe{
		window:   window,
		server:   server,
		finished: make(chan struct{}, 1),
		closed:   make(chan struct{}),
	}

	// Registered before it is served, so that a seal racing this finds it;
	// and refused when the tunnel it belongs to has gone in the meantime.
	n.tunnelMu.Lock()
	if n.tunnelClosed || n.tunnel != tunnel {
		n.tunnelMu.Unlock()

		_ = serve.close()

		return unavailable("the tunnel was turned off")
	}

	previous := n.pairing
	n.pairing = serve
	n.tunnelMu.Unlock()

	if previous != nil {
		n.closePairingServe(previous)
	}

	go func() {
		err := n.server.ServePairingTunnel(server.Listener(),
			pairingGate{node: n, window: window}, n.pairingHandler(serve))
		if err != nil && !errors.Is(err, transport.ErrTunnelClosed) {
			n.log.Warn("the pairing server stopped", "error", err.Error())
		}
	}()

	go n.runPairingServer(serve)

	n.log.Info("a pairing server is up for the displayed code")
	n.observedTunnel("pairing_server_started")

	return offNetwork{
		address:  server.Address(),
		version:  tunnel.Version(),
		sentence: "A machine on another network can pair with the full code, through the tunnel",
	}
}

// startPairing starts a pairing server inside pairingServerStart.
//
// Tunnel.StartPairing takes no context, because gomobile binds none, so the
// bound is kept here; a server that comes up after the code has been shown
// without it is closed as soon as it does.
func startPairing(tunnel Tunnel) (PairingServer, error) {
	type started struct {
		server PairingServer
		err    error
	}

	done := make(chan started, 1)

	go func() {
		server, err := tunnel.StartPairing(PairingServerClients)
		done <- started{server: server, err: err}
	}()

	timer := time.NewTimer(pairingServerStart)
	defer timer.Stop()

	select {
	case got := <-done:
		if got.err != nil {
			return nil, got.err
		}

		if got.server == nil {
			return nil, errors.New("no server")
		}

		return got.server, nil
	case <-timer.C:
		go func() {
			if got := <-done; got.server != nil {
				_ = got.server.Close()
			}
		}()

		return nil, fmt.Errorf("not up inside %s", pairingServerStart)
	}
}

// runPairingServer closes a pairing server at the right moment: a grace after
// the exchange that spent the code has returned, the moment the window stops
// admitting anybody, at the window's expiry at the latest, or with the node.
func (n *Node) runPairingServer(serve *pairingServe) {
	window := serve.window

	expiry := time.NewTimer(time.Until(window.expires))
	defer expiry.Stop()

	defer n.closePairingServe(serve)

	select {
	case <-window.spent:
	case <-window.done:
		return
	case <-expiry.C:
		return
	case <-serve.closed:
		return
	case <-n.lifetime().Done():
		return
	}

	// Spent. Whatever is still being served is the exchange that spent the
	// code, or one about to be told it was spent; both are owed their answer.
	for serve.busy() {
		select {
		case <-serve.finished:
		case <-expiry.C:
			return
		case <-serve.closed:
			return
		}
	}

	wait := n.pairingGrace
	if wait <= 0 {
		wait = pairingServerGrace
	}

	grace := time.NewTimer(min(wait, time.Until(window.expires)))
	defer grace.Stop()

	select {
	case <-grace.C:
	case <-expiry.C:
	case <-serve.closed:
	}
}

// closePairingServe closes one pairing server and forgets it.
func (n *Node) closePairingServe(serve *pairingServe) {
	n.tunnelMu.Lock()
	if n.pairing == serve {
		n.pairing = nil
	}
	n.tunnelMu.Unlock()

	if err := serve.close(); err != nil {
		n.log.Debug("could not close the pairing server", "error", err.Error())
	}
}

// closePairingServer closes whichever pairing server is up, which is what
// sealing, shutting down and turning the tunnel off do to it first (§3): a
// server that admits anybody is the last thing that should outlive any of
// them.
func (n *Node) closePairingServer() {
	n.tunnelMu.Lock()
	serve := n.pairing
	n.pairing = nil
	n.tunnelMu.Unlock()

	if serve != nil {
		n.closePairingServe(serve)
	}
}

// pairingHandler is the pairing server's mux: the pairing service and nothing
// else, counting what it is serving for the runner.
func (n *Node) pairingHandler(serve *pairingServe) http.Handler {
	mux := http.NewServeMux()

	mux.Handle(ladulasv1connect.NewPairingServiceHandler(&peerService{node: n},
		connect.WithReadMaxBytes(maxRequestBytes)))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve.begin()
		defer serve.end()

		mux.ServeHTTP(w, r)
	})
}

// pairingGate is a pairing server's door.
//
// It admits any identity while the server's own window is the one open here
// — the bound listener's rule for a window, and the tailcat allowlist has
// already admitted any client key — and the PIN exchange's two rounds and
// nothing else. Not SettlePairing: settling goes to the long-lived listener,
// whose gate knows the pending identity and the client key it offered, and the
// pairing server is gone by then anyway. Not the older proof either: a joiner
// that found this address is a build that speaks the PIN.
type pairingGate struct {
	node   *Node
	window *pairingWindow
}

var _ transport.TunnelGate = pairingGate{}

// The two procedures a pairing server answers.
const (
	pairStartProcedure  = ladulasv1connect.PairingServicePairStartProcedure
	pairFinishProcedure = ladulasv1connect.PairingServicePairFinishProcedure
)

// Admit lets anybody in while the window is open.
func (g pairingGate) Admit(string, []byte) error {
	if g.node.openWindow() != g.window {
		return errPairingClosed
	}

	return nil
}

// Permit allows the PIN exchange.
func (g pairingGate) Permit(_, procedure string) error {
	if procedure != pairStartProcedure && procedure != pairFinishProcedure {
		return errors.New("a pairing server answers the PIN exchange and nothing else")
	}

	return nil
}

// reachPairingServer is the joining half: a tailcat client raised against the
// pairing server's address in a full code, and the pinned handshake through it
// (decision AZ).
//
// Joining this way needs the upgrade on here, and the long-lived server up.
// The pairing that comes out of it may have no direct path at all — that is
// the case it exists for — so its tunnels are the only way it can ever
// settle, and the offer this side sends in the exchange is the one the
// displaying side admits for exactly that. A joiner without one is refused
// before anything is sent, rather than allowed to make a pair that could
// never complete.
//
// The client is raised with this instance's own client key. The pairing
// server admits any key, so a key made for the purpose would buy nothing; and
// the address it is raised against is held to the region rule like any other
// peer-supplied address, because it names a relay this instance is about to
// connect to.
func (n *Node) reachPairingServer(
	ctx context.Context, code *ladulasv1.PairingCode, expected ssh.PublicKey,
) (*reachedListener, error) {
	tunnel := n.currentTunnel()
	if tunnel == nil {
		return nil, ErrTunnelNeeded
	}

	if theirs, ours := code.GetTunnelVersion(), uint32(max(tunnel.Version(), 0)); theirs != ours {
		return nil, fmt.Errorf("the other machine's tunnel speaks version %d and "+
			"this one's %d, so it cannot be reached across networks; update one "+
			"of them, or pair on the same network", theirs, ours)
	}

	if offer := n.offer(); !trust.TunnelServes(offer) {
		return nil, errors.New("the tunnel here is not up yet, and a pairing " +
			"across networks needs it to settle; try again once `ladulas status` " +
			"says it is")
	}

	address := code.GetTunnelAddress()

	if refused := n.checkOfferRegion(address); refused != "" {
		return nil, errors.New(refused)
	}

	raw, err := tunnel.Raise(address)
	if err != nil {
		return nil, fmt.Errorf("raise a client: %w", err)
	}

	client, err := transport.NewTunnelClient(transport.ClientOptions{
		Identity: n.identity,
		Expect:   expected,
	}, raw)
	if err != nil {
		closeRaw(raw)

		return nil, err
	}

	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > tunnelRaiseTimeout {
		deadline = time.Now().Add(tunnelRaiseTimeout)
	}

	if err := raw.Ping(deadline.UnixNano()); err != nil {
		closeRaw(raw)

		return nil, fmt.Errorf("the pairing server did not answer: %w", err)
	}

	peer, err := client.Handshake(ctx, transport.TunnelHost)
	if err != nil {
		client.CloseIdle()
		closeRaw(raw)

		return nil, err
	}

	// Where the listener was reached, for the confirmation card: not the
	// in-netstack address, which is nobody's.
	peer.RemoteAddr = PairingServerPath

	return &reachedListener{
		client:  client,
		peer:    peer,
		address: transport.TunnelHost,
		raw:     raw,
	}, nil
}
