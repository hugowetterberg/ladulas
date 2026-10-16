package peer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// Some of M4 goes the other way down a pairing from everything before it.
//
// An approver browsing a requester's published documentation, or asking for the
// rest of a diff it was only sent part of, is the side that does not normally
// dial: it was dialled. connect-go over HTTP/2 has no reverse call, so the
// approver dials back — which it can, because a pairing records the addresses
// each side advertised whichever direction the approvals flow in, and the far
// end's gate lets any paired identity through.
//
// A link's client is preferred when there is one, because it is already warm.
// Otherwise a dialler is built for the call and dropped afterwards: these are
// occasional, human-paced operations, and a connection pool per peer that is
// never normally dialled would be state kept for nothing.

// ErrNoAddress is returned for a peer with nowhere to dial.
var ErrNoAddress = errors.New("peer: the peer advertises no address")

// reach is what the last dial of a peer that is not kept on a link found.
//
// A link reports its own state and is preferred; this is for the peers there is
// no link to, which on a phone is every peer it approves for. Collecting from
// one is a dial like any other, and its outcome is the only evidence a phone
// has that it can reach anything at all.
type reach struct {
	online   bool
	path     pathKind
	lastErr  string
	lastSeen time.Time
}

// noteReach records how a dial went. It is called for every call made without a
// link, whatever the call was for — fetching a diff, reading a project,
// collecting an inbox — because all of them answer the same question.
func (n *Node) noteReach(fingerprint string, via pathKind, err error) {
	if fingerprint == "" {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	state := n.reached[fingerprint]
	if state == nil {
		state = &reach{}
		n.reached[fingerprint] = state
	}

	if err != nil {
		state.online = false
		state.path = pathNone
		state.lastErr = err.Error()

		return
	}

	state.online = true
	state.path = via
	state.lastErr = ""
	state.lastSeen = time.Now()
}

func (n *Node) reachOf(fingerprint string) *reach {
	n.mu.Lock()
	defer n.mu.Unlock()

	state := n.reached[fingerprint]
	if state == nil {
		return nil
	}

	copied := *state

	return &copied
}

// call runs something against a peer, trying its paths in turn.
//
// A link's paths are tried when there is a link, in the order its established
// path gives (link.targets). Otherwise the dialer's: a warm client, the address
// it last reached the peer on, and — for a peer whose offer names a server —
// a tunnel raised on demand (decision AY), with the raise raced against the
// direct probe whenever no path is established, so that no call waits on it.
func (n *Node) call(
	ctx context.Context,
	record *storepb.TrustRecord,
	fn func(ctx context.Context, client *http.Client, baseURL string) error,
) error {
	if existing := n.link(record.GetFingerprint()); existing != nil {
		used, err := n.callOver(ctx, existing.targets(ctx), fn)
		existing.called(used)

		return err
	}

	// A peer with no link still gets a client that stays warm and an address
	// that is remembered, because the calls that go this way — a listing, a
	// page, a sync manifest — are the repeated ones.
	held, err := n.dialerFor(record)
	if err != nil {
		return err
	}

	tunnel := held.tunnelFor(n, record)

	used, err := n.callOver(ctx, held.targets(ctx, n, tunnel, record.GetAddresses()), fn)

	switch {
	case used.kind != pathNone:
		held.rememberRoute(used)

		// The first thing done over a direct contact after the tunnel failed
		// is to say the offer again, so an allowlist entry the far end lost
		// heals itself (§8).
		if used.kind == pathDirect && tunnel.takeReoffer() {
			go n.reoffer(held.client, used.address)
		}
	case ctx.Err() == nil:
		// Every path failed, and the address that worked before is the least
		// likely to be the right guess on whatever network this is now.
		held.forget()
	}

	// A cancelled call says nothing about the peer — it is the app going into
	// the background, or a long poll being torn down — so it is not recorded as
	// having failed to reach anybody.
	if ctx.Err() == nil {
		n.noteReach(record.GetFingerprint(), used.kind, err)
	}

	return err
}

// callOver tries a peer's paths in turn and reports the most informative
// failure, which is not the last one. It returns the route that worked, of
// kind pathNone when none did.
//
// It returned the last error until 2026-08-21, and the last address is the worst
// one by construction — the list is ordered best first, so the final attempt is
// the one nobody expected to work. On a machine whose peer had recorded its
// loopback address, the last attempt reached *this instance*, and what got
// reported for an unreachable peer was an identity mismatch naming that peer,
// with the real failure — a refused connection on the address that mattered —
// discarded on the way past. A whole evening went on reading the crypto stack
// for a fault that was a sealed store four addresses earlier. So:
//
//   - an address that answers with our own identity is not a failure at all. It
//     is an address that belongs to this machine, and it is skipped; a peer whose
//     every address is one of ours gets an error saying exactly that;
//   - of the real failures, the one that got furthest is reported, because a
//     name that would not resolve says less than a connection that was refused,
//     and a refusal says less than a peer that answered and complained;
//   - the count of the others goes in the message, so that "there were four
//     more" is visible without a log level.
//
// probeTimeout bounds the race that decides which address to call first.
//
// It is short on purpose. A peer that is actually reachable answers a TCP
// connect in milliseconds over a tailnet and in tens of them over anything
// else; two seconds is far past that and far short of the ten a blackholed
// address takes to admit defeat.
const probeTimeout = 2 * time.Second

// reachableFirst reorders a peer's addresses so that one that answered a TCP
// connect is tried first.
//
// **The race is on the connection, not on the call.** Running fn against every
// address at once would be the obvious happy-eyeballs shape and is wrong here:
// callOver carries answers, endorsements and grant reports as well as reads, so
// racing the call itself would apply a mutation once per address that answered.
// What is raced is a bare TCP connect, which tells a blackholed address from a
// live one — exactly the failure this exists for — and the identity pin is
// still checked by the real call, as it always was.
//
// It is a reordering rather than a decision. Everything callOver already does
// still happens: the winner is simply not the address that takes ten seconds to
// time out. A race that finds nothing changes nothing.
//
// The case it is for: two machines on a tailnet whose IPv6 is blackholed and
// whose IPv4 works. Serially that is a ten-second wait before the first address
// that could have worked is tried, on every call; the phone pays it four times
// over and looks broken rather than slow.
func reachableFirst(ctx context.Context, addresses []string) []string {
	if len(addresses) < 2 {
		return addresses
	}

	first := firstAnswering(ctx, addresses, nil)
	if first == "" {
		return addresses
	}

	out := make([]string, 0, len(addresses))
	out = append(out, first)

	for _, address := range addresses {
		if address != first {
			out = append(out, address)
		}
	}

	return out
}

// firstAnswering is the race itself: the first address that accepts a TCP
// connect inside probeTimeout, or "" when none does. It probes a single
// address too, because deciding between direct TCP and a relayed tunnel needs
// to know whether that one address answers (route.go). dial is Options.Dial,
// nil for a plain net.Dialer.
func firstAnswering(ctx context.Context, addresses []string, dial transport.DialFunc) string {
	if len(addresses) == 0 {
		return ""
	}

	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	winner := make(chan string, len(addresses))

	var wait sync.WaitGroup

	for _, address := range addresses {
		wait.Add(1)

		go func() {
			defer wait.Done()

			conn, err := dial(probeCtx, "tcp", address)
			if err != nil {
				return
			}

			_ = conn.Close()

			winner <- address
		}()
	}

	done := make(chan struct{})

	go func() {
		wait.Wait()
		close(done)
	}()

	var first string

	select {
	case first = <-winner:
	case <-done:
		// Every probe finished without connecting, or one slipped in just as
		// they did; either way the drain below settles it.
		select {
		case first = <-winner:
		default:
		}
	case <-probeCtx.Done():
	}

	return first
}

func (n *Node) callOver(
	ctx context.Context,
	targets []target,
	fn func(ctx context.Context, client *http.Client, baseURL string) error,
) (route, error) {
	if len(targets) == 0 {
		return route{}, ErrNoAddress
	}

	var (
		best      error
		bestRank  int
		attempted int
		ourselves int
	)

	for _, t := range targets {
		client, baseURL, err := t.resolve()
		if err == nil {
			err = fn(ctx, client.HTTP(), baseURL)
			if err == nil {
				return t.via, nil
			}

			if t.via.kind == pathTunnel && ctx.Err() == nil &&
				transportFailure(err) {
				// The tunnel was up and the call through it failed on the way
				// rather than in the answer: it is torn down and held back, and
				// the rest of the list is the fallback (§8). Not when the
				// caller's own budget ran out: a diff fetch that outlives its
				// thirty seconds over a slow relay says nothing against the
				// tunnel, and tearing it down for that would break the presence
				// stream riding on it.
				t.tunnel.failed(err)
			}
		} else if t.via.kind == pathTunnel && len(targets) > 1 {
			// A tunnel that is not up yet is the fallback position doing
			// nothing, not a failure worth reporting over the addresses.
			continue
		}

		if ctx.Err() != nil {
			return route{}, err
		}

		if errors.Is(err, transport.ErrSelfAddress) {
			ourselves++

			continue
		}

		attempted++

		if t.via.kind == pathTunnel {
			var tunnelErr *transport.TunnelError
			if !errors.As(err, &tunnelErr) {
				err = &transport.TunnelError{Err: err}
			}
		}

		if rank := failureRank(err); best == nil || rank >= bestRank {
			best = fmt.Errorf("peer: reach %s: %w", t, err)
			bestRank = rank
		}
	}

	switch {
	case best != nil && attempted > 1:
		return route{}, fmt.Errorf("%w (%d more paths also failed)",
			best, attempted-1)
	case best != nil:
		return route{}, best
	case ourselves > 0:
		// Every address the peer advertises is one of this machine's own, which
		// is a trust record to repair rather than a peer to wait for.
		return route{}, fmt.Errorf(
			"peer: every address recorded for this peer is one of ours, so it "+
				"was never dialled: %w", transport.ErrSelfAddress)
	default:
		return route{}, ErrNoAddress
	}
}

// transportFailure reports whether a call failed on the way to the peer or
// back — a connection that broke, a deadline, nothing answering — rather than
// in an answer the peer gave. Only the first says anything against the path
// the call took; a refusal or a not-found came back over a path that works.
func transportFailure(err error) bool {
	var (
		tunnelErr *transport.TunnelError
		netErr    net.Error
	)

	switch {
	case errors.As(err, &tunnelErr), errors.As(err, &netErr),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return true
	}

	switch connect.CodeOf(err) {
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded:
		return true
	default:
		return false
	}
}

// failureRank orders dial failures by how far the attempt got, so that the most
// informative one is the one reported.
//
// It is deliberately coarse. The distinction worth drawing is between an address
// that was never reached at all and one that answered, because the first says
// nothing about the peer and the second is the peer talking.
//
// A tunnel that was never reached has a rank of its own, above an address that
// was never reached and below anything that answered (decision AY). Before it
// had one, a raise that timed out and a refused direct address tied — both
// "nothing answered" — and the later won, so the report read "reach
// 192.168…: connection refused" and hid that the tunnel was the path expected
// to work. A tunnel failure that did get an answer — a handshake with the
// wrong identity, a gate that refused the client key — ranks as the answer.
func failureRank(err error) int {
	var (
		dns       *net.DNSError
		tunnelErr *transport.TunnelError
	)

	rank := 4

	switch {
	case errors.Is(err, transport.ErrUnknownPeer):
		// Somebody answered as the wrong identity. Rare, serious, and the one
		// failure worth reporting over a refusal.
		return 5
	case errors.As(err, &dns):
		// A name that does not resolve. Ordinary and uninformative: an
		// advertised tailnet name is unresolvable to a peer with MagicDNS off,
		// and the addresses behind it are what that peer uses.
		rank = 1
	case errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, os.ErrDeadlineExceeded),
		errors.Is(err, errTunnelDown):
		// The address is real and nothing is listening, or nothing answered.
		rank = 2
	default:
		// A handshake or an RPC that got an answer it did not like.
	}

	if errors.As(err, &tunnelErr) && rank < 3 {
		return 3
	}

	return rank
}
