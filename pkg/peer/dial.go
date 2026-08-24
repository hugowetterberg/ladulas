package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
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
	lastErr  string
	lastSeen time.Time
}

// noteReach records how a dial went. It is called for every call made without a
// link, whatever the call was for — fetching a diff, reading a project,
// collecting an inbox — because all of them answer the same question.
func (n *Node) noteReach(fingerprint string, err error) {
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
		state.lastErr = err.Error()

		return
	}

	state.online = true
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

// call runs something against a peer, trying its addresses in turn.
func (n *Node) call(
	ctx context.Context,
	record *storepb.TrustRecord,
	fn func(ctx context.Context, client *http.Client, baseURL string) error,
) error {
	if existing := n.link(record.GetFingerprint()); existing != nil {
		return n.callOver(ctx, existing.client, existing.addresses(), fn)
	}

	key, err := trust.PublicKey(record)
	if err != nil {
		return err
	}

	client, err := transport.NewClient(transport.ClientOptions{
		Identity: n.identity,
		Expect:   key,
	})
	if err != nil {
		return err
	}

	defer client.CloseIdle()

	err = n.callOver(ctx, client, record.GetAddresses(), fn)

	// A cancelled call says nothing about the peer — it is the app going into
	// the background, or a long poll being torn down — so it is not recorded as
	// having failed to reach anybody.
	if ctx.Err() == nil {
		n.noteReach(record.GetFingerprint(), err)
	}

	return err
}

// callOver tries a peer's addresses in turn and reports the most informative
// failure, which is not the last one.
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
func (n *Node) callOver(
	ctx context.Context,
	client *transport.Client,
	addresses []string,
	fn func(ctx context.Context, client *http.Client, baseURL string) error,
) error {
	if len(addresses) == 0 {
		return ErrNoAddress
	}

	var (
		best      error
		bestRank  int
		attempted int
		ourselves int
	)

	for _, address := range addresses {
		err := fn(ctx, client.HTTP(), client.URL(address))
		if err == nil {
			return nil
		}

		if ctx.Err() != nil {
			return err
		}

		if errors.Is(err, transport.ErrSelfAddress) {
			ourselves++

			continue
		}

		attempted++

		if rank := failureRank(err); best == nil || rank >= bestRank {
			best = fmt.Errorf("peer: reach %s: %w", address, err)
			bestRank = rank
		}
	}

	switch {
	case best != nil && attempted > 1:
		return fmt.Errorf("%w (%d more addresses also failed)",
			best, attempted-1)
	case best != nil:
		return best
	case ourselves > 0:
		// Every address the peer advertises is one of this machine's own, which
		// is a trust record to repair rather than a peer to wait for.
		return fmt.Errorf(
			"peer: every address recorded for this peer is one of ours, so it "+
				"was never dialled: %w", transport.ErrSelfAddress)
	default:
		return ErrNoAddress
	}
}

// failureRank orders dial failures by how far the attempt got, so that the most
// informative one is the one reported.
//
// It is deliberately coarse. The distinction worth drawing is between an address
// that was never reached at all and one that answered, because the first says
// nothing about the peer and the second is the peer talking.
func failureRank(err error) int {
	var dns *net.DNSError

	switch {
	case errors.As(err, &dns):
		// A name that does not resolve. Ordinary and uninformative: an
		// advertised tailnet name is unresolvable to a peer with MagicDNS off,
		// and the addresses behind it are what that peer uses.
		return 1
	case errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, os.ErrDeadlineExceeded):
		// The address is real and nothing is listening, or nothing answered.
		return 2
	case errors.Is(err, transport.ErrUnknownPeer):
		// Somebody answered as the wrong identity. Rare, serious, and the one
		// failure worth reporting over a refusal.
		return 4
	default:
		// A handshake or an RPC that got an answer it did not like.
		return 3
	}
}
