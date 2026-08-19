package peer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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

func (n *Node) callOver(
	ctx context.Context,
	client *transport.Client,
	addresses []string,
	fn func(ctx context.Context, client *http.Client, baseURL string) error,
) error {
	if len(addresses) == 0 {
		return ErrNoAddress
	}

	var lastErr error

	for _, address := range addresses {
		err := fn(ctx, client.HTTP(), client.URL(address))
		if err == nil {
			return nil
		}

		if ctx.Err() != nil {
			return err
		}

		lastErr = fmt.Errorf("peer: reach %s: %w", address, err)
	}

	return lastErr
}
