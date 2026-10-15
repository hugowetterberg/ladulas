package frontend

import (
	"context"
	"errors"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/bridge"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The local-network list on the Add a machine screen (decision AW).
//
// The daemon browses for as long as somebody holds its BrowsePairings stream,
// and the screen is a page that polls. So this holds the stream on the page's
// behalf, and lets go of it when the page stops asking: a lease, renewed by
// every List. A page that is closed, navigated away from or simply stops
// polling therefore stops the browse within nearbyLease without having to say
// so — and one that does say so (Stop) stops it at once.

// nearbyLease is how long the browse outlives the last time the screen asked.
// The screen asks every two seconds; five missed polls is a screen that has
// gone.
const nearbyLease = 10 * time.Second

// nearbyControl is the bridge.Nearby a front end offers.
type nearbyControl struct {
	front *Frontend

	mu      sync.Mutex
	cancel  context.CancelFunc
	lease   *time.Timer
	entries []bridge.NearbyView
	err     error
	// generation counts browses, so that a stream ending after another has
	// started cannot clear the newer one's state on its way out.
	generation int
}

var _ bridge.Nearby = (*nearbyControl)(nil)

// List starts browsing if nothing is, renews the lease, and returns what has
// been heard so far. The first call returns an empty list: the network has
// not had time to answer, and the screen's next poll has what it said.
func (c *nearbyControl) List(_ context.Context) ([]bridge.NearbyView, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cancel != nil {
		c.lease.Reset(nearbyLease)

		return append([]bridge.NearbyView(nil), c.entries...), nil
	}

	// The last browse ended under the screen, and this poll is the one that
	// hears why; the next one starts again.
	if c.err != nil {
		err := c.err
		c.err = nil

		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	stream, err := c.front.client.BrowsePairings(ctx,
		connect.NewRequest(&ladulasv1.BrowsePairingsRequest{}))
	if err != nil {
		cancel()

		return nil, err
	}

	c.generation++
	generation := c.generation

	c.cancel = cancel
	c.entries = nil
	c.err = nil
	c.lease = time.AfterFunc(nearbyLease, func() { c.expire(generation) })

	go c.follow(stream, generation)

	return []bridge.NearbyView{}, nil
}

// follow keeps the latest list, and forgets the browse when its stream ends.
func (c *nearbyControl) follow(
	stream *connect.ServerStreamForClient[ladulasv1.NearbyPairings],
	generation int,
) {
	defer func() {
		if err := stream.Close(); err != nil {
			c.front.log.Debug("closing the nearby stream", "error", err.Error())
		}
	}()

	for stream.Receive() {
		entries := nearbyViews(stream.Msg().GetPairings())

		c.mu.Lock()
		if c.generation == generation {
			c.entries = entries
		}
		c.mu.Unlock()
	}

	err := stream.Err()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.generation != generation || c.cancel == nil {
		return
	}

	// A stream the daemon ended — a seal, a daemon restart — is reported
	// once, on the next poll, and that poll's successor starts again.
	c.cancel()
	c.cancel = nil
	c.lease.Stop()

	if err != nil && !errors.Is(err, context.Canceled) {
		c.err = err
	}
}

func (c *nearbyControl) expire(generation int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.generation == generation {
		c.stopLocked()
	}
}

// Stop ends the browse now.
func (c *nearbyControl) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stopLocked()
}

func (c *nearbyControl) stopLocked() {
	if c.cancel == nil {
		return
	}

	c.cancel()
	c.cancel = nil
	c.lease.Stop()
	c.entries = nil
	c.err = nil
	c.generation++
}

// Join joins a listed machine. The daemon resolves the entry against its own
// list, so the browse has to be live when this is called — which it is, since
// the screen this is pressed on is the one polling.
func (c *nearbyControl) Join(
	ctx context.Context, id, pin string,
) (bridge.JoinView, error) {
	return c.front.joinWith(ctx, &ladulasv1.PairWithPeerRequest{
		Nearby: id,
		Code:   pin,
	})
}

func nearbyViews(entries []*ladulasv1.NearbyPairing) []bridge.NearbyView {
	out := make([]bridge.NearbyView, 0, len(entries))

	for _, entry := range entries {
		out = append(out, bridge.NearbyView{
			ID:        entry.GetId(),
			Name:      entry.GetName(),
			Interface: entry.GetInterface(),
			Address:   entry.GetAddress(),
			Duplicate: entry.GetDuplicate(),
		})
	}

	return out
}
