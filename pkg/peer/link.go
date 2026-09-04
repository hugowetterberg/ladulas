package peer

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// link is this instance's standing relationship with a peer that approves for
// it: a pinned dialler, a presence stream that says whether the peer is there,
// and the remote approver registered with the engine.
//
// The presence stream is not how a request gets sent — a request opens its own
// stream when it needs to. What the presence stream buys is knowing, before
// anything is asked, whether there is anyone to ask, which is what `ladulas
// status` shows and what will decide whether a wake-up push is needed at all
// when M6 arrives (§11).
type link struct {
	node   *Node
	client *transport.Client
	key    ssh.PublicKey

	mu         sync.Mutex
	record     *storepb.TrustRecord
	preferred  string
	misses     int
	online     bool
	lastErr    string
	lastSeen   time.Time
	offered    []*ladulasv1.KeyRef
	cancel     context.CancelFunc
	unregister func()
	done       chan struct{}
}

func newLink(node *Node, record *storepb.TrustRecord) (*link, error) {
	key, err := trust.PublicKey(record)
	if err != nil {
		return nil, err
	}

	client, err := transport.NewClient(transport.ClientOptions{
		Identity: node.identity,
		Expect:   key,
	})
	if err != nil {
		return nil, err
	}

	return &link{
		node:   node,
		client: client,
		key:    key,
		record: record,
	}, nil
}

// Name is the peer's name, as this instance recorded it.
func (l *link) Name() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.record.GetName()
}

// Fingerprint identifies the peer.
func (l *link) Fingerprint() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.record.GetFingerprint()
}

// Record returns the trust record the link is working from.
func (l *link) Record() *storepb.TrustRecord {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.record
}

// State reports what the link knows about the peer's reachability.
func (l *link) State() (online bool, lastErr string, lastSeen time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.online, l.lastErr, l.lastSeen
}

func (l *link) update(record *storepb.TrustRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.record = record
}

// addresses returns the addresses to try, the one that last worked first.
func (l *link) addresses() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	all := l.record.GetAddresses()

	out := make([]string, 0, len(all))

	if l.preferred != "" {
		out = append(out, l.preferred)
	}

	for _, address := range all {
		if address != l.preferred {
			out = append(out, address)
		}
	}

	return out
}

func (l *link) succeeded(address string) {
	l.mu.Lock()

	first := !l.online

	l.preferred = address
	l.misses = 0
	l.online = true
	l.lastErr = ""
	l.lastSeen = time.Now()

	fingerprint := l.record.GetFingerprint()

	l.mu.Unlock()

	// A link coming up is the moment to hand over anything this instance did
	// under that peer's delegations while it could not be reached (decision P).
	// It is what makes a machine that has been offline catch up the moment it
	// is not, rather than at whatever the peer's next poll happens to be.
	if first {
		l.node.PushGrantActivity(fingerprint)
	}
}

func (l *link) failed(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.online = false
	l.offered = nil
	l.misses++

	if err != nil {
		l.lastErr = err.Error()
	}
}

// offeredKeys is what the peer last said it would sign with for us, and can
// still be asked to sign with now.
//
// It is emptied when the link goes down, because an agent that kept listing a
// sleeping desktop's keys would answer ssh with identities it cannot use, and
// ssh would spend the server's authentication attempts on them. That is a
// statement about the agent socket and not about the keys: what the peer
// offered is written down in the store and outlives this (decision N), so the
// listings that can say "held by a phone, last seen four hours ago" go on
// saying it while this is empty.
func (l *link) offeredKeys() []*ladulasv1.KeyRef {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.offered
}

// learnKeys asks the peer which of its keys this instance may use.
//
// It runs when a link comes up and again on every heartbeat, rather than when a
// key is wanted: the caller that wants one is an SSH agent answering a request
// for identities, and ssh does not wait. Asking again is what makes `ladulas
// peers allow --key` on the holder take effect on the requester without either
// side being restarted — the grant is the holder's to make, and the requester
// finds out within a heartbeat.
func (l *link) learnKeys(ctx context.Context, address string) {
	client := ladulasv1connect.NewKeyServiceClient(
		l.client.HTTP(), l.client.URL(address))

	resp, err := client.ListKeys(ctx, connect.NewRequest(&ladulasv1.ListKeysRequest{}))
	if err != nil {
		// A peer that offers nothing and a peer that refuses to say are the same
		// thing to a requester, and neither is a reason to drop the link: the
		// peer may still be an approver, which is the other half of what a link
		// is for.
		l.node.log.Debug("a peer did not say which keys it offers",
			"peer", l.Name(), "error", err.Error())

		// Only the usable-now set is cleared. What was remembered stays
		// remembered, because a holder that could not be asked has said nothing,
		// and nothing is not the same answer as an empty list (decision N).
		l.setOffered(nil)

		return
	}

	keys := validKeys(resp.Msg.GetKeys())

	l.setOffered(keys)
	l.node.rememberKeys(l.Fingerprint(), keys)
}

// setOffered replaces the cached key set, and says so only when it moved: a
// heartbeat that learns the same three keys is not news.
func (l *link) setOffered(keys []*ladulasv1.KeyRef) {
	l.mu.Lock()
	changed := !sameKeys(l.offered, keys)
	l.offered = keys
	l.mu.Unlock()

	if !changed {
		return
	}

	l.node.log.Info("what a peer offers to sign with changed",
		"peer", l.Name(), "keys", len(keys))
}

func sameKeys(a, b []*ladulasv1.KeyRef) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i].GetFingerprint() != b[i].GetFingerprint() {
			return false
		}
	}

	return true
}

// start brings the link up: the remote approver joins the engine's fan-out, and
// the presence loop begins.
func (l *link) start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)

	approver := &RemoteApprover{link: l}

	l.mu.Lock()
	l.cancel = cancel
	l.unregister = l.node.engine.Register(approver)
	l.done = make(chan struct{})
	done := l.done
	l.mu.Unlock()

	go func() {
		defer close(done)

		l.watch(ctx)
	}()
}

func (l *link) stop() {
	l.mu.Lock()
	cancel := l.cancel
	unregister := l.unregister
	done := l.done
	l.cancel = nil
	l.unregister = nil
	l.mu.Unlock()

	if unregister != nil {
		unregister()
	}

	if cancel != nil {
		cancel()
	}

	l.client.CloseIdle()

	if done != nil {
		<-done
	}
}

// watch keeps a presence stream open, reconnecting with a backoff that starts
// at a second and stops doubling at a minute.
//
// The ceiling matters more than the floor. A desktop that has been asleep all
// weekend should be reachable within a minute of waking up, and a backoff that
// had reached half an hour by then would leave a headless box unable to get
// anything signed long after its approver came back.
func (l *link) watch(ctx context.Context) {
	delay := l.node.floor

	for {
		// Where the approver can dial this instance back is read afresh for
		// every stream, so a requester that moved networks says so on the
		// reconnect (decision AQ).
		err := l.presence(ctx, l.node.Advertised())

		if ctx.Err() != nil {
			return
		}

		l.failed(err)

		if err != nil {
			l.node.log.Debug("the link to a peer went down",
				"peer", l.Name(), "error", err.Error())
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(delay)):
		}

		delay *= 2
		if delay > l.node.ceiling {
			delay = l.node.ceiling
		}
	}
}

// jitter spreads reconnections out, so that a set of instances that all lost
// the same network do not come back in lockstep.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}

	return d/2 + time.Duration(rand.Int64N(int64(d)))
}

// presenceMisses is how many consecutive failures the address that last worked
// is given before the presence loop starts trying the rest of the record.
//
// It is a compromise between two costs that pull opposite ways. Trying every
// address every time is what a record written before decision AH makes
// expensive: fourteen of them, most on interfaces that belong to a container
// runtime on the *other* machine, each worth a dial timeout to a peer that is
// simply asleep. Trying only the preferred one for ever is no failover at all,
// which is what this code had. Three failures is long enough that a peer coming
// back on the address it left on never reaches the sweep, and short enough that
// one that has genuinely moved is found inside the minute the backoff ceiling
// promises.
const presenceMisses = 3

// presenceOrder is the addresses to try this time round.
//
// It is not link.addresses, which the call paths use and which always offers
// the whole record: a signature somebody is waiting for should try everything
// it has, while presence runs on a timer and can afford to be patient.
func (l *link) presenceOrder() []string {
	l.mu.Lock()
	preferred := l.preferred
	misses := l.misses
	l.mu.Unlock()

	if preferred != "" && misses < presenceMisses {
		return []string{preferred}
	}

	return l.addresses()
}

// presence opens a presence stream and reads it until it breaks, telling the
// approver where this instance can be dialled as it opens.
func (l *link) presence(ctx context.Context, advertised []string) error {
	addresses := l.presenceOrder()
	if len(addresses) == 0 {
		return errors.New("the peer has no address to dial")
	}

	var lastErr error

	for _, address := range addresses {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		client := ladulasv1connect.NewPresenceServiceClient(
			l.client.HTTP(), l.client.URL(address))

		stream, err := client.Watch(ctx, connect.NewRequest(&ladulasv1.WatchRequest{
			ListenAddresses: advertised,
		}))
		if err != nil {
			lastErr = err

			continue
		}

		// Nothing may be claimed until a beat has arrived. connect hands the
		// stream back as soon as the request is queued and deliberately keeps
		// the transport error for the first Receive — its own comment on
		// CallServerStream says so — so a nil error here means the request was
		// written, and nothing more. Treating it as a connection is what had a
		// laptop asleep with its lid shut logged as "linked to a peer" every
		// twenty seconds, marked online, and sent grant activity; and it is why
		// this loop never advanced past its first address, since the address
		// that could not be reached never reported that it could not be reached.
		//
		// The first beat is free evidence: Watch's handler sends one before it
		// waits on its ticker, so a stream that yields nothing is a peer that
		// is not there.
		if !stream.Receive() {
			lastErr = noHeartbeat(stream)

			continue
		}

		l.succeeded(address)

		l.node.log.Info("linked to a peer",
			"peer", l.Name(), "address", address)

		// The keys are learned once the link is up, so a keyless box's agent has
		// something to list the moment ssh asks.
		l.learnKeys(ctx, address)

		// And where the approver says it can be dialled, which is on every
		// beat (decision AQ). succeeded ran first so the address this stream
		// is on is what learnAddresses keeps.
		l.node.learnAddresses(l.Fingerprint(), stream.Msg().GetListenAddresses())

		for stream.Receive() {
			l.succeeded(address)

			// And again on every beat, so a key granted on the holder reaches
			// the requester without either side being restarted.
			l.learnKeys(ctx, address)
			l.node.learnAddresses(l.Fingerprint(), stream.Msg().GetListenAddresses())
		}

		closeErr := stream.Close()

		if streamErr := stream.Err(); streamErr != nil {
			return streamErr
		}

		return closeErr
	}

	return lastErr
}

// noHeartbeat is why a presence stream produced no first beat, and it closes the
// stream on the way past so that trying the next address does not leak this one.
//
// A stream that ends without an error and without a beat is a peer that
// authenticated and then said nothing, which no build of this does; it gets a
// sentence of its own rather than a nil error that would read as success.
func noHeartbeat(
	stream *connect.ServerStreamForClient[ladulasv1.PresenceEvent],
) error {
	err := stream.Err()
	closeErr := stream.Close()

	switch {
	case err != nil:
		return err
	case closeErr != nil:
		return closeErr
	default:
		return errors.New(
			"the peer ended the presence stream without a heartbeat")
	}
}

// approvalClient builds an approval client for an address.
func (l *link) approvalClient(address string) ladulasv1connect.ApprovalServiceClient {
	return ladulasv1connect.NewApprovalServiceClient(
		l.client.HTTP(), l.client.URL(address),
		connect.WithSendMaxBytes(maxRequestBytes))
}
