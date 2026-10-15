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
	// tunnel is the link's own raised client to the peer's tunnel server, held
	// for as long as the link lives (decision AY). It raises only while the
	// peer offers something this instance can raise against.
	tunnel *tunnelPath

	mu     sync.Mutex
	record *storepb.TrustRecord
	// preferred is the direct address that last worked. Only a direct route
	// sets it (path.go): it is an address, and a path that is not one has none
	// to give it.
	preferred string
	// unverified says the link last came up over a path that is not an
	// address, so preferred is the direct address from before that and nothing
	// has confirmed it since. It is kept, so that a direct success puts things
	// back as they were, but it is neither put first nor tried alone, and it
	// is not the address this instance is reaching the peer on (lastReached).
	unverified bool
	// path is the kind of path the link is up over, pathNone while it is not.
	path       pathKind
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

	client, err := node.newDirectClient(transport.ClientOptions{
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
		tunnel: newTunnelPath(node, record, key),
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

// directAddress is the direct address the link last confirmed, "" when it has
// none or it is unverified.
func (l *link) directAddress() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.unverified {
		return ""
	}

	return l.preferred
}

// currentPath is the kind of path the link is up over, pathNone while down.
func (l *link) currentPath() pathKind {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.online {
		return pathNone
	}

	return l.path
}

func (l *link) update(record *storepb.TrustRecord) {
	l.mu.Lock()
	l.record = record
	l.mu.Unlock()

	// A new offer, a withdrawal or a rotated key re-raises or drops the
	// tunnel; the next beat decides whether the link moves.
	l.tunnel.sync(record)
}

// addresses returns the addresses to try, the one that last worked first.
//
// An unverified one is not put first: it worked before the link moved to a
// path that is not an address, and the network may have moved with it, so the
// record's own order is as good a guess and does not single it out.
func (l *link) addresses() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	all := l.record.GetAddresses()

	first := l.preferred
	if l.unverified {
		first = ""
	}

	out := make([]string, 0, len(all)+1)

	if first != "" {
		out = append(out, first)
	}

	for _, address := range all {
		if address != first {
			out = append(out, address)
		}
	}

	return out
}

// succeeded reports a direct dial reaching the peer at address.
func (l *link) succeeded(address string) {
	l.reached(direct(address))
}

// called reports a call — not the presence stream — reaching the peer over a
// route, or failing to when the route is of kind pathNone.
//
// The presence stream owns the link's path. A call that works while the link
// is down brings it up, as it always has; one that works while the link is up
// does not move it, because which path the link is on is the stream's to say,
// and a signature that happened to go through the tunnel while the stream
// held a direct connection is not a path change. A direct success is still
// evidence about the address, and is recorded as such.
func (l *link) called(via route) {
	if via.kind == pathNone {
		return
	}

	l.mu.Lock()
	online := l.online

	if online {
		if via.kind == pathDirect {
			l.preferred = via.address
			l.unverified = false
		}

		l.misses = 0
		l.lastSeen = time.Now()
	}
	l.mu.Unlock()

	if !online {
		l.reached(via)
	}
}

// targets is the order a call tries the link's paths in: by the precedence
// while the link is up (onPath), and with the raise raced against the direct
// probe while it is not (Node.arrange).
func (l *link) targets(ctx context.Context) []target {
	direct := directTargets(l.client, l.addresses())

	if path := l.currentPath(); path != pathNone {
		return onPath(path, l.tunnel, direct)
	}

	return l.node.arrange(ctx, l.tunnel, direct)
}

// reached reports the link's peer reached over a route.
//
// A direct route is the address machinery's evidence: the address becomes the
// one to try first and the one decision AQ keeps in the record. Any other
// route leaves the address alone and marks it unverified, so that if that path
// is lost the presence loop sweeps the whole record rather than spending three
// rounds on an address that was last confirmed before the link moved off it —
// the café laptop whose last direct address is its home LAN's.
func (l *link) reached(via route) {
	l.mu.Lock()

	l.path = via.kind

	if via.kind == pathDirect {
		l.preferred = via.address
		l.unverified = false
	} else {
		l.unverified = true
	}

	first := !l.online

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
		if l.node.linked != nil {
			l.node.linked(fingerprint)
		}

		l.node.PushGrantActivity(fingerprint)
	}
}

// failed is the link going down: presence lost on every path. A path change is
// not this (presence), and must never be routed through it — it empties the
// offered keys, so the SSH agent would list nothing for the length of a
// reconnect, and the next success would push grant activity and log a new
// link (§8, decision AY).
func (l *link) failed(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.online = false
	l.offered = nil
	l.path = pathNone
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
func (l *link) learnKeys(ctx context.Context, over target) {
	pinned, baseURL, err := over.resolve()
	if err != nil {
		// A tunnel that is not up has asked nobody anything. Blanking the set
		// for it would empty the agent's key list on a path change — a beat
		// that raced a tunnel failure, RefreshKeys taking a tunnel still
		// raising as its first target — and a path change is not a presence
		// change (decision AY). If the peer is really gone, failed() empties
		// the set when the presence loop says so.
		return
	}

	client := ladulasv1connect.NewKeyServiceClient(pinned.HTTP(), baseURL)

	resp, err := client.ListKeys(ctx, connect.NewRequest(&ladulasv1.ListKeysRequest{}))
	if err != nil {
		// A peer that offers nothing and a peer that refuses to say are the same
		// thing to a requester, and neither is a reason to drop the link: the
		// peer may still be an approver, which is the other half of what a link
		// is for.
		l.node.log.Debug("a peer did not say which keys it offers",
			"peer", l.Name(), "error", err.Error())

		// Only a refusal clears the usable-now set. A call that broke on the
		// way — the tunnel it went through torn down under it while the link
		// falls back — is not the peer saying anything, and what it last said
		// stands until it says otherwise or the link goes down (decision AY).
		// What was remembered stays remembered either way, because a holder
		// that could not be asked has said nothing, and nothing is not the
		// same answer as an empty list (decision N).
		if refused(err) {
			l.setOffered(nil)
		} else {
			l.pathFailed(over, err)
		}

		return
	}

	keys := validKeys(resp.Msg.GetKeys())

	l.setOffered(keys)
	l.node.rememberKeys(l.Fingerprint(), keys)
}

// refused is an error that is the peer's answer — it would not say, or does
// not know how — rather than a call that broke on the way.
func refused(err error) bool {
	switch connect.CodeOf(err) {
	case connect.CodePermissionDenied, connect.CodeUnauthenticated,
		connect.CodeUnimplemented, connect.CodeNotFound,
		connect.CodeFailedPrecondition:
		return true
	default:
		return false
	}
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

	// The tunnel is raised in the background from the start, so that the
	// first presence race has a raise to race against (decision AY).
	l.tunnel.sync(l.Record())

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

	// The link's client to the peer's tunnel goes with it: seal closes the
	// clients before the server (§3).
	l.tunnel.close()
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
		err := l.presence(ctx, l.node.Advertised(), l.node.offer())

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
	unverified := l.unverified
	l.mu.Unlock()

	if preferred != "" && !unverified && misses < presenceMisses {
		return []string{preferred}
	}

	return l.addresses()
}

// presence opens a presence stream and reads it until the peer is lost on
// every path, telling the approver where this instance can be dialled, and
// what it offers of its tunnel, every time a stream opens.
//
// The stream is held on one path at a time, and the path can change under it
// without the link going down (§8, decision AY): **a path change is not a
// presence change.** The link moves make-before-break when a better path
// appears — the new stream is opened and its first beat received before the
// old one is closed — and when the path it is on breaks, the others are tried
// at once, before anything is declared lost. Either way failed() is never
// called, so the offered keys stay listed, no grant activity is pushed, and
// nothing logs a new link. Only when every path has failed does this return,
// and the watch loop take the link down.
func (l *link) presence(
	ctx context.Context, advertised []string, offer *ladulasv1.TunnelOffer,
) error {
	targets := l.presenceTargets(ctx)
	if len(targets) == 0 {
		return errors.New("the peer has no address to dial")
	}

	held, err := l.openWatch(ctx, targets, advertised, offer)
	if err != nil {
		return err
	}

	l.reached(held.via)
	l.tunnel.presence()

	l.node.log.Info("linked to a peer",
		"peer", l.Name(), "path", l.pathWord(held.via), "address", held.via.address)

	// The keys are learned once the link is up, so a keyless box's agent has
	// something to list the moment ssh asks; and where the approver says it
	// can be dialled, which is on every beat (decision AQ). reached ran first
	// so the address this stream is on is what learnAddresses keeps.
	l.beat(ctx, held)

	for {
		for held.stream.Receive() {
			l.reached(held.via)

			// And again on every beat, so a key granted on the holder reaches
			// the requester without either side being restarted — and a
			// rotated tunnel key, the same way (decision AX).
			l.beat(ctx, held)

			// The precedence is re-evaluated on beats (decision AY). A new
			// stream says where this instance is and what it offers as it is
			// now, not as it was when the first stream opened.
			if better := l.better(ctx, held.via); better != nil {
				advertised, offer = l.node.Advertised(), l.node.offer()

				if next := l.switchTo(ctx, held, *better, advertised, offer); next != nil {
					held = next
				}
			}
		}

		err := held.end()

		if ctx.Err() != nil {
			return err
		}

		// The path broke under a link that was up. Before the link is taken
		// down, every other path gets one attempt: a tunnel that dropped falls
		// back to the direct addresses, and a direct path that dropped falls
		// to an established tunnel, and neither is a presence change.
		advertised, offer = l.node.Advertised(), l.node.offer()

		next := l.fallback(ctx, held.via, err, advertised, offer)
		if next == nil {
			return err
		}

		held = next
	}
}

// heldStream is a presence stream and the path it is on.
type heldStream struct {
	stream *connect.ServerStreamForClient[ladulasv1.PresenceEvent]
	via    route
	over   target
	cancel context.CancelFunc
}

// end closes the stream and reports why it ended.
func (h *heldStream) end() error {
	closeErr := h.stream.Close()
	h.cancel()

	if streamErr := h.stream.Err(); streamErr != nil {
		return streamErr
	}

	return closeErr
}

// presenceTargets is the paths to try when the link is down: the addresses in
// presenceOrder's rationed order, with the raise raced against them.
func (l *link) presenceTargets(ctx context.Context) []target {
	return l.node.arrange(ctx, l.tunnel, directTargets(l.client, l.presenceOrder()))
}

// openWatch opens a presence stream on the first target that yields a beat.
//
// Nothing may be claimed until a beat has arrived. connect hands the stream
// back as soon as the request is queued and deliberately keeps the transport
// error for the first Receive — its own comment on CallServerStream says so —
// so a nil error from Watch means the request was written, and nothing more.
// Treating it as a connection is what had a laptop asleep with its lid shut
// logged as "linked to a peer" every twenty seconds, marked online, and sent
// grant activity; and it is why this loop never advanced past its first
// address, since the address that could not be reached never reported that it
// could not be reached. The first beat is free evidence: Watch's handler sends
// one before it waits on its ticker, so a stream that yields nothing is a peer
// that is not there.
func (l *link) openWatch(
	ctx context.Context, targets []target,
	advertised []string, offer *ladulasv1.TunnelOffer,
) (*heldStream, error) {
	var lastErr error

	for _, over := range targets {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		held, err := l.watchOn(ctx, over, advertised, offer, 0)
		if err == nil {
			return held, nil
		}

		if over.via.kind == pathTunnel && errors.Is(err, errTunnelDown) && len(targets) > 1 {
			continue
		}

		lastErr = err
	}

	if lastErr == nil {
		lastErr = errors.New("the peer has no address to dial")
	}

	return nil, lastErr
}

// watchOn opens one presence stream on one target and waits for its first
// beat, for no longer than limit when one is given.
func (l *link) watchOn(
	ctx context.Context, over target,
	advertised []string, offer *ladulasv1.TunnelOffer, limit time.Duration,
) (*heldStream, error) {
	pinned, baseURL, err := over.resolve()
	if err != nil {
		return nil, err
	}

	streamCtx, cancel := context.WithCancel(ctx)

	if limit > 0 {
		timer := time.AfterFunc(limit, cancel)
		defer timer.Stop()
	}

	client := ladulasv1connect.NewPresenceServiceClient(pinned.HTTP(), baseURL)

	stream, err := client.Watch(streamCtx, connect.NewRequest(&ladulasv1.WatchRequest{
		ListenAddresses: advertised,
		// The requester's tunnel offer rides beside its addresses (decision
		// AX), on every stream it opens — which is also how a fallback to the
		// direct path re-offers, so an allowlist entry the far end lost heals
		// itself (§8).
		Tunnel: offer,
	}))
	if err != nil {
		cancel()
		l.pathFailed(over, err)

		return nil, err
	}

	if !stream.Receive() {
		err := noHeartbeat(stream)
		cancel()
		l.pathFailed(over, err)

		return nil, err
	}

	return &heldStream{stream: stream, via: over.via, over: over, cancel: cancel}, nil
}

// pathFailed tells the tunnel that a stream through it failed on the way.
func (l *link) pathFailed(over target, err error) {
	if over.via.kind == pathTunnel && transportFailure(err) {
		over.tunnel.failed(err)
	}
}

// beat is everything a beat on the held stream is evidence of.
func (l *link) beat(ctx context.Context, held *heldStream) {
	msg := held.stream.Msg()

	l.learnKeys(ctx, held.over)
	l.node.learnAddresses(l.Fingerprint(), msg.GetListenAddresses())
	l.node.learnTunnel(l.Fingerprint(), msg.GetTunnel())
	// How the approver's server sees this link's tunnel client, whichever path
	// the stream is on (decision AY).
	l.tunnel.learn(msg.GetTunnelPath())

	// A raise or a tunnel failed since the offer was last said over a direct
	// contact, and this is one: say it again.
	if held.via.kind == pathDirect && l.tunnel.takeReoffer() {
		go l.node.reoffer(l.client, held.via.address)
	}
}

// better is the path the link should move to from the one it is on, by the
// precedence, or nil to stay: a punched tunnel outranks direct TCP, and direct
// TCP outranks a relayed tunnel.
func (l *link) better(ctx context.Context, current route) *target {
	switch current.kind {
	case pathDirect:
		// On the direct path the tunnel is raised in the background — this is
		// the backoff's next chance — and taken once it is up, punched, and
		// has held for the dwell if it failed before.
		l.tunnel.kick()

		if snap := l.tunnel.snapshot(); snap.up && snap.preferred && !snap.relayed {
			return &tunnelTarget(l.tunnel)[0]
		}
	case pathTunnel:
		// A relayed tunnel yields to any direct address that answers.
		if snap := l.tunnel.snapshot(); snap.up && snap.relayed {
			if winner := l.node.probeOf()(ctx, l.addresses()); winner != "" {
				return &directTargets(l.client, []string{winner})[0]
			}
		}
	case pathNone:
	}

	return nil
}

// switchTo moves the held stream to a better path, make-before-break: the
// new stream is opened and its first beat received, the link's path moved,
// and only then is the old stream closed. It returns the new stream, or nil
// having left the old one alone when the better path did not come up.
func (l *link) switchTo(
	ctx context.Context, held *heldStream, better target,
	advertised []string, offer *ladulasv1.TunnelOffer,
) *heldStream {
	next, err := l.watchOn(ctx, better, advertised, offer, probeTimeout+transport.DialTimeout)
	if err != nil {
		l.node.log.Debug("a link stayed on its path",
			"peer", l.Name(), "wanted", l.pathWord(better.via), "error", err.Error())

		return nil
	}

	from := l.pathWord(held.via)

	l.reached(next.via)
	_ = held.end()

	l.node.log.Info("the link to a peer changed path",
		"peer", l.Name(), "from", from, "to", l.pathWord(next.via))
	l.node.observedTunnel("switched")

	l.beat(ctx, next)

	return next
}

// fallback tries the paths the link was not on, once each, after the one it
// was on broke. It returns the new stream, or nil when nothing came up and the
// link is down.
func (l *link) fallback(
	ctx context.Context, broken route, err error,
	advertised []string, offer *ladulasv1.TunnelOffer,
) *heldStream {
	var targets []target

	switch broken.kind {
	case pathTunnel:
		l.tunnel.failed(err)
		targets = directTargets(l.client, l.addresses())
	case pathDirect:
		if snap := l.tunnel.snapshot(); snap.up {
			targets = tunnelTarget(l.tunnel)
		}
	case pathNone:
	}

	if len(targets) == 0 {
		return nil
	}

	next, ferr := l.openWatch(ctx, targets, advertised, offer)
	if ferr != nil {
		return nil
	}

	l.reached(next.via)

	reason := "the stream ended"
	if err != nil {
		reason = err.Error()
	}

	l.node.log.Info("the link to a peer fell back to another path",
		"peer", l.Name(), "from", l.pathWord(broken), "to", l.pathWord(next.via),
		"reason", reason)
	l.node.observedTunnel("fallback")

	l.beat(ctx, next)

	return next
}

// pathWord is a route's path word, with the tunnel's punched-or-relayed.
func (l *link) pathWord(via route) string {
	if via.kind == pathTunnel {
		return l.tunnel.word()
	}

	return via.kind.word()
}

// currentWord is the path word the link is up over now, "" while it is down.
func (l *link) currentWord() string {
	path := l.currentPath()
	if path == pathTunnel {
		return l.tunnel.word()
	}

	return path.word()
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

// approvalClient builds an approval client for one of the link's targets.
func (l *link) approvalClient(over target) (ladulasv1connect.ApprovalServiceClient, error) {
	pinned, baseURL, err := over.resolve()
	if err != nil {
		return nil, err
	}

	return ladulasv1connect.NewApprovalServiceClient(
		pinned.HTTP(), baseURL,
		connect.WithSendMaxBytes(maxRequestBytes)), nil
}
