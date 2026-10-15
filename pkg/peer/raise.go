package peer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// Raising a client to a peer's tunnel (§8, decision AY).
//
// Every side that issues RPCs to a peer raises its own client to that peer's
// server address, because "the side that dials" is not one side: a requester's
// link dials each approver, both sides of a mutual pair link each other, and an
// approver dials back to a requester through the dialer for documentation and
// diffs. So a link holds a tunnelPath for as long as it lives — a mutual pair
// has one in each direction, which is expected — and the dialer holds one on
// demand, for peers whose offer names a server, and the reaper closes it when
// nothing has used it for a while.
//
// A raise is always in the background. It builds a tailcat client against the
// server address, runs the same pinned TLS through it against the same
// fingerprint a direct connection pins, and calls Ping; only a pinned Ping
// that succeeds over the tunnel counts as established. A tunnel that comes up
// and reaches somebody else is a failed handshake, not a new peer. No call
// ever waits for one: a call with no established path races the raise against
// the direct probe (route.go), and the raise timeout bounds the background
// attempt only. A sequential "raise, then fall back" would spend decision AJ's
// ssh login budget per holder, turn decision AT's cheap fall-through to the
// next holder into a wait, and push a woken phone past the wake grace.

// Raise timing.
const (
	// tunnelRaiseTimeout bounds one background raise: tailcat's start and its
	// MEOW round trip, which has a ten-second budget of its own, then the
	// pinned handshake and the Ping through it.
	tunnelRaiseTimeout = 20 * time.Second

	// DefaultTunnelDwell is how long a tunnel that failed while in use has to
	// hold, once it has been raised again, before it is preferred again. A
	// few minutes, so that a tunnel flapping on a bad uplink does not drag a
	// link back and forth between paths on every beat; short enough that one
	// transient failure costs a few minutes on the direct path and nothing
	// else.
	DefaultTunnelDwell = 3 * time.Minute

	// DefaultTunnelIdle is how long the dialer keeps a raised client nobody is
	// using. A raised client is a whole network stack — engine, netstack,
	// DERP connection — and the documentation it is for is read in bursts.
	DefaultTunnelIdle = 5 * time.Minute
)

// tunnelPath is one raised client to one peer, and what is known about it.
type tunnelPath struct {
	node        *Node
	fingerprint string
	key         ssh.PublicKey

	mu sync.Mutex
	// address is the server address the client is raised against, "" while
	// the peer offers nothing this instance can raise against.
	address string
	raw     TunnelClient
	client  *transport.Client
	// raising is a raise under way, and finished is closed when it ends,
	// however it ends.
	raising  bool
	finished chan struct{}
	// established is when the pinned Ping last succeeded over this client,
	// zero while it has not.
	established time.Time
	// relayed and relay are the listening side's view of this client, from
	// the last report (TunnelPathReport). Relayed until told otherwise: a
	// fresh tunnel starts on DERP and punches a few seconds later, and a
	// path that has not been reported punched must not outrank direct TCP.
	relayed bool
	relay   string
	// tainted is when the tunnel last failed while in use; until it has been
	// raised again and held for the dwell it is not preferred (hysteresis).
	tainted time.Time
	// fallback is why traffic left the tunnel, while it is held back.
	fallback string
	// backoff and next pace the raises after a failure. The backoff never
	// grows past the presence loop's ceiling, and resets when the peer's
	// presence comes back over any path or the tunnel has held for the
	// dwell, so a desktop unsealed after a long seal is back on its tunnel
	// within a minute.
	backoff time.Duration
	next    time.Time
	lastErr string
	// reoffer says a raise or the tunnel has failed since this instance last
	// told the peer its offer over a direct contact (Node.reoffer).
	reoffer  bool
	lastUsed time.Time
	closed   bool
}

func newTunnelPath(node *Node, record *storepb.TrustRecord, key ssh.PublicKey) *tunnelPath {
	return &tunnelPath{
		node:        node,
		fingerprint: record.GetFingerprint(),
		key:         key,
		relayed:     true,
		lastUsed:    time.Now(),
	}
}

// tunnelSnapshot is a tunnelPath at one moment, for deciding which path wins.
type tunnelSnapshot struct {
	// usable is an offer this instance can raise against.
	usable bool
	// up is an established tunnel; preferred is one that has also passed the
	// dwell after its last failure in use.
	up        bool
	preferred bool
	relayed   bool
	// finished is closed when the raise under way ends; nil when none is.
	finished chan struct{}
}

func (t *tunnelPath) snapshot() tunnelSnapshot {
	if t == nil {
		return tunnelSnapshot{}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	return t.snapshotLocked()
}

func (t *tunnelPath) snapshotLocked() tunnelSnapshot {
	snap := tunnelSnapshot{
		usable:  t.address != "" && !t.closed,
		up:      !t.established.IsZero(),
		relayed: t.relayed,
	}

	if t.raising {
		snap.finished = t.finished
	}

	if snap.up {
		snap.preferred = t.tainted.IsZero() ||
			time.Since(t.established) >= t.node.dwell()

		// Held for the dwell since it came back: the failure is forgiven, and
		// so is the backoff it ran up.
		if snap.preferred && !t.tainted.IsZero() {
			t.tainted = time.Time{}
			t.fallback = ""
			t.backoff = 0
			t.next = time.Time{}
		}
	}

	return snap
}

// sync brings the tunnel into line with what the peer offers now: raised
// against its current server address, or dropped when there is nothing this
// instance can raise against — the upgrade off here, a withdrawal, a version
// that does not meet, an offer that has aged out.
func (t *tunnelPath) sync(record *storepb.TrustRecord) {
	if t == nil {
		return
	}

	wanted := ""
	if t.node.raisable(record) {
		wanted = record.GetTunnel().GetServerAddress()
	}

	t.mu.Lock()

	if t.closed {
		t.mu.Unlock()

		return
	}

	var stale TunnelClient

	if wanted != t.address {
		// A new address is a new server, or a rotated key: what was raised
		// against the old one reaches nothing worth reaching. The backoff
		// goes with it, since it was about an address nobody offers now.
		stale = t.dropLocked()
		t.address = wanted
		t.backoff, t.next, t.tainted, t.fallback, t.lastErr = 0, time.Time{}, time.Time{}, "", ""
	}

	t.mu.Unlock()

	closeRaw(stale)

	t.kick()
}

// kick starts a raise in the background, unless there is nothing to raise
// against, one is established or under way, or the backoff says not yet.
func (t *tunnelPath) kick() {
	if t == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	switch {
	case t.closed, t.address == "", t.raising, !t.established.IsZero(),
		time.Now().Before(t.next):
		return
	}

	t.raising = true
	t.finished = make(chan struct{})

	go t.raise(t.address, t.finished)
}

// raise runs one background attempt against one address.
func (t *tunnelPath) raise(address string, finished chan struct{}) {
	ctx, cancel := context.WithTimeout(t.node.lifetime(), tunnelRaiseTimeout)
	defer cancel()

	raw, client, report, err := t.attempt(ctx, address)

	t.mu.Lock()

	current := t.address == address && !t.closed && t.finished == finished
	if current {
		t.raising = false
	}

	switch {
	case !current:
		// Replaced or closed while it ran: what it raised belongs to nobody.
		t.mu.Unlock()
		close(finished)
		closeRaw(raw)

		return
	case err != nil:
		t.backoff = min(max(t.backoff*2, t.node.floor), t.node.ceiling)
		t.next = time.Now().Add(t.backoff)
		t.lastErr = err.Error()
		t.reoffer = true
		t.mu.Unlock()
		close(finished)
		closeRaw(raw)

		t.node.log.Debug("could not raise a tunnel to a peer",
			"peer", t.fingerprint, "error", err.Error())
		t.node.observedTunnel("raise_failed")

		return
	}

	t.raw, t.client = raw, client
	t.established = time.Now()
	t.lastErr = ""
	t.learnLocked(report)
	t.mu.Unlock()
	close(finished)

	t.node.log.Debug("raised a tunnel to a peer", "peer", t.fingerprint)
	t.node.observedTunnel("raised")
}

// attempt is the raise itself: the region rule again, the client, its MEOW,
// and the pinned Ping through it carrying this instance's offer.
func (t *tunnelPath) attempt(
	ctx context.Context, address string,
) (TunnelClient, *transport.Client, *ladulasv1.TunnelPathReport, error) {
	tunnel := t.node.currentTunnel()
	if tunnel == nil {
		return nil, nil, nil, errors.New("the tunnel is off here")
	}

	// Checked when the offer was written down, and again here: the local DERP
	// map it is held against may have changed since, and this is the moment
	// this instance would connect to whatever the address names.
	if refused := t.node.checkOfferRegion(address); refused != "" {
		return nil, nil, nil, errors.New(refused)
	}

	raw, err := tunnel.Raise(address)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("raise a client: %w", err)
	}

	client, err := transport.NewTunnelClient(transport.ClientOptions{
		Identity: t.node.identity,
		Expect:   t.key,
	}, raw)
	if err != nil {
		return raw, nil, nil, err
	}

	deadline, _ := ctx.Deadline()

	if err := raw.Ping(deadline.UnixNano()); err != nil {
		return raw, nil, nil, fmt.Errorf("the tunnel server did not answer: %w", err)
	}

	resp, err := ladulasv1connect.NewPresenceServiceClient(
		client.HTTP(), client.URL(transport.TunnelHost),
	).Ping(ctx, connect.NewRequest(&ladulasv1.PingRequest{
		SentAt: timestamppb.Now(),
		Tunnel: t.node.offer(),
	}))
	if err != nil {
		client.CloseIdle()

		return raw, nil, nil, fmt.Errorf("the pinned Ping through the tunnel failed: %w", err)
	}

	return raw, client, resp.Msg.GetTunnelPath(), nil
}

// refresh asks the far end again how it sees this client, with a Ping
// through the established tunnel, and takes its word (learn). It is how a
// dialer, which has no stream to be told on, hears that its tunnel has punched
// since the raise — or has fallen back to a relay. The Ping carries this
// instance's offer, as every direct contact does.
func (t *tunnelPath) refresh(ctx context.Context) error {
	client := t.establishedClient()
	if client == nil {
		return &transport.TunnelError{Err: errTunnelDown}
	}

	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	resp, err := ladulasv1connect.NewPresenceServiceClient(
		client.HTTP(), client.URL(transport.TunnelHost),
	).Ping(ctx, connect.NewRequest(&ladulasv1.PingRequest{
		SentAt: timestamppb.Now(),
		Tunnel: t.node.offer(),
	}))
	if err != nil {
		return &transport.TunnelError{Err: err}
	}

	t.learn(resp.Msg.GetTunnelPath())

	return nil
}

// established is the pinned client through the tunnel, or nil while there is
// no established tunnel. Asking counts as using it, for the reaper.
func (t *tunnelPath) establishedClient() *transport.Client {
	if t == nil {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.established.IsZero() {
		return nil
	}

	t.lastUsed = time.Now()

	return t.client
}

// failed is the tunnel failing while in use: a call or a stream through it
// ended in a transport failure. It is torn down, held back from being
// preferred until it has been raised again and held (hysteresis), and the
// next raise waits out the backoff.
func (t *tunnelPath) failed(err error) {
	if t == nil {
		return
	}

	t.mu.Lock()

	if t.established.IsZero() {
		t.mu.Unlock()

		return
	}

	stale := t.dropLocked()
	t.tainted = time.Now()
	t.fallback = tunnelReason(err)
	t.backoff = min(max(t.backoff*2, t.node.floor), t.node.ceiling)
	t.next = time.Now().Add(t.backoff)
	t.reoffer = true
	t.mu.Unlock()

	closeRaw(stale)

	t.node.log.Info("a tunnel to a peer failed while in use",
		"peer", t.fingerprint, "reason", tunnelReason(err))
	t.node.observedTunnel("failed")
}

// tunnelReason is a failure in the few words "fallback to direct, because …"
// has room for.
func tunnelReason(err error) string {
	if err == nil {
		return "the tunnel stopped"
	}

	reason := err.Error()
	if i := strings.LastIndex(reason, ": "); i >= 0 && i+2 < len(reason) {
		reason = reason[i+2:]
	}

	return reason
}

// learn takes the listening side's word for how it sees this client.
func (t *tunnelPath) learn(report *ladulasv1.TunnelPathReport) {
	if t == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.learnLocked(report)
}

func (t *tunnelPath) learnLocked(report *ladulasv1.TunnelPathReport) {
	if !report.GetConnected() {
		// A report from a server that does not see this client says nothing
		// about the path: the beat may be on the direct path while the tunnel
		// is still coming up, or from a build without the field.
		return
	}

	t.relayed = report.GetRelayed()
	t.relay = report.GetRelay()
}

// presence is the peer's presence coming back over any path, which resets the
// backoff: a peer that is plainly there is worth raising to again at once.
func (t *tunnelPath) presence() {
	if t == nil {
		return
	}

	t.mu.Lock()
	t.backoff, t.next = 0, time.Time{}
	t.mu.Unlock()

	t.kick()
}

// takeReoffer reports, once, that the offer should be told over the next
// direct contact.
func (t *tunnelPath) takeReoffer() bool {
	if t == nil {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	want := t.reoffer
	t.reoffer = false

	return want
}

// word is the tunnel's path word: punched, or relayed through a region.
func (t *tunnelPath) word() string {
	if t == nil {
		return trust.PathTunnelDirect
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	return trust.TunnelPath(t.relayed, t.relay)
}

// facts fills in the raise's half of what DescribeTunnel is told.
func (t *tunnelPath) facts(facts *trust.TunnelFacts) {
	if t == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.established.IsZero() && time.Now().Before(t.next) {
		facts.BackoffUntil = t.next.Unix()
	}

	if !t.tainted.IsZero() {
		facts.Fallback = t.fallback
	}
}

// reapIfIdle closes the client when nothing has used it for d and nothing is
// raising it, and reports whether it did. The test and the drop are one hold
// of the lock: done as two, a dial-back that took the client between them —
// and so refreshed lastUsed — had it closed under its request. The path is
// left able to raise again, which the next call that wants it does.
func (t *tunnelPath) reapIfIdle(d time.Duration) bool {
	t.mu.Lock()

	if t.raising || t.established.IsZero() || time.Since(t.lastUsed) <= d {
		t.mu.Unlock()

		return false
	}

	stale := t.dropLocked()
	t.mu.Unlock()

	closeRaw(stale)

	return true
}

// reset drops the client and forgets the address it was raised against,
// without raising again: the tunnel this instance raises with has changed or
// gone (Node.SetTunnel), so what was raised belongs to the old one. The next
// sync — a dialer's next call — finds the address unset and starts over from
// the record, with no backoff left over from a tunnel that is not there.
func (t *tunnelPath) reset() {
	if t == nil {
		return
	}

	t.mu.Lock()
	stale := t.dropLocked()
	t.address = ""
	t.backoff, t.next, t.tainted, t.fallback, t.lastErr = 0, time.Time{}, time.Time{}, "", ""
	t.mu.Unlock()

	closeRaw(stale)
}

// close closes the client for good.
func (t *tunnelPath) close() {
	if t == nil {
		return
	}

	t.mu.Lock()
	stale := t.dropLocked()
	t.closed = true
	t.mu.Unlock()

	closeRaw(stale)
}

// dropLocked forgets the raised client and hands it back to be closed outside
// the lock, since closing a tailcat client takes its whole stack down.
func (t *tunnelPath) dropLocked() TunnelClient {
	stale := t.raw

	if t.client != nil {
		t.client.CloseIdle()
	}

	t.raw, t.client = nil, nil
	t.established = time.Time{}
	t.relayed, t.relay = true, ""

	if t.raising {
		// The raise under way will find it is no longer current and close
		// what it made.
		t.raising = false
		t.finished = nil
	}

	return stale
}

func closeRaw(raw TunnelClient) {
	if raw == nil {
		return
	}

	go func() {
		_ = raw.Close()
	}()
}

// raisable reports whether this instance would raise a client against a
// peer's offer now: it has a tunnel, the offer names a server in a version
// that meets, and the offer has not aged out.
func (n *Node) raisable(record *storepb.TrustRecord) bool {
	return trust.TunnelRaisable(record.GetTunnel(), n.tunnelVersion()) &&
		!n.tunnelStaleFor(record)
}

// dialable is trust.Dialable with this instance's tunnel version.
func (n *Node) dialable(record *storepb.TrustRecord) bool {
	return trust.Dialable(record, n.tunnelVersion())
}

// currentTunnel is the node's tunnel, nil when there is none.
func (n *Node) currentTunnel() Tunnel {
	n.tunnelMu.Lock()
	defer n.tunnelMu.Unlock()

	if n.tunnelClosed {
		return nil
	}

	return n.tunnel
}

// dwell is the hysteresis dwell, defaulted.
func (n *Node) dwell() time.Duration {
	if n.tunnelDwell <= 0 {
		return DefaultTunnelDwell
	}

	return n.tunnelDwell
}

// clientReport is how this instance's tunnel server sees a peer's client, for
// the beats and the Ping that carry it to the peer (decision AY).
func (n *Node) clientReport(record *storepb.TrustRecord) *ladulasv1.TunnelPathReport {
	key := admissible(record.GetTunnel())
	if key == nil {
		return nil
	}

	n.tunnelMu.Lock()
	tunnel := n.tunnel
	running := n.tunnelAddress != ""
	n.tunnelMu.Unlock()

	if tunnel == nil || !running {
		return nil
	}

	return parseClientPath(tunnel.ClientPath(key))
}

// parseClientPath is Tunnel.ClientPath's answer as the report carries it.
func parseClientPath(path string) *ladulasv1.TunnelPathReport {
	switch path {
	case "":
		return nil
	case ClientPathDirect:
		return &ladulasv1.TunnelPathReport{Connected: true}
	default:
		region, _ := strings.CutPrefix(path, ClientPathRelayed)

		return &ladulasv1.TunnelPathReport{
			Connected: true,
			Relayed:   true,
			Relay:     strings.TrimSpace(region),
		}
	}
}

// reapTunnels closes the dialer's raised clients that nothing has used for a
// while. CloseIdle cannot do it — it drops pooled connections, and a raised
// client is a whole network stack under them — so it is a reaper of its own.
func (n *Node) reapTunnels(ctx context.Context) {
	idle := n.tunnelIdle
	if idle <= 0 {
		idle = DefaultTunnelIdle
	}

	ticker := time.NewTicker(max(idle/4, 10*time.Millisecond))
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		n.reapOnce(idle)
	}
}

// reapOnce is one round of the reaper.
func (n *Node) reapOnce(idle time.Duration) {
	n.dialMu.Lock()
	held := make([]*dialer, 0, len(n.dialers))

	for _, d := range n.dialers {
		held = append(held, d)
	}
	n.dialMu.Unlock()

	for _, d := range held {
		if tunnel := d.tunnelPath(); tunnel != nil && tunnel.reapIfIdle(idle) {
			n.log.Debug("closed an idle tunnel", "peer", tunnel.fingerprint)
		}
	}
}

// reoffer says this instance's offer to a peer over a direct address, with a
// Ping (§8, decision AY). It runs after a raise or the tunnel has failed and
// a direct contact has worked: the far end may have lost the allowlist entry
// that let this instance's client in, and an offer is how it gets it back.
// A link's fallback onto the direct path does this by opening its stream,
// which carries the offer; this is for the contacts that carry none.
func (n *Node) reoffer(client *transport.Client, address string) {
	offer := n.offer()
	if offer == nil {
		return
	}

	ctx, cancel := context.WithTimeout(n.lifetime(), transport.DialTimeout)
	defer cancel()

	_, err := ladulasv1connect.NewPresenceServiceClient(
		client.HTTP(), client.URL(address),
	).Ping(ctx, connect.NewRequest(&ladulasv1.PingRequest{
		SentAt: timestamppb.Now(),
		Tunnel: offer,
	}))
	if err != nil {
		n.log.Debug("could not re-offer the tunnel to a peer", "error", err.Error())

		return
	}

	n.observedTunnel("reoffered")
}
