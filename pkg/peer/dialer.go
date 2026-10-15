package peer

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// Keeping a connection to a peer this instance has no link to.
//
// A link already carries the two things a repeated caller wants: a client whose
// connections stay pooled, and the address that last worked. It gets them
// because a requester holds a link to each of its approvers, which is the
// direction approvals travel.
//
// **Nothing held either of them for the other direction**, and that is the
// direction documentation travels. An approver reading its requester's
// documentation went through `call` with no link, which built a client, made
// one request on it, and called CloseIdle on the way out — so every listing,
// every page and every sync manifest paid a TCP connect and a TLS 1.3
// handshake, and the HTTP/2 connection that could have carried all of them was
// thrown away between each one. On a phone across a tailnet that is the
// difference between a screen that draws and one that waits.
//
// So the same two things are kept here for peers there is no link to: one
// client per peer, reused, and the address it last reached them on.
//
// The address is remembered in memory rather than written to the trust record.
// It is a fact about this moment on this network — the tailnet is up, this
// interface is the one that works — and a machine that moves between a desk and
// a train would be carrying yesterday's answer into today's network. Losing it
// on restart costs one race.

// dialer is a warm client for one peer.
type dialer struct {
	mu     sync.Mutex
	client *transport.Client
	// key is the peer key the client is pinned to, so that a peer which paired
	// again is not talked to over a client expecting the key it replaced.
	key string
	// preferred is the direct address that last worked, and is what makes the
	// ordinary call skip the race entirely. Only a direct route sets it
	// (path.go).
	preferred string
	// onTunnel says the last call that worked went through the tunnel, and
	// checked is when the path was last decided by a race rather than taken
	// from that: a relayed tunnel yields to a direct address that answers, and
	// asking the probe on every page of a document would cost two seconds a
	// page whenever none does, so it is asked once a heartbeat (decision AY).
	onTunnel bool
	checked  time.Time
	// tunnel is the client raised on demand to a peer whose offer names a
	// server (decision AY), nil until one is wanted. The reaper closes it when
	// nothing has used it for a while (reapTunnels).
	tunnel *tunnelPath
}

// dialerFor returns the warm client for a peer, building one if there is none
// or if the peer's key has changed since the last was made.
func (n *Node) dialerFor(record *storepb.TrustRecord) (*dialer, error) {
	key, err := trust.PublicKey(record)
	if err != nil {
		return nil, err
	}

	marshalled := string(key.Marshal())
	fingerprint := record.GetFingerprint()

	n.dialMu.Lock()
	defer n.dialMu.Unlock()

	if n.dialers == nil {
		n.dialers = map[string]*dialer{}
	}

	existing, ok := n.dialers[fingerprint]
	if ok && existing.key == marshalled {
		return existing, nil
	}

	client, err := n.newDirectClient(transport.ClientOptions{
		Identity: n.identity,
		Expect:   key,
	})
	if err != nil {
		return nil, err
	}

	// A peer that paired again has a client pinned to the key it replaced, and
	// the connections under it are to a machine that will not authenticate.
	if ok {
		existing.close()
	}

	made := &dialer{client: client, key: marshalled}
	n.dialers[fingerprint] = made

	return made, nil
}

// tunnelFor is the dialer's raised tunnel to a peer, created the first time a
// call wants one and brought into line with the peer's offer on every call;
// nil for a peer that offers nothing this instance can raise against.
func (d *dialer) tunnelFor(n *Node, record *storepb.TrustRecord) *tunnelPath {
	d.mu.Lock()
	tunnel := d.tunnel

	if tunnel == nil && n.raisable(record) {
		key, err := trust.PublicKey(record)
		if err == nil {
			tunnel = newTunnelPath(n, record, key)
			d.tunnel = tunnel
		}
	}
	d.mu.Unlock()

	tunnel.sync(record)

	if !tunnel.snapshot().usable {
		return nil
	}

	return tunnel
}

// tunnelPath is the dialer's tunnel, nil when it has none.
func (d *dialer) tunnelPath() *tunnelPath {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.tunnel
}

// targets orders a call's paths: the one the last call took when there is
// one, by the precedence (onPath), and otherwise the race (Node.arrange).
func (d *dialer) targets(
	ctx context.Context, n *Node, tunnel *tunnelPath, addresses []string,
) []target {
	d.mu.Lock()
	preferred := d.preferred
	onTunnel := d.onTunnel
	recent := time.Since(d.checked) < n.heartbeat
	d.mu.Unlock()

	direct := directTargets(d.client, addresses)

	switch {
	case onTunnel && tunnel.snapshot().up && recent:
		return onPath(pathTunnel, tunnel, direct)
	case onTunnel && tunnel.snapshot().up:
		// The dialer has no stream for the far end to say how it sees this
		// client, so the raise's Ping was the only report it had — and that
		// Ping runs before hole-punching, so it nearly always says relayed.
		// Once a heartbeat it asks again through the tunnel, which costs one
		// round trip where the probe it would otherwise re-race costs up to
		// probeTimeout. A punched tunnel then keeps the call ahead of direct
		// TCP, as the precedence says; a relayed one, or one that did not
		// answer, goes to the race (decision AY).
		d.mu.Lock()
		d.checked = time.Now()
		d.mu.Unlock()

		if tunnel.refresh(ctx) == nil && !tunnel.snapshot().relayed {
			return onPath(pathTunnel, tunnel, direct)
		}
	case preferred != "" && slices.Contains(addresses, preferred):
		return onPath(pathDirect, tunnel, promote(direct, preferred))
	}

	d.mu.Lock()
	d.checked = time.Now()
	d.mu.Unlock()

	return n.arrange(ctx, tunnel, direct)
}

// order is the addresses to try, best first.
//
// A remembered address goes first and nothing is raced, which is the ordinary
// call: one connection, already open, to the address that worked last time.
// Without one the addresses are raced, because there is nothing better to go on
// than which of them answers — and that race is what a blackholed address costs
// instead of a dial timeout each.
func (d *dialer) order(
	race func([]string) []string, addresses []string,
) []string {
	d.mu.Lock()
	preferred := d.preferred
	d.mu.Unlock()

	if preferred == "" {
		return race(addresses)
	}

	out := make([]string, 0, len(addresses))
	found := false

	for _, address := range addresses {
		if address == preferred {
			found = true

			continue
		}

		out = append(out, address)
	}

	if !found {
		// The peer stopped advertising it, which happens when a machine's
		// addresses are pruned (decision AH). Nothing to prefer.
		return race(addresses)
	}

	return append([]string{preferred}, out...)
}

// remember records the address a direct call reached the peer on.
func (d *dialer) remember(address string) {
	d.rememberRoute(direct(address))
}

// rememberRoute records the route a call reached the peer on.
//
// Only a direct route has an address to remember. Any other route drops the
// one there was, for the reason a link marks its own unverified: it was
// confirmed before the peer was reached some other way, and a later direct
// call should race the whole list rather than trust it first. A dialer has no
// presence loop to spend rounds on a stale address, so forgetting is the whole
// of "unverified" here.
func (d *dialer) rememberRoute(via route) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.onTunnel = via.kind == pathTunnel

	if via.kind != pathDirect {
		d.preferred = ""

		return
	}

	d.preferred = via.address
}

// remembered is the direct address the last call reached the peer on.
func (d *dialer) remembered() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.preferred
}

// forget drops the remembered address, so that the next call races again.
//
// A call that failed on every address says the network moved rather than that
// the peer is gone: the same addresses may work from the next one, and the one
// that worked here is the least likely to be right there.
func (d *dialer) forget() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.preferred = ""
	d.onTunnel = false
}

func (d *dialer) close() {
	d.mu.Lock()
	tunnel := d.tunnel
	d.tunnel = nil

	if d.client != nil {
		d.client.CloseIdle()
	}
	d.mu.Unlock()

	tunnel.close()
}

// closeIdle drops the dialer's pooled connections, direct and through the
// tunnel, and keeps the tunnel itself: a raised client is a network stack, not
// a pooled connection, and the reaper is what closes one (reapTunnels).
func (d *dialer) closeIdle() {
	d.mu.Lock()
	tunnel := d.tunnel

	if d.client != nil {
		d.client.CloseIdle()
	}
	d.mu.Unlock()

	if client := tunnel.establishedClient(); client != nil {
		client.CloseIdle()
	}
}

// closeDialers hangs up every warm connection, which is what stopping does.
func (n *Node) closeDialers() {
	n.dialMu.Lock()
	held := n.dialers
	n.dialers = nil
	n.dialMu.Unlock()

	for _, held := range held {
		held.close()
	}
}

// CloseIdle drops every pooled connection to every peer and keeps everything
// else: the clients, the remembered addresses, the links.
//
// It is for the moment a host knows its network has changed under it and the
// pool does not. A phone coming back to the foreground is the case it was
// written for: the connection that carried an approval a few minutes ago is
// still in the pool, iOS has since suspended the process and the tailnet has
// moved on, and the first request written to it fails on the read — and HTTP/2
// multiplexes, so the listing, the poll and the sync manifest all fail on it
// together, every time the app comes back. Waiting for IdleConnTimeout would
// have caught the long absences and missed exactly the short ones a person
// notices.
//
// The remembered address is deliberately kept: the network may have moved, but
// the address that worked is still the best first guess, and losing it would
// cost a race on every return. What is dropped is only the claim that the old
// connection to it is still alive, which is the one claim known to be doubtful.
func (n *Node) CloseIdle() {
	n.dialMu.Lock()
	dialers := make([]*dialer, 0, len(n.dialers))

	for _, held := range n.dialers {
		dialers = append(dialers, held)
	}

	n.dialMu.Unlock()

	for _, held := range dialers {
		held.closeIdle()
	}

	n.mu.Lock()
	links := make([]*link, 0, len(n.links))

	for _, existing := range n.links {
		links = append(links, existing)
	}

	n.mu.Unlock()

	// A link's presence stream is a live request, not an idle connection, so
	// this leaves a stream that is still up alone and only drops the pooled
	// connection beside it. A stream that died with the network is found by
	// the watch loop's own read failing, which is what its backoff is for.
	for _, existing := range links {
		existing.client.CloseIdle()

		if client := existing.tunnel.establishedClient(); client != nil {
			client.CloseIdle()
		}
	}
}
