package peer

import (
	"sync"

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
	// preferred is the address that last worked, and is what makes the ordinary
	// call skip the race entirely.
	preferred string
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

	client, err := transport.NewClient(transport.ClientOptions{
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

// remember records the address a call reached the peer on.
func (d *dialer) remember(address string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.preferred = address
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
}

func (d *dialer) close() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.client != nil {
		d.client.CloseIdle()
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
		held.close()
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
	}
}
