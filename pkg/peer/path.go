package peer

import (
	"errors"

	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// A path is not an address.
//
// Everything that keeps track of where a peer is assumed, until now, that the
// way a call reached a peer and the address it dialled were one fact. A link's
// and a dialer's `preferred` is the address that last worked; decision AQ
// keeps that address in the trust record even when the peer stops advertising
// it (learnAddresses, lastReached); and the joining side of a pairing writes
// the address it dialled first. All three are right for a direct dial, and all
// three go wrong for a path that is not one: nothing on such a path updates
// `preferred`, so the last direct address before the switch would be carried
// for good and re-added on every beat, defeating decision AH's pruning; and
// writing the path's own endpoint into the record would hand the direct
// dialler a string it cannot connect to.
//
// So a call reports the route it took — which kind of path, and for a direct
// one the address — and only a direct route touches the address machinery.
// The kind was in the code before the second kind was, so that the rule did
// not have to be discovered in three places when it arrived; the second is the
// tunnel (decision AY).

// pathKind is which kind of path a call reached a peer over.
type pathKind int

const (
	// pathNone is no contact.
	pathNone pathKind = iota
	// pathDirect is a pinned TLS connection to one of the peer's addresses.
	pathDirect
	// pathTunnel is the same pinned TLS through the peer's tunnel server
	// (decision AY). It is not an address: the address list neither produced
	// it nor learns from it.
	pathTunnel
)

// word is the path's name on the control API and the surfaces
// (ladulasv1.PeerStatus.path), and "" for no contact. A tunnel's word says
// whether it is punched or relayed, which the kind does not know; whoever
// holds the tunnel says that (tunnelPath.word), and this is the punched one.
func (k pathKind) word() string {
	switch k {
	case pathDirect:
		return trust.PathDirect
	case pathTunnel:
		return trust.PathTunnelDirect
	case pathNone:
	}

	return ""
}

// route is how one call reached a peer.
type route struct {
	kind pathKind
	// address is the host:port a direct route dialled. It is empty for any
	// other kind, which is what keeps such a route out of the address list.
	address string
}

// direct is the route of a direct dial to an address.
func direct(address string) route {
	return route{kind: pathDirect, address: address}
}

// tunnelRoute is the route of a call through the tunnel.
var tunnelRoute = route{kind: pathTunnel}

// target is one way to try a peer: the pinned client that takes it, and the
// route a success reports. A direct target is one address; a tunnel target is
// the peer's raised tunnel, resolved when it is tried rather than when the list
// is made, because a raise still under way when a call starts may have come up
// by the time the call has worked through the addresses before it.
type target struct {
	client *transport.Client
	via    route
	tunnel *tunnelPath
}

// directTargets is a list of addresses as targets for one client.
func directTargets(client *transport.Client, addresses []string) []target {
	out := make([]target, 0, len(addresses))

	for _, address := range addresses {
		out = append(out, target{client: client, via: direct(address)})
	}

	return out
}

// tunnelTarget is the tunnel as a target, when there is a tunnel to try.
func tunnelTarget(tunnel *tunnelPath) []target {
	if tunnel == nil {
		return nil
	}

	return []target{{via: tunnelRoute, tunnel: tunnel}}
}

// resolve is the client and base URL to call the target with, or an error for
// a tunnel that is not up now.
func (t target) resolve() (*transport.Client, string, error) {
	if t.via.kind != pathTunnel {
		return t.client, t.client.URL(t.via.address), nil
	}

	client := t.tunnel.establishedClient()
	if client == nil {
		return nil, "", &transport.TunnelError{Err: errTunnelDown}
	}

	return client, client.URL(transport.TunnelHost), nil
}

// String names the target in a failure report: the address, or the tunnel.
func (t target) String() string {
	if t.via.kind == pathTunnel {
		return "the tunnel"
	}

	return t.via.address
}

// errTunnelDown is a tunnel target tried while no raise has established one.
var errTunnelDown = errors.New("the tunnel is not up")
