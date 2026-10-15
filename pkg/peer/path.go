package peer

import "github.com/hugowetterberg/ladulas/pkg/trust"

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
// Direct is the only kind that can be taken today; the kind exists so that the
// rule is in the code before the second kind is, rather than discovered in
// three places when it arrives.

// pathKind is which kind of path a call reached a peer over.
type pathKind int

const (
	// pathNone is no contact.
	pathNone pathKind = iota
	// pathDirect is a pinned TLS connection to one of the peer's addresses.
	pathDirect
	// pathIndirect stands for every path that is not an address: whatever
	// reaches the peer, the address list neither produced it nor learns from
	// it. Nothing takes one yet; it is what the rules below are tested with.
	pathIndirect
)

// word is the path's name on the control API and the surfaces
// (ladulasv1.PeerStatus.path), and "" for no contact.
func (k pathKind) word() string {
	switch k {
	case pathDirect:
		return trust.PathDirect
	case pathIndirect:
		return "indirect"
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
