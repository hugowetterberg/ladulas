package trust

import (
	"net"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// Whether a peer can be dialled, and over what.
//
// Until now one fact answered both questions: a peer whose record carried an
// address was a machine that listens, so it got a link or a dial-back; one
// whose record carried none was a phone, so it got an inbox and was waited for
// (§3). That held because the only way to reach a peer was a TCP connection to
// one of its addresses, so "has an address" and "can be dialled" were the same
// sentence.
//
// They stop being the same sentence the moment there is a second kind of path.
// A peer reachable only through a tunnel has no address worth writing into
// Addresses — the tunnel's endpoint is not something a TCP dialler can use —
// and under the old test it would be taken for a phone, given an inbox, and
// never dialled. So the question is asked in one place, here, and every caller
// that used to look at len(Addresses) asks this instead. A later path kind
// adds its own field to the record and its own clause to dialable; nothing
// that decides between a link and an inbox has to learn about it.
//
// The path a peer is reached over is a word of its own for the same reason.
// The machinery that learns addresses (decision AQ) assumed the path *was* an
// address — the one a dial last reached — and a path that is not an address
// must never be written back into the list as though it were.

// PathDirect is the path word for a pinned TLS connection to one of a peer's
// addresses: a host:port this instance dialled, or the address a peer dialled
// it on. It is the only path there is today, so every peer that is connected
// is connected over it; the word exists so that the surfaces which show a
// path, and the code that keeps the address list, can tell it apart from
// paths that are not addresses.
const PathDirect = "direct"

// IsDirectAddress reports whether an address is something a direct dial can
// use: a host and a port, in the form net.SplitHostPort accepts.
//
// It is a test of shape and not of reachability. What it keeps out of a
// record's address list is anything that is not a TCP endpoint — a tunnel's
// address string among them — because the direct dialler would try to connect
// to whatever is there, and a string with no port in it fails every time,
// costing a turn of the presence loop and a line in the failure report for an
// address that could never have worked.
func IsDirectAddress(address string) bool {
	_, port, err := net.SplitHostPort(address)

	return err == nil && port != ""
}

// DirectAddresses is the subset of a list that IsDirectAddress accepts, in the
// order given. It returns nil rather than an empty slice when nothing is left,
// so that "the peer said nothing usable" reads the same as "the peer said
// nothing" to the callers that treat an empty list as no news (decision AQ).
func DirectAddresses(addresses []string) []string {
	var out []string

	for _, address := range addresses {
		if IsDirectAddress(address) {
			out = append(out, address)
		}
	}

	return out
}

// Dialable reports whether this instance can reach out to a peer at all, which
// is what decides between a link and an inbox for an approver (§3), between a
// push and a wake-up for a key handover, and whether a requester is one an
// approver can dial back.
//
// Today that is "the record carries a direct address".
func Dialable(record *storepb.TrustRecord) bool {
	return dialable(record.GetAddresses())
}

// PendingDialable is Dialable for a pairing that has not completed. It is the
// same question for the same reason: the convergence loop dials a pending peer
// to settle the pairing, and a peer it cannot dial is one that will come to it.
func PendingDialable(pending *storepb.PendingPairing) bool {
	return dialable(pending.GetAddresses())
}

// StatusDialable is Dialable as the control API reports it.
//
// The daemon computes it from the record, so a client never repeats the rule.
// It also accepts an address list as proof, which is what an older daemon
// sends instead of the field; that half stays true whatever paths are added,
// because a direct address is always a way to dial.
func StatusDialable(status *ladulasv1.PeerStatus) bool {
	return status.GetDialable() || dialable(status.GetAddresses())
}

// dialable is the one rule, over the parts of a record it reads. A path kind
// that is not an address joins it as a second argument.
func dialable(addresses []string) bool {
	return len(addresses) > 0
}
