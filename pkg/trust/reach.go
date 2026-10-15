package trust

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

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
// That is "the record carries a direct address", and — once this build can
// raise a client over the tunnel — "or a usable tunnel server address"
// (decision AX). A peer reachable only through its tunnel is then a machine
// that listens, not a phone: it gets a link or a dial-back, never an inbox it
// would have no reason to collect from.
//
// Usable is a property of the offer and not of this instance or the moment:
// it has versions and a server address. Whether this build has a tunnel to
// raise with, whether the versions meet, and whether the offer has gone stale
// are reasons a raise does not happen (DescribeTunnel), and none of them turns
// a desktop into a phone. Deciding link-or-inbox on them would move a peer
// between the two every time a beat aged out an offer.
func Dialable(record *storepb.TrustRecord) bool {
	return dialable(record.GetAddresses(), record.GetTunnel())
}

// PendingDialable is Dialable for a pairing that has not completed. It is the
// same question for the same reason: the convergence loop dials a pending peer
// to settle the pairing, and a peer it cannot dial is one that will come to it.
func PendingDialable(pending *storepb.PendingPairing) bool {
	return dialable(pending.GetAddresses(), pending.GetTunnel())
}

// StatusDialable is Dialable as the control API reports it.
//
// The daemon computes it from the record, so a client never repeats the rule.
// It also accepts an address list as proof, which is what an older daemon
// sends instead of the field; that half stays true whatever paths are added,
// because a direct address is always a way to dial.
func StatusDialable(status *ladulasv1.PeerStatus) bool {
	return status.GetDialable() || dialable(status.GetAddresses(), nil)
}

// dialable is the one rule, over the parts of a record it reads: a direct
// address, or — when tunnelDialling is on — a tunnel offer that names a server.
func dialable(addresses []string, tunnel *ladulasv1.TunnelOffer) bool {
	return len(addresses) > 0 || (tunnelDialling && TunnelServes(tunnel))
}

// tunnelDialling is whether a link can reach a peer over its tunnel, and so
// whether a tunnel offer counts towards Dialable. It is off until the step that
// raises clients and dials through them lands (decision AX).
//
// The clause was first switched on with the offer itself, and that was a bug
// with a victim: an approver running with no peer listener is a collector, and
// one that turned the upgrade on still started its server and offered its
// address, so its requesters' Reconcile moved it from an inbox to a link —
// a link that could never connect, because links take the direct path only.
// From that beat on, that approver was asked nothing at all. A path counts
// towards Dialable when something can take it, not when it is announced.
const tunnelDialling = false

// TunnelServes reports whether an offer is one a client could be raised
// against at all: it has versions, so it is not a withdrawal, and it names a
// server, so it is not a phone's. Whether the versions meet this instance's is
// a separate question (DescribeTunnel), because it is not about the peer.
func TunnelServes(offer *ladulasv1.TunnelOffer) bool {
	return len(offer.GetVersions()) > 0 && offer.GetServerAddress() != ""
}

// The tunnel's words, defined once (decision AX). §7 makes DescribeState the
// single source of what the surfaces say about a peer, and the tunnel's half
// of that is these: every surface that shows a peer's tunnel shows one of
// them, so a pill, `ladulas status` and the desktop cannot drift apart.
const (
	TunnelOffHere    = "tunnel off here"
	TunnelNoOffer    = "peer offers no tunnel"
	TunnelWithdrawn  = "peer withdrew its tunnel"
	TunnelStale      = "tunnel offer stale"
	TunnelOffered    = "tunnel offered"
	TunnelClientOnly = "peer offers a client key only"
)

// DescribeTunnel says what this instance knows about a tunnel to a peer.
//
// ours is the tunnel wire version this instance speaks, zero when it has no
// tunnel to raise. It is an int32 rather than the offer's uint32 because
// gomobile binds signed integers only (§21) — a build without tailcat, or the upgrade switched off.
// stale is whether the offer has aged out (no beat has re-confirmed it for the
// configured period, or a direct contact carrying no offer contradicted it).
//
// It describes what is known, not a path in use: "tunnel offered" is a peer
// this instance could raise a client to, which is all this step can say.
func DescribeTunnel(record *storepb.TrustRecord, ours int32, stale bool) string {
	offer := record.GetTunnel()

	switch {
	case ours <= 0:
		return TunnelOffHere
	case offer == nil:
		return TunnelNoOffer
	case len(offer.GetVersions()) == 0:
		return TunnelWithdrawn
	case !slices.Contains(offer.GetVersions(), uint32(ours)):
		return fmt.Sprintf("version mismatch (ours %d, theirs %s)",
			ours, versionList(offer.GetVersions()))
	case offer.GetServerAddress() == "":
		return TunnelClientOnly
	case stale:
		return TunnelStale
	default:
		return TunnelOffered
	}
}

func versionList(versions []uint32) string {
	words := make([]string, 0, len(versions))
	for _, version := range versions {
		words = append(words, strconv.FormatUint(uint64(version), 10))
	}

	return strings.Join(words, ", ")
}
