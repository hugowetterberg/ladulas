package trust

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

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
// it on. The word exists so that the surfaces which show a path, and the code
// that keeps the address list, can tell it apart from paths that are not
// addresses — the tunnel's (PathTunnelDirect, PathTunnelRelayed).
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
// That is "the record carries a direct address", or "the peer offers a tunnel
// server this instance can raise a client to" (decisions AX and AY). A peer
// reachable only through its tunnel is then a machine that listens, not a
// phone: it gets a link or a dial-back, never an inbox it would have no reason
// to collect from.
//
// ours is the tunnel wire version this instance speaks, zero when it has no
// tunnel — a build without tailcat, or the upgrade off here — and the tunnel
// counts only when the offer names that version. That is a fact about this
// instance as well as the offer, and it has to be: a link to a tunnel-only peer
// that this instance cannot raise a client to is a link that never connects,
// which is the exact bug decision AX switched the clause off for — a collector
// moved off its inbox onto a link, and asked nothing from that beat on.
// Whether the offer has gone stale is deliberately left out: staleness comes
// and goes with beats, and deciding link-or-inbox on it would move a peer
// between the two every time an offer aged out. The version and the switch
// change only when an offer or a setting does, and both of those reconcile.
func Dialable(record *storepb.TrustRecord, ours int32) bool {
	return len(record.GetAddresses()) > 0 || TunnelRaisable(record.GetTunnel(), ours)
}

// PendingDialable is Dialable for a pairing that has not completed: the
// convergence loop dials a pending peer to settle the pairing, and a peer it
// cannot dial is one that will come to it.
//
// It is the same rule as Dialable: a direct address, or a tunnel offer this
// instance can raise a client against. The offer counts since the pairing
// server (decision AZ), which is how a pairing is born with no direct path
// between its two sides at all — a café laptop and a desktop at home — and
// then the long-lived tunnels the exchange carried are the only way either
// side can reach the other to settle. Until then this counted direct
// addresses only, because nothing could produce a pending pairing that was
// dialable any other way, and counting a tunnel the settle path did not take
// would have made a pending peer neither dialled nor waited for.
func PendingDialable(pending *storepb.PendingPairing, ours int32) bool {
	return len(pending.GetAddresses()) > 0 || TunnelRaisable(pending.GetTunnel(), ours)
}

// StatusDialable is Dialable as the control API reports it.
//
// The daemon computes it from the record, so a client never repeats the rule.
// It also accepts an address list as proof, which is what an older daemon
// sends instead of the field; that half stays true whatever paths are added,
// because a direct address is always a way to dial.
func StatusDialable(status *ladulasv1.PeerStatus) bool {
	return status.GetDialable() || len(status.GetAddresses()) > 0
}

// Until 2026-10-14 the tunnel clause above sat behind a constant,
// tunnelDialling, that was false: the offer was exchanged a step before links
// could dial over it (decision AX), and counting an offer that nothing could
// take moved collectors off their inboxes onto links that never connected. It
// was switched on with the raise (decision AY), and with this instance's own
// version made part of the rule, so that the same failure cannot come back
// through an instance that has the upgrade off.

// TunnelServes reports whether an offer is one a client could be raised
// against at all: it has versions, so it is not a withdrawal, and it names a
// server, so it is not a phone's. Whether the versions meet this instance's is
// a separate question (TunnelRaisable), because it is not about the peer.
func TunnelServes(offer *ladulasv1.TunnelOffer) bool {
	return len(offer.GetVersions()) > 0 && offer.GetServerAddress() != ""
}

// TunnelRaisable reports whether this instance, speaking tunnel version ours
// (zero for none), could raise a client against an offer.
func TunnelRaisable(offer *ladulasv1.TunnelOffer, ours int32) bool {
	return ours > 0 && TunnelServes(offer) &&
		slices.Contains(offer.GetVersions(), uint32(ours))
}

// The path words for the tunnel (decision AY). PathDirect is a pinned TLS
// connection to an address; these are the same TLS through the tunnel, over a
// punched UDP path or through a DERP relay. Which of the three a peer is on is
// what the pill names after "connected" (DescribeState).
const (
	PathTunnelDirect  = "tunnel direct"
	PathTunnelRelayed = "tunnel relayed"
)

// TunnelPath is the path word for a tunnel: punched, or relayed through a
// region when the region is known.
func TunnelPath(relayed bool, region string) string {
	switch {
	case !relayed:
		return PathTunnelDirect
	case region != "":
		return PathTunnelRelayed + " " + region
	default:
		return PathTunnelRelayed
	}
}

// IsTunnelPath reports whether a path word is one of the tunnel's.
func IsTunnelPath(path string) bool {
	return path == PathTunnelDirect || strings.HasPrefix(path, PathTunnelRelayed)
}

// The tunnel's words, defined once (decisions AX and AY). §7 makes
// DescribeState the single source of what the surfaces say about a peer, and
// the tunnel's half of that is these: every surface that shows a peer's tunnel
// shows one of them, so a pill, `ladulas status` and the desktop cannot drift
// apart. The ones that carry a value — "direct <address>", "tunnel relayed
// <region>", "fallback to direct, because <reason>", "tunnel in backoff until
// <time>", "version mismatch (…)" — are built in DescribeTunnel.
const (
	TunnelOffHere     = "tunnel off here"
	TunnelNoOffer     = "peer offers no tunnel"
	TunnelWithdrawn   = "peer withdrew its tunnel"
	TunnelStale       = "tunnel offer stale"
	TunnelStaleDirect = "tunnel address stale, no direct path"
	TunnelOffered     = "tunnel offered"
	TunnelClientOnly  = "peer offers a client key only"
)

// TunnelFacts is what DescribeTunnel needs to know beyond the record: this
// instance's side of the tunnel and what the raise is doing now. A pointer
// to a struct of plain fields, because that is what gomobile binds (§21).
type TunnelFacts struct {
	// Ours is the tunnel wire version this instance speaks, zero when it has
	// no tunnel to raise. An int32 rather than the offer's uint32 because
	// gomobile binds signed integers only.
	Ours int32
	// Stale is whether the offer has aged out: no beat has re-confirmed it for
	// the configured period, or direct contacts have kept carrying no offer.
	Stale bool
	// Path is the path word of the contact in use, when there is one: PathDirect
	// or one of the tunnel's (TunnelPath).
	Path string
	// Address is the direct address in use when Path is PathDirect.
	Address string
	// Fallback is why the tunnel was given up, while traffic is back on the
	// direct path because of it.
	Fallback string
	// BackoffUntil is when the next raise may run, as Unix seconds, zero when
	// nothing is holding it back.
	BackoffUntil int64
}

// DescribeTunnel says what this instance knows about a tunnel to a peer, and
// which path the peer is on because of it.
//
// The order is the order of the questions somebody asks. Is the tunnel even
// possible here and there (the switch, the offer, the version)? Is the peer on
// it? If not, is it being held back — because its address has stopped working
// with nothing to fall back to, because its offer has aged out, because a raise
// is in backoff, or because traffic fell back from it? And only then the
// ordinary answers: on the direct path at an address, or merely offered.
func DescribeTunnel(record *storepb.TrustRecord, facts *TunnelFacts) string {
	if facts == nil {
		facts = &TunnelFacts{}
	}

	offer := record.GetTunnel()

	switch {
	case facts.Ours <= 0:
		return TunnelOffHere
	case offer == nil:
		return TunnelNoOffer
	case len(offer.GetVersions()) == 0:
		return TunnelWithdrawn
	case !slices.Contains(offer.GetVersions(), uint32(facts.Ours)):
		return fmt.Sprintf("version mismatch (ours %d, theirs %s)",
			facts.Ours, versionList(offer.GetVersions()))
	case offer.GetServerAddress() == "":
		return TunnelClientOnly
	case IsTunnelPath(facts.Path):
		return facts.Path
	case facts.BackoffUntil > 0 && len(record.GetAddresses()) == 0:
		// The tunnel is the only carrier and it is failing: the case of a
		// region the fleet withdrew, which nothing but a shared network or a
		// re-pair recovers (§8).
		return TunnelStaleDirect
	case facts.Stale:
		return TunnelStale
	case facts.Fallback != "" && facts.Path == PathDirect:
		return "fallback to direct, because " + facts.Fallback
	case facts.BackoffUntil > 0:
		return "tunnel in backoff until " +
			time.Unix(facts.BackoffUntil, 0).Local().Format("15:04:05")
	case facts.Path == PathDirect && facts.Address != "":
		return "direct " + facts.Address
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
