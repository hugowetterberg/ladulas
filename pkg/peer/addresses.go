package peer

import (
	"slices"

	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// Where a peer can be dialled is written into its trust record when the two
// pair, and until decision AQ nothing ever wrote it again. That made the record
// a photograph of one moment on one network: a machine that started advertising
// its LAN address after the pairing was still dialled on the tailnet alone, a
// tailnet address that resolved wrongly during a boot was carried for good (§8),
// and the only repair was to pair again.
//
// So a peer now says where it can be reached every time the two are in
// contact anyway. An approver says it on every presence heartbeat, which is the
// stream a requester holds open to it; a requester says it when it opens that
// stream, which is the approver's one chance to hear from a machine it only ever
// dials back for documentation; and a requester says it on every poll a
// collector makes, because a phone has no link to hear it on and the poll is
// the one call it reliably makes. All three arrive here.

// learnAddresses replaces what is recorded of where a peer can be dialled with
// what the peer itself has just said, when the two differ.
//
// An empty list says nothing and changes nothing: nothing that arrives over the
// wire empties a record, and an instance with its channel off is not thereby
// forgotten as a machine that once listened.
//
// The address this instance is reaching the peer on right now stays in the list
// whether or not the peer advertises it, for the reason pairing puts the dialled
// address first: reaching a machine is better evidence than being told about
// it, and a typed address that works from here through a forwarded port is
// exactly the kind the peer does not know it has.
//
// The peer is authenticated and can only change its own record's dial list, and
// every address on it is still dialled with the peer's identity pinned. The most
// a peer can do with this is send this instance's connection attempts somewhere
// that will not authenticate as it, which is what advertising an address at
// pairing already let it do.
func (n *Node) learnAddresses(fingerprint string, advertised []string) {
	if len(advertised) == 0 {
		return
	}

	record, ok := n.trust.Peer(fingerprint)
	if !ok {
		return
	}

	wanted := advertised

	if reached := n.lastReached(fingerprint); reached != "" &&
		!slices.Contains(advertised, reached) {
		wanted = peerAddresses(advertised, reached)
	}

	if sameAddresses(record.GetAddresses(), wanted) {
		return
	}

	revised := trust.Readdressed(record, wanted)

	if err := n.trust.PutPeer(revised); err != nil {
		n.log.Error("could not record where a peer can be reached",
			"peer", record.GetName(), "error", err.Error())

		return
	}

	n.log.Info("where a peer can be reached changed",
		"peer", record.GetName(),
		"from", record.GetAddresses(), "to", wanted)

	// The links work from the record they were built with, and Reconcile is
	// what hands them a new one.
	n.Reconcile()
}

// lastReached is the address this instance most recently reached a peer on,
// whichever of the two warm clients it went through, or "" when it has not.
func (n *Node) lastReached(fingerprint string) string {
	if existing := n.link(fingerprint); existing != nil {
		existing.mu.Lock()
		defer existing.mu.Unlock()

		return existing.preferred
	}

	n.dialMu.Lock()
	held := n.dialers[fingerprint]
	n.dialMu.Unlock()

	if held == nil {
		return ""
	}

	held.mu.Lock()
	defer held.mu.Unlock()

	return held.preferred
}

// sameAddresses says whether two lists dial the same places, in whatever order.
// The order in a record is the first attempt's, and a peer that is reachable on
// the same set of addresses in a different order is not news.
func sameAddresses(recorded, advertised []string) bool {
	if len(recorded) != len(advertised) {
		return false
	}

	for _, address := range advertised {
		if !slices.Contains(recorded, address) {
			return false
		}
	}

	return true
}
