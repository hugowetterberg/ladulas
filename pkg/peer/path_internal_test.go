package peer

import (
	"slices"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// A link that comes up over a path that is not an address must leave the
// address machinery as it found it, and stop trusting the address it had.
//
// The case is the café laptop. At home its link's preferred address was the
// desktop's LAN address; it moved onto a path that is not an address, and then
// that path dropped. Nothing on the indirect path updated preferred, so if it
// were still trusted the presence loop would spend three rounds on a LAN
// address that is blackholed from the café before sweeping, and decision AQ
// would re-add it to the record on every beat. Nothing takes an indirect path
// yet; this is the rule being in place before anything does.
func TestAnIndirectRouteLeavesTheAddressMachineryAlone(t *testing.T) {
	t.Parallel()

	record := []string{"100.74.235.31:7373", "192.168.1.10:7373"}
	fingerprint := "SHA256:desk"

	l := &link{
		record: &storepb.TrustRecord{
			Fingerprint: fingerprint,
			Addresses:   record,
		},
		// Already up, so that succeeded takes this for a link that was, which is
		// the path that does not push grant activity through a nil node.
		online: true,
	}

	n := &Node{links: map[string]*link{fingerprint: l}}

	l.succeeded("192.168.1.10:7373")

	if got := l.presenceOrder(); !slices.Equal(got, []string{"192.168.1.10:7373"}) {
		t.Fatalf("after a direct beat tried %v, want only the address that beat", got)
	}

	if got := n.lastReached(fingerprint); got != "192.168.1.10:7373" {
		t.Fatalf("after a direct beat the reached address is %q", got)
	}

	if got := l.currentPath(); got != pathDirect {
		t.Errorf("after a direct beat the link is on %v", got)
	}

	l.reached(route{kind: pathIndirect})

	if l.preferred != "192.168.1.10:7373" {
		t.Errorf("an indirect route rewrote the direct address to %q", l.preferred)
	}

	// Not reported as where the peer is being reached, so learnAddresses keeps
	// nothing the peer stopped advertising.
	if got := n.lastReached(fingerprint); got != "" {
		t.Errorf("over an indirect path the reached address is still %q", got)
	}

	// And not tried alone, nor first: the record in its own order.
	if got := l.presenceOrder(); !slices.Equal(got, record) {
		t.Errorf("over an indirect path presence would try %v, want the record %v",
			got, record)
	}

	if got := l.addresses(); !slices.Equal(got, record) {
		t.Errorf("over an indirect path calls would try %v, want the record %v",
			got, record)
	}

	if got := l.currentPath(); got != pathIndirect {
		t.Errorf("the link reports %v, want the indirect path", got)
	}

	// A direct dial confirms an address again, and things are as they were.
	l.succeeded("100.74.235.31:7373")

	if got := l.presenceOrder(); !slices.Equal(got, []string{"100.74.235.31:7373"}) {
		t.Errorf("after a direct beat again tried %v", got)
	}

	if got := n.lastReached(fingerprint); got != "100.74.235.31:7373" {
		t.Errorf("after a direct beat again the reached address is %q", got)
	}
}

// The dialer's half: a call that went some other way drops the remembered
// address, so the next direct call races rather than trusting it.
func TestADialerForgetsWhatAnIndirectRouteSaysNothingAbout(t *testing.T) {
	t.Parallel()

	held := &dialer{}
	addresses := []string{"100.64.0.5:7373", "192.168.1.10:7373"}

	raced := false
	race := func(all []string) []string {
		raced = true

		return all
	}

	held.remember("192.168.1.10:7373")

	if got := held.order(race, addresses); raced ||
		got[0] != "192.168.1.10:7373" {
		t.Fatalf("a remembered direct address gave %v, raced %v", got, raced)
	}

	held.rememberRoute(route{kind: pathIndirect})

	if held.preferred != "" {
		t.Errorf("an indirect route left %q remembered", held.preferred)
	}

	held.order(race, addresses)

	if !raced {
		t.Error("after an indirect route the next direct call did not race")
	}
}

// Decision AQ keeps the reached address in the record whether or not the peer
// advertises it, and that is a rule about direct dials (§8). An address that
// was reached before the peer moved onto another path is not kept, so the
// peer's own list replaces it and decision AH's pruning holds.
func TestTheReachedAddressRuleIsForDirectDialsOnly(t *testing.T) {
	approver := newInstance(t, "desk")
	requester := newInstance(t, "builder")

	pair(t, approver, requester)

	// The approver dials its requester back for documentation, through the
	// dialer, and nothing else in this test dials it: no link to race with.
	fingerprint := requester.identity.Fingerprint()

	record, ok := approver.store.Peer(fingerprint)
	if !ok {
		t.Fatal("the approver has no record of the requester")
	}

	held, err := approver.node.dialerFor(record)
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}

	const (
		reached = "192.0.2.10:7373"
		moved   = "198.51.100.20:7373"
		later   = "203.0.113.30:7373"
	)

	held.remember(reached)
	approver.node.learnAddresses(fingerprint, []string{moved})

	record, _ = approver.store.Peer(fingerprint)
	if !slices.Equal(record.GetAddresses(), []string{reached, moved}) {
		t.Fatalf("after a direct dial the record is %v, want the reached "+
			"address kept first", record.GetAddresses())
	}

	held.rememberRoute(route{kind: pathIndirect})
	approver.node.learnAddresses(fingerprint, []string{later})

	record, _ = approver.store.Peer(fingerprint)
	if !slices.Equal(record.GetAddresses(), []string{later}) {
		t.Errorf("after an indirect route the record is %v, want only what the "+
			"peer advertises", record.GetAddresses())
	}
}

// Nothing that is not a host:port goes into an address list, from either side
// of a pairing or from a beat, because the direct dialler is what reads it.
func TestOnlyDirectAddressesAreRecorded(t *testing.T) {
	t.Parallel()

	// The joining side dialled something that is not an address. It is not
	// put first, nor anywhere.
	got := peerAddresses(
		[]string{"192.168.1.10:7373", "tc1qexampleaddress"},
		"tc1qpairingserver")

	if !slices.Equal(got, []string{"192.168.1.10:7373"}) {
		t.Errorf("a pairing dialled through a non-direct address recorded %v", got)
	}

	// And the ordinary case is unchanged: the dialled address first.
	got = peerAddresses(
		[]string{"192.168.1.10:7373", "100.74.235.31:7373"}, "100.74.235.31:7373")

	if !slices.Equal(got, []string{"100.74.235.31:7373", "192.168.1.10:7373"}) {
		t.Errorf("a direct pairing recorded %v, want the dialled address first", got)
	}
}

// A beat that names something which is not an address changes the record only
// by what it names that is.
func TestABeatRecordsOnlyDirectAddresses(t *testing.T) {
	approver := newInstance(t, "desk")
	requester := newInstance(t, "builder")

	pair(t, approver, requester)

	fingerprint := requester.identity.Fingerprint()
	before, _ := approver.store.Peer(fingerprint)

	// Nothing direct at all is the same as nothing: no change.
	approver.node.learnAddresses(fingerprint, []string{"tc1qexampleaddress"})

	after, _ := approver.store.Peer(fingerprint)
	if !slices.Equal(before.GetAddresses(), after.GetAddresses()) {
		t.Errorf("a list with no direct address changed the record from %v to %v",
			before.GetAddresses(), after.GetAddresses())
	}

	approver.node.learnAddresses(fingerprint,
		[]string{"tc1qexampleaddress", "192.0.2.40:7373"})

	after, _ = approver.store.Peer(fingerprint)
	if !slices.Equal(after.GetAddresses(), []string{"192.0.2.40:7373"}) {
		t.Errorf("the record is %v, want only the direct address",
			after.GetAddresses())
	}
}

// The daemon says whether a peer is dialable and what path it is on, so that no
// surface works either out from the address list (§3, §7).
func TestThePeerStatusCarriesDialableAndPath(t *testing.T) {
	approver := newInstance(t, "desk")
	requester := newInstance(t, "builder")
	phone := newPhone(t, "phone")

	pair(t, approver, requester)
	waitForLink(t, requester, approver.identity.Fingerprint())
	scanQR(t, requester, phone)

	byName := map[string]bool{}

	for _, status := range requester.node.PeerStatuses() {
		byName[status.GetName()] = true

		switch status.GetFingerprint() {
		case approver.identity.Fingerprint():
			if !status.GetDialable() {
				t.Error("a machine that listens is reported not dialable")
			}

			if status.GetPath() != trust.PathDirect {
				t.Errorf("a linked approver is on path %q, want %q",
					status.GetPath(), trust.PathDirect)
			}
		case phone.identity.Fingerprint():
			if status.GetDialable() {
				t.Error("a phone is reported dialable")
			}

			if !status.GetOnline() && status.GetPath() != "" {
				t.Errorf("a phone not in contact reports path %q", status.GetPath())
			}
		}
	}

	if len(byName) != 2 {
		t.Errorf("the requester lists %d peers, want 2", len(byName))
	}
}
