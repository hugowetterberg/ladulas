package peer

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// An address nothing in the suite listens on, standing in for the tailnet
// address a machine wrote into a pairing during a boot when its resolver was
// wrong, or the LAN address it has since moved off (§8).
const staleAddress = "10.255.255.1:7373"

// misrecord writes a record of the peer down with the stale address on it, the
// way a pairing made on the wrong network would have, and tells the node so
// its links work from the new record.
func misrecord(t *testing.T, side *instance, fingerprint string, addresses ...string) {
	t.Helper()

	record, ok := side.store.Peer(fingerprint)
	if !ok {
		t.Fatalf("%s has no record of %s", side.identity.Name(), fingerprint)
	}

	if err := side.store.PutPeer(trust.Readdressed(record, addresses)); err != nil {
		t.Fatalf("readdress: %v", err)
	}

	side.node.Reconcile()
}

// waitReaddressed waits for the record to stop naming the stale address and to
// name everything the peer advertises.
func waitReaddressed(t *testing.T, side *instance, fingerprint string, advertised []string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	var last []string

	for time.Now().Before(deadline) {
		record, ok := side.store.Peer(fingerprint)
		if !ok {
			t.Fatalf("%s lost its record of %s", side.identity.Name(), fingerprint)
		}

		last = record.GetAddresses()

		if !slices.Contains(last, staleAddress) &&
			containsAll(last, advertised) {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("%s still records %v for %s, the peer advertises %v",
		side.identity.Name(), last, fingerprint, advertised)
}

func containsAll(have, want []string) bool {
	for _, address := range want {
		if !slices.Contains(have, address) {
			return false
		}
	}

	return true
}

// The approver moved networks, or paired while its address was wrong. The
// requester holds a stream to it and is told where it is on every beat, so the
// record repairs itself without anybody pairing again (decision AQ).
func TestARequesterLearnsWhereItsApproverIsOverTheHeartbeat(t *testing.T) {
	approver := newInstance(t, "desk")
	requester := newInstance(t, "builder")

	pair(t, approver, requester)
	waitForLink(t, requester, approver.identity.Fingerprint())

	misrecord(t, requester, approver.identity.Fingerprint(),
		staleAddress, approver.address())

	waitReaddressed(t, requester, approver.identity.Fingerprint(),
		approver.node.Advertised())

	// The address the stream is actually on is kept whether or not the approver
	// advertises it; here it does, so the record is exactly the advertisement.
	record, _ := requester.store.Peer(approver.identity.Fingerprint())

	if !sameAddresses(record.GetAddresses(), approver.node.Advertised()) {
		t.Errorf("the requester records %v, the approver advertises %v",
			record.GetAddresses(), approver.node.Advertised())
	}
}

// The approver only ever dials a requester back, so the one time it hears where
// the requester is now is when the requester opens its stream (decision AQ).
func TestAnApproverLearnsWhereItsRequesterIsWhenTheStreamOpens(t *testing.T) {
	approver := newInstance(t, "desk")
	requester := newInstance(t, "builder")

	pair(t, approver, requester)
	waitForLink(t, requester, approver.identity.Fingerprint())

	// Nothing that reaches the approver over the held stream carries the
	// requester's address, so the record stays wrong until the stream reopens.
	misrecord(t, approver, requester.identity.Fingerprint(), staleAddress)

	time.Sleep(3 * requester.node.heartbeat)

	if record, _ := approver.store.Peer(requester.identity.Fingerprint()); !slices.Equal(
		record.GetAddresses(), []string{staleAddress}) {
		t.Fatalf("the approver's record changed under a held stream: %v",
			record.GetAddresses())
	}

	// The requester restarts, which is what opens a new stream.
	relink(t, requester, approver.identity.Fingerprint())

	waitReaddressed(t, approver, requester.identity.Fingerprint(),
		requester.node.Advertised())
}

// A phone holds no stream and is dialled by nobody, so the poll it makes is where
// it hears the requester's addresses (decision AQ). This is the case that
// prompted the decision: a desktop that started advertising its LAN address
// after the phone had paired with it over the tailnet.
func TestAPhoneLearnsWhereItsRequesterIsOnThePoll(t *testing.T) {
	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	scanQR(t, requester, phone)

	misrecord(t, phone, requester.identity.Fingerprint(),
		requester.address(), staleAddress)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := phone.node.Collect(ctx, 0); err != nil {
		t.Fatalf("collect: %v", err)
	}

	record, _ := phone.store.Peer(requester.identity.Fingerprint())

	if slices.Contains(record.GetAddresses(), staleAddress) ||
		!containsAll(record.GetAddresses(), requester.node.Advertised()) {
		t.Errorf("after a poll the phone records %v, the requester advertises %v",
			record.GetAddresses(), requester.node.Advertised())
	}
}

// A peer that says nothing about its addresses is not thereby forgotten: the
// list is only ever replaced by a non-empty one.
func TestAnEmptyAddressListChangesNothing(t *testing.T) {
	approver := newInstance(t, "desk")
	requester := newInstance(t, "builder")

	pair(t, approver, requester)

	before, _ := requester.store.Peer(approver.identity.Fingerprint())

	requester.node.learnAddresses(approver.identity.Fingerprint(), nil)

	after, _ := requester.store.Peer(approver.identity.Fingerprint())

	if !slices.Equal(before.GetAddresses(), after.GetAddresses()) {
		t.Errorf("an empty list changed the record from %v to %v",
			before.GetAddresses(), after.GetAddresses())
	}
}

// relink tears a requester's link down and brings it up again, which is what a
// restart does to it.
func relink(t *testing.T, requester *instance, fingerprint string) {
	t.Helper()

	existing := requester.node.link(fingerprint)
	if existing == nil {
		t.Fatalf("%s holds no link to %s", requester.identity.Name(), fingerprint)
	}

	requester.node.mu.Lock()
	ctx := requester.node.ctx
	requester.node.mu.Unlock()

	existing.stop()
	existing.start(ctx)

	waitForLink(t, requester, fingerprint)
}
