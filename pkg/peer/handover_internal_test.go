package peer

import (
	"context"
	"strings"
	"testing"
	"time"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Handing a key over has two paths and one outcome (decision S): pushed at a
// peer that listens, collected by one that cannot be, and in both cases the key
// arrives as something nobody has accepted and the sender writes down that it
// has gone.

func generatePortable(t *testing.T, on *instance, label string) string {
	t.Helper()

	key, err := on.vault.GenerateKey(label, "")
	if err != nil {
		t.Fatalf("generate a portable key: %v", err)
	}

	return key.GetFingerprint()
}

func TestAKeyPushedToAPeerWaitsToBeAccepted(t *testing.T) {
	holder := newInstance(t, "phone")
	desktop := newInstance(t, "desktop")

	pair(t, desktop, holder)

	fingerprint := generatePortable(t, holder, "work")

	key, err := holder.vault.PortableKey("work")
	if err != nil {
		t.Fatalf("resolve the key: %v", err)
	}

	record, ok := holder.store.Peer(desktop.identity.Fingerprint())
	if !ok {
		t.Fatal("the desktop is not paired")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := holder.node.SendKey(ctx, record, key); err != nil {
		t.Fatalf("send the key: %v", err)
	}

	// Delivered in the call, so nothing is left queued and the key says where
	// it now also lives.
	if queued := holder.vault.QueuedHandovers(); len(queued) != 0 {
		t.Errorf("the key is still queued after a delivery: %d", len(queued))
	}

	var handedTo int

	for _, held := range holder.vault.Keys() {
		if held.GetFingerprint() == fingerprint {
			handedTo = len(held.GetHandedTo())
		}
	}

	if handedTo != 1 {
		t.Errorf("the sender did not write down where the key went")
	}

	offers := desktop.vault.PendingKeyOffers()
	if len(offers) != 1 {
		t.Fatalf("the desktop holds %d offers", len(offers))
	}

	if offers[0].GetFingerprint() != fingerprint {
		t.Errorf("a different key arrived")
	}

	if offers[0].GetPeerName() != "phone" {
		t.Errorf("the offer does not say who sent it: %q", offers[0].GetPeerName())
	}

	// Nothing is usable until somebody says so.
	if len(desktop.vault.Keys()) != 0 {
		t.Errorf("an unanswered offer became a key")
	}

	// Both ends say so in the one place somebody would look after losing a
	// device.
	assertKeyTransfer(t, holder, "handed the key")
	assertKeyTransfer(t, desktop, "handed over the key")
}

func TestAKeyForAPhoneIsQueuedWokenAndCollected(t *testing.T) {
	// A phone binds nothing and advertises no address, so it can only ever be
	// the side that dials (§3).
	phone := newPhone(t, "phone")
	desktop := newInstance(t, "desktop")

	pair(t, desktop, phone)

	fingerprint := generatePortable(t, desktop, "work")

	key, err := desktop.vault.PortableKey("work")
	if err != nil {
		t.Fatalf("resolve the key: %v", err)
	}

	record, ok := desktop.store.Peer(phone.identity.Fingerprint())
	if !ok {
		t.Fatal("the phone is not paired")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := desktop.node.SendKey(ctx, record, key); err != nil {
		t.Fatalf("send the key: %v", err)
	}

	// It cannot have been delivered: there was nobody to deliver it to.
	queued := desktop.vault.QueuedHandovers()
	if len(queued) != 1 {
		t.Fatalf("the key was not queued for the phone: %d", len(queued))
	}

	if len(phone.vault.PendingKeyOffers()) != 0 {
		t.Fatal("a phone that was never dialled has the key already")
	}

	// The phone comes and asks, which is what the wake-up is for.
	desktopRecord, ok := phone.store.Peer(desktop.identity.Fingerprint())
	if !ok {
		t.Fatal("the desktop is not paired on the phone")
	}

	if err := phone.node.collectKeysFrom(ctx, desktopRecord); err != nil {
		t.Fatalf("collect the key: %v", err)
	}

	offers := phone.vault.PendingKeyOffers()
	if len(offers) != 1 {
		t.Fatalf("the phone collected %d offers", len(offers))
	}

	if offers[0].GetFingerprint() != fingerprint {
		t.Errorf("a different key arrived")
	}

	if offers[0].GetHandoverId() != queued[0].GetId() {
		t.Errorf("the offer cannot be acknowledged: %q", offers[0].GetHandoverId())
	}

	// Still held by the sender, because nothing has said it arrived.
	if len(desktop.vault.QueuedHandovers()) != 1 {
		t.Errorf("the sender let go of the key before it was acknowledged")
	}

	// A second collection acknowledges the first, and comes back empty.
	if err := phone.node.collectKeysFrom(ctx, desktopRecord); err != nil {
		t.Fatalf("collect again: %v", err)
	}

	if len(desktop.vault.QueuedHandovers()) != 0 {
		t.Errorf("the acknowledged key is still queued")
	}

	if len(phone.vault.PendingKeyOffers()) != 1 {
		t.Errorf("collecting twice made two offers")
	}

	// And accepting is what finally makes it a key.
	accepted, err := phone.vault.AcceptKeyOffer(offers[0].GetId(), "")
	if err != nil {
		t.Fatalf("accept the key: %v", err)
	}

	if accepted.GetReceivedFrom().GetPeerName() != "desktop" {
		t.Errorf("the accepted key does not say where it came from")
	}
}

func TestARevokedPeerTakesItsKeysWithIt(t *testing.T) {
	phone := newPhone(t, "phone")
	desktop := newInstance(t, "desktop")

	pair(t, desktop, phone)

	key, err := desktop.vault.PortableKey(
		generatePortableLabel(t, desktop, "work"))
	if err != nil {
		t.Fatalf("resolve the key: %v", err)
	}

	record, ok := desktop.store.Peer(phone.identity.Fingerprint())
	if !ok {
		t.Fatal("the phone is not paired")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := desktop.node.SendKey(ctx, record, key); err != nil {
		t.Fatalf("send the key: %v", err)
	}

	if len(desktop.vault.QueuedHandovers()) != 1 {
		t.Fatal("the key was not queued")
	}

	desktop.node.dropPeerHandovers(record)

	if len(desktop.vault.QueuedHandovers()) != 0 {
		t.Errorf("revoking a peer left a key queued for it")
	}
}

// generatePortableLabel makes a key and returns its label, for the tests that
// resolve one the way a person types it.
func generatePortableLabel(t *testing.T, on *instance, label string) string {
	t.Helper()

	generatePortable(t, on, label)

	return label
}

func assertKeyTransfer(t *testing.T, on *instance, contains string) {
	t.Helper()

	for _, entry := range readAudit(t, on.audit) {
		if entry.GetEvent() != ladulasv1.AuditEvent_AUDIT_EVENT_KEY_TRANSFER {
			continue
		}

		if entry.GetKeyFingerprint() == "" {
			t.Errorf("a key transfer was logged without the key")
		}

		if strings.Contains(entry.GetDetail(), contains) {
			return
		}
	}

	t.Errorf("no key transfer mentioning %q was logged", contains)
}

// A key queued for a phone knocks, and says which of the relay's two sentences
// to send: "a key is waiting" rather than "somebody wants a signature" (§11).
func TestAQueuedKeyWakesThePhoneAboutAKey(t *testing.T) {
	rig := newTestRelay(t)

	phone := newPhone(t, "phone")
	desktop := newInstance(t, "desktop")

	phoneWakeups := withWakeups(phone)
	desktopWakeups := withWakeups(desktop)

	scanQR(t, desktop, phone)
	registerPhone(t, phone, phoneWakeups, rig)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	phone.node.AnnounceWakeups(ctx)
	waitRoute(t, desktopWakeups, phone.identity.Fingerprint())

	key, err := desktop.vault.PortableKey(
		generatePortableLabel(t, desktop, "work"))
	if err != nil {
		t.Fatalf("resolve the key: %v", err)
	}

	record, ok := desktop.store.Peer(phone.identity.Fingerprint())
	if !ok {
		t.Fatal("the phone is not paired")
	}

	if _, err := desktop.node.SendKey(ctx, record, key); err != nil {
		t.Fatalf("send the key: %v", err)
	}

	if style := rig.waitPush(t); style != ladulasv1.WakeStyle_WAKE_STYLE_ALERT {
		t.Fatalf("the phone was woken with a %s push", style)
	}

	subjects := rig.pushedSubjects()
	if len(subjects) != 1 ||
		subjects[0] != ladulasv1.WakeSubject_WAKE_SUBJECT_KEY_OFFER {
		t.Errorf("the phone was told the wrong thing: %v", subjects)
	}
}

// The case that would otherwise never end: a key accepted before the sender
// heard that it arrived. The acknowledgement rides on the next collection, and
// an accepted offer is no longer in the list that acknowledgement is built
// from — so without settling it here, the sender would offer the same key on
// every poll for as long as the pairing lasted.
func TestAKeyAcceptedBeforeItWasAcknowledged(t *testing.T) {
	phone := newPhone(t, "phone")
	desktop := newInstance(t, "desktop")

	pair(t, desktop, phone)

	key, err := desktop.vault.PortableKey(
		generatePortableLabel(t, desktop, "work"))
	if err != nil {
		t.Fatalf("resolve the key: %v", err)
	}

	record, ok := desktop.store.Peer(phone.identity.Fingerprint())
	if !ok {
		t.Fatal("the phone is not paired")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := desktop.node.SendKey(ctx, record, key); err != nil {
		t.Fatalf("send the key: %v", err)
	}

	desktopRecord, ok := phone.store.Peer(desktop.identity.Fingerprint())
	if !ok {
		t.Fatal("the desktop is not paired on the phone")
	}

	if err := phone.node.collectKeysFrom(ctx, desktopRecord); err != nil {
		t.Fatalf("collect the key: %v", err)
	}

	offers := phone.vault.PendingKeyOffers()
	if len(offers) != 1 {
		t.Fatalf("the phone collected %d offers", len(offers))
	}

	// Accepted before the next poll, which is what somebody with the app open
	// does, and which empties the list the acknowledgement is read from.
	if _, err := phone.vault.AcceptKeyOffer(offers[0].GetId(), ""); err != nil {
		t.Fatalf("accept the key: %v", err)
	}

	// This round is offered the key again and has nowhere to put it.
	if err := phone.node.collectKeysFrom(ctx, desktopRecord); err != nil {
		t.Fatalf("collect again: %v", err)
	}

	if len(phone.vault.PendingKeyOffers()) != 0 {
		t.Errorf("a key that is already held came back as an offer")
	}

	// And the round after it says so, which is what ends this.
	if err := phone.node.collectKeysFrom(ctx, desktopRecord); err != nil {
		t.Fatalf("collect a third time: %v", err)
	}

	if len(desktop.vault.QueuedHandovers()) != 0 {
		t.Errorf("the sender is still holding a key the phone has")
	}

	// Nothing is left waiting to be acknowledged either.
	phone.node.mu.Lock()
	left := len(phone.node.settled)
	phone.node.mu.Unlock()

	if left != 0 {
		t.Errorf("%d acknowledgements were remembered after being sent", left)
	}
}
