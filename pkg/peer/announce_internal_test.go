package peer

import (
	"errors"
	"sync"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// recordingAnnouncer is the local network, reduced to what was said on it.
type recordingAnnouncer struct {
	mu        sync.Mutex
	announced []string
	withdrawn int
	refuse    bool
	// live is whether anything is on the network now.
	live bool
}

func (r *recordingAnnouncer) AnnouncePairing(name string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.refuse {
		return "Not announced on the local network: loopback only", errors.New("loopback only")
	}

	r.announced = append(r.announced, name)
	r.live = true

	return "Announced on the local network as " + name, nil
}

func (r *recordingAnnouncer) WithdrawPairing() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.withdrawn++
	r.live = false
}

func (r *recordingAnnouncer) isLive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.live
}

func (r *recordingAnnouncer) counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.announced), r.withdrawn
}

// A window is announced under the instance's name, and a screen going away
// withdraws its own window and never the one a second screen opened since:
// one window at a time means the second BeginPairing closes the first, whose
// deferred withdraw then runs while the second is on the network (decision
// AW).
func TestAWindowIsAnnouncedAndOnlyItsOwnScreenWithdrawsIt(t *testing.T) {
	desktop := newInstance(t, "desktop")
	network := &recordingAnnouncer{}

	desktop.node.AnnouncePairingWith(network)

	first, _, err := desktop.node.beginPairing(trust.IntentMutual)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	if note := desktop.node.announce(first); note == "" {
		t.Error("an announced window has nothing to say about it")
	}

	second, _, err := desktop.node.beginPairing(trust.IntentMutual)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	desktop.node.announce(second)

	// The first screen's deferred withdraw, arriving late.
	desktop.node.withdrawWindow(first)

	if announced, withdrawn := network.counts(); announced != 2 || withdrawn != 0 {
		t.Fatalf("announced %d, withdrew %d; the first screen took the "+
			"second's announcement down", announced, withdrawn)
	}

	desktop.node.withdrawWindow(second)
	desktop.node.withdrawWindow(second)

	if _, withdrawn := network.counts(); withdrawn != 1 {
		t.Fatalf("withdrew %d times, want once", withdrawn)
	}

	if network.announced[0] != "desktop" {
		t.Errorf("announced as %q, want the instance name", network.announced[0])
	}
}

// Closing the node is what sealing does to it, and a sealed instance
// announces nothing (§3).
func TestClosingTheNodeWithdrawsItsWindow(t *testing.T) {
	desktop := newInstance(t, "desktop")
	network := &recordingAnnouncer{}

	desktop.node.AnnouncePairingWith(network)

	window, _, err := desktop.node.beginPairing(trust.IntentMutual)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	desktop.node.announce(window)

	if err := desktop.node.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, withdrawn := network.counts(); withdrawn != 1 {
		t.Fatalf("closing the node withdrew %d times", withdrawn)
	}
}

// Not being announced says why and is not a failure: the PIN goes on screen,
// and the full code and an address still work. A node with no announcer —
// every phone — has nothing to say about the network at all.
func TestAnUnannouncedWindowSaysWhy(t *testing.T) {
	desktop := newInstance(t, "desktop")

	window, _, err := desktop.node.beginPairing(trust.IntentMutual)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	if note := desktop.node.announce(window); note != "" {
		t.Errorf("a node without an announcer said %q", note)
	}

	desktop.node.AnnouncePairingWith(&recordingAnnouncer{refuse: true})

	if note := desktop.node.announce(window); note == "" {
		t.Error("a refused announcement gave no reason")
	}

	if desktop.node.openWindow() != window {
		t.Error("a refused announcement closed the window")
	}
}

// A screen going away and a second screen opening, at the same moment, must
// not leave the second screen's PIN up with nothing on the network. With the
// check and the call made separately, the first screen's withdraw could pass
// its check, the second's announce run in full, and the withdraw then take
// the second's announcement down.
func TestAStaleWithdrawRacingANewWindowLeavesItAnnounced(t *testing.T) {
	desktop := newInstance(t, "desktop")
	network := &recordingAnnouncer{}

	desktop.node.AnnouncePairingWith(network)

	first, _, err := desktop.node.beginPairing(trust.IntentMutual)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	second, _, err := desktop.node.beginPairing(trust.IntentMutual)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	for range 500 {
		desktop.node.announce(first)

		var wg sync.WaitGroup

		wg.Go(func() { desktop.node.withdrawWindow(first) })
		wg.Go(func() { desktop.node.announce(second) })
		wg.Wait()

		desktop.node.mu.Lock()
		current := desktop.node.announcedWindow
		desktop.node.mu.Unlock()

		if current == second && !network.isLive() {
			t.Fatal("the first screen's withdraw took the second's announcement down")
		}

		desktop.node.withdrawWindow(second)
	}
}

// A window whose BeginPairing reaches announce after the node closed is not
// announced: nothing would ever withdraw it.
func TestAClosedNodeAnnouncesNothing(t *testing.T) {
	desktop := newInstance(t, "desktop")
	network := &recordingAnnouncer{}

	desktop.node.AnnouncePairingWith(network)

	window, _, err := desktop.node.beginPairing(trust.IntentMutual)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	if err := desktop.node.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if note := desktop.node.announce(window); note != "" {
		t.Errorf("a closed node said %q", note)
	}

	if announced, _ := network.counts(); announced != 0 {
		t.Errorf("a closed node announced %d windows", announced)
	}
}
