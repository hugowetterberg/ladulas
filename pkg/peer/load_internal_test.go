package peer

import "testing"

// The per-peer cap holds a peer to maxDecisionsPerPeer decisions in flight, and
// a released slot is usable again — so an honest peer that answers its requests
// is never throttled, only one that piles them up (M3).
func TestPeerLoadCapsInFlightDecisions(t *testing.T) {
	load := newPeerLoad()

	for i := 0; i < maxDecisionsPerPeer; i++ {
		if !load.acquire("SHA256:peer") {
			t.Fatalf("slot %d was refused below the cap", i)
		}
	}

	if load.acquire("SHA256:peer") {
		t.Fatal("a slot past the cap was granted")
	}

	// Another peer is accounted for on its own.
	if !load.acquire("SHA256:other") {
		t.Fatal("a second peer was refused a first slot")
	}

	load.release("SHA256:peer")

	if !load.acquire("SHA256:peer") {
		t.Fatal("a released slot was not reusable")
	}
}

// Releasing back to empty forgets the peer rather than leaving a zero behind, so
// the map does not grow one entry per peer ever seen.
func TestPeerLoadForgetsAnEmptyPeer(t *testing.T) {
	load := newPeerLoad()

	load.acquire("SHA256:peer")
	load.release("SHA256:peer")

	load.mu.Lock()
	_, present := load.count["SHA256:peer"]
	load.mu.Unlock()

	if present {
		t.Error("an emptied peer was left in the count map")
	}
}
