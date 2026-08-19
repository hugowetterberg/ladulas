package peer

import (
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// A phone is never dialled, so everything a surface can say about whether it is
// there comes from what it did on its own: collecting what is parked for it,
// announcing its keys, reading a published document. This is that path, and
// before it existed a phone somebody had just used was reported as one nothing
// had ever heard from.
func TestPeerStatusOfADeviceThatComesToUs(t *testing.T) {
	t.Parallel()

	node := &Node{
		links:      map[string]*link{},
		reached:    map[string]*reach{},
		seen:       map[string]time.Time{},
		collecting: map[string]int{},
	}

	phone := &storepb.TrustRecord{
		Fingerprint: "SHA256:phone",
		Name:        "iPhone",
		MayApprove:  true,
	}

	// Nothing yet. The absence has to be an absence rather than a zero time on
	// the wire, because a nil timestamp reads as 1970 on the other side.
	status := node.peerStatus(phone)

	if status.GetOnline() {
		t.Error("a phone nothing has heard from is reported as online")
	}

	if status.GetLastSeenAt() != nil {
		t.Errorf("a phone nothing has heard from carries a last-seen of %v",
			status.GetLastSeenAt().AsTime())
	}

	// It read a document, or announced its keys, or polled once and hung up.
	node.saw(phone.GetFingerprint())

	status = node.peerStatus(phone)

	if status.GetOnline() {
		t.Error("a phone that made one call is reported as still connected")
	}

	if status.GetLastSeenAt() == nil {
		t.Fatal("a call from a phone was not recorded")
	}

	if since := time.Since(status.GetLastSeenAt().AsTime()); since > time.Minute {
		t.Errorf("the recorded contact is %s old", since)
	}

	// And a call it is holding open is as connected as a device that does not
	// listen ever gets.
	release := node.holding(phone.GetFingerprint())

	if !node.peerStatus(phone).GetOnline() {
		t.Error("a phone holding a poll open is not reported as connected")
	}

	release()

	if node.peerStatus(phone).GetOnline() {
		t.Error("a phone that hung up is still reported as connected")
	}

	if node.peerStatus(phone).GetLastSeenAt() == nil {
		t.Error("hanging up lost when the phone was last here")
	}
}

// Two calls at once are one presence, and the first of them ending does not make
// the peer disappear while the second is still open.
func TestHoldingCountsCalls(t *testing.T) {
	t.Parallel()

	node := &Node{
		seen:       map[string]time.Time{},
		collecting: map[string]int{},
	}

	first := node.holding("SHA256:phone")
	second := node.holding("SHA256:phone")

	first()

	if holding, _ := node.presence("SHA256:phone"); !holding {
		t.Error("a peer with a call still open is reported as gone")
	}

	second()

	if holding, _ := node.presence("SHA256:phone"); holding {
		t.Error("a peer that ended both calls is still reported as holding one")
	}
}
