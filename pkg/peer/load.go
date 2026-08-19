package peer

import "sync"

// maxDecisionsPerPeer bounds how many decisions one paired peer can have in
// flight at once (M3). A decision that needs a human holds its slot until it is
// answered, so what this really caps is how many prompts a single peer can have
// on an approver's screen at one time: enough for any honest burst — a login and
// a couple of signatures at once — and far short of the flood a compromised
// requester would raise to bury a real prompt among decoys or to wear somebody
// down into approving. A request the policy or a grant answers holds its slot
// only for the moment the decision takes, so the cap bites on pending prompts,
// not on throughput.
//
// It is a count, not a rate: a token bucket would put a clock on something that
// is really about how much a person can be asked at once, and the person, not
// the second, is the bound. §16 names approval fatigue as the long-term risk;
// this is the blunt ceiling under the richer countermeasures (scoped grants,
// notify-on-auto-approve, decision X's disclosure).
const maxDecisionsPerPeer = 16

// peerLoad counts the decisions each peer has in flight, by fingerprint.
type peerLoad struct {
	mu    sync.Mutex
	count map[string]int
}

func newPeerLoad() *peerLoad {
	return &peerLoad{count: map[string]int{}}
}

// acquire takes a slot for a peer, returning false when the peer already holds
// the most it may. A caller that is granted a slot must release it.
func (l *peerLoad) acquire(fingerprint string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.count[fingerprint] >= maxDecisionsPerPeer {
		return false
	}

	l.count[fingerprint]++

	return true
}

func (l *peerLoad) release(fingerprint string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.count[fingerprint] <= 1 {
		delete(l.count, fingerprint)

		return
	}

	l.count[fingerprint]--
}
