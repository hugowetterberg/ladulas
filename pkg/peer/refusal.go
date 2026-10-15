package peer

import (
	"context"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// A refusal made here is held until the other side has heard it (§7,
// decision AZ).
//
// Withdrawal used to propagate by asking alone: the side that dropped a
// pairing forgot it, and the side still holding it found out the next time it
// asked, because an instance with no record of a session says so. That leaned
// on the asker getting as far as the question, and it does not. Both doors
// refuse an identity with no record and nothing pending — the bound listener's
// gate in the handshake, and the tunnel listener's gate, behind a tailcat
// allowlist the drop had just taken the asker's client key off. A pairing born
// through a pairing server, whose only path is the tunnel, could therefore
// never be told that the other side had declined it while it was asleep: its
// convergence loop failed on every attempt, forever, and its allowlist kept
// the decliner's key. The direct path had the same hole whenever no window
// happened to be open.
//
// So a pending pairing that this side refuses — declined or called off here,
// not ended by the peer's own word — is held after it leaves the pending set:
// the identity, the session, the answer and its reason, and the client key the
// exchange admitted, which stays on the allowlist. Both gates admit the held
// identity, and through the tunnel only for SettlePairing; SettlePairing
// answers its session with the refusal and the reason; and the convergence loop
// goes on taking the refusal to the peer by whatever path it has, the tunnel
// included. Whichever end gets through first ends the hold.
//
// It is in memory and bounded, and that is what keeps it from being the
// tombstone decision M rejected. That one was to be delivered — impossible to
// a phone, which has no address — and would have been a second mechanism
// beside asking. This one is the asking made to work: a phone that asks is
// answered from it, and delivery is only the loop doing what it already did
// for a pending pairing. A restart or a seal forgets it, and the peer is then
// back where it was before the hold existed, with `ladulas pairings withdraw`
// on its own side as the remedy (ops.md).

// heldRefusalCap bounds the refusals held at once. Each costs a few hundred
// bytes and one allowlist entry, and the pending set they come from is bounded
// at sixteen; past the cap the oldest is let go, which is what every refusal
// was before the hold.
const heldRefusalCap = 32

// heardRefusalGrace is how long a refusal is held after the peer has asked and
// been answered from it. The answer may not reach it — the connection carrying
// it can drop — and an asker that comes back for it must find it, not a
// refusal at the door. Released at once, the client key's revocation would
// also disconnect the very tunnel client the answer is still travelling on.
const heardRefusalGrace = time.Minute

// heldRefusal is one refusal waiting to be heard.
type heldRefusal struct {
	// pending is the entry as it was dropped, with this side's answer on it.
	pending *storepb.PendingPairing
	reason  string
	key     []byte
	at      time.Time
	// heard is set once the peer has been answered from it, and the release
	// is then on a timer.
	heard bool
}

// refusalState is the held refusals, under their own mutex: both gates read it
// during a handshake.
type refusalState struct {
	refusalMu sync.Mutex
	refusals  map[string]*heldRefusal
	// refusalGrace is heardRefusalGrace, and the delay before a dropped
	// pending pairing's client key comes off the allowlist; zero for the
	// default. Tests shorten it.
	refusalGrace time.Duration
}

// lingerFor is refusalGrace, defaulted.
func (n *Node) lingerFor() time.Duration {
	if n.refusalGrace > 0 {
		return n.refusalGrace
	}

	return heardRefusalGrace
}

// holdRefusal keeps a refusal made here until the peer has heard it. Called
// under pairingMu, by dropPending, in place of taking the client key off the
// allowlist.
func (n *Node) holdRefusal(pending *storepb.PendingPairing, reason string) {
	held := &heldRefusal{
		pending: proto.Clone(pending).(*storepb.PendingPairing),
		reason:  reason,
		key:     admissible(pending.GetTunnel()),
		at:      time.Now(),
	}

	var evicted *heldRefusal

	n.refusalMu.Lock()

	if n.refusals == nil {
		n.refusals = map[string]*heldRefusal{}
	}

	n.refusals[pending.GetSessionId()] = held

	if len(n.refusals) > heldRefusalCap {
		var oldest string

		for session, other := range n.refusals {
			if oldest == "" || other.at.Before(n.refusals[oldest].at) {
				oldest = session
			}
		}

		evicted = n.refusals[oldest]
		delete(n.refusals, oldest)
	}

	n.refusalMu.Unlock()

	if evicted != nil {
		n.revokeUnheld(evicted.key)
	}
}

// heldRefusalOf is the refusal held for an identity, if any. A refusal is held
// per session, but one identity has at most one pending pairing at a time, so
// the newest is the one to admit it under.
func (n *Node) heldRefusalOf(fingerprint string) (*heldRefusal, bool) {
	n.refusalMu.Lock()
	defer n.refusalMu.Unlock()

	var found *heldRefusal

	for _, held := range n.refusals {
		if held.pending.GetFingerprint() != fingerprint {
			continue
		}

		if found == nil || held.at.After(found.at) {
			found = held
		}
	}

	return found, found != nil
}

// answerHeldRefusal is SettlePairing's answer for a session this side refused
// and the peer had not heard about: the refusal itself, with its reason, rather
// than "no record". Called under pairingMu.
func (n *Node) answerHeldRefusal(
	fingerprint, session string,
) (*ladulasv1.SettlePairingResponse, bool) {
	n.refusalMu.Lock()

	held, ok := n.refusals[session]
	if !ok || held.pending.GetFingerprint() != fingerprint {
		n.refusalMu.Unlock()

		return nil, false
	}

	first := !held.heard
	held.heard = true

	n.refusalMu.Unlock()

	if first {
		time.AfterFunc(n.lingerFor(), func() {
			n.releaseRefusal(session)
		})
	}

	return &ladulasv1.SettlePairingResponse{
		State:  ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_GONE,
		Answer: held.pending.GetOurAnswer(),
		Reason: held.reason,
	}, true
}

// releaseRefusal ends a hold: the peer has heard, or will not be asked again.
func (n *Node) releaseRefusal(session string) {
	n.refusalMu.Lock()
	held, ok := n.refusals[session]
	delete(n.refusals, session)
	n.refusalMu.Unlock()

	if ok {
		n.revokeUnheld(held.key)
	}
}

// revokeUnheld takes a key off the allowlist unless something still holds it:
// a trust record or pending pairing that carries the same key — a re-pair of
// the same machine — or another held refusal.
func (n *Node) revokeUnheld(key []byte) {
	if key == nil || n.admissibleKeys()[string(key)] {
		return
	}

	n.revokeKey(key)
}

// heldRefusalKeys is the client keys the held refusals keep on the allowlist,
// for admitAll.
func (n *Node) heldRefusalKeys() [][]byte {
	n.refusalMu.Lock()
	defer n.refusalMu.Unlock()

	keys := make([][]byte, 0, len(n.refusals))

	for _, held := range n.refusals {
		if held.key != nil {
			keys = append(keys, held.key)
		}
	}

	return keys
}

// deliverRefusals is the convergence loop's half: each held refusal taken to
// its peer on the pairing cadence, by every path a pending pairing would take.
// Any answer at all means the peer has heard — it drops its half on reading
// the refusal — so any answer ends the hold.
func (n *Node) deliverRefusals(ctx context.Context) {
	n.refusalMu.Lock()

	held := make([]*heldRefusal, 0, len(n.refusals))
	for _, refusal := range n.refusals {
		if !refusal.heard {
			held = append(held, refusal)
		}
	}

	n.refusalMu.Unlock()

	for _, refusal := range held {
		if ctx.Err() != nil {
			return
		}

		if !n.shouldSettle(refusal.pending) {
			continue
		}

		callCtx, cancel := context.WithTimeout(ctx, settleTimeout)
		_, err := n.callSettle(callCtx, refusal.pending, refusal.reason)

		cancel()

		if err != nil {
			n.log.Debug("could not tell the peer about a pairing refused here",
				"session", refusal.pending.GetSessionId(), "error", err.Error())

			continue
		}

		n.releaseRefusal(refusal.pending.GetSessionId())
	}
}

// refusedHere reports whether a pending pairing is being dropped because of
// this side's answer, with the peer's not a refusal: the one case the peer has
// not already heard, since every other drop is the peer's own word arriving.
func refusedHere(pending *storepb.PendingPairing) bool {
	return refusal(pending.GetOurAnswer()) && !refusal(pending.GetTheirAnswer())
}
