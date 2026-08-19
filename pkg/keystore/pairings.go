package keystore

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// Pairings under way live in the same age-encrypted document the trust records
// do, and for the same reason: which machines are trying to pair with this one
// is the same map an attacker with the disk would want (§7, §10).
//
// The cost of putting them there is real and is not worked around anywhere: a
// sealed instance can neither list a pending pairing nor answer one, exactly as
// it can neither list a peer nor revoke one. Unlocking is the way in.

// ErrNoSuchPairing is returned when nothing answers to a reference.
var ErrNoSuchPairing = errors.New("keystore: no such pending pairing")

// MaxPendingPairings bounds the pending set.
//
// It is clutter control rather than a security boundary — every entry is
// listed, and any of them can be dismissed by hand — but it has to be bounded
// by something, because a peer that has proved a code once should not be able
// to fill the store by proving it again. Two things already make that hard: a
// code is single use, so each new entry costs somebody a deliberate action at
// the machine displaying one, and a second attempt from an identity that is
// already pending replaces its entry rather than adding to it. Sixteen is
// therefore far more than a person will ever have and still small enough to
// read in one screen.
const MaxPendingPairings = 16

// PendingPairings returns the pairings under way, oldest first.
func (v *Vault) PendingPairings() []*storepb.PendingPairing {
	v.mu.RLock()
	defer v.mu.RUnlock()

	out := make([]*storepb.PendingPairing, 0, len(v.doc.GetPendingPairings()))
	for _, pending := range v.doc.GetPendingPairings() {
		out = append(out, proto.CloneOf(pending))
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].GetStartedAt().AsTime().Before(out[j].GetStartedAt().AsTime())
	})

	return out
}

// PendingPairing finds one by session id, peer fingerprint or peer name.
func (v *Vault) PendingPairing(ref string) (*storepb.PendingPairing, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	for _, pending := range v.doc.GetPendingPairings() {
		if matchesPairing(pending, ref) {
			return proto.CloneOf(pending), true
		}
	}

	return nil, false
}

// PutPendingPairing writes a pending pairing, replacing whatever this instance
// held for the same session or the same identity.
//
// Replacing by identity is the interesting half. A second attempt from a
// machine that is already pending is the same person trying again — the first
// attempt having been left on a screen somebody walked away from — and two
// entries for one machine would be two questions about the same decision.
func (v *Vault) PutPendingPairing(pending *storepb.PendingPairing) error {
	switch {
	case pending.GetSessionId() == "":
		return errors.New("keystore: a pending pairing needs a session id")
	case pending.GetFingerprint() == "":
		return errors.New("keystore: a pending pairing needs a fingerprint")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	stored := proto.CloneOf(pending)

	kept := make([]*storepb.PendingPairing, 0, len(v.doc.GetPendingPairings())+1)

	for _, existing := range v.doc.GetPendingPairings() {
		if existing.GetSessionId() == stored.GetSessionId() ||
			existing.GetFingerprint() == stored.GetFingerprint() {
			continue
		}

		kept = append(kept, existing)
	}

	kept = append(kept, stored)

	v.doc.PendingPairings = boundPairings(kept)

	return v.save()
}

// boundPairings drops the oldest entries once there are too many.
//
// Oldest first, and unanswered before answered: an entry this side has already
// said yes to is one half of a decision somebody made, and is worth more than
// one nobody has looked at.
func boundPairings(pairings []*storepb.PendingPairing) []*storepb.PendingPairing {
	if len(pairings) <= MaxPendingPairings {
		return pairings
	}

	ordered := make([]*storepb.PendingPairing, len(pairings))
	copy(ordered, pairings)

	sort.SliceStable(ordered, func(i, j int) bool {
		return pairingWeight(ordered[i]) > pairingWeight(ordered[j])
	})

	return ordered[:MaxPendingPairings]
}

// pairingWeight is how much an entry is worth keeping when the set is full.
func pairingWeight(pending *storepb.PendingPairing) int64 {
	weight := pending.GetStartedAt().AsTime().Unix()

	if pending.GetOurAnswer() !=
		ladulasv1.PairingAnswer_PAIRING_ANSWER_UNSPECIFIED {
		// Far enough ahead that any answered entry outranks any unanswered one,
		// whatever the timestamps say.
		weight += pairingAnsweredBonus
	}

	return weight
}

// pairingAnsweredBonus is a century in seconds, which is longer than any two
// entries' timestamps can differ by in practice.
const pairingAnsweredBonus = 100 * 365 * 24 * 60 * 60

// RemovePendingPairing forgets an attempt and returns what it forgot.
func (v *Vault) RemovePendingPairing(ref string) (*storepb.PendingPairing, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	kept := make([]*storepb.PendingPairing, 0, len(v.doc.GetPendingPairings()))

	var removed *storepb.PendingPairing

	for _, pending := range v.doc.GetPendingPairings() {
		if removed == nil && matchesPairing(pending, ref) {
			removed = pending

			continue
		}

		kept = append(kept, pending)
	}

	if removed == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchPairing, ref)
	}

	v.doc.PendingPairings = kept

	if err := v.save(); err != nil {
		return nil, err
	}

	return proto.CloneOf(removed), nil
}

// matchesPairing reports whether an entry answers to a reference. A session id
// is the exact name for one; a fingerprint and a name are what a person has in
// front of them.
func matchesPairing(pending *storepb.PendingPairing, ref string) bool {
	return pending.GetSessionId() == ref ||
		pending.GetFingerprint() == ref ||
		strings.EqualFold(pending.GetName(), ref)
}
