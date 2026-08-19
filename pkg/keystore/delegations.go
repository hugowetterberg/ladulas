package keystore

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// The requester's half of a delegated grant (decision P).
//
// `grants` in the same document are promises this instance made and keeps.
// These are promises it was given: an approver signed a scope and an expiry,
// handed the artifact over, and went to sleep. They are the reason this
// instance can answer for itself, and they are the thing that has to survive a
// restart — a delegation that only lived in memory would send everybody back to
// waiting for a phone the moment the daemon was upgraded.
//
// The ledger travels with them. What was self-approved under a delegation is
// kept here until the approver has acknowledged hearing about it, which is what
// makes a week offline produce an account rather than a silence.

// maxUnreportedUses bounds the ledger.
//
// It is a cap on memory of a promise already made, not a cap on the promise:
// hitting it drops the oldest entries and the count goes on being right, so
// what is lost is the detail of what happened rather than the fact that
// something did. A machine that has been offline long enough to sign a thousand
// times has a bigger problem than a shortened list.
const maxUnreportedUses = 256

// Delegations returns the live delegations this instance holds, dropping any
// that have expired. Expired ones are pruned as a side effect, exactly as
// Grants does with the other half.
func (v *Vault) Delegations() ([]*storepb.HeldDelegation, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	live, changed := liveDelegations(v.doc.GetHeldDelegations(), time.Now())

	if changed {
		v.doc.HeldDelegations = live

		if err := v.save(); err != nil {
			return nil, err
		}
	}

	out := make([]*storepb.HeldDelegation, 0, len(live))
	for _, held := range live {
		out = append(out, proto.CloneOf(held))
	}

	return out, nil
}

func liveDelegations(
	all []*storepb.HeldDelegation, now time.Time,
) ([]*storepb.HeldDelegation, bool) {
	var (
		live    []*storepb.HeldDelegation
		changed bool
	)

	for _, held := range all {
		if held.GetDelegation().GetExpiresAt().AsTime().After(now) {
			live = append(live, held)

			continue
		}

		changed = true
	}

	return live, changed
}

// UsableDelegations is the delegations that may still be applied: live, and
// from a peer this instance still trusts to approve for it.
//
// The trust check belongs with the delegations rather than with the engine
// because it is a question about trust records, and this is the one place that
// holds both. A pairing revoked between one request and the next has to take
// its standing permissions with it — otherwise a peer that is no longer trusted
// would go on answering for this instance until its last delegation ran out.
func (v *Vault) UsableDelegations() ([]*ladulasv1.Delegation, error) {
	held, err := v.Delegations()
	if err != nil {
		return nil, err
	}

	approvers := make(map[string]bool)

	for _, record := range v.Peers() {
		if record.GetMayApprove() {
			approvers[record.GetFingerprint()] = true
		}
	}

	out := make([]*ladulasv1.Delegation, 0, len(held))

	for _, item := range held {
		d := item.GetDelegation()

		if !approvers[d.GetApproverFingerprint()] {
			continue
		}

		out = append(out, d)
	}

	return out, nil
}

// AddDelegation records a delegation this instance has been given.
//
// One that arrives twice replaces what was there rather than being added
// beside it: an approver re-issuing a delegation after a lost answer is the
// ordinary case, and two records of one promise would report every use twice.
// The ledger is carried across, because it is about the promise and not about
// the copy of the artifact.
func (v *Vault) AddDelegation(
	signed *ladulasv1.SignedDelegation, d *ladulasv1.Delegation,
) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	held := &storepb.HeldDelegation{
		Signed:     proto.CloneOf(signed),
		Delegation: proto.CloneOf(d),
		ReceivedAt: timestamppb.Now(),
	}

	kept := make([]*storepb.HeldDelegation, 0, len(v.doc.GetHeldDelegations())+1)

	for _, existing := range v.doc.GetHeldDelegations() {
		if existing.GetDelegation().GetDelegationId() == d.GetDelegationId() {
			held.UnreportedUses = existing.GetUnreportedUses()
			held.UseCount = existing.GetUseCount()

			continue
		}

		kept = append(kept, existing)
	}

	v.doc.HeldDelegations = append(kept, held)

	return v.save()
}

// DropDelegations forgets delegations by id and says how many there were.
//
// It is what a revocation arriving from the approver does, and what revoking
// the pairing itself does to everything that approver ever granted.
func (v *Vault) DropDelegations(ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}

	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[id] = true
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	var dropped int

	kept := make([]*storepb.HeldDelegation, 0, len(v.doc.GetHeldDelegations()))

	for _, held := range v.doc.GetHeldDelegations() {
		if wanted[held.GetDelegation().GetDelegationId()] {
			dropped++

			continue
		}

		kept = append(kept, held)
	}

	if dropped == 0 {
		return 0, nil
	}

	v.doc.HeldDelegations = kept

	if err := v.save(); err != nil {
		return 0, err
	}

	return dropped, nil
}

// DropDelegationsFrom forgets everything one approver granted. Revoking a
// pairing has to take the standing permissions with it, or a peer that is no
// longer trusted would go on answering for this instance until its last
// delegation ran out.
func (v *Vault) DropDelegationsFrom(approverFingerprint string) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	var dropped int

	kept := make([]*storepb.HeldDelegation, 0, len(v.doc.GetHeldDelegations()))

	for _, held := range v.doc.GetHeldDelegations() {
		if held.GetDelegation().GetApproverFingerprint() == approverFingerprint {
			dropped++

			continue
		}

		kept = append(kept, held)
	}

	if dropped == 0 {
		return 0, nil
	}

	v.doc.HeldDelegations = kept

	if err := v.save(); err != nil {
		return 0, err
	}

	return dropped, nil
}

// RecordDelegationUse writes down that a delegation answered a request.
//
// It is called on the way to signing rather than after it, because the promise
// was spent when it was applied: a signature that then failed for some other
// reason is still something the approver asked to be told about.
func (v *Vault) RecordDelegationUse(use *ladulasv1.GrantUse) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	for _, held := range v.doc.GetHeldDelegations() {
		if held.GetDelegation().GetDelegationId() != use.GetGrantId() {
			continue
		}

		held.UseCount++
		held.UnreportedUses = append(held.GetUnreportedUses(), proto.CloneOf(use))

		if extra := len(held.GetUnreportedUses()) - maxUnreportedUses; extra > 0 {
			held.UnreportedUses = held.GetUnreportedUses()[extra:]
		}

		return v.save()
	}

	return fmt.Errorf("no delegation %q to record a use against", use.GetGrantId())
}

// UnreportedUses is everything this instance has self-approved and not yet been
// acknowledged for, oldest first, across every delegation it holds.
func (v *Vault) UnreportedUses(approverFingerprint string) []*ladulasv1.GrantUse {
	v.mu.Lock()
	defer v.mu.Unlock()

	var out []*ladulasv1.GrantUse

	for _, held := range v.doc.GetHeldDelegations() {
		if approverFingerprint != "" &&
			held.GetDelegation().GetApproverFingerprint() != approverFingerprint {
			continue
		}

		for _, use := range held.GetUnreportedUses() {
			out = append(out, proto.CloneOf(use))
		}
	}

	return out
}

// AcknowledgeUses drops the entries an approver has said it recorded.
//
// Acknowledging by request id rather than by "everything up to here" is what
// makes a report that was delivered while its answer was lost harmless: the
// second delivery names the same ids, and the second acknowledgement finds
// nothing left to drop.
func (v *Vault) AcknowledgeUses(requestIDs []string) error {
	if len(requestIDs) == 0 {
		return nil
	}

	done := make(map[string]bool, len(requestIDs))
	for _, id := range requestIDs {
		done[id] = true
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	var changed bool

	for _, held := range v.doc.GetHeldDelegations() {
		kept := make([]*ladulasv1.GrantUse, 0, len(held.GetUnreportedUses()))

		for _, use := range held.GetUnreportedUses() {
			if done[use.GetRequestId()] {
				changed = true

				continue
			}

			kept = append(kept, use)
		}

		held.UnreportedUses = kept
	}

	if !changed {
		return nil
	}

	return v.save()
}

// RecordGrantUses files what a requester reported against the grant that
// allowed it — the approver's side of the same ledger.
//
// The count is complete and the list is the tail (decision P): a grant used two
// hundred times is one line that says two hundred, and the last few are there
// for whoever wants to see what they were.
func (v *Vault) RecordGrantUses(uses []*ladulasv1.GrantUse) error {
	if len(uses) == 0 {
		return nil
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	var changed bool

	for _, use := range uses {
		for _, grant := range v.doc.GetGrants() {
			if grant.GetGrantId() != use.GetGrantId() {
				continue
			}

			if hasUse(grant.GetRecentUses(), use.GetRequestId()) {
				break
			}

			grant.UseCount++
			grant.RecentUses = append(grant.GetRecentUses(), proto.CloneOf(use))

			if extra := len(grant.GetRecentUses()) - maxRecentUses; extra > 0 {
				grant.RecentUses = grant.GetRecentUses()[extra:]
			}

			changed = true

			break
		}
	}

	if !changed {
		return nil
	}

	return v.save()
}

// maxRecentUses bounds what is kept about a grant on the approver.
const maxRecentUses = 64

func hasUse(uses []*ladulasv1.GrantUse, requestID string) bool {
	for _, use := range uses {
		if use.GetRequestId() == requestID {
			return true
		}
	}

	return false
}

// HoldsKey reports whether a key is one this instance holds itself.
//
// It is what decides where a TTL grant lives (decision P): a key held here is
// one the requester has to come back for every time, so a promise about it can
// only be kept here. A key it holds itself is one it could already sign with
// unasked, and keeping the promise here would only mean it waiting for this
// instance to be awake.
func (v *Vault) HoldsKey(fingerprint string) bool {
	if fingerprint == "" {
		return false
	}

	for _, key := range v.Keys() {
		if key.GetFingerprint() == fingerprint {
			return true
		}
	}

	return false
}
