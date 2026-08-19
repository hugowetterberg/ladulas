package keystore

import (
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// The store's half of decision AG: promises other holders of a key have made
// about a requester, and the retractions that take them back.
//
// Two lists and they are not symmetric, which is the design rather than an
// accident of implementation. An endorsement is kept only while it could still
// be acted on and is dropped the moment anything makes it inert. A retraction
// is kept whether or not there is anything here to apply it to, because it can
// arrive before the endorsement it kills — endorsements are carried by the
// requester and retractions gossip between holders, so the two travel by
// different roads at different speeds, and the road the retraction takes is the
// one that does not run through the party with a reason to be slow.

// Endorsements returns the endorsements this instance holds, dropping any that
// have expired. Expired ones are pruned as a side effect, exactly as Grants and
// Delegations do.
func (v *Vault) Endorsements() ([]*storepb.HeldEndorsement, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	live, changed := liveEndorsements(v.doc.GetHeldEndorsements(), time.Now())

	if changed {
		v.doc.HeldEndorsements = live

		if err := v.save(); err != nil {
			return nil, err
		}
	}

	out := make([]*storepb.HeldEndorsement, 0, len(live))
	for _, held := range live {
		out = append(out, proto.CloneOf(held))
	}

	return out, nil
}

func liveEndorsements(
	all []*storepb.HeldEndorsement, now time.Time,
) ([]*storepb.HeldEndorsement, bool) {
	var (
		live    []*storepb.HeldEndorsement
		changed bool
	)

	for _, held := range all {
		if held.GetEndorsement().GetExpiresAt().AsTime().After(now) {
			live = append(live, held)

			continue
		}

		changed = true
	}

	return live, changed
}

// UsableEndorsements is the endorsements this instance may actually act on.
//
// Three questions, and none of them is about the artifact — the signatures were
// checked when it arrived. What is left is whether this instance holds the key,
// because an endorsement is a promise about signing and only a holder can keep
// one; whether the issuer is a peer this instance would have taken a live
// approval from, which is the narrow half of decision AG; and whether anybody
// has taken it back.
//
// The trust question is asked here rather than in the engine for the reason the
// same question about a delegation is: it is a question about trust records,
// and this is the one place that holds both. A pairing revoked between one
// request and the next takes its endorsements with it.
func (v *Vault) UsableEndorsements() ([]*ladulasv1.Endorsement, error) {
	held, err := v.Endorsements()
	if err != nil {
		return nil, err
	}

	retracted := v.retractionIndex()
	approvers := make(map[string]bool)

	for _, record := range v.Peers() {
		if record.GetMayApprove() {
			approvers[record.GetFingerprint()] = true
		}
	}

	out := make([]*ladulasv1.Endorsement, 0, len(held))

	for _, item := range held {
		e := item.GetEndorsement()

		if !v.HoldsKey(e.GetKeyFingerprint()) {
			continue
		}

		if !approvers[e.GetIssuerFingerprint()] {
			continue
		}

		if retracted.covers(e) {
			continue
		}

		out = append(out, e)
	}

	return out, nil
}

// InertBecause says why an endorsement would not be acted on here, in the words
// a listing shows, and is empty for one that would be.
//
// It exists because "this instance is not acting on that" and "this instance
// has never heard of that" look identical in a list that only shows what is
// live — and the second is the state somebody is looking for when they are
// working out why a machine keeps asking. A copy carried by a requester that
// holds no key is inert here and is the ordinary case, not a fault.
func (v *Vault) InertBecause(e *ladulasv1.Endorsement) string {
	if !v.HoldsKey(e.GetKeyFingerprint()) {
		return "this instance does not hold that key"
	}

	if v.retractionIndex().covers(e) {
		return "it has been retracted"
	}

	record, ok := v.Peer(e.GetIssuerFingerprint())
	if !ok {
		return "the machine that issued it is not paired with this one"
	}

	if !record.GetMayApprove() {
		return "the machine that issued it does not approve for this one"
	}

	return ""
}

// AddEndorsement records one, replacing any earlier copy of the same promise.
//
// One that arrives twice is ordinary rather than suspicious: it is published to
// the holders and carried by the requester, so the same artifact reaches a
// holder by both roads. The ledger carries across, because it is about the
// promise and not about the copy — and `published` is sticky in the true
// direction, since a holder that was told before the promise was spent stays a
// holder that was told.
//
// A retraction already on file wins. Storing an endorsement that something has
// already taken back would leave it in the list looking live until the next
// time anything read the retractions, and the window between those two is
// exactly when it would be spent.
func (v *Vault) AddEndorsement(
	signed *ladulasv1.SignedEndorsement, e *ladulasv1.Endorsement,
	published bool,
) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if index := v.retractionIndexLocked(); index.covers(e) {
		return fmt.Errorf("%w: %s", ErrRetracted, e.GetEndorsementId())
	}

	held := &storepb.HeldEndorsement{
		Signed:      proto.CloneOf(signed),
		Endorsement: proto.CloneOf(e),
		ReceivedAt:  timestamppb.Now(),
		Published:   published,
	}

	kept := make([]*storepb.HeldEndorsement, 0, len(v.doc.GetHeldEndorsements())+1)

	for _, existing := range v.doc.GetHeldEndorsements() {
		if existing.GetEndorsement().GetEndorsementId() == e.GetEndorsementId() {
			held.UnreportedUses = existing.GetUnreportedUses()
			held.UseCount = existing.GetUseCount()
			held.Published = held.GetPublished() || existing.GetPublished()

			continue
		}

		kept = append(kept, existing)
	}

	v.doc.HeldEndorsements = append(kept, held)

	return v.save()
}

// ErrRetracted is an endorsement that arrived after the retraction that kills
// it, which is an ordinary race rather than an attack: the two travel by
// different roads and the retraction's is the faster one by design.
var ErrRetracted = fmt.Errorf("keystore: the endorsement has been retracted")

// DropEndorsementsFrom forgets everything one issuer promised, for a pairing
// being revoked. UsableEndorsements would already refuse them; this is so that
// a list stops showing promises from a machine this one has forgotten.
func (v *Vault) DropEndorsementsFrom(issuerFingerprint string) (int, error) {
	return v.dropEndorsements(func(e *ladulasv1.Endorsement) bool {
		return e.GetIssuerFingerprint() == issuerFingerprint
	})
}

// DropEndorsementsAbout forgets everything promised about one requester, for a
// pairing with that requester being revoked.
func (v *Vault) DropEndorsementsAbout(requesterFingerprint string) (int, error) {
	return v.dropEndorsements(func(e *ladulasv1.Endorsement) bool {
		return e.GetRequesterFingerprint() == requesterFingerprint
	})
}

// DropEndorsementsForKey forgets everything about one key, for a key being
// removed from the store.
func (v *Vault) DropEndorsementsForKey(fingerprint string) (int, error) {
	return v.dropEndorsements(func(e *ladulasv1.Endorsement) bool {
		return e.GetKeyFingerprint() == fingerprint
	})
}

func (v *Vault) dropEndorsements(match func(*ladulasv1.Endorsement) bool) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	var dropped int

	kept := make([]*storepb.HeldEndorsement, 0, len(v.doc.GetHeldEndorsements()))

	for _, held := range v.doc.GetHeldEndorsements() {
		if match(held.GetEndorsement()) {
			dropped++

			continue
		}

		kept = append(kept, held)
	}

	if dropped == 0 {
		return 0, nil
	}

	v.doc.HeldEndorsements = kept

	if err := v.save(); err != nil {
		return 0, err
	}

	return dropped, nil
}

// RecordEndorsementUse writes down that an endorsement answered a request.
//
// Called on the way to signing rather than after it, for the reason a
// delegation's ledger is: the promise was spent when it was applied, and a
// signature that then failed for some other reason is still something the
// issuer asked to be told about.
func (v *Vault) RecordEndorsementUse(use *ladulasv1.GrantUse) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	for _, held := range v.doc.GetHeldEndorsements() {
		if held.GetEndorsement().GetEndorsementId() != use.GetGrantId() {
			continue
		}

		held.UseCount++
		held.UnreportedUses = append(held.GetUnreportedUses(), proto.CloneOf(use))

		if extra := len(held.GetUnreportedUses()) - maxUnreportedUses; extra > 0 {
			held.UnreportedUses = held.GetUnreportedUses()[extra:]
		}

		return v.save()
	}

	return fmt.Errorf("no endorsement %q to record a use against",
		use.GetGrantId())
}

// UnreportedEndorsementUses is what one issuer has not been told about yet.
func (v *Vault) UnreportedEndorsementUses(
	issuerFingerprint string,
) []*ladulasv1.GrantUse {
	v.mu.Lock()
	defer v.mu.Unlock()

	var out []*ladulasv1.GrantUse

	for _, held := range v.doc.GetHeldEndorsements() {
		if held.GetEndorsement().GetIssuerFingerprint() != issuerFingerprint {
			continue
		}

		for _, use := range held.GetUnreportedUses() {
			out = append(out, proto.CloneOf(use))
		}
	}

	return out
}

// AcknowledgeEndorsementUses drops what an issuer has confirmed hearing.
func (v *Vault) AcknowledgeEndorsementUses(requestIDs []string) error {
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

	for _, held := range v.doc.GetHeldEndorsements() {
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

// Retractions returns what this instance remembers, forgetting the ones whose
// target could not still be live.
func (v *Vault) Retractions() ([]*storepb.HeldRetraction, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	live, changed := liveRetractions(v.doc.GetRetractions(), time.Now())

	if changed {
		v.doc.Retractions = live

		if err := v.save(); err != nil {
			return nil, err
		}
	}

	out := make([]*storepb.HeldRetraction, 0, len(live))
	for _, held := range live {
		out = append(out, proto.CloneOf(held))
	}

	return out, nil
}

func liveRetractions(
	all []*storepb.HeldRetraction, now time.Time,
) ([]*storepb.HeldRetraction, bool) {
	var (
		live    []*storepb.HeldRetraction
		changed bool
	)

	for _, held := range all {
		if held.GetRetraction().GetRememberUntil().AsTime().After(now) {
			live = append(live, held)

			continue
		}

		changed = true
	}

	return live, changed
}

// AddRetraction remembers one and drops whatever it kills, and says whether
// this was news.
//
// The answer is what gossip runs on: an instance that passes on every
// retraction it is told about would bounce one between two holders for as long
// as it is remembered, and one that passes on only what it had not heard
// converges after a round.
func (v *Vault) AddRetraction(
	signed *ladulasv1.SignedRetraction, r *ladulasv1.Retraction,
) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	for _, existing := range v.doc.GetRetractions() {
		if existing.GetRetraction().GetRetractionId() == r.GetRetractionId() {
			return false, nil
		}
	}

	v.doc.Retractions = append(v.doc.GetRetractions(), &storepb.HeldRetraction{
		Signed:     proto.CloneOf(signed),
		Retraction: proto.CloneOf(r),
		ReceivedAt: timestamppb.Now(),
	})

	kept := make([]*storepb.HeldEndorsement, 0, len(v.doc.GetHeldEndorsements()))

	for _, held := range v.doc.GetHeldEndorsements() {
		if retractionCovers(r, held.GetEndorsement()) {
			continue
		}

		kept = append(kept, held)
	}

	v.doc.HeldEndorsements = kept

	return true, v.save()
}

// RetractionsForKey is what this instance knows about one key, for an answer to
// a peer publishing an endorsement of it.
func (v *Vault) RetractionsForKey(
	keyFingerprint string,
) []*ladulasv1.SignedRetraction {
	held, err := v.Retractions()
	if err != nil {
		return nil
	}

	var out []*ladulasv1.SignedRetraction

	for _, item := range held {
		if item.GetRetraction().GetKeyFingerprint() != keyFingerprint {
			continue
		}

		out = append(out, item.GetSigned())
	}

	return out
}

// NoteGossiped writes down that a retraction has been passed to a peer, so that
// the next round does not send it again.
func (v *Vault) NoteGossiped(retractionID, peerFingerprint string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	for _, held := range v.doc.GetRetractions() {
		if held.GetRetraction().GetRetractionId() != retractionID {
			continue
		}

		for _, told := range held.GetGossipedTo() {
			if told == peerFingerprint {
				return nil
			}
		}

		held.GossipedTo = append(held.GetGossipedTo(), peerFingerprint)

		return v.save()
	}

	return nil
}

// retractions is the set, indexed for the one question anybody asks of it.
type retractions []*ladulasv1.Retraction

func (r retractions) covers(e *ladulasv1.Endorsement) bool {
	for _, item := range r {
		if retractionCovers(item, e) {
			return true
		}
	}

	return false
}

func (v *Vault) retractionIndex() retractions {
	v.mu.Lock()
	defer v.mu.Unlock()

	return v.retractionIndexLocked()
}

func (v *Vault) retractionIndexLocked() retractions {
	now := time.Now()
	out := make(retractions, 0, len(v.doc.GetRetractions()))

	for _, held := range v.doc.GetRetractions() {
		r := held.GetRetraction()

		if !r.GetRememberUntil().AsTime().After(now) {
			continue
		}

		out = append(out, r)
	}

	return out
}

// retractionCovers is the whole of what a retraction means.
//
// The key has to match in either form: a retraction is signed with one key's
// private half and says nothing about any other, so an identifier that happened
// to collide across two keys would otherwise let a holder of one take back a
// promise about the other.
func retractionCovers(r *ladulasv1.Retraction, e *ladulasv1.Endorsement) bool {
	if r.GetKeyFingerprint() != e.GetKeyFingerprint() {
		return false
	}

	if id := r.GetEndorsementId(); id != "" {
		return id == e.GetEndorsementId()
	}

	before := r.GetIssuedBefore()
	if before == nil {
		return false
	}

	return !e.GetCreatedAt().AsTime().After(before.AsTime())
}

// NoteEndorsementReach writes onto a grant which holders were told about its
// endorsement and which could not be reached (decision AG).
//
// The second list is the one that matters and the reason both are kept. An
// endorsement is honoured by a holder that was told nothing about it, because
// the requester carries a copy and presents it — so a holder that could not be
// reached is a holder that will keep the promise and cannot yet be told to
// stop. Rounding that off in either direction is the mistake `revoke_pending`
// exists to avoid on the other half of decision P.
func (v *Vault) NoteEndorsementReach(grantID string, told, unreached []string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	for _, g := range v.doc.GetGrants() {
		if g.GetGrantId() != grantID {
			continue
		}

		g.Endorsed = true
		g.PublishedTo = told
		g.UnreachedHolders = unreached

		return v.save()
	}

	return nil
}

// KeyHolders is every paired instance this one has reason to believe holds a
// key.
//
// Three sources and not one of them is a guess: a peer that advertises the key
// as one it lends (decision N), a peer this instance handed the key to, and the
// peer it was received from — a transfer is a copy and the store writes down
// both ends (decision S). What it cannot know about is a holder further down a
// chain of handovers this instance was not part of, which is the honest limit
// of publishing and the reason the requester carries its own copy.
func (v *Vault) KeyHolders(keyFingerprint string) []string {
	v.mu.Lock()
	defer v.mu.Unlock()

	seen := make(map[string]bool)

	var out []string

	add := func(fingerprint string) {
		if fingerprint == "" || seen[fingerprint] {
			return
		}

		seen[fingerprint] = true
		out = append(out, fingerprint)
	}

	for _, borrowed := range v.doc.GetBorrowedKeys() {
		if borrowed.GetKey().GetFingerprint() == keyFingerprint {
			add(borrowed.GetPeerFingerprint())
		}
	}

	for _, key := range v.doc.GetKeys() {
		if key.GetFingerprint() != keyFingerprint {
			continue
		}

		for _, to := range key.GetHandedTo() {
			add(to.GetPeerFingerprint())
		}

		add(key.GetReceivedFrom().GetPeerFingerprint())
	}

	return out
}

// PortableSigner answers only for a key whose private half is in this store,
// which is what confines endorsing to keys another instance could hold
// (decision AG, decision S).
func (v *Vault) PortableSigner(fingerprint string) (ssh.Signer, error) {
	if _, err := v.PortableKey(fingerprint); err != nil {
		return nil, err
	}

	signer, _, err := v.Signer(fingerprint)
	if err != nil {
		return nil, err
	}

	return signer, nil
}
