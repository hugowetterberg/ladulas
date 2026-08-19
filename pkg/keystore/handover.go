package keystore

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// Handing a portable key to a paired peer is the one thing in Ladulås that
// moves key material, and decision S is what it is allowed to look like: the
// sender writes down that the key has gone, the receiver holds the offer aside
// until somebody accepts it, and neither end pretends the transfer can be
// undone (§10).
//
// This file is both halves of the store's part of it. What is deliberately not
// here: any way to send without naming a peer, any way for an offer to become a
// key without an acceptance, and any acceptance that keeps a note about a
// refusal — a refused key is forgotten, because the only record worth having is
// on the side that decided to send it.

// ErrHardwareKey is returned when something asks for the private half of a key
// that has none here.
var ErrHardwareKey = errors.New("keystore: the key is in the secure element and cannot be handed over")

// ErrNoSuchOffer is returned for an offer id nothing knows.
var ErrNoSuchOffer = errors.New("keystore: no key offer with that id")

// MaxPendingKeyOffers caps how many unanswered offers a store keeps.
//
// A paired peer can write to this list by sending, so it is bounded: an
// approver that has been taken over should not be able to grow somebody's store
// a megabyte at a time. The number is small because the list is a thing a
// person answers, and a store with eight unanswered key offers in it has a
// problem that a ninth would not describe any better.
const MaxPendingKeyOffers = 8

// ErrTooManyOffers is returned when the pending list is full.
var ErrTooManyOffers = fmt.Errorf(
	"keystore: %d key offers are already waiting to be answered", MaxPendingKeyOffers)

// PortableKey resolves a key by label or fingerprint for handing over.
//
// It returns the private half, which almost nothing in this package does. The
// two refusals are the ones worth being explicit about: a key that is not here,
// and a key whose private half is in the secure element, where "cannot be sent"
// is a property of the hardware rather than a rule this code enforces.
func (v *Vault) PortableKey(ref string) (*storepb.StoredKey, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	for _, k := range v.doc.GetKeys() {
		if k.GetFingerprint() != ref && !strings.EqualFold(k.GetLabel(), ref) {
			continue
		}

		if k.GetHardwareHandle() != "" {
			return nil, fmt.Errorf("%w: %s", ErrHardwareKey, k.GetLabel())
		}

		return proto.CloneOf(k), nil
	}

	return nil, fmt.Errorf("%w: %s", ErrNoSuchKey, ref)
}

// noteHandoverLocked writes onto the key that it is now somewhere else too.
//
// What it records became true when the bytes left, which is why it is written at
// delivery and not at acceptance: whether the far side ever says yes changes
// nothing about where the key has been. A second handover to the same peer
// replaces the first — the fact worth keeping is that the peer has it, not how
// many times it was sent. Callers hold the write lock.
func (v *Vault) noteHandoverLocked(done *storepb.QueuedKeyHandover, at time.Time) {
	for _, k := range v.doc.GetKeys() {
		if k.GetFingerprint() != done.GetFingerprint() {
			continue
		}

		kept := make([]*storepb.KeyTransfer, 0, len(k.GetHandedTo())+1)

		for _, transfer := range k.GetHandedTo() {
			if transfer.GetPeerFingerprint() != done.GetPeerFingerprint() {
				kept = append(kept, transfer)
			}
		}

		k.HandedTo = append(kept, &storepb.KeyTransfer{
			PeerFingerprint: done.GetPeerFingerprint(),
			PeerName:        done.GetPeerName(),
			At:              timestamppb.New(at),
		})

		return
	}
}

// PendingKeyOffers returns the keys peers have handed over and nobody has
// answered.
func (v *Vault) PendingKeyOffers() []*storepb.PendingKeyOffer {
	v.mu.RLock()
	defer v.mu.RUnlock()

	out := make([]*storepb.PendingKeyOffer, 0, len(v.doc.GetPendingKeyOffers()))
	for _, offer := range v.doc.GetPendingKeyOffers() {
		out = append(out, proto.CloneOf(offer))
	}

	return out
}

// QueueHandover writes down that this instance means to give a key to a peer.
//
// Everything that sends a key goes through here first, including a send to a
// peer that is reachable this second: the queue is what makes delivery something
// that can be retried, and a desktop that was reachable when the passphrase was
// typed and gone by the time the call went out is not a reason to ask for the
// passphrase again. A second queue entry for the same key and peer replaces the
// first, because sending twice is one intention.
func (v *Vault) QueueHandover(
	peerFingerprint, peerName string, key *storepb.StoredKey, at time.Time,
) (*storepb.QueuedKeyHandover, error) {
	if key.GetHardwareHandle() != "" {
		return nil, fmt.Errorf("%w: %s", ErrHardwareKey, key.GetLabel())
	}

	id, err := newOfferID()
	if err != nil {
		return nil, err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	kept := make([]*storepb.QueuedKeyHandover, 0, len(v.doc.GetQueuedKeyHandovers())+1)

	for _, queued := range v.doc.GetQueuedKeyHandovers() {
		same := queued.GetPeerFingerprint() == peerFingerprint &&
			queued.GetFingerprint() == key.GetFingerprint()
		if !same {
			kept = append(kept, queued)
		}
	}

	handover := &storepb.QueuedKeyHandover{
		Id:              id,
		PeerFingerprint: peerFingerprint,
		PeerName:        peerName,
		Label:           key.GetLabel(),
		Comment:         key.GetComment(),
		Fingerprint:     key.GetFingerprint(),
		PrivateKey:      key.GetPrivateKey(),
		QueuedAt:        timestamppb.New(at),
	}

	v.doc.QueuedKeyHandovers = append(kept, handover)

	if err := v.save(); err != nil {
		return nil, err
	}

	return proto.CloneOf(handover), nil
}

// QueuedHandovers returns what has been promised to peers and not delivered.
func (v *Vault) QueuedHandovers() []*storepb.QueuedKeyHandover {
	v.mu.RLock()
	defer v.mu.RUnlock()

	out := make([]*storepb.QueuedKeyHandover, 0, len(v.doc.GetQueuedKeyHandovers()))
	for _, queued := range v.doc.GetQueuedKeyHandovers() {
		out = append(out, proto.CloneOf(queued))
	}

	return out
}

// CompleteHandover records that a queued key has reached its peer: the queue
// entry goes, and the key it was taken from says where it now also lives.
//
// One call and one save, because the two facts are the same fact. A completion
// for a key that has since been removed from the store still empties the queue —
// the bytes went, and there is nothing left here to write it onto.
func (v *Vault) CompleteHandover(id string, at time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	var (
		done *storepb.QueuedKeyHandover
		kept = make([]*storepb.QueuedKeyHandover, 0, len(v.doc.GetQueuedKeyHandovers()))
	)

	for _, queued := range v.doc.GetQueuedKeyHandovers() {
		if queued.GetId() == id {
			done = queued

			continue
		}

		kept = append(kept, queued)
	}

	if done == nil {
		return fmt.Errorf("%w: %s", ErrNoSuchHandover, id)
	}

	v.doc.QueuedKeyHandovers = kept

	v.noteHandoverLocked(done, at)

	return v.save()
}

// ErrNoSuchHandover is returned for a queued handover nothing knows.
var ErrNoSuchHandover = errors.New("keystore: no queued key handover with that id")

// DropPeerHandovers forgets what was queued for a peer being revoked.
func (v *Vault) DropPeerHandovers(peerFingerprint string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	kept := make([]*storepb.QueuedKeyHandover, 0, len(v.doc.GetQueuedKeyHandovers()))

	for _, queued := range v.doc.GetQueuedKeyHandovers() {
		if queued.GetPeerFingerprint() != peerFingerprint {
			kept = append(kept, queued)
		}
	}

	if len(kept) == len(v.doc.GetQueuedKeyHandovers()) {
		return nil
	}

	v.doc.QueuedKeyHandovers = kept

	return v.save()
}

// AddKeyOffer records a key a peer has handed over, to be answered later.
//
// The key is parsed here rather than at acceptance, so that a peer sending
// something that is not a private key is told so while it is still listening,
// and so that nothing unparseable is ever written into the store.
func (v *Vault) AddKeyOffer(
	peerFingerprint, peerName, label, comment, handoverID string,
	keyPEM []byte, at time.Time,
) (*storepb.PendingKeyOffer, error) {
	signer, normalized, err := parsePrivateKey(keyPEM, "")
	if err != nil {
		return nil, err
	}

	public := signer.PublicKey()
	fingerprint := ssh.FingerprintSHA256(public)

	if comment == "" {
		comment = keyComment(normalized)
	}

	id, err := newOfferID()
	if err != nil {
		return nil, err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	for _, k := range v.doc.GetKeys() {
		if k.GetFingerprint() == fingerprint {
			return nil, fmt.Errorf("%w as %q", ErrDuplicateKey, k.GetLabel())
		}
	}

	kept := make([]*storepb.PendingKeyOffer, 0, len(v.doc.GetPendingKeyOffers())+1)

	// The same peer offering the same key again replaces its earlier offer,
	// which is what a resend after a phone lost track of the answer looks like.
	for _, offer := range v.doc.GetPendingKeyOffers() {
		same := offer.GetPeerFingerprint() == peerFingerprint &&
			offer.GetFingerprint() == fingerprint
		if !same {
			kept = append(kept, offer)
		}
	}

	if len(kept) >= MaxPendingKeyOffers {
		return nil, ErrTooManyOffers
	}

	offer := &storepb.PendingKeyOffer{
		Id:              id,
		PeerFingerprint: peerFingerprint,
		PeerName:        peerName,
		Label:           label,
		Comment:         comment,
		Algorithm:       public.Type(),
		Fingerprint:     fingerprint,
		PublicKey:       public.Marshal(),
		PrivateKey:      normalized,
		ReceivedAt:      timestamppb.New(at),
		HandoverId:      handoverID,
	}

	v.doc.PendingKeyOffers = append(kept, offer)

	if err := v.save(); err != nil {
		return nil, err
	}

	return proto.CloneOf(offer), nil
}

// AcceptKeyOffer takes an offered key into the store.
//
// label renames it on the way in; empty keeps what the sender called it. The
// removal and the addition happen under one lock and one save, so there is no
// moment in which the key is both offered and held, or neither.
func (v *Vault) AcceptKeyOffer(id, label string) (*storepb.StoredKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	offer, kept := takeOffer(v.doc.GetPendingKeyOffers(), id)
	if offer == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchOffer, id)
	}

	signer, err := ssh.ParsePrivateKey(offer.GetPrivateKey())
	if err != nil {
		return nil, fmt.Errorf("load the offered key: %w", err)
	}

	if label == "" {
		label = offer.GetLabel()
	}

	before := v.doc.GetPendingKeyOffers()
	v.doc.PendingKeyOffers = kept

	key, err := v.addKeyLocked(
		signer, offer.GetPrivateKey(), label,
		storepb.KeyOrigin_KEY_ORIGIN_RECEIVED,
		&storepb.KeyTransfer{
			PeerFingerprint: offer.GetPeerFingerprint(),
			PeerName:        offer.GetPeerName(),
			At:              offer.GetReceivedAt(),
		})
	if err != nil {
		// Nothing has been written yet — addKeyLocked saves last — so putting
		// the offer back is enough to leave a refusable offer refusable.
		v.doc.PendingKeyOffers = before

		return nil, err
	}

	return key, nil
}

// RefuseKeyOffer forgets an offered key.
func (v *Vault) RefuseKeyOffer(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	offer, kept := takeOffer(v.doc.GetPendingKeyOffers(), id)
	if offer == nil {
		return fmt.Errorf("%w: %s", ErrNoSuchOffer, id)
	}

	v.doc.PendingKeyOffers = kept

	return v.save()
}

// DropPeerKeyOffers forgets what a peer offered, for a peer that is being
// revoked.
//
// Key material that arrived under a trust relationship has no business
// outliving it, the same way a delegation and a wake-up route do not (§7).
func (v *Vault) DropPeerKeyOffers(peerFingerprint string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	kept := make([]*storepb.PendingKeyOffer, 0, len(v.doc.GetPendingKeyOffers()))

	for _, offer := range v.doc.GetPendingKeyOffers() {
		if offer.GetPeerFingerprint() != peerFingerprint {
			kept = append(kept, offer)
		}
	}

	if len(kept) == len(v.doc.GetPendingKeyOffers()) {
		return nil
	}

	v.doc.PendingKeyOffers = kept

	return v.save()
}

func takeOffer(
	offers []*storepb.PendingKeyOffer, id string,
) (*storepb.PendingKeyOffer, []*storepb.PendingKeyOffer) {
	var (
		found *storepb.PendingKeyOffer
		kept  = make([]*storepb.PendingKeyOffer, 0, len(offers))
	)

	for _, offer := range offers {
		if offer.GetId() == id {
			found = offer

			continue
		}

		kept = append(kept, offer)
	}

	return found, kept
}

func newOfferID() (string, error) {
	handle, err := newKeyHandle()
	if err != nil {
		return "", err
	}

	return strings.TrimPrefix(handle, "ladulas-key-"), nil
}
