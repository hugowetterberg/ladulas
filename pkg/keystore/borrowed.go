package keystore

import (
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// The public halves of the keys paired peers offer live in the store document
// beside the trust records (§10, decision N).
//
// They are a cache in the sense that they can always be learned again, and
// configuration in the sense that they are what a listing shows when nobody can
// be asked. The store is where they belong for the same reason the trust
// records are there: which machine holds which key is exactly the map somebody
// with the disk would want, and there is no reason to leave it lying beside the
// ciphertext.
//
// Nothing here holds private material and nothing here can be made to. A cached
// entry answers "what is there and who has it"; producing a signature is still
// a call to the holder, decided by the holder (§8, §16).

// BorrowedKeys returns the keys paired peers have offered this instance.
func (v *Vault) BorrowedKeys() []*storepb.BorrowedKey {
	v.mu.RLock()
	defer v.mu.RUnlock()

	out := make([]*storepb.BorrowedKey, 0, len(v.doc.GetBorrowedKeys()))
	for _, borrowed := range v.doc.GetBorrowedKeys() {
		out = append(out, proto.CloneOf(borrowed))
	}

	return out
}

// SetBorrowedKeys records what a peer offers, replacing everything remembered
// about that peer.
//
// Replacing rather than merging is the whole of "a key the holder no longer
// offers disappears on the next successful refresh". The caller must only reach
// here with an answer the holder actually gave: a holder that could not be
// asked has said nothing, and nothing is not the same as an empty list.
func (v *Vault) SetBorrowedKeys(
	fingerprint string, keys []*ladulasv1.KeyRef, seen time.Time,
) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	kept := make([]*storepb.BorrowedKey, 0, len(v.doc.GetBorrowedKeys())+len(keys))

	for _, borrowed := range v.doc.GetBorrowedKeys() {
		if borrowed.GetPeerFingerprint() != fingerprint {
			kept = append(kept, borrowed)
		}
	}

	at := timestamppb.New(seen)

	for _, key := range keys {
		kept = append(kept, &storepb.BorrowedKey{
			PeerFingerprint: fingerprint,
			Key:             proto.CloneOf(key),
			LastSeenAt:      at,
		})
	}

	current := v.doc.GetBorrowedKeys()

	if sameBorrowed(current, kept) && !staleBorrowed(current, fingerprint, seen) {
		return nil
	}

	v.doc.BorrowedKeys = kept

	return v.save()
}

// borrowedSeenResolution is how far the recorded last-seen may fall behind the
// truth before it is worth rewriting the store to correct it.
//
// The document is held whole and re-encrypted on every change, and a heartbeat
// that learns the same three keys every thirty seconds is not a change. What
// the recorded time has to be good enough for is the sentence a listing prints
// beside a key whose holder is not there — "last seen 4 hours ago" — and five
// minutes of slack costs that sentence nothing.
const borrowedSeenResolution = 5 * time.Minute

// staleBorrowed reports whether a peer's recorded last-seen has drifted far
// enough behind to be worth correcting. Callers hold the lock.
func staleBorrowed(
	current []*storepb.BorrowedKey, fingerprint string, seen time.Time,
) bool {
	for _, borrowed := range current {
		if borrowed.GetPeerFingerprint() != fingerprint {
			continue
		}

		if seen.Sub(borrowed.GetLastSeenAt().AsTime()) > borrowedSeenResolution {
			return true
		}
	}

	return false
}

// DropBorrowedKeys forgets everything a peer offered, and says how much it
// forgot.
//
// This is the other half of revoking a pairing, the same shape the published
// documentation has: a peer that is no longer trusted should not still be
// occupying the key list (§7).
func (v *Vault) DropBorrowedKeys(fingerprint string) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	kept := make([]*storepb.BorrowedKey, 0, len(v.doc.GetBorrowedKeys()))

	var dropped int

	for _, borrowed := range v.doc.GetBorrowedKeys() {
		if borrowed.GetPeerFingerprint() == fingerprint {
			dropped++

			continue
		}

		kept = append(kept, borrowed)
	}

	if dropped == 0 {
		return 0, nil
	}

	v.doc.BorrowedKeys = kept

	if err := v.save(); err != nil {
		return 0, err
	}

	return dropped, nil
}

// sameBorrowed reports whether two sets hold the same keys for the same peers.
//
// It exists so that a heartbeat that learns the same three keys does not
// re-encrypt and rewrite the whole store thirty seconds later. The timestamp is
// deliberately not compared: "we heard the same answer again" is not a change
// worth a disk write, and the last-seen a surface shows comes from the live
// link while there is one.
func sameBorrowed(a, b []*storepb.BorrowedKey) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i].GetPeerFingerprint() != b[i].GetPeerFingerprint() {
			return false
		}

		if a[i].GetKey().GetFingerprint() != b[i].GetKey().GetFingerprint() {
			return false
		}
	}

	return true
}
