package keystore

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// The trust records live in the same age-encrypted document as the keys (§10).
// They are not secret in the way a private key is — a peer's identity public
// key is public by construction — but which machines a person has paired with,
// and what each is allowed to do, is exactly the map an attacker with the disk
// would want, and there is no reason to leave it lying beside the ciphertext.

var _ trust.Store = (*Vault)(nil)

// Peers returns the paired peers.
func (v *Vault) Peers() []*storepb.TrustRecord {
	v.mu.RLock()
	defer v.mu.RUnlock()

	out := make([]*storepb.TrustRecord, 0, len(v.doc.GetPeers()))
	for _, record := range v.doc.GetPeers() {
		out = append(out, proto.CloneOf(record))
	}

	return out
}

// Peer finds a peer by fingerprint or by name.
func (v *Vault) Peer(ref string) (*storepb.TrustRecord, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	for _, record := range v.doc.GetPeers() {
		if trust.MatchesRef(record, ref) {
			return proto.CloneOf(record), true
		}
	}

	return nil, false
}

// PutPeer writes a trust record, replacing any record for the same identity.
//
// Replacement rather than refusal, because re-pairing a machine that was
// reinstalled is an ordinary thing to do and the identity key is what decides
// whether it is the same peer. A key that has changed is a different peer and
// gets a record of its own — and a prompt of its own, since pairing always asks.
func (v *Vault) PutPeer(record *storepb.TrustRecord) error {
	if record.GetFingerprint() == "" {
		return fmt.Errorf("keystore: a trust record needs a fingerprint")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	stored := proto.CloneOf(record)

	for i, existing := range v.doc.GetPeers() {
		if existing.GetFingerprint() == record.GetFingerprint() {
			v.doc.Peers[i] = stored

			return v.save()
		}
	}

	v.doc.Peers = append(v.doc.GetPeers(), stored)

	return v.save()
}

// RemovePeer forgets a peer, by fingerprint or by name, and reports which
// identity it forgot so the caller can go and drop the connection.
func (v *Vault) RemovePeer(ref string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	kept := make([]*storepb.TrustRecord, 0, len(v.doc.GetPeers()))

	var removed string

	for _, record := range v.doc.GetPeers() {
		if removed == "" && trust.MatchesRef(record, ref) {
			removed = record.GetFingerprint()

			continue
		}

		kept = append(kept, record)
	}

	if removed == "" {
		return "", fmt.Errorf("%w: %s", trust.ErrNoSuchPeer, ref)
	}

	v.doc.Peers = kept

	if err := v.save(); err != nil {
		return "", err
	}

	return removed, nil
}

// SetPeerDirections changes what a peer is allowed to do.
//
// The key references are resolved here, where the keys are: a caller may name a
// key by the label somebody gave it, and the record only ever holds
// fingerprints, because a label is a name this instance chose and a fingerprint
// is the key.
func (v *Vault) SetPeerDirections(
	ref string, directions trust.Directions,
) (*storepb.TrustRecord, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	resolved := make([]string, 0, len(directions.AllowedKeys))

	for _, key := range directions.AllowedKeys {
		fingerprint, err := v.keyFingerprint(key)
		if err != nil {
			return nil, err
		}

		if !contains(resolved, fingerprint) {
			resolved = append(resolved, fingerprint)
		}
	}

	directions.AllowedKeys = resolved

	for i, record := range v.doc.GetPeers() {
		if !trust.MatchesRef(record, ref) {
			continue
		}

		// The revised record takes the old one's place rather than the old one
		// being edited. Peers and Peer hand out copies, so nothing outside is
		// looking at this message — but the rule is the one trust.Store states,
		// and it holds here because a store that keeps to it is a store whose
		// readers never need a lock (§7).
		revised := directions.Applied(record)

		v.doc.Peers[i] = revised

		if err := v.save(); err != nil {
			return nil, err
		}

		return proto.CloneOf(revised), nil
	}

	return nil, fmt.Errorf("%w: %s", trust.ErrNoSuchPeer, ref)
}

// keyFingerprint resolves a label or a fingerprint to a fingerprint. Callers
// must hold the lock.
func (v *Vault) keyFingerprint(ref string) (string, error) {
	for _, key := range v.doc.GetKeys() {
		if key.GetFingerprint() == ref || strings.EqualFold(key.GetLabel(), ref) {
			return key.GetFingerprint(), nil
		}
	}

	return "", fmt.Errorf("%w: %s", ErrNoSuchKey, ref)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}

	return false
}

// RenamePeer gives a peer a different name.
func (v *Vault) RenamePeer(ref, name string) (*storepb.TrustRecord, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	for i, record := range v.doc.GetPeers() {
		if !trust.MatchesRef(record, ref) {
			continue
		}

		for _, other := range v.doc.GetPeers() {
			if other != record && strings.EqualFold(other.GetName(), name) {
				return nil, fmt.Errorf("keystore: the name %q is already taken", name)
			}
		}

		// Swapped rather than edited, for the reason SetPeerDirections gives:
		// the name is what prompts and listings call this peer, and it is read
		// off records that are out being read.
		revised := trust.Renamed(record, name)

		v.doc.Peers[i] = revised

		if err := v.save(); err != nil {
			return nil, err
		}

		return proto.CloneOf(revised), nil
	}

	return nil, fmt.Errorf("%w: %s", trust.ErrNoSuchPeer, ref)
}
