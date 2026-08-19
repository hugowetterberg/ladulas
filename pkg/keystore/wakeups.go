package keystore

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// Wake-up routes live in the store document beside the trust records (§11).
//
// Both halves belong there for the same reason the trust records do. What a peer
// announced is "that machine is a phone, reachable at this relay under this
// identifier" — the peer map again, plus a capability that wakes it. What this
// instance registered is the identifier somebody else's requester will use to
// wake this device, which is the same thing seen from the other end.
//
// Nothing here is authority for anything, and a store that has lost all of it
// still approves: an instance with no routes polls, which is where every wake-up
// path degrades to anyway.

// PeerWakeups returns what peers have announced about being woken.
func (v *Vault) PeerWakeups() []*storepb.PeerWakeup {
	v.mu.RLock()
	defer v.mu.RUnlock()

	out := make([]*storepb.PeerWakeup, 0, len(v.doc.GetPeerWakeups()))
	for _, wakeup := range v.doc.GetPeerWakeups() {
		out = append(out, proto.CloneOf(wakeup))
	}

	return out
}

// PeerWakeup returns one peer's route.
func (v *Vault) PeerWakeup(fingerprint string) (*storepb.PeerWakeup, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	for _, wakeup := range v.doc.GetPeerWakeups() {
		if wakeup.GetPeerFingerprint() == fingerprint {
			return proto.CloneOf(wakeup), true
		}
	}

	return nil, false
}

// PutPeerWakeup records what a peer announced, replacing what it announced
// before. An announcement is the whole truth about that peer's route: a phone
// that has re-registered under a new identifier is not a phone with two.
func (v *Vault) PutPeerWakeup(wakeup *storepb.PeerWakeup) error {
	if wakeup.GetPeerFingerprint() == "" {
		return errors.New("keystore: a wake-up route names no peer")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	stored := proto.CloneOf(wakeup)

	for i, existing := range v.doc.GetPeerWakeups() {
		if existing.GetPeerFingerprint() != wakeup.GetPeerFingerprint() {
			continue
		}

		// A wake-up that learned nothing new is not a change worth re-encrypting
		// the whole document for, and the timestamps move on every push.
		if sameRoute(existing, stored) {
			return nil
		}

		v.doc.PeerWakeups[i] = stored

		return v.save()
	}

	v.doc.PeerWakeups = append(v.doc.GetPeerWakeups(), stored)

	return v.save()
}

// DropPeerWakeup forgets a peer's route, and says whether there was one.
//
// Called when a peer withdraws, when a relay says nothing is registered under
// its identifier, and when a pairing is revoked — the third for the same reason
// borrowed keys and published documentation go: a peer that is no longer trusted
// should not still be occupying anything.
func (v *Vault) DropPeerWakeup(fingerprint string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	kept := make([]*storepb.PeerWakeup, 0, len(v.doc.GetPeerWakeups()))

	var dropped bool

	for _, wakeup := range v.doc.GetPeerWakeups() {
		if wakeup.GetPeerFingerprint() == fingerprint {
			dropped = true

			continue
		}

		kept = append(kept, wakeup)
	}

	if !dropped {
		return false, nil
	}

	v.doc.PeerWakeups = kept

	if err := v.save(); err != nil {
		return false, err
	}

	return true, nil
}

// WakeupSettings reports how this instance has asked to be woken. Never nil, so
// that a caller reading a field off it does not have to check first.
func (v *Vault) WakeupSettings() *storepb.WakeupSettings {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.doc.GetWakeups() == nil {
		return &storepb.WakeupSettings{}
	}

	return proto.CloneOf(v.doc.GetWakeups())
}

// SetWakeupSettings records them, minting an instance id when there is none.
//
// The id is minted here rather than by the caller because it is the one part of
// the arrangement that must not change casually: it is what every requester
// holds, and a new one means every requester's route is dead until the next
// announcement. So it survives the token changing, the app restarting and
// wake-ups being switched off and on again, and it is replaced only when the
// relay is — an identifier means nothing at a relay that never issued it.
func (v *Vault) SetWakeupSettings(settings *storepb.WakeupSettings) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	stored := proto.CloneOf(settings)
	if stored == nil {
		stored = &storepb.WakeupSettings{}
	}

	current := v.doc.GetWakeups()

	switch {
	case stored.GetInstanceId() != "":
	case current.GetInstanceId() != "" &&
		current.GetRelayUrl() == stored.GetRelayUrl():
		stored.InstanceId = current.GetInstanceId()
	default:
		id, err := NewWakeupInstanceID()
		if err != nil {
			return err
		}

		stored.InstanceId = id
	}

	if proto.Equal(current, stored) {
		return nil
	}

	v.doc.Wakeups = stored

	return v.save()
}

// wakeupIDEncoding keeps the identifier short and free of anything a URL or a
// log would want to escape.
var wakeupIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewWakeupInstanceID mints an opaque identifier for a relay.
//
// Sixteen bytes, because it is a capability rather than a name: whoever holds
// one can make the device it belongs to show an empty notification, so it has to
// be unguessable, and it is never derived from anything — an identifier derived
// from an identity key would tell the relay which instance it belonged to, which
// is the one thing the relay is designed not to learn (§11).
func NewWakeupInstanceID() (string, error) {
	var buf [16]byte

	if _, err := rand.Read(buf[:]); err != nil {
		return "", errors.New("keystore: no randomness for a wake-up identifier")
	}

	return strings.ToLower(wakeupIDEncoding.EncodeToString(buf[:])), nil
}

func sameRoute(a, b *storepb.PeerWakeup) bool {
	return proto.Equal(a.GetRoute(), b.GetRoute()) &&
		a.GetQuietUntil().AsTime().Equal(b.GetQuietUntil().AsTime())
}
