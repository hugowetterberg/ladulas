package keystore

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// Where the peer channel listens is in the store, and decision AH says why.
//
// It is not secret and it is not a key, which is the argument for a file beside
// the policy; what puts it here is that the control socket is the whole
// management surface (decision K) and the store is what that surface writes.
// The cost is one thing and it is stated: a sealed instance cannot be told where
// to listen, which matters not at all, because a sealed instance does not listen
// — the identity key that authenticates the channel is inside the store.

// PeerListen reports where this instance has been told to listen, or nil when
// nobody has said.
//
// Nil rather than an empty message, because the difference is load-bearing here:
// nothing stored means the flag decides, and a stored `auto` means somebody
// asked for the automatic policy and outranks a flag that says nothing.
func (v *Vault) PeerListen() *storepb.PeerListenSettings {
	v.mu.RLock()
	defer v.mu.RUnlock()

	settings := v.doc.GetPeerListen()
	if settings == nil {
		return nil
	}

	return proto.CloneOf(settings)
}

// SetPeerListen records where to listen. A nil settings clears it, which is what
// puts the flag back in charge.
func (v *Vault) SetPeerListen(settings *storepb.PeerListenSettings) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	current := v.doc.GetPeerListen()

	// The timestamp is not part of the comparison. It changes every time, so
	// including it would make setting the same address twice a write to the
	// store and a re-encryption of everything in it.
	if current.GetSpec() == settings.GetSpec() &&
		current.GetAllowPublic() == settings.GetAllowPublic() &&
		(current == nil) == (settings == nil) {
		return nil
	}

	var stored *storepb.PeerListenSettings

	if settings != nil {
		stored = proto.CloneOf(settings)
		stored.UpdatedAt = timestamppb.Now()
	}

	v.doc.PeerListen = stored

	return v.save()
}
