package keystore

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// The tunnel upgrade's setting and keys (§8, decision AX).
//
// The keys are transport credentials and not identity: they decide who can
// reach the pinned TLS handshake, never who is on the far end of it. They are
// kept here beside the identity key anyway, sealed with everything else,
// because a stolen client key reaches the handshake of every peer that admits
// it, and because the server key and pre-shared key are half of the address
// every peer holds — losing them changes the address, and a pair whose only
// carrier is the tunnel would have no way to hear the new one.
//
// They are generated here rather than by tailcat, so that this package stays
// free of it: a WireGuard private key is thirty-two random bytes clamped the
// way X25519 clamps them, and a pre-shared key is thirty-two random bytes.

// tunnelKeySize is the size of every tunnel key: Curve25519 private keys and a
// WireGuard pre-shared key alike.
const tunnelKeySize = 32

// TunnelSettings reports the tunnel setting and keys, or nil when nobody has
// turned the upgrade on.
func (v *Vault) TunnelSettings() *storepb.TunnelSettings {
	v.mu.RLock()
	defer v.mu.RUnlock()

	settings := v.doc.GetTunnel()
	if settings == nil {
		return nil
	}

	return proto.CloneOf(settings)
}

// SetTunnelEnabled turns the upgrade on or off and returns the setting as it
// now stands. Turning it on the first time generates the keys; turning it off
// keeps them, so that turning it back on offers the same address.
func (v *Vault) SetTunnelEnabled(enabled bool) (*storepb.TunnelSettings, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	settings := proto.CloneOf(v.doc.GetTunnel())
	if settings == nil {
		settings = &storepb.TunnelSettings{}
	}

	if settings.GetEnabled() == enabled && (!enabled || hasTunnelKeys(settings)) {
		return proto.CloneOf(settings), nil
	}

	settings.Enabled = enabled

	if enabled && !hasTunnelKeys(settings) {
		if err := generateTunnelKeys(settings); err != nil {
			return nil, err
		}
	}

	return v.putTunnelLocked(settings)
}

// SetTunnelDERPMap records a self-hosted DERP map URL, or the empty string for
// the default fleet. With repick the persisted region is forgotten as well, so
// that the next start picks again from whichever map is set — the only way a
// region is ever re-picked, because a region that changes under a pair with no
// direct path strands it (§8).
func (v *Vault) SetTunnelDERPMap(url string, repick bool) (*storepb.TunnelSettings, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	settings := proto.CloneOf(v.doc.GetTunnel())
	if settings == nil {
		settings = &storepb.TunnelSettings{}
	}

	if settings.GetDerpMapUrl() == url && (!repick || len(settings.GetRegion()) == 0) {
		return proto.CloneOf(settings), nil
	}

	settings.DerpMapUrl = url

	if repick {
		settings.Region = nil
	}

	return v.putTunnelLocked(settings)
}

// SetTunnelRegion persists the region the server was started in the first
// time, so that it is never re-picked implicitly.
func (v *Vault) SetTunnelRegion(region []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	settings := proto.CloneOf(v.doc.GetTunnel())
	if settings == nil {
		settings = &storepb.TunnelSettings{}
	}

	if bytes.Equal(settings.GetRegion(), region) {
		return nil
	}

	settings.Region = append([]byte(nil), region...)

	_, err := v.putTunnelLocked(settings)

	return err
}

func (v *Vault) putTunnelLocked(settings *storepb.TunnelSettings) (*storepb.TunnelSettings, error) {
	settings.UpdatedAt = timestamppb.Now()
	v.doc.Tunnel = settings

	if err := v.save(); err != nil {
		return nil, err
	}

	return proto.CloneOf(settings), nil
}

func hasTunnelKeys(settings *storepb.TunnelSettings) bool {
	return len(settings.GetServerKey()) == tunnelKeySize &&
		len(settings.GetClientKey()) == tunnelKeySize &&
		len(settings.GetPresharedKey()) == tunnelKeySize
}

// generateTunnelKeys fills in whichever of the three keys is missing.
func generateTunnelKeys(settings *storepb.TunnelSettings) error {
	var err error

	if len(settings.GetServerKey()) != tunnelKeySize {
		if settings.ServerKey, err = newCurve25519Key(); err != nil {
			return err
		}
	}

	if len(settings.GetClientKey()) != tunnelKeySize {
		if settings.ClientKey, err = newCurve25519Key(); err != nil {
			return err
		}
	}

	if len(settings.GetPresharedKey()) != tunnelKeySize {
		settings.PresharedKey = make([]byte, tunnelKeySize)
		if _, err := rand.Read(settings.PresharedKey); err != nil {
			return fmt.Errorf("keystore: generate the tunnel pre-shared key: %w", err)
		}
	}

	return nil
}

// newCurve25519Key is a WireGuard private key: random, clamped as RFC 7748
// clamps an X25519 scalar, which is what tailscale's own key.NewNode does.
func newCurve25519Key() ([]byte, error) {
	key := make([]byte, tunnelKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("keystore: generate a tunnel key: %w", err)
	}

	key[0] &= 248
	key[31] = (key[31] & 127) | 64

	return key, nil
}
