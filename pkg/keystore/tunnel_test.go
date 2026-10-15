package keystore_test

import (
	"bytes"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/keystore"
)

// The tunnel keys are generated the first time the upgrade is turned on and
// never again: turning it off keeps them, so turning it back on offers the
// same address, and the region persisted at the first start survives a
// restart, so it is never re-picked implicitly (decision AX).
func TestTunnelKeysAndRegionAreKept(t *testing.T) {
	vault, opts := newVault(t)

	if vault.TunnelSettings() != nil {
		t.Fatal("a new store has tunnel settings")
	}

	on, err := vault.SetTunnelEnabled(true)
	if err != nil {
		t.Fatalf("turn on: %v", err)
	}

	for name, key := range map[string][]byte{
		"server": on.GetServerKey(), "client": on.GetClientKey(),
		"pre-shared": on.GetPresharedKey(),
	} {
		if len(key) != 32 {
			t.Errorf("the %s key is %d bytes", name, len(key))
		}
	}

	// Clamped as an X25519 scalar, as a WireGuard private key is.
	if on.GetClientKey()[0]&7 != 0 || on.GetClientKey()[31]&0xc0 != 0x40 {
		t.Errorf("the client key is not clamped: %x", on.GetClientKey())
	}

	if bytes.Equal(on.GetServerKey(), on.GetClientKey()) {
		t.Error("the server and client keys are the same key")
	}

	if err := vault.SetTunnelRegion([]byte(`{"RegionID":900}`)); err != nil {
		t.Fatalf("persist the region: %v", err)
	}

	off, err := vault.SetTunnelEnabled(false)
	if err != nil {
		t.Fatalf("turn off: %v", err)
	}

	if off.GetEnabled() || !bytes.Equal(off.GetServerKey(), on.GetServerKey()) {
		t.Error("turning the tunnel off lost its keys")
	}

	reopened, err := keystore.Open(opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	again, err := reopened.SetTunnelEnabled(true)
	if err != nil {
		t.Fatalf("turn on again: %v", err)
	}

	if !bytes.Equal(again.GetServerKey(), on.GetServerKey()) ||
		!bytes.Equal(again.GetClientKey(), on.GetClientKey()) ||
		!bytes.Equal(again.GetPresharedKey(), on.GetPresharedKey()) {
		t.Error("turning the tunnel back on generated new keys")
	}

	if string(again.GetRegion()) != `{"RegionID":900}` {
		t.Errorf("the persisted region is %q", again.GetRegion())
	}

	// A new DERP map leaves the region alone unless a re-pick is asked for.
	kept, err := reopened.SetTunnelDERPMap("https://derp.example.net/map.json", false)
	if err != nil {
		t.Fatalf("set the map: %v", err)
	}

	if len(kept.GetRegion()) == 0 {
		t.Error("setting a DERP map re-picked the region without being asked")
	}

	repicked, err := reopened.SetTunnelDERPMap("https://derp.example.net/map.json", true)
	if err != nil {
		t.Fatalf("re-pick: %v", err)
	}

	if len(repicked.GetRegion()) != 0 {
		t.Error("a deliberate re-pick kept the region")
	}
}
