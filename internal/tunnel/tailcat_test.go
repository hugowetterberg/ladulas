//go:build !notailcat

package tunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tailscale/tailcat"
	"go4.org/mem"
	"golang.org/x/crypto/curve25519"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func randomKey(t *testing.T) []byte {
	t.Helper()

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("random: %v", err)
	}

	raw[0] &= 248
	raw[31] = (raw[31] & 127) | 64

	return raw
}

func options(t *testing.T) Options {
	t.Helper()

	return Options{
		ServerKey:    randomKey(t),
		PresharedKey: randomKey(t),
		ClientKey:    randomKey(t),
	}
}

// The client key a peer admits is the X25519 public half of the raw key the
// store generated: the store generates keys without tailcat, so the two have
// to agree on what a key is (decision AX).
func TestTheClientKeyIsTheStoredKeysPublicHalf(t *testing.T) {
	opts := options(t)

	tunnel, err := New(opts)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	want, err := curve25519.X25519(opts.ClientKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}

	if !bytes.Equal(tunnel.ClientKey(), want) {
		t.Errorf("client key %x, want %x", tunnel.ClientKey(), want)
	}
}

// A key of the wrong size, or a persisted region that does not read, is a
// tunnel that is not built rather than one that starts with something else.
func TestNewRefusesWhatItCannotUse(t *testing.T) {
	short := options(t)
	short.ServerKey = short.ServerKey[:16]

	if _, err := New(short); err == nil {
		t.Error("a short server key was accepted")
	}

	garbled := options(t)
	garbled.Region = []byte("{")

	if _, err := New(garbled); err == nil {
		t.Error("an unreadable region was accepted")
	}
}

// RelayRegion hands pkg/peer's region rule what an address embeds, and
// KnownRelays always includes the region this server runs in, so that a peer
// in the same region is matched rather than judged (§11, §16).
func TestRelayRegionsAsTheRuleReadsThem(t *testing.T) {
	region := &tailcfg.DERPRegion{
		RegionID:   900,
		RegionCode: "home",
		Nodes: []*tailcfg.DERPNode{
			{Name: "1", HostName: "derp.example.net", IPv4: "203.0.113.9"},
			{Name: "stun", HostName: "stun.example.net", STUNOnly: true},
		},
	}

	encoded, err := json.Marshal(region)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	opts := options(t)
	opts.Region = encoded

	tunnel, err := New(opts)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	// A second region, because an address carries a list and a client
	// connects to every region in it: the rule has to see all of them.
	second := &tailcfg.DERPRegion{
		RegionID: 901,
		Nodes: []*tailcfg.DERPNode{
			{Name: "2", HostName: "metadata.internal", IPv4: "169.254.169.254",
				DERPPort: 80, STUNPort: 53, CertName: "elsewhere.example"},
		},
	}

	info := tailcat.ConnInfo{
		ServerPublic: tailcat.NodePublic{NodePublic: key.NewNode().Public()},
		Region:       []*tailcfg.DERPRegion{region, second},
	}

	got, err := tunnel.RelayRegion(string(info.Addr()))
	if err != nil {
		t.Fatalf("relay region: %v", err)
	}

	var parsed []relayRegion
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("unmarshal %q: %v", got, err)
	}

	if len(parsed) != 2 {
		t.Fatalf("the address embeds two regions and read as %+v", parsed)
	}

	if len(parsed[0].Nodes) != 1 || parsed[0].Nodes[0].Host != "derp.example.net" ||
		parsed[0].Nodes[0].IPv4 != "203.0.113.9" {
		t.Errorf("the first embedded region read as %+v", parsed[0])
	}

	if len(parsed[1].Nodes) != 1 || parsed[1].Nodes[0] != (relayNode{
		Host: "metadata.internal", IPv4: "169.254.169.254",
		DERPPort: 80, STUNPort: 53, CertName: "elsewhere.example",
	}) {
		t.Errorf("the second embedded region read as %+v", parsed[1])
	}

	if !strings.Contains(tunnel.KnownRelays(), "derp.example.net") {
		t.Errorf("the server's own region is not among the known relays: %s",
			tunnel.KnownRelays())
	}

	if tunnel.Region() != "home" {
		t.Errorf("the region is called %q", tunnel.Region())
	}

	if _, err := tunnel.RelayRegion("not an address"); err == nil {
		t.Error("a string that is not a tailcat address parsed")
	}
}

// The allowlist can be changed before the server starts and after it closes,
// since the node rebuilds it whenever a server comes up.
func TestTheAllowlistNeedsNoServer(t *testing.T) {
	tunnel, err := New(options(t))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	peer := key.NewNode().Public().AppendTo(nil)

	tunnel.Admit(peer)

	if !tunnel.allow.Contains(key.NodePublicFromRaw32(mem.B(peer))) {
		t.Error("an admitted key is not in the set")
	}

	tunnel.Revoke(peer)

	if tunnel.allow.Contains(key.NodePublicFromRaw32(mem.B(peer))) {
		t.Error("a revoked key is still in the set")
	}

	if err := tunnel.Close(); err != nil {
		t.Errorf("close an unstarted tunnel: %v", err)
	}

	if _, err := tunnel.Start(); err == nil {
		t.Error("a closed tunnel started")
	}
}
