package trust_test

import (
	"slices"
	"testing"
	"time"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// What may go into an address list is what a TCP dial can use, and nothing
// else: a tunnel's address string is the case this is for.
func TestIsDirectAddress(t *testing.T) {
	t.Parallel()

	for address, want := range map[string]bool{
		"192.168.1.10:7373":            true,
		"[fd7a:115c:a1e0::9701]:7373":  true,
		"guppy.tail1234.ts.net:7373":   true,
		"tc1qexampletailcataddress":    false,
		"192.168.1.10":                 false,
		"guppy.tail1234.ts.net:":       false,
		"":                             false,
		"fd7a:115c:a1e0::9701:eb1f:73": false,
	} {
		if got := trust.IsDirectAddress(address); got != want {
			t.Errorf("IsDirectAddress(%q) = %v, want %v", address, got, want)
		}
	}

	got := trust.DirectAddresses([]string{
		"tc1qexample", "192.168.1.10:7373", "nope", "100.74.235.31:7373",
	})

	if !slices.Equal(got, []string{"192.168.1.10:7373", "100.74.235.31:7373"}) {
		t.Errorf("DirectAddresses kept %v", got)
	}

	if got := trust.DirectAddresses([]string{"tc1qexample"}); got != nil {
		t.Errorf("nothing direct left %v, want nil", got)
	}
}

// One rule for whether a peer can be dialled, asked the same way of a record,
// a pending pairing and the control API's peer: "has an address", or "offers a
// tunnel server this instance can raise a client to" (decision AY). The point
// of the test is that every caller gets that answer from here.
func TestDialableIsOneRule(t *testing.T) {
	t.Parallel()

	addressed := []string{"192.168.1.10:7373"}

	if !trust.Dialable(&storepb.TrustRecord{Addresses: addressed}, 0) {
		t.Error("a record with an address is not dialable")
	}

	if trust.Dialable(&storepb.TrustRecord{}, 1) {
		t.Error("a record with no address, a phone's, is dialable")
	}

	tunnelOnly := &storepb.TrustRecord{Tunnel: &ladulasv1.TunnelOffer{
		Versions: []uint32{1}, ServerAddress: "tcdesk", ClientKey: []byte{1},
	}}

	if !trust.Dialable(tunnelOnly, 1) {
		t.Error("a tunnel-only peer this instance can raise to is not dialable")
	}

	// The bug decision AX switched the clause off for, which must not come
	// back through an instance with the upgrade off: a tunnel-only peer moved
	// onto a link that could never connect, and asked nothing from then on.
	if trust.Dialable(tunnelOnly, 0) {
		t.Error("a tunnel-only peer is dialable with the upgrade off here")
	}

	if trust.Dialable(tunnelOnly, 2) {
		t.Error("a tunnel-only peer is dialable in a version that does not meet")
	}

	phoneOffer := &storepb.TrustRecord{Tunnel: &ladulasv1.TunnelOffer{
		Versions: []uint32{1}, ClientKey: []byte{1},
	}}

	if trust.Dialable(phoneOffer, 1) {
		t.Error("a phone's offer, a client key and no server, is dialable")
	}

	if !trust.PendingDialable(&storepb.PendingPairing{Addresses: addressed}) {
		t.Error("a pending pairing with an address is not dialable")
	}

	if trust.PendingDialable(&storepb.PendingPairing{}) {
		t.Error("a pending pairing with no address is dialable")
	}

	// The daemon's word is taken without an address list: once a path that is
	// not an address exists, a dialable peer may have none to report.
	if !trust.StatusDialable(&ladulasv1.PeerStatus{Dialable: true}) {
		t.Error("a peer the daemon calls dialable is not")
	}

	// An older daemon does not send the field, and its address list is proof.
	if !trust.StatusDialable(&ladulasv1.PeerStatus{Addresses: addressed}) {
		t.Error("a peer from an older daemon with an address is not dialable")
	}

	if trust.StatusDialable(&ladulasv1.PeerStatus{}) {
		t.Error("a peer with neither is dialable")
	}
}

// The pill reads dialability, not the address list. A peer the daemon says it
// can dial is described as a machine that listens even with no address in the
// status, which is what a tunnel-only peer will look like.
func TestDescribeStatusReadsDialableNotAddresses(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

	listens := &ladulasv1.PeerStatus{
		Dialable:   true,
		MayApprove: true,
		LastError:  "connection refused",
	}

	if state := trust.DescribeStatus(listens, now); state != "offline" {
		t.Errorf("a dialable peer with no address and a failed dial is %q", state)
	}

	phone := &ladulasv1.PeerStatus{MayApprove: true}

	if state := trust.DescribeStatus(phone, now); state != "waiting to hear from it" {
		t.Errorf("a phone nothing has heard from is %q", state)
	}
}

// The ordinary path is not named, so every pill that read "connected" before
// still does. A path that is not the ordinary one is.
func TestDescribeStateNamesOnlyAnUnusualPath(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

	for path, want := range map[string]string{
		trust.PathDirect: "connected",
		// An older daemon sends no path.
		"":                     "connected",
		trust.PathTunnelDirect: "connected, tunnel direct",
		"tunnel relayed fra":   "connected, tunnel relayed fra",
	} {
		state := trust.DescribeState(trust.PeerState{
			Online: true, Dialable: true, Path: path, MayApprove: true,
		}, now)

		if state != want {
			t.Errorf("online over %q is %q, want %q", path, state, want)
		}
	}
}

// The tunnel's words, in the order somebody asks about them (decision AY).
func TestDescribeTunnel(t *testing.T) {
	t.Parallel()

	offer := &ladulasv1.TunnelOffer{
		Versions: []uint32{1}, ServerAddress: "tcdesk", ClientKey: []byte{1},
	}
	both := &storepb.TrustRecord{Addresses: []string{"192.168.1.10:7373"}, Tunnel: offer}
	tunnelOnly := &storepb.TrustRecord{Tunnel: offer}
	later := time.Now().Add(time.Minute).Unix()

	for _, tc := range []struct {
		name   string
		record *storepb.TrustRecord
		facts  *trust.TunnelFacts
		want   string
	}{
		{"off here", both, &trust.TunnelFacts{}, trust.TunnelOffHere},
		{"no offer", &storepb.TrustRecord{}, &trust.TunnelFacts{Ours: 1}, trust.TunnelNoOffer},
		{"withdrawn", &storepb.TrustRecord{Tunnel: &ladulasv1.TunnelOffer{}},
			&trust.TunnelFacts{Ours: 1}, trust.TunnelWithdrawn},
		{"mismatch", both, &trust.TunnelFacts{Ours: 2}, "version mismatch (ours 2, theirs 1)"},
		{"punched", both, &trust.TunnelFacts{Ours: 1, Path: trust.PathTunnelDirect},
			"tunnel direct"},
		{"relayed", both, &trust.TunnelFacts{
			Ours: 1, Path: trust.TunnelPath(true, "fra"),
		}, "tunnel relayed fra"},
		{"stranded", tunnelOnly, &trust.TunnelFacts{Ours: 1, BackoffUntil: later},
			trust.TunnelStaleDirect},
		{"stale", both, &trust.TunnelFacts{Ours: 1, Stale: true}, trust.TunnelStale},
		{"fallback", both, &trust.TunnelFacts{
			Ours: 1, Path: trust.PathDirect, Address: "192.168.1.10:7373",
			Fallback: "i/o timeout", BackoffUntil: later,
		}, "fallback to direct, because i/o timeout"},
		{"backoff", both, &trust.TunnelFacts{Ours: 1, BackoffUntil: later},
			"tunnel in backoff until " + time.Unix(later, 0).Local().Format("15:04:05")},
		{"direct", both, &trust.TunnelFacts{
			Ours: 1, Path: trust.PathDirect, Address: "192.168.1.10:7373",
		}, "direct 192.168.1.10:7373"},
		{"offered", both, &trust.TunnelFacts{Ours: 1}, trust.TunnelOffered},
	} {
		if got := trust.DescribeTunnel(tc.record, tc.facts); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}
