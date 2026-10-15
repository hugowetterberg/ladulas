package dnssd

import (
	"net"
	"testing"
)

// A connection confined to named interfaces neither hears nor speaks on any
// other, and one with no names keeps upstream's behaviour of all of them
// (see doc.go). The receive half is what stops a query arriving on docker0
// from being answered at all.
func TestAConfinedConnectionKeepsToItsInterfaces(t *testing.T) {
	confined := &mdnsConn{ifaces: []string{"wlan0", "enp3s0"}}

	for name, want := range map[string]bool{
		"wlan0": true, "enp3s0": true, "docker0": false, "tailscale0": false,
	} {
		if got := confined.allowed(&net.Interface{Name: name}); got != want {
			t.Errorf("allowed(%s) = %v, want %v", name, got, want)
		}
	}

	if confined.allowed(nil) {
		t.Error("a confined connection spoke on an unnamed interface")
	}

	if open := (&mdnsConn{}); !open.allowed(&net.Interface{Name: "docker0"}) {
		t.Error("an unconfined connection refused an interface")
	}

	// Writing on a refused interface is dropped before any socket is used:
	// this connection has none, and would panic if it got that far.
	if err := confined.writeMsgTo(nil, &net.Interface{Name: "docker0"},
		AddrIPv4LinkLocalMulticast); err != nil {
		t.Errorf("a refused write returned %v", err)
	}
}
