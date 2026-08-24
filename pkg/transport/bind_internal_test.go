package transport

import (
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestOneTierIsChosen is decision AH: the best group of addresses present is
// bound, and the others are reported rather than dropped.
func TestOneTierIsChosen(t *testing.T) {
	tailnet := []string{"100.74.235.31:7373"}
	private := []string{"192.168.1.201:7373"}
	loopback := []string{"127.0.0.1:7373"}

	cases := []struct {
		name    string
		in      [3][]string
		tier    string
		bind    []string
		skipped []string
	}{
		{
			name: "a tailnet takes everything else out",
			in:   [3][]string{tailnet, private, loopback},
			tier: TierTailnet,
			bind: tailnet,
			// Both of the others, and each with a reason: an address that is
			// missing from the listener has to be findable with an explanation
			// attached.
			skipped: []string{"192.168.1.201:7373", "127.0.0.1:7373"},
		},
		{
			name:    "no tailnet leaves the local network",
			in:      [3][]string{nil, private, loopback},
			tier:    TierPrivate,
			bind:    private,
			skipped: []string{"127.0.0.1:7373"},
		},
		{
			name: "loopback is what is left when there is nothing else",
			in:   [3][]string{nil, nil, loopback},
			tier: TierLoopback,
			bind: loopback,
		},
		{
			name: "a machine with no addresses can still pair with itself",
			in:   [3][]string{nil, nil, nil},
			tier: TierLoopback,
			bind: []string{"127.0.0.1:7373"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := chooseTier("7373", tc.in[0], tc.in[1], tc.in[2], nil)

			if got.Tier != tc.tier {
				t.Errorf("chose the %s tier, want %s", got.Tier, tc.tier)
			}

			if !slices.Equal(got.Bind, tc.bind) {
				t.Errorf("bound %v, want %v", got.Bind, tc.bind)
			}

			var skipped []string
			for _, one := range got.Skipped {
				skipped = append(skipped, one.Address)

				if one.Reason == "" {
					t.Errorf("%s was skipped with no reason given", one.Address)
				}
			}

			if !slices.Equal(skipped, tc.skipped) {
				t.Errorf("skipped %v, want %v", skipped, tc.skipped)
			}
		})
	}
}

// TestContainerInterfacesAreNotBound records which names are read as a runtime's
// and which are not, since the rule is a guess about a name and the guess is
// what the reported reason exists to make visible.
func TestContainerInterfacesAreNotBound(t *testing.T) {
	virtual := []string{
		"docker0", "br-44b66d223581", "veth8459992", "virbr0",
		"mpqemubr0", "vnet3", "podman0", "vboxnet0", "vmnet1",
	}

	real := []string{"eth0", "enp1s0f0", "wlan0", "tailscale0", "lo", "br0",
		"bridge0", "bond0", "wg0"}

	for _, name := range virtual {
		if !virtualInterface(name) {
			t.Errorf("%s was taken for a real interface", name)
		}
	}

	for _, name := range real {
		if virtualInterface(name) {
			t.Errorf("%s was taken for a container's", name)
		}
	}
}

// TestTailnetNameIsAdvertisedInFrontOfTheAddress covers the friendly half of
// §8's advertising: the name goes first because it is what a person recognises,
// and the address stays because a peer with no MagicDNS still has to be able to
// dial.
func TestTailnetNameIsAdvertisedInFrontOfTheAddress(t *testing.T) {
	previous := tailnetName

	forgetTailnetNames()

	t.Cleanup(func() {
		tailnetName = previous

		forgetTailnetNames()
	})

	tailnetName = func(host string) string {
		if host == "100.74.235.31" || host == "fd7a:115c:a1e0::9701:eb1f" {
			return "horatio.tail97712.ts.net"
		}

		return ""
	}

	got := advertise([]string{
		"100.74.235.31:7373", "[fd7a:115c:a1e0::9701:eb1f]:7373",
	}, nil)

	want := []string{
		"horatio.tail97712.ts.net:7373",
		"100.74.235.31:7373", "[fd7a:115c:a1e0::9701:eb1f]:7373",
	}

	if !slices.Equal(got, want) {
		t.Errorf("advertised %v, want %v", got, want)
	}

	// One name for two addresses of the same node, not two identical entries.
	if strings.Count(strings.Join(got, " "), "horatio") != 1 {
		t.Errorf("the node name is advertised more than once: %v", got)
	}

	// A LAN address is advertised as itself. Its reverse name is somebody's
	// router's idea of a hostname and resolves nowhere a peer can use.
	lan := advertise([]string{"192.168.1.201:7373"}, nil)
	if !slices.Equal(lan, []string{"192.168.1.201:7373"}) {
		t.Errorf("advertised %v for a local network address", lan)
	}
}

// TestAListenSpecificationCanNameSeveralAddresses covers the management half of
// decision AH: what `ladulas listen set` writes down has to be resolvable.
func TestAListenSpecificationCanNameSeveralAddresses(t *testing.T) {
	selection, err := Select("127.0.0.1:7373, 10.1.2.3, 127.0.0.1:7373", false)
	if err != nil {
		t.Fatalf("resolve a list: %v", err)
	}

	want := []string{"127.0.0.1:7373", "10.1.2.3:7373"}

	if !slices.Equal(selection.Bind, want) {
		t.Errorf("bound %v, want %v — a repeated address is bound once",
			selection.Bind, want)
	}

	if selection.Tier != TierExplicit {
		t.Errorf("a named list chose the %s tier", selection.Tier)
	}

	// `auto` alongside an address is the "the policy, plus this one" case, and
	// has to produce both.
	mixed, err := Select("auto,10.1.2.3", false)
	if err != nil {
		t.Fatalf("resolve auto with an address: %v", err)
	}

	if !slices.Contains(mixed.Bind, "10.1.2.3:7373") {
		t.Errorf("the named address is missing from %v", mixed.Bind)
	}

	if len(mixed.Bind) < 2 {
		t.Errorf("the automatic addresses are missing from %v", mixed.Bind)
	}

	for _, spec := range []string{"off", "none", " off "} {
		selection, err := Select(spec, false)
		if err != nil {
			t.Fatalf("resolve %q: %v", spec, err)
		}

		if len(selection.Bind) != 0 || selection.Tier != TierNone {
			t.Errorf("%q resolved to %v (%s), want nothing",
				spec, selection.Bind, selection.Tier)
		}
	}

	if _, err := Select("127.0.0.1,off", false); err == nil {
		t.Error("`off` was accepted as one address among several")
	}
}

// TestTheAutomaticPolicyBindsNothingItCannotExplain is the property the reported
// skips exist for: every address on the machine is either bound or accounted
// for, so that "where did my listener go" always has an answer.
func TestTheAutomaticPolicyBindsNothingItCannotExplain(t *testing.T) {
	selection, err := Select("", false)
	if err != nil {
		t.Fatalf("resolve the automatic policy: %v", err)
	}

	addresses, err := net.Interfaces()
	if err != nil {
		t.Skipf("no interfaces to check against: %v", err)
	}

	for _, iface := range addresses {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || (ipNet.IP.IsLinkLocalUnicast() && ipNet.IP.To4() == nil) {
				continue
			}

			address := net.JoinHostPort(ipNet.IP.String(), "7373")

			if slices.Contains(selection.Bind, address) {
				continue
			}

			if !slices.ContainsFunc(selection.Skipped,
				func(one SkippedAddress) bool {
					return one.Address == address
				}) {
				t.Errorf("%s on %s was neither bound nor accounted for",
					address, iface.Name)
			}
		}
	}
}

// TestAFailedNameLookupIsAskedAgain is the bug the lazy lookup exists for.
//
// The name used to be resolved once, when the channel bound, and a resolver
// that was a second from being ready — which is the ordinary state of a machine
// that has just restarted the daemon — cost the node name for as long as the
// channel stayed up. A pairing made in that window wrote the number into the
// peer's trust record, and nothing refreshes one.
//
// So: a miss must not be final, and a hit must not be re-asked every time
// somebody looks. Both halves are here, because the cheap fix for either one
// alone is the other one's bug.
func TestAFailedNameLookupIsAskedAgain(t *testing.T) {
	previous := tailnetName
	previousMissTTL := tailnetMissTTL

	forgetTailnetNames()

	t.Cleanup(func() {
		tailnetName = previous
		tailnetMissTTL = previousMissTTL

		forgetTailnetNames()
	})

	// Long enough that the second call inside the window is served from the
	// cache, short enough that the test is not a sleep.
	tailnetMissTTL = 20 * time.Millisecond

	var (
		lookups int
		ready   bool
	)

	tailnetName = func(string) string {
		lookups++

		if !ready {
			return ""
		}

		return "horatio.tail97712.ts.net"
	}

	address := []string{"100.74.235.31:7373"}

	var missed []string

	miss := func(host string) {
		missed = append(missed, host)
	}

	// The resolver is not answering yet: the address is advertised as itself,
	// which is the documented fallback, and the caller is told once.
	if got := advertise(address, miss); !slices.Equal(got, address) {
		t.Errorf("advertised %v before the resolver answered, want %v",
			got, address)
	}

	if !slices.Equal(missed, []string{"100.74.235.31"}) {
		t.Errorf("reported misses %v, want the address once", missed)
	}

	// Asking again inside the window costs no lookup and no second log line.
	_ = advertise(address, miss)

	if lookups != 1 {
		t.Errorf("%d lookups inside the miss window, want 1", lookups)
	}

	if len(missed) != 1 {
		t.Errorf("reported %d misses inside the window, want 1", len(missed))
	}

	// The resolver comes up, and the answer stops being the one from before.
	ready = true

	time.Sleep(2 * tailnetMissTTL)

	want := []string{"horatio.tail97712.ts.net:7373", "100.74.235.31:7373"}
	if got := advertise(address, miss); !slices.Equal(got, want) {
		t.Errorf("advertised %v once the resolver answered, want %v", got, want)
	}

	// And the name that was found is kept, rather than looked up per question.
	before := lookups

	_ = advertise(address, miss)

	if lookups != before {
		t.Errorf("looked the name up again after finding it (%d then %d)",
			before, lookups)
	}
}
