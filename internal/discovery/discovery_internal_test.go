package discovery

import (
	"context"
	"io"
	"log/slog"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/internal/dnssd"
)

const lanFlags = net.FlagUp | net.FlagRunning | net.FlagMulticast | net.FlagBroadcast

func mustNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}

	ipNet.IP = ip

	return ipNet
}

// testInterfaces is a desktop with everything the rules have an opinion
// about: a LAN, a Docker bridge, a tailnet, loopback and a second LAN.
func testInterfaces(t *testing.T) []iface {
	t.Helper()

	return []iface{
		{name: "lo", flags: net.FlagUp | net.FlagRunning | net.FlagLoopback,
			nets: []*net.IPNet{mustNet(t, "127.0.0.1/8")}},
		{name: "wlan0", flags: lanFlags, nets: []*net.IPNet{
			mustNet(t, "192.168.1.10/24"),
			mustNet(t, "fe80::1/64"),
			mustNet(t, "2001:db8::10/64"),
		}},
		{name: "docker0", flags: lanFlags,
			nets: []*net.IPNet{mustNet(t, "172.17.0.1/16")}},
		{name: "tailscale0", flags: net.FlagUp | net.FlagRunning | net.FlagMulticast,
			nets: []*net.IPNet{mustNet(t, "100.101.102.103/32")}},
		{name: "enp3s0", flags: lanFlags,
			nets: []*net.IPNet{mustNet(t, "10.0.0.5/24")}},
	}
}

func TestAnnounceTargetFollowsTheBoundAddresses(t *testing.T) {
	// What the automatic policy binds on that desktop: the tailnet and both
	// LANs. The tailnet is bound and still not announced.
	got, err := announceTarget([]string{
		"100.101.102.103:7373", "192.168.1.10:7373", "10.0.0.5:7373",
	}, testInterfaces(t))
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(got.ifaces, []string{"wlan0", "enp3s0"}) {
		t.Errorf("interfaces = %v, want wlan0 and enp3s0", got.ifaces)
	}

	if got.port != 7373 {
		t.Errorf("port = %d", got.port)
	}

	want := []net.IP{net.ParseIP("192.168.1.10"), net.ParseIP("10.0.0.5")}
	if !slices.EqualFunc(got.ips, want, net.IP.Equal) {
		t.Errorf("addresses = %v, want %v", got.ips, want)
	}
}

func TestAnnounceTargetOnlyWhatWasBound(t *testing.T) {
	got, err := announceTarget([]string{"10.0.0.5:7400"}, testInterfaces(t))
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(got.ifaces, []string{"enp3s0"}) || got.port != 7400 {
		t.Errorf("target = %+v, want enp3s0 on 7400", got)
	}
}

func TestAnnounceTargetWildcardTakesEveryEligibleInterface(t *testing.T) {
	got, err := announceTarget([]string{"[::]:7373"}, testInterfaces(t))
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(got.ifaces, []string{"wlan0", "enp3s0"}) {
		t.Errorf("interfaces = %v", got.ifaces)
	}

	// The global IPv6 address is not announced; link-local is, because a
	// wildcard listens on it.
	for _, ip := range got.ips {
		if ip.Equal(net.ParseIP("2001:db8::10")) {
			t.Errorf("announced a global address: %v", got.ips)
		}
	}

	if !slices.ContainsFunc(got.ips, net.ParseIP("fe80::1").Equal) {
		t.Errorf("link-local missing under a wildcard: %v", got.ips)
	}
}

func TestAnnounceTargetRefusesWhatIsNotALocalNetwork(t *testing.T) {
	for name, bound := range map[string][]string{
		"nothing bound":  nil,
		"loopback only":  {"127.0.0.1:7373"},
		"tailnet only":   {"100.101.102.103:7373"},
		"docker only":    {"172.17.0.1:7373"},
		"not an address": {"desk:7373"},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := announceTarget(bound, testInterfaces(t)); err == nil {
				t.Errorf("announced %+v", got)
			}
		})
	}
}

func TestPickAddressStaysOnTheInterface(t *testing.T) {
	wlan := testInterfaces(t)[1]

	cases := []struct {
		name string
		ips  []string
		want string
	}{
		{"on the subnet", []string{"192.168.1.20"}, "192.168.1.20:7373"},
		{"IPv4 before IPv6", []string{"fe80::2", "192.168.1.20"}, "192.168.1.20:7373"},
		{"link-local takes the zone", []string{"fe80::2"}, "[fe80::2%wlan0]:7373"},
		{"another subnet", []string{"10.0.0.7"}, ""},
		{"a public address", []string{"8.8.8.8"}, ""},
		{"a tailnet address", []string{"100.64.1.1"}, ""},
		{"loopback", []string{"127.0.0.1"}, ""},
		{"global IPv6", []string{"2001:db8::20"}, ""},
		{"first good one only", []string{"8.8.8.8", "192.168.1.20", "192.168.1.21"},
			"192.168.1.20:7373"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ips []net.IP
			for _, s := range c.ips {
				ips = append(ips, net.ParseIP(s))
			}

			if got := pickAddress(ips, 7373, wlan); got != c.want {
				t.Errorf("pickAddress = %q, want %q", got, c.want)
			}
		})
	}

	if got := pickAddress([]net.IP{net.ParseIP("192.168.1.20")}, 0, wlan); got != "" {
		t.Errorf("no port gave %q", got)
	}
}

func TestArrangeMergesOneWindowAndFlagsTwo(t *testing.T) {
	got := arrange([]Entry{
		{ID: "m3", Name: "desk (2)", Interface: "wlan0", tag: "bbb", order: 3},
		{ID: "m1", Name: "desk", Interface: "wlan0", tag: "aaa", order: 1},
		{ID: "m2", Name: "desk", Interface: "enp3s0", tag: "aaa", order: 2},
		{ID: "m4", Name: "laptop", Interface: "wlan0", tag: "ccc", order: 4},
	})

	ids := make([]string, 0, len(got))
	for _, entry := range got {
		ids = append(ids, entry.ID)
	}

	// The same window on two interfaces is one row, the first heard.
	if !slices.Equal(ids, []string{"m1", "m3", "m4"}) {
		t.Fatalf("rows = %v", ids)
	}

	if !got[0].Duplicate || !got[1].Duplicate {
		t.Error("two windows called desk were not both flagged")
	}

	if got[2].Duplicate {
		t.Error("laptop was flagged")
	}

	// The tag is copyable. A second row under the real window's tag and a
	// renamed name is still a second machine claiming desk.
	copied := arrange([]Entry{
		{ID: "m1", Name: "desk", Interface: "wlan0", tag: "aaa", order: 1},
		{ID: "m2", Name: "desk (2)", Interface: "wlan0", tag: "aaa", order: 2},
	})

	if len(copied) != 2 || !copied[0].Duplicate || !copied[1].Duplicate {
		t.Errorf("a copied tag hid a duplicate: %+v", copied)
	}
}

// fakeLookup stands in for the network: it hands its callbacks to the test
// and blocks until the browse is stopped.
type fakeLookup struct {
	started chan struct{}
	add     dnssd.AddFunc
	rmv     dnssd.RmvFunc
	ifs     []string
	stopped chan struct{}
}

func (f *fakeLookup) lookup(
	ctx context.Context, service string, add dnssd.AddFunc, rmv dnssd.RmvFunc,
	ifs ...string,
) error {
	if service != "_ladulas-pair._tcp.local." {
		panic("browsed for " + service)
	}

	f.add, f.rmv, f.ifs = add, rmv, ifs
	close(f.started)
	<-ctx.Done()
	close(f.stopped)

	return ctx.Err()
}

func testBrowser(t *testing.T) (*Browser, *fakeLookup) {
	t.Helper()

	fake := &fakeLookup{started: make(chan struct{}), stopped: make(chan struct{})}
	browser := NewBrowser(slog.New(slog.NewTextHandler(io.Discard, nil)))
	browser.lookup = fake.lookup

	interfaces := testInterfaces(t)
	browser.interfaces = func() ([]iface, error) { return interfaces, nil }

	return browser, fake
}

func wait(t *testing.T, ch <-chan struct{}) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}

func announcement(name, ifaceName, ip, tag string) dnssd.BrowseEntry {
	return dnssd.BrowseEntry{
		IPs:       []net.IP{net.ParseIP(ip)},
		Port:      7373,
		IfaceName: ifaceName,
		Name:      name,
		Type:      ServiceType,
		Domain:    "local",
		Text:      map[string]string{"v": "2", "tag": tag},
	}
}

func TestBrowserListsOnlyWhatPassesTheRules(t *testing.T) {
	browser, fake := testBrowser(t)

	updates, release, err := browser.Subscribe()
	if err != nil {
		t.Fatal(err)
	}

	wait(t, fake.started)

	// The question goes out on the LANs only: asking on docker0 or
	// tailscale0 tells whatever is there that this box is pairing.
	if !slices.Equal(fake.ifs, []string{"wlan0", "enp3s0"}) {
		t.Errorf("browsed on %v, want wlan0 and enp3s0", fake.ifs)
	}

	fake.add(announcement("desk", "wlan0", "192.168.1.20", "aaa"))
	wait(t, updates)

	// Each of these is something on the link that must not become a dial.
	fake.add(announcement("bridge", "docker0", "172.17.0.2", "bbb"))
	fake.add(announcement("tailnet", "tailscale0", "100.64.1.1", "ccc"))
	fake.add(announcement("elsewhere", "wlan0", "10.9.9.9", "ddd"))
	fake.add(announcement("gone", "eth9", "192.168.1.30", "eee"))

	older := announcement("old", "wlan0", "192.168.1.31", "fff")
	older.Text["v"] = "1"
	fake.add(older)

	list := browser.List()
	if len(list) != 1 || list[0].Name != "desk" ||
		list[0].Address != "192.168.1.20:7373" || list[0].Interface != "wlan0" {
		t.Fatalf("list = %+v", list)
	}

	entry, ok := browser.Resolve(list[0].ID)
	if !ok || entry.Address != "192.168.1.20:7373" {
		t.Fatalf("resolve = %+v, %v", entry, ok)
	}

	fake.rmv(announcement("desk", "wlan0", "192.168.1.20", "aaa"))
	wait(t, updates)

	if list := browser.List(); len(list) != 0 {
		t.Fatalf("goodbye left %+v", list)
	}

	if _, ok := browser.Resolve(entry.ID); ok {
		t.Error("resolved an entry that said goodbye")
	}

	// The last subscriber leaving stops the browse.
	release()
	wait(t, fake.stopped)
}

func TestBrowserForgetsWhenNobodyIsLooking(t *testing.T) {
	browser, fake := testBrowser(t)

	_, release, err := browser.Subscribe()
	if err != nil {
		t.Fatal(err)
	}

	wait(t, fake.started)

	add := fake.add
	add(announcement("desk", "wlan0", "192.168.1.20", "aaa"))

	release()
	wait(t, fake.stopped)

	if list := browser.List(); len(list) != 0 {
		t.Fatalf("a stopped browse kept %+v", list)
	}

	// A callback arriving after the stop is from a browse nobody is
	// looking at, and is dropped.
	add(announcement("late", "wlan0", "192.168.1.21", "bbb"))

	if list := browser.List(); len(list) != 0 {
		t.Fatalf("a late callback listed %+v", list)
	}
}

func TestBrowserCloseEndsSubscriptions(t *testing.T) {
	browser, fake := testBrowser(t)

	updates, release, err := browser.Subscribe()
	if err != nil {
		t.Fatal(err)
	}

	defer release()

	wait(t, fake.started)

	browser.Close()
	wait(t, fake.stopped)

	if _, open := <-updates; open {
		t.Error("the subscription survived the close")
	}

	if _, _, err := browser.Subscribe(); err == nil {
		t.Error("a closed browser took a subscriber")
	}
}
