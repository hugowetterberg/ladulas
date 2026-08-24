package transport

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// DefaultPort is where the peer channel listens.
const DefaultPort = 7373

// ListenNone is the bind specification of an instance that never accepts a
// connection and only ever dials out.
//
// It is what a phone is (§3). iOS forbids a background listener outright, and
// designing around that rather than against it is what makes the mobile story
// the same on both platforms: the phone dials its requesters, and a requester
// that cannot reach the phone waits for the phone to come to it.
//
// An instance with no listener still has an identity, still pairs, still
// borrows and lends keys, and still approves. What it does not have is an
// address to advertise, and the pairing that records that is what tells the
// other side to expect to be visited rather than to visit.
const ListenNone = "none"

// ListenAuto is the bind specification that asks for the automatic policy, and
// is what an empty specification means.
//
// It exists so that a stored setting can say "go back to choosing for me"
// without the setting being empty, which is indistinguishable from unset
// (decision AH).
const ListenAuto = "auto"

// ErrPublicBind is returned when a bind would put the listener on an address
// reachable from outside the local network, without that having been asked for.
//
// Listening on the open internet is supported — the channel does not trust the
// network it runs on (§15) — but decision H says it must never be the result of
// leaving a flag out.
var ErrPublicBind = errors.New(
	"transport: that address is reachable from outside the local network")

// tailscaleV4 and tailscaleV6 are the ranges a tailnet hands out: 100.64/10 is
// the carrier-grade NAT range Tailscale allocates from, and fd7a:115c:a1e0::/48
// is its IPv6 prefix. Neither is private in the RFC 1918 sense, and both are
// exactly the kind of address decision H means by "tailnet".
var (
	tailscaleV4 = &net.IPNet{
		IP:   net.IPv4(100, 64, 0, 0),
		Mask: net.CIDRMask(10, 32),
	}
	tailscaleV6 = &net.IPNet{
		IP:   net.IP{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Mask: net.CIDRMask(48, 128),
	}
)

// IsTailnetIP reports whether an address looks like a tailnet one. It is a
// display and ordering hint, never an authorization decision: §7 is explicit
// that a compromised Tailscale control plane can produce a node that looks
// right, and the identity key is what survives that.
func IsTailnetIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		return tailscaleV4.Contains(v4)
	}

	return tailscaleV6.Contains(ip)
}

// IsLocalIP reports whether an address is one this machine can be reached at
// without the packet crossing the open internet: loopback, RFC 1918 and its
// IPv6 equivalent, link-local, and a tailnet.
func IsLocalIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		IsTailnetIP(ip)
}

// The tiers the automatic policy chooses between, best first, and the headline
// of decision AH: it picks one tier rather than binding every address it can
// find. TierExplicit is what a specification that named its own addresses gets,
// since nothing was chosen for it.
//
// Plain strings and not a named type, because §21: a named string type is one
// `gomobile` cannot bind, and nothing here is worth a field the phone's bind
// silently drops.
const (
	TierExplicit = "explicit"
	TierTailnet  = "tailnet"
	TierPrivate  = "private"
	TierLoopback = "loopback"
	TierNone     = "none"
)

// SkippedAddress is one address the automatic policy passed over, with the
// interface it was found on and why it was not bound.
//
// It is reported rather than dropped because the cost of this policy is a
// listener that is missing from somewhere somebody expected it, and the first
// question then is which rule ate it. A machine with a container runtime on it
// has a dozen addresses that look local and reach nobody; the answer "it was a
// container bridge" has to be available without a packet capture.
type SkippedAddress struct {
	// Address is the host:port that would have been bound.
	Address string
	// Interface is where it was found, which is usually the whole answer.
	Interface string
	// Reason is one clause, written to be read in a table.
	Reason string
}

// Selection is what a listen specification resolved to.
//
// What to advertise is not here and is not the same list, which it was until
// 2026-08-21: what a peer should dial is not always what was bound, since a
// tailnet address has a name and the name is what a person recognises (§7),
// while loopback is bound on a machine that has nothing else and is a lie told
// to anybody off it. It is Server.Advertised, and it is worked out when somebody
// asks rather than here, because it needs a resolver and this does not — see
// cachedTailnetName for what that cost when the two were computed together.
type Selection struct {
	// Bind is what to open sockets on, best first.
	Bind []string
	// Skipped is what the automatic policy did not bind, and why.
	Skipped []SkippedAddress
	// Tier says which kind of address was chosen.
	Tier string
}

// ResolveBindAddresses turns a listen specification into the addresses to
// actually bind, applying decisions H and AH.
//
// It is Select without the reasoning, kept because binding is all most callers
// want and the reasoning is only worth carrying to a management surface.
func ResolveBindAddresses(spec string, allowPublic bool) ([]string, error) {
	selection, err := Select(spec, allowPublic)
	if err != nil {
		return nil, err
	}

	return selection.Bind, nil
}

// Select resolves a listen specification, keeping what it decided against.
//
// The specification is `off`/`none` for nothing at all, `auto` or empty for the
// automatic policy, or a comma-separated list of addresses. An element with no
// host is a port for the automatic policy to use, so `7373` and
// `auto,192.168.1.5` both mean something sensible and can be combined.
//
// The automatic policy is decision AH, and it is a cascade rather than a sweep:
//
//   - an interface that is up but not running is skipped, which is what takes
//     out the bridge a container runtime left behind when the last container
//     stopped. IFF_UP survives that and IFF_RUNNING does not;
//   - an interface whose name belongs to a container runtime or a virtual
//     machine is skipped whether or not it is running, because a bridge with a
//     container on it is running and still reaches nobody who could pair;
//   - what is left is grouped into tailnet, other private, and loopback, and
//     **only the best group present is bound**. A machine on a tailnet binds
//     its tailnet addresses and nothing else: the tailnet reaches the peer from
//     wherever it is, the LAN address reaches it only from the same building,
//     and binding both meant every peer holding a list of both spent its
//     reconnection attempts on the address that could not work.
//
// Before 2026-08-21 it bound every private and tailnet address the machine had,
// and loopback besides. On a desktop with Docker and libvirt on it that was
// fourteen sockets, eleven of which no peer could ever connect to, and the list
// was also what got advertised — so a peer's stored addresses were mostly
// unreachable, its reconnections mostly failed, and the error it reported was
// whichever address happened to be last. Do not go back to binding a tier that
// a better one is already covering; add an address on purpose instead.
func Select(spec string, allowPublic bool) (*Selection, error) {
	elements, err := splitSpec(spec)
	if err != nil {
		return nil, err
	}

	if len(elements) == 0 {
		return &Selection{Tier: TierNone}, nil
	}

	var (
		explicit []string
		automate string
	)

	for _, element := range elements {
		host, port, err := splitBindSpec(element)
		if err != nil {
			return nil, err
		}

		if host == "" || host == ListenAuto {
			// Asking for the public internet and naming no address is the one
			// way to get a wildcard, and predates the automatic policy having
			// anything to choose between: decision H's "a wildcard bind is
			// available and has to be asked for" is this line.
			if allowPublic {
				explicit = append(explicit, net.JoinHostPort("", port))

				continue
			}

			automate = port

			continue
		}

		address, err := explicitAddress(host, port, allowPublic)
		if err != nil {
			return nil, err
		}

		explicit = append(explicit, address)
	}

	selection := &Selection{Tier: TierExplicit, Bind: explicit}

	if automate != "" {
		automatic, err := automaticAddresses(automate)
		if err != nil {
			return nil, err
		}

		if len(explicit) == 0 {
			selection.Tier = automatic.Tier
		}

		selection.Bind = append(selection.Bind, automatic.Bind...)
		selection.Skipped = automatic.Skipped
	}

	selection.Bind = dedupe(selection.Bind)

	return selection, nil
}

// explicitAddress resolves one address somebody named outright. A wildcard is
// the one that has to be asked for twice: `*` and an empty host mean the
// automatic policy, and only an unspecified address spelled out means every
// interface.
func explicitAddress(host, port string, allowPublic bool) (string, error) {
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		if !allowPublic {
			return "", fmt.Errorf(
				"%w: %s binds every interface; drop the host to let the "+
					"automatic policy choose, or say so explicitly",
				ErrPublicBind, host)
		}

		return net.JoinHostPort(host, port), nil
	}

	if err := checkBindHost(host, allowPublic); err != nil {
		return "", err
	}

	return net.JoinHostPort(host, port), nil
}

// splitSpec breaks a specification into its elements, resolving the two words
// that mean something on their own.
func splitSpec(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)

	switch spec {
	case ListenNone, "off":
		return nil, nil
	case "", ListenAuto:
		return []string{""}, nil
	}

	var out []string

	for element := range strings.SplitSeq(spec, ",") {
		element = strings.TrimSpace(element)
		if element == "" {
			continue
		}

		if element == ListenNone || element == "off" {
			return nil, fmt.Errorf(
				"transport: %q switches the listener off and cannot be one "+
					"address among several", element)
		}

		out = append(out, element)
	}

	if len(out) == 0 {
		return nil, errors.New("transport: the listen specification is empty")
	}

	return out, nil
}

func splitBindSpec(spec string) (string, string, error) {
	spec = strings.TrimSpace(spec)

	if spec == "" {
		return "", strconv.Itoa(DefaultPort), nil
	}

	if !strings.Contains(spec, ":") {
		// A bare port, or a bare host. A number is a port; anything else is a
		// host that wants the default port.
		if _, err := strconv.Atoi(spec); err == nil {
			return "", spec, nil
		}

		return spec, strconv.Itoa(DefaultPort), nil
	}

	host, port, err := net.SplitHostPort(spec)
	if err != nil {
		return "", "", fmt.Errorf("transport: unusable listen address %q: %w", spec, err)
	}

	if port == "" {
		port = strconv.Itoa(DefaultPort)
	}

	if host == "*" {
		host = ""
	}

	return host, port, nil
}

// checkBindHost applies the policy to an address the user named outright.
func checkBindHost(host string, allowPublic bool) error {
	if allowPublic {
		return nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("transport: resolve %q: %w", host, err)
	}

	for _, ip := range ips {
		if !IsLocalIP(ip) {
			return fmt.Errorf(
				"%w: %s resolves to %s; pass the public-listen option to bind it anyway",
				ErrPublicBind, host, ip)
		}
	}

	return nil
}

// virtualInterface reports whether an interface belongs to a container runtime
// or a virtual machine, by the only signal available without asking a runtime
// this package will not depend on: what it is called.
//
// The names are the ones the runtimes pick for themselves. `br-` with the
// hyphen is Docker's per-network bridge and a real LAN bridge is `br0` or
// `bridge0`, so the hyphen is doing work and is not a typo. A `tap` or a `dummy`
// with an address a peer could use is possible and is the honest cost of the
// rule; an explicit address always wins, and every skip is reported with its
// reason so that a listener missing from somewhere is a question with an answer.
func virtualInterface(name string) bool {
	for _, prefix := range []string{
		"docker", "br-", "veth", "virbr", "vnet", "podman", "cni", "flannel",
		"kube", "lxcbr", "lxdbr", "vboxnet", "vmnet", "mpqemubr", "tap", "dummy",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}

// automaticAddresses is the policy of decision AH: one tier, and a note of
// everything it went past.
func automaticAddresses(port string) (*Selection, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("transport: list network interfaces: %w", err)
	}

	var (
		tailnet, private, loopback []string
		skipped                    []SkippedAddress
	)

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP

			// An IPv6 link-local address only means anything together with the
			// interface it was learned on, and a peer cannot type that. It is
			// dropped without a note: every interface has one, and a table of
			// them would bury the skips somebody is looking for.
			if ip.IsLinkLocalUnicast() && ip.To4() == nil {
				continue
			}

			address := net.JoinHostPort(ip.String(), port)

			switch {
			case !IsLocalIP(ip):
				skipped = append(skipped, SkippedAddress{
					Address:   address,
					Interface: iface.Name,
					Reason:    "reachable from outside the local network",
				})
			case virtualInterface(iface.Name):
				skipped = append(skipped, SkippedAddress{
					Address:   address,
					Interface: iface.Name,
					Reason:    "a container or virtual machine interface",
				})
			case iface.Flags&net.FlagRunning == 0:
				skipped = append(skipped, SkippedAddress{
					Address:   address,
					Interface: iface.Name,
					Reason:    "the interface is up but not running",
				})
			case IsTailnetIP(ip):
				tailnet = append(tailnet, address)
			case ip.IsLoopback():
				loopback = append(loopback, address)
			default:
				private = append(private, address)
			}
		}
	}

	return chooseTier(port, tailnet, private, loopback, skipped), nil
}

// chooseTier takes the best group that has anything in it, and writes down why
// the others were left.
func chooseTier(
	port string,
	tailnet, private, loopback []string,
	skipped []SkippedAddress,
) *Selection {
	tiers := []struct {
		tier      string
		addresses []string
		because   string
	}{
		{TierTailnet, tailnet, "a tailnet address is bound instead"},
		{TierPrivate, private, "a local network address is bound instead"},
		{TierLoopback, loopback, ""},
	}

	for i, candidate := range tiers {
		if len(candidate.addresses) == 0 {
			continue
		}

		for _, worse := range tiers[i+1:] {
			for _, address := range worse.addresses {
				skipped = append(skipped, SkippedAddress{
					Address: address,
					Reason:  candidate.because,
				})
			}
		}

		return &Selection{
			Tier:    candidate.tier,
			Bind:    candidate.addresses,
			Skipped: skipped,
		}
	}

	// A machine with no addresses at all is not a machine peers can reach, but
	// it can still pair with something on itself.
	return &Selection{
		Tier:    TierLoopback,
		Bind:    []string{net.JoinHostPort("127.0.0.1", port)},
		Skipped: skipped,
	}
}

func dedupe(addresses []string) []string {
	seen := make(map[string]bool, len(addresses))
	out := make([]string, 0, len(addresses))

	for _, address := range addresses {
		if seen[address] {
			continue
		}

		seen[address] = true
		out = append(out, address)
	}

	return out
}
