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

// ResolveBindAddresses turns a listen specification into the addresses to
// actually bind, applying decision H.
//
// The default — an empty specification, or one that names only a port — does
// not bind a wildcard. It enumerates the machine's own private and tailnet
// addresses and binds each of them, so that the socket is not merely
// unauthenticated-but-refusing on a public interface: it is not there. A
// wildcard bind, or an explicit public address, is available and has to be
// asked for with allowPublic.
//
// Ordering matters beyond the bind itself, because the same list is what gets
// advertised to a peer during pairing as the addresses to dial back on. Tailnet
// addresses come first (they work from anywhere the peer also is), then other
// private ones, and loopback last, since it is only useful to a peer on this
// same machine — which is exactly the case the tests run in.
func ResolveBindAddresses(spec string, allowPublic bool) ([]string, error) {
	if strings.TrimSpace(spec) == ListenNone {
		return nil, nil
	}

	host, port, err := splitBindSpec(spec)
	if err != nil {
		return nil, err
	}

	if host == "" || host == "*" {
		if allowPublic {
			return []string{net.JoinHostPort("", port)}, nil
		}

		return localBindAddresses(port)
	}

	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		if !allowPublic {
			return nil, fmt.Errorf(
				"%w: %s binds every interface; drop the host to bind only the "+
					"private ones, or say so explicitly",
				ErrPublicBind, host)
		}

		return []string{net.JoinHostPort(host, port)}, nil
	}

	if err := checkBindHost(host, allowPublic); err != nil {
		return nil, err
	}

	return []string{net.JoinHostPort(host, port)}, nil
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

// localBindAddresses is the default policy: every private and tailnet address
// the machine has, and loopback as the fallback that always exists.
func localBindAddresses(port string) ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("transport: list network interfaces: %w", err)
	}

	var tailnet, private, loopback []string

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
			// interface it was learned on, and a peer cannot type that.
			if ip.IsLinkLocalUnicast() && ip.To4() == nil {
				continue
			}

			if !IsLocalIP(ip) {
				continue
			}

			address := net.JoinHostPort(ip.String(), port)

			switch {
			case IsTailnetIP(ip):
				tailnet = append(tailnet, address)
			case ip.IsLoopback():
				loopback = append(loopback, address)
			default:
				private = append(private, address)
			}
		}
	}

	out := make([]string, 0, len(tailnet)+len(private)+len(loopback))
	out = append(out, tailnet...)
	out = append(out, private...)
	out = append(out, loopback...)

	if len(out) == 0 {
		// A machine with no addresses at all is not a machine peers can reach,
		// but it can still pair with something on itself.
		out = append(out, net.JoinHostPort("127.0.0.1", port))
	}

	return out, nil
}
