// Package discovery finds a machine showing a pairing PIN on the local
// network, so that a person joining it picks a name from a list rather than
// typing an address (§7, decision AW).
//
// It is DNS-SD over multicast DNS, through github.com/brutella/dnssd, and it
// is the daemon's alone. Phones pair by scanning the QR, which carries the
// displaying side's identity key and so pins the right machine from the first
// byte; a phone never browses and never announces, which keeps this package —
// and its netlink and multicast dependencies — out of the gomobile build. That
// is why it is under internal/ and reaches pkg/peer only through the
// peer.PairingAnnouncer interface.
//
// Two halves, both short-lived by design:
//
//   - the Announcer puts `_ladulas-pair._tcp` on the network for exactly as
//     long as a pairing window's screen is showing its PIN, and withdraws it
//     with goodbye packets when the screen goes. Nothing is announced at any
//     other time — the deliberate departure from Syncthing, whose local
//     discovery announces every thirty seconds for as long as it runs;
//   - the Browser listens for those announcements for exactly as long as a
//     joining screen or `ladulas pair --join` is listing them.
//
// Nothing that comes through here is believed. An announcement is a name and
// an address, and anybody on the link can send one: the PIN exchange (CPace,
// decision AV) is what proves the machine that answers is the one whose screen
// the PIN is on, and the fingerprints on both cards are what prove it was not
// somebody who read the PIN off that screen. What this package does is keep
// an announcement from pointing the daemon anywhere it should not dial.
package discovery

import (
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"

	dnslog "github.com/hugowetterberg/ladulas/internal/dnssd/log"

	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// ServiceType is the DNS-SD service type a pairing window is announced as.
const ServiceType = "_ladulas-pair._tcp"

// serviceName is the type as the browser asks for it, with its domain.
const serviceName = ServiceType + ".local."

// TXT keys and the one version this build speaks. `v` is the pairing
// protocol the announcing side expects — 2 is the PIN exchange, and an
// announcement of anything else is not listed, because a PIN typed at a
// machine that cannot take one would be a guess handed to whoever answered.
// `tag` is a random string per window, and it is for the list only: two
// entries with the same name and the same tag are one window seen on two
// interfaces, and two with the same name and different tags are two windows,
// one of which somebody did not open. It is never an input to the PIN
// exchange, because anybody on the link can copy it.
const (
	txtVersion = "v"
	txtTag     = "tag"
	version    = "2"
)

// quietOnce routes the library's own logging into ours, once. Its Info
// logger writes to stdout by default, which on a daemon is a stream nobody
// reads and in `go test` is noise between the results.
var quietOnce sync.Once

func quietLibrary(log *slog.Logger) {
	quietOnce.Do(func() {
		writer := &slogWriter{log: log}

		dnslog.Info.SetOutput(writer)
		dnslog.Debug.SetOutput(io.Discard)
	})
}

// slogWriter turns the library's lines into debug entries.
type slogWriter struct {
	log *slog.Logger
}

func (w *slogWriter) Write(p []byte) (int, error) {
	w.log.Debug("dns-sd", "line", strings.TrimSpace(string(p)))

	return len(p), nil
}

// iface is what the two halves need to know about a network interface. It is
// its own type rather than net.Interface so that the rules below are tested
// against interfaces that do not exist on the machine running the tests.
type iface struct {
	name  string
	flags net.Flags
	nets  []*net.IPNet
}

// systemInterfaces is every interface on the machine with its addresses.
func systemInterfaces() ([]iface, error) {
	found, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	out := make([]iface, 0, len(found))

	for _, candidate := range found {
		addrs, err := candidate.Addrs()
		if err != nil {
			continue
		}

		entry := iface{name: candidate.Name, flags: candidate.Flags}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				entry.nets = append(entry.nets, ipNet)
			}
		}

		out = append(out, entry)
	}

	return out, nil
}

// eligible says whether an interface is one a pairing may be announced on or
// discovered through, and if not, why not.
//
// It is the automatic bind policy's interface rules (decisions AH and AR) plus
// two of its own. A container bridge or a VM's interface is left out for the
// reason the listener leaves it out: nothing that could pair is on the other
// side of it. A tailnet interface is left out although the listener binds it,
// because a tailnet already has names (§8) and nothing in DNS-SD is the right
// way to find a node on it — whether Tailscale forwards multicast between
// nodes at all was not tested, and an announcement that went to every machine
// on somebody's tailnet would be a stranger's list entry on all of them.
// Loopback is left out because a machine pairing with itself does not need
// to find itself.
func (i iface) eligible() (bool, string) {
	switch {
	case i.flags&net.FlagUp == 0:
		return false, "down"
	case i.flags&net.FlagRunning == 0:
		return false, "up but not running"
	case i.flags&net.FlagLoopback != 0:
		return false, "loopback"
	case i.flags&net.FlagMulticast == 0:
		return false, "no multicast"
	case transport.IsVirtualInterface(i.name):
		return false, "a container or virtual machine interface"
	case strings.HasPrefix(i.name, "tailscale"):
		return false, "a tailnet interface"
	}

	for _, ipNet := range i.nets {
		if transport.IsTailnetIP(ipNet.IP) {
			return false, "a tailnet interface"
		}
	}

	return true, ""
}

// linkLocalOrPrivate is the address range a discovered or announced address
// has to be in: RFC 1918 and its IPv6 equivalent, or link-local. A tailnet
// address is neither, on purpose.
func linkLocalOrPrivate(ip net.IP) bool {
	if transport.IsTailnetIP(ip) || ip.IsLoopback() {
		return false
	}

	return ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
