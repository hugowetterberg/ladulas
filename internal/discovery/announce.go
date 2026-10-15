package discovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hugowetterberg/ladulas/internal/dnssd"
)

// withdrawTimeout bounds waiting for the goodbye packets. The library sends
// two per interface a quarter of a second apart, so a second is plenty; a
// responder that has not finished by then is one whose goodbyes are not
// coming, and peers' caches will drop the record when its TTL runs out.
const withdrawTimeout = 2 * time.Second

// probeWait bounds how long AnnouncePairing waits for the probe before
// putting the PIN on screen anyway. An uncontested probe is a random delay
// of up to a quarter of a second and three queries a quarter of a second
// apart, so this is only reached when somebody else answers for the name and
// the responder is working its way through "desk (2)", "desk (3)".
const probeWait = 3 * time.Second

// Announcer announces one pairing window at a time on the local network
// (decision AW). It implements peer.PairingAnnouncer.
//
// What goes out, and nothing else:
//
//   - the instance name, as the DNS-SD instance name, because it is what
//     every browser displays and what the person at the other machine is
//     looking for;
//   - a neutral host name minted per window, `ladulas-<random>`, so the box's
//     own host name — which on a laptop is often its owner's name — stays off
//     the network;
//   - the addresses the peer channel actually bound on the interfaces it
//     announces on, and its port;
//   - TXT `v=2` and the window's random tag. Nothing in it is a credential.
//
// It is announced only on interfaces the bind policy chose (decisions H, AH,
// AR) — an interface with a bound address on it, or every eligible one when
// the listener was explicitly bound to a wildcard — minus container bridges
// and the tailnet (see iface.eligible).
type Announcer struct {
	log   *slog.Logger
	bound func() []string
	// Observe, when set, is told how each announcement went: "announced" or
	// "not_announced". It is a function field so the counter lives in
	// internal/observe and nowhere else.
	Observe func(outcome string)

	// serial keeps one AnnouncePairing running at a time. Without it two
	// overlapping calls each withdrew whatever was there, each built a
	// responder, and the second's store into cancel dropped the first's on
	// the floor: a responder nobody could stop, announcing the name until the
	// daemon exited and probing against its twin. WithdrawPairing does not
	// take it, so that a withdraw can cut a probe short.
	serial sync.Mutex

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// NewAnnouncer builds an announcer that asks bound for the peer listener's
// bound addresses each time it announces. It asks rather than being told
// once, because the listener can be rebound while the daemon runs (§14).
func NewAnnouncer(log *slog.Logger, bound func() []string) *Announcer {
	quietLibrary(log)

	return &Announcer{log: log, bound: bound}
}

// errNothingToAnnounce is a listener with no address on a local network
// interface: off, loopback only, or a tailnet only. Pairing still works by
// address or full code; the screen says why the machine will not show up in
// anybody's list.
var errNothingToAnnounce = errors.New(
	"the peer channel has no address on a local network interface")

// AnnouncePairing starts announcing a window, replacing whatever was being
// announced. It returns a sentence for the screen showing the PIN: where the
// window is announced and under which name, or — with the error — why it is
// not.
//
// It waits for the probe, up to probeWait, because the probe is what decides
// both of those: the library renames on conflict ("name (2)"), which is the
// moment two windows with the same name become visible as two entries to
// whoever is browsing, and a probe that fails or is withdrawn means nothing
// went out. Saying "announced" before it ran said it about announcements
// that never happened.
//
// The window's tag is minted here, because nothing but the list it is for
// has any use for it.
func (a *Announcer) AnnouncePairing(name string) (string, error) {
	a.serial.Lock()
	defer a.serial.Unlock()

	a.WithdrawPairing()

	tag, err := newTag()
	if err != nil {
		return a.failed(err)
	}

	interfaces, err := systemInterfaces()
	if err != nil {
		return a.failed(fmt.Errorf("list network interfaces: %w", err))
	}

	target, err := announceTarget(a.bound(), interfaces)
	if err != nil {
		return a.failed(err)
	}

	host, err := neutralHost()
	if err != nil {
		return a.failed(err)
	}

	service, err := dnssd.NewService(dnssd.Config{
		Name: name,
		Type: ServiceType,
		Host: host,
		Text: map[string]string{txtVersion: version, txtTag: tag},
		Port: target.port,
		// Ifaces restricts where the records go. IPs is the field the library
		// calls deprecated, and it is used deliberately: without it every
		// address on each interface is announced — IPv6 link-local and
		// global ones included — while the listener is bound to only some of
		// them. A list entry whose address does not answer is worse than no
		// entry. The library announces the whole list on each interface, so
		// a box on two LANs announces both addresses on both; the joining
		// side keeps only the one inside the subnet it heard the answer on
		// (pickAddress), which is the rule that has to hold against a forged
		// record anyway.
		Ifaces: target.ifaces,
		IPs:    target.ips,
	})
	if err != nil {
		return a.failed(err)
	}

	// The responder hears and answers on the announced interfaces only. The
	// upstream library's answered a query on whichever interface it arrived,
	// docker0 and tailscale0 included, so that anything in a container could
	// read the name, the port and the tag off a PIN screen; that is what the
	// patched copy in internal/dnssd is for (decision AW).
	responder, err := dnssd.NewResponder(target.ifaces...)
	if err != nil {
		return a.failed(fmt.Errorf("open the multicast DNS socket: %w", err))
	}

	// Add cannot fail on a responder that is not responding yet: it only
	// queues the service for Respond to probe. Were that to change, the
	// socket NewResponder opened would be left open here, since only Respond
	// closes it.
	handle, err := responder.Add(service)
	if err != nil {
		return a.failed(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	a.mu.Lock()
	a.cancel = cancel
	a.done = done
	a.mu.Unlock()

	var respondErr error

	go func() {
		defer close(done)

		// Respond probes, announces, answers queries, and sends the goodbyes
		// and closes its socket when its context is cancelled — or closes it
		// and returns early if the probe fails or is withdrawn. It returns the
		// context's error on withdrawal, which is the ordinary way to end.
		respondErr = responder.Respond(ctx)
		if respondErr != nil && !errors.Is(respondErr, context.Canceled) {
			a.log.Debug("the pairing announcement stopped",
				"error", respondErr.Error())
		}
	}()

	where := strings.Join(target.ifaces, ", ")

	select {
	case <-responder.Ready():
		// The name the probe settled on, which is the instance name unless
		// another responder already answers for it.
		announced := handle.Service().Name

		a.log.Info("announcing a pairing window on the local network",
			"interfaces", strings.Join(target.ifaces, ","),
			"port", target.port, "name", announced)

		if a.Observe != nil {
			a.Observe("announced")
		}

		return fmt.Sprintf("Announced on the local network (%s) as %q",
			where, announced), nil
	case <-done:
		// Read after done is closed, which is what orders it after the write.
		if errors.Is(respondErr, context.Canceled) {
			return a.failed(errors.New("the window closed while its name was being checked"))
		}

		return a.failed(fmt.Errorf("check the name is free: %w", respondErr))
	case <-time.After(probeWait):
		a.log.Info("still checking the pairing window's name is free",
			"interfaces", strings.Join(target.ifaces, ","), "port", target.port)

		if a.Observe != nil {
			a.Observe("announced")
		}

		return fmt.Sprintf("Announcing on the local network (%s), still "+
			"checking that %q is free; if another machine answers for it, this "+
			"one is listed under a numbered name", where, name), nil
	}
}

func (a *Announcer) failed(err error) (string, error) {
	a.log.Info("not announcing the pairing window", "error", err.Error())

	if a.Observe != nil {
		a.Observe("not_announced")
	}

	return "Not announced on the local network: " + err.Error() +
		". Join with the full code, or with the PIN and an address.", err
}

// WithdrawPairing stops the announcement, if there is one, and waits for its
// goodbye packets. It is safe to call at any time and more than once.
func (a *Announcer) WithdrawPairing() {
	a.mu.Lock()
	cancel, done := a.cancel, a.done
	a.cancel, a.done = nil, nil
	a.mu.Unlock()

	if cancel == nil {
		return
	}

	cancel()

	select {
	case <-done:
	case <-time.After(withdrawTimeout):
		a.log.Warn("the pairing announcement did not say goodbye in time")
	}
}

// target is where an announcement goes: which interfaces, which addresses,
// which port.
type target struct {
	ifaces []string
	ips    []net.IP
	port   int
}

// announceTarget works out the target from what the listener bound.
//
// An explicit bound address announces the interface it is on. A wildcard —
// which only an explicit `allow public` bind produces (decision H) — announces
// every eligible interface with a local address. In both cases only link-local
// and private addresses go out, and an interface the eligibility rules leave
// out stays out whatever is bound on it.
//
// One port per announcement, because one DNS-SD record carries one: if the
// listener was bound on two ports, the first address's wins and the others
// are not announced. That takes an explicit specification nobody writes.
func announceTarget(bound []string, interfaces []iface) (*target, error) {
	var (
		port     int
		wildcard bool
		explicit []net.IP
	)

	for _, address := range bound {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}

		p, err := strconv.Atoi(portText)
		if err != nil || p <= 0 || p > 65535 {
			continue
		}

		ip := net.ParseIP(host)
		if host != "" && ip == nil {
			continue
		}

		if port == 0 {
			port = p
		}

		if p != port {
			continue
		}

		if host == "" || ip.IsUnspecified() {
			wildcard = true

			continue
		}

		explicit = append(explicit, ip)
	}

	if port == 0 {
		return nil, errNothingToAnnounce
	}

	found := &target{port: port}

	for _, candidate := range interfaces {
		if ok, _ := candidate.eligible(); !ok {
			continue
		}

		var ips []net.IP

		for _, ipNet := range candidate.nets {
			ip := ipNet.IP
			if !linkLocalOrPrivate(ip) {
				continue
			}

			if !wildcard && !slices.ContainsFunc(explicit, ip.Equal) {
				continue
			}

			// IPv6 link-local is only reachable through a wildcard bind: the
			// automatic policy never binds it, because a peer cannot type the
			// zone (§8). Announcing it otherwise would be an address nothing
			// is listening on.
			if ip.To4() == nil && ip.IsLinkLocalUnicast() && !wildcard {
				continue
			}

			ips = append(ips, ip)
		}

		if len(ips) == 0 {
			continue
		}

		found.ifaces = append(found.ifaces, candidate.name)
		found.ips = append(found.ips, ips...)
	}

	if len(found.ifaces) == 0 {
		return nil, errNothingToAnnounce
	}

	return found, nil
}

// neutralHost is a host name for one window, unrelated to the machine's own.
func neutralHost() (string, error) {
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("mint a host name: %w", err)
	}

	return "ladulas-" + hex.EncodeToString(raw), nil
}

// newTag mints a window's session tag. It distinguishes list entries from
// different screen openings and nothing else.
func newTag() (string, error) {
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("mint a session tag: %w", err)
	}

	return hex.EncodeToString(raw), nil
}
