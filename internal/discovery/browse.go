package discovery

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/hugowetterberg/ladulas/internal/dnssd"
)

// Entry is one machine showing a pairing PIN, as a joining screen lists it.
type Entry struct {
	// ID is what a join names. It is this browser's own, stable for as long
	// as the entry is listed, and means nothing anywhere else.
	ID string
	// Name is the instance name the machine announced.
	Name string
	// Interface is where the announcement was heard.
	Interface string
	// Address is the one address a join dials (see pickAddress).
	Address string
	// Duplicate is another listed entry claiming the same name, counting a
	// responder's conflict rename ("desk (2)") as the same name: two screens
	// claiming one machine, at most one of which is the machine the person
	// means (decision AW).
	Duplicate bool
	// SeenAt is when it was first heard.
	SeenAt time.Time

	tag   string
	order uint64
}

// ErrBrowserClosed is a browser whose instance sealed (§3): the list goes
// with the store, as everything that exists to pair does.
var ErrBrowserClosed = errors.New(
	"discovery: the instance sealed; unlock it to look for machines again")

// lookupFunc is dnssd.LookupType, replaceable in tests.
type lookupFunc func(
	ctx context.Context, service string, add dnssd.AddFunc, rmv dnssd.RmvFunc,
	ifs ...string,
) error

// Browser lists the machines on the local network showing a pairing PIN, for
// as long as somebody is looking (decision AW).
//
// It browses only while it has a subscriber — a joining screen open, or
// `ladulas pair --join` listing — and forgets everything it heard when the
// last one leaves, so that nothing is listening on 5353 for an instance
// nobody is pairing.
//
// Three rules stand between an announcement and a dial, because an
// announcement is something anybody on the link can send:
//
//   - **the interface is checked**: an answer heard on an interface the
//     announcing side would not use — a container bridge, a tailnet — is not
//     listed. The browse is confined to the eligible interfaces as they were
//     when it started (the patched library in internal/dnssd queries and
//     hears on those only), and each answer is checked again on IfaceName,
//     because an interface can change under a browse that is still running;
//   - **the address belongs to that interface**: an entry's address must be
//     link-local, or private and inside a subnet of the interface it was
//     heard on. Otherwise a forged SRV and A record could point this daemon
//     at any host:port anywhere, and it would dial it;
//   - **one address per entry**: the entry carries the single address a join
//     dials, so a PIN goes to one place per press and never on to the next
//     address when the first refuses (decision AV's joiner cap).
type Browser struct {
	log        *slog.Logger
	lookup     lookupFunc
	interfaces func() ([]iface, error)

	mu          sync.Mutex
	subscribers map[chan struct{}]struct{}
	cancel      context.CancelFunc
	entries     map[string]*Entry
	next        uint64
	closed      bool
}

// NewBrowser builds a browser that is not browsing yet.
func NewBrowser(log *slog.Logger) *Browser {
	quietLibrary(log)

	return &Browser{
		log:         log,
		lookup:      dnssd.LookupType,
		interfaces:  systemInterfaces,
		subscribers: map[chan struct{}]struct{}{},
		entries:     map[string]*Entry{},
	}
}

// Subscribe starts browsing, if nobody else already is, and returns a channel
// that is signalled whenever the list changes and closed if the browser is,
// with the function that ends the subscription. The last subscriber leaving
// stops the browse.
func (b *Browser) Subscribe() (<-chan struct{}, func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, nil, ErrBrowserClosed
	}

	updates := make(chan struct{}, 1)
	b.subscribers[updates] = struct{}{}

	if b.cancel == nil {
		ctx, cancel := context.WithCancel(context.Background())
		b.cancel = cancel

		go b.browse(ctx)
	}

	var once sync.Once

	release := func() {
		once.Do(func() { b.unsubscribe(updates) })
	}

	return updates, release, nil
}

func (b *Browser) unsubscribe(updates chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subscribers[updates]; !ok {
		return
	}

	delete(b.subscribers, updates)

	if len(b.subscribers) == 0 {
		b.stopLocked()
	}
}

// stopLocked ends the browse and forgets what it heard. An entry is only as
// good as the announcements keeping it fresh, and with nothing listening for
// goodbyes a remembered one could be a window long since closed.
func (b *Browser) stopLocked() {
	if b.cancel != nil {
		b.cancel()
		b.cancel = nil
	}

	clear(b.entries)
}

// Close stops browsing for good and ends every subscription. It is what
// sealing does to the browser.
func (b *Browser) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}

	b.closed = true
	b.stopLocked()

	for updates := range b.subscribers {
		close(updates)
	}

	clear(b.subscribers)
}

// browse runs one lookup, on the interfaces eligible when it starts.
//
// Naming them is not optional: the upstream library queried on every
// multicast interface, so a joining screen put a question for
// _ladulas-pair._tcp onto docker0 and tailscale0 as well, announcing to
// whatever was there that this box was looking for something to pair with.
// With no eligible interface there is nothing to browse — and passing an
// empty list would mean every interface — so the list stays empty until the
// last subscriber leaves and the next one starts a fresh browse; a laptop
// that joins a network while its screen is open finds machines when the
// screen is reopened.
func (b *Browser) browse(ctx context.Context) {
	interfaces, err := b.interfaces()
	if err != nil {
		b.log.Warn("looking for machines showing a pairing PIN failed",
			"error", err.Error())

		return
	}

	var names []string

	for _, candidate := range interfaces {
		if ok, _ := candidate.eligible(); ok {
			names = append(names, candidate.name)
		}
	}

	if len(names) == 0 {
		b.log.Info("not looking for machines showing a pairing PIN: " +
			"no local network interface to look on")

		return
	}

	err = b.lookup(ctx, serviceName,
		func(found dnssd.BrowseEntry) { b.added(ctx, found) },
		func(gone dnssd.BrowseEntry) { b.removed(ctx, gone) },
		names...)
	if err != nil && !errors.Is(err, context.Canceled) {
		b.log.Warn("looking for machines showing a pairing PIN failed",
			"error", err.Error())
	}
}

// key is what the library identifies an entry by: an instance name heard on
// one interface.
func key(name, ifaceName string) string {
	return name + "\x00" + ifaceName
}

func (b *Browser) added(ctx context.Context, found dnssd.BrowseEntry) {
	if found.Text[txtVersion] != version {
		b.log.Debug("passed over a pairing announcement with another version",
			"name", found.Name, "version", found.Text[txtVersion])

		return
	}

	interfaces, err := b.interfaces()
	if err != nil {
		return
	}

	index := slices.IndexFunc(interfaces, func(i iface) bool {
		return i.name == found.IfaceName
	})
	if index < 0 {
		return
	}

	heardOn := interfaces[index]

	if ok, why := heardOn.eligible(); !ok {
		b.log.Debug("passed over a pairing announcement",
			"name", found.Name, "interface", found.IfaceName, "why", why)

		return
	}

	address := pickAddress(found.IPs, found.Port, heardOn)
	if address == "" {
		b.log.Debug("passed over a pairing announcement with no usable address",
			"name", found.Name, "interface", found.IfaceName)

		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// A late callback from a browse that has since been stopped would put a
	// stale entry into the next one's list.
	if ctx.Err() != nil {
		return
	}

	b.next++

	b.entries[key(found.Name, found.IfaceName)] = &Entry{
		ID:        "m" + strconv.FormatUint(b.next, 10),
		Name:      found.Name,
		Interface: found.IfaceName,
		Address:   address,
		SeenAt:    time.Now(),
		tag:       found.Text[txtTag],
		order:     b.next,
	}

	b.notifyLocked()
}

func (b *Browser) removed(ctx context.Context, gone dnssd.BrowseEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if ctx.Err() != nil {
		return
	}

	k := key(gone.Name, gone.IfaceName)
	if _, ok := b.entries[k]; !ok {
		return
	}

	delete(b.entries, k)
	b.notifyLocked()
}

func (b *Browser) notifyLocked() {
	for updates := range b.subscribers {
		select {
		case updates <- struct{}{}:
		default:
		}
	}
}

// List is what is on the network now, oldest first.
//
// One window heard on two interfaces is one row, the first heard. Two
// windows claiming the same name are both listed and both marked duplicate,
// because the list cannot know which is the real one and must not choose:
// choosing is exactly what a forged announcement wants done for it. A name
// the responder renamed on conflict — "desk (2)" — counts as the same name
// for this, since that is what a conflict looks like after probing.
func (b *Browser) List() []Entry {
	b.mu.Lock()
	all := make([]Entry, 0, len(b.entries))

	for _, entry := range b.entries {
		all = append(all, *entry)
	}
	b.mu.Unlock()

	return arrange(all)
}

// arrange merges and marks a list (see List).
func arrange(all []Entry) []Entry {
	slices.SortFunc(all, func(x, y Entry) int {
		switch {
		case x.order < y.order:
			return -1
		case x.order > y.order:
			return 1
		default:
			return 0
		}
	})

	type window struct{ name, tag string }

	seen := map[window]bool{}
	rows := map[string]int{}

	out := make([]Entry, 0, len(all))

	for _, entry := range all {
		w := window{name: entry.Name, tag: entry.tag}
		if seen[w] {
			continue
		}

		seen[w] = true
		rows[baseName(entry.Name)]++

		out = append(out, entry)
	}

	// Duplicate is counted in rows, not in tags. The tag is anybody's to
	// copy, so "desk (2)" announced with the real window's tag is still a
	// second row claiming desk, and has to be flagged as one: counting
	// distinct tags would have let exactly that entry through unmarked.
	for i := range out {
		out[i].Duplicate = rows[baseName(out[i].Name)] > 1
	}

	return out
}

// renamed is the suffix a DNS-SD responder adds to an instance name that
// conflicted while probing.
var renamed = regexp.MustCompile(` \([0-9]+\)$`)

func baseName(name string) string {
	return renamed.ReplaceAllString(name, "")
}

// Resolve finds a listed entry by id. A join resolves its entry when it
// starts and dials the address it found then, once.
func (b *Browser) Resolve(id string) (Entry, bool) {
	for _, entry := range b.List() {
		if entry.ID == id {
			return entry, true
		}
	}

	return Entry{}, false
}

// pickAddress chooses the one address a join dials, or nothing.
//
// IPv4 first, because the automatic bind policy binds it wherever there is a
// LAN and IPv6 link-local only ever through a wildcard (§8). An IPv4 or
// unique-local IPv6 address has to sit inside a subnet of the interface the
// announcement was heard on; an IPv6 link-local one is only meaningful on
// that interface, and carries it as its zone.
func pickAddress(ips []net.IP, port int, heardOn iface) string {
	if port <= 0 || port > 65535 {
		return ""
	}

	portText := strconv.Itoa(port)

	ordered := slices.Clone(ips)
	slices.SortStableFunc(ordered, func(x, y net.IP) int {
		xv4, yv4 := x.To4() != nil, y.To4() != nil

		switch {
		case xv4 && !yv4:
			return -1
		case !xv4 && yv4:
			return 1
		default:
			return 0
		}
	})

	for _, ip := range ordered {
		if !linkLocalOrPrivate(ip) {
			continue
		}

		if ip.To4() == nil && ip.IsLinkLocalUnicast() {
			return net.JoinHostPort(ip.String()+"%"+heardOn.name, portText)
		}

		if slices.ContainsFunc(heardOn.nets, func(n *net.IPNet) bool {
			return n.Contains(ip)
		}) {
			return net.JoinHostPort(ip.String(), portText)
		}
	}

	return ""
}
