package transport

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

// tailnetLookupTimeout bounds the name lookup. A tailnet's resolver is on this
// machine — tailscaled answers on 100.100.100.100 — so a lookup that takes
// longer than this is one that is not going to work, and the address itself is
// always the fallback.
const tailnetLookupTimeout = 2 * time.Second

// tailnetNameTTL and tailnetMissTTL are how long an answer is reused. They are
// variables so that a test can shorten them rather than sleep through them.
//
// They differ because the two answers are different kinds of fact. A name that
// resolved is stable — a node keeps it across reboots and across the address
// changing, which is the whole reason it goes in front of the address. A lookup
// that failed is a question worth asking again soon, because the commonest
// reason for one is a resolver that was not ready yet, and that is a state which
// ends by itself.
var (
	tailnetNameTTL = 5 * time.Minute
	tailnetMissTTL = 30 * time.Second
)

// tailnetName is the lookup, as a package variable so that a test can answer it
// without a resolver. Nothing else replaces it: the daemon wants the real name
// of the real node it is running on.
var tailnetName = lookupTailnetName

type tailnetNameEntry struct {
	name    string
	expires time.Time
}

var (
	tailnetNameMu    sync.Mutex
	tailnetNameCache = map[string]tailnetNameEntry{}
)

// cachedTailnetName is the lookup with a short memory in front of it, and it
// reports whether it did the work or reused an answer.
//
// The memory is what makes the lookup affordable where it is now made. It used
// to run once, when the channel bound, and whatever it answered in that instant
// was what every later reader got — so a resolver that was a moment from being
// ready cost the node name until something rebound, and a pairing made in that
// window wrote the number into the peer's trust record for good, since nothing
// refreshes one (§8). Asking when somebody asks is the repair; the cache is what
// keeps that from being a resolver round trip per question.
//
// The "did the work" half is for the caller's log: a lookup that finds nothing
// is worth a line the first time and worth silence for the answers after it.
func cachedTailnetName(host string) (string, bool) {
	tailnetNameMu.Lock()
	entry, ok := tailnetNameCache[host]
	tailnetNameMu.Unlock()

	if ok && time.Now().Before(entry.expires) {
		return entry.name, false
	}

	name := tailnetName(host)

	ttl := tailnetNameTTL
	if name == "" {
		ttl = tailnetMissTTL
	}

	tailnetNameMu.Lock()
	tailnetNameCache[host] = tailnetNameEntry{
		name:    name,
		expires: time.Now().Add(ttl),
	}
	tailnetNameMu.Unlock()

	return name, true
}

// forgetTailnetNames empties the cache. It is for tests, which replace
// tailnetName and would otherwise be answered by the previous one.
func forgetTailnetNames() {
	tailnetNameMu.Lock()
	defer tailnetNameMu.Unlock()

	clear(tailnetNameCache)
}

// advertise turns the addresses that were bound into the addresses to tell a
// peer to dial.
//
// A tailnet address gets its node name put in front of it — `horatio.tailnet.ts.net:7373`
// rather than `100.74.235.31:7373` — because that is the string a person
// recognises on the other machine's screen, in `ladulas peers list` and on a
// pairing confirmation, and because a tailnet address is not promised to be
// stable while a name is. The address stays in the list behind the name: the
// name is only resolvable by a node whose MagicDNS is on, and a peer whose is
// off must not lose the ability to dial the number.
//
// It is a display and reachability convenience and nothing more. §7 is explicit
// that a tailnet name is corroborating and never authoritative — what the
// channel authenticates is the identity key at the other end, so an address
// list that has been lied to costs a failed connection and never a wrong peer.
//
// miss is called with the address whose name was looked up and not found, once
// per lookup rather than once per question. It may be nil.
func advertise(bind []string, miss func(host string)) []string {
	if len(bind) == 0 {
		return nil
	}

	out := make([]string, 0, len(bind)+1)
	names := make([]string, 0, 1)

	for _, address := range bind {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}

		ip := net.ParseIP(host)
		if ip == nil || !IsTailnetIP(ip) {
			continue
		}

		name, looked := cachedTailnetName(host)
		if name == "" {
			if looked && miss != nil {
				miss(host)
			}

			continue
		}

		if slices.Contains(names, name) {
			continue
		}

		names = append(names, name)
		out = append(out, net.JoinHostPort(name, port))
	}

	return append(out, bind...)
}

// lookupTailnetName asks the resolver what the node at an address is called, and
// confirms the answer before believing it.
//
// Forward confirmation is what keeps a stale or hostile PTR record from
// replacing a working address with a name that resolves somewhere else. It costs
// a second lookup against a resolver on this machine, and what it buys is that
// the name we hand a peer is one that resolves back to the address we are
// actually listening on.
func lookupTailnetName(host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), tailnetLookupTimeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, host)
	if err != nil {
		return ""
	}

	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		if name == "" {
			continue
		}

		addresses, err := net.DefaultResolver.LookupHost(ctx, name)
		if err != nil {
			continue
		}

		if slices.Contains(addresses, host) {
			return name
		}
	}

	return ""
}
