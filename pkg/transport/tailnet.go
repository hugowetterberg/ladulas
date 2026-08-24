package transport

import (
	"context"
	"net"
	"slices"
	"strings"
	"time"
)

// tailnetLookupTimeout bounds the name lookup. A tailnet's resolver is on this
// machine — tailscaled answers on 100.100.100.100 — so a lookup that takes
// longer than this is one that is not going to work, and the address itself is
// always the fallback.
const tailnetLookupTimeout = 2 * time.Second

// tailnetName is the lookup, as a package variable so that a test can answer it
// without a resolver. Nothing else replaces it: the daemon wants the real name
// of the real node it is running on.
var tailnetName = lookupTailnetName

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
func advertise(bind []string) []string {
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

		name := tailnetName(host)
		if name == "" || slices.Contains(names, name) {
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
