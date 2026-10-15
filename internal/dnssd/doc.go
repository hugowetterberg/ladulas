// Package dnssd is github.com/brutella/dnssd v1.2.14, carried in the tree
// with a small patch because the upstream responder cannot be confined to
// the interfaces Ladulås announces on (decision AW, architecture §7).
//
// Upstream is MIT licensed; LICENSE is its licence, kept beside the code.
// The tests, the cmd/ tools and LookupInstance were left behind, and the
// lint the repository runs was made clean. What differs in behaviour:
//
//   - NewResponder and LookupType take interface names, and the connection
//     under them hears and speaks on those interfaces only. Upstream joins
//     the groups on every multicast interface and answers a query on
//     whichever one it arrived — docker0 and tailscale0 included — whatever
//     Config.Ifaces says, since that field restricts only the records and
//     the unsolicited announcements. Filtering has to happen on receive as
//     well as on join: a socket bound to *:5353 is handed datagrams for
//     groups any socket on the host joined, on any interface.
//   - Respond closes its connection when it returns before answering, which
//     is what a context cancelled during the probe does. Upstream leaked
//     both sockets.
//   - Responder.Ready is closed once probing is done, so a caller can tell
//     "announced as this name" from "still probing" from "failed".
//   - The read loops stop when their context ends or the socket closes,
//     rather than blocking on a channel nobody reads or spinning on a
//     closed socket, and the browse's query sender stops with the browse.
//
// Moving to a newer upstream means re-applying exactly that list. If
// upstream grows an interface-restricted responder, the copy should go.
package dnssd
