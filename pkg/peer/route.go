package peer

import (
	"context"
	"time"
)

// Which path wins (§8, decision AY).
//
// The precedence is **a tunnel with a punched direct path, then direct TCP,
// then a relayed tunnel.** A relayed tunnel can always be raised while DERP is
// up, so "the tunnel whenever it is up" would send a tailnet pair, or a LAN
// pair whose punching failed, through a throttled relay with a direct path
// that answers in milliseconds beside it. So a relayed tunnel yields to any
// direct address that answers the probe, and is what carries traffic when
// none does. Which of the two a tunnel is comes from the listening side
// (TunnelPathReport), which knows, rather than from the dialling side's own
// client, which could only probe.
//
// The tunnel is preferred while it works and never exclusive: when it cannot
// be raised, calls take the direct dialler under its existing rules. That is
// what keeps a laptop and a desktop on one Wi-Fi with the uplink down able to
// approve, and every upgraded pair working on the day the public DERP fleet is
// throttled or withdrawn.

// raceWindow bounds how long a call with no established path waits for the
// first of a direct address answering and the raise coming up. It is the
// direct probe's own bound with a little more for the raise, because the raise
// is the slower of the two by construction — a DERP connect and a MEOW round
// trip before the handshake — and it is well inside the wake grace a woken
// phone has before its loud alert.
const raceWindow = 5 * time.Second

// probeFunc finds the first of a list of addresses that answers a TCP connect,
// or "" when none does inside probeTimeout.
type probeFunc func(ctx context.Context, addresses []string) string

// probeOf is the node's probe: the real one, or a test's.
func (n *Node) probeOf() probeFunc {
	if n.probe != nil {
		return n.probe
	}

	return firstAnswering
}

// arrange orders the ways to try a peer when no path is established for it,
// racing the raise against the direct probe.
//
// The cases, in the order they are decided:
//
//   - no tunnel to raise: the direct addresses, raced among themselves as they
//     always were (reachableFirst);
//   - a tunnel that is up, punched and preferred: the tunnel, then the
//     addresses, with nothing raced and nothing waited for;
//   - otherwise the race. A raise is started if none is under way and the
//     backoff allows it, and the probe runs beside it. A direct address that
//     answers wins at once, with the tunnel kept as the last thing to try. A
//     raise that comes up punched wins at once. A raise that comes up relayed
//     waits for the probe, because direct TCP outranks a relayed tunnel. And
//     when the window closes with neither, the addresses go first with the
//     tunnel behind them — the tunnel target is resolved when it is tried, so
//     a raise that comes up while the addresses are timing out is still used.
//
// A tunnel that failed in use and has been raised again but has not held for
// the dwell is never put first while a direct address answers; it goes first
// only when nothing direct does, because a tunnel on probation is better than
// no path at all.
func (n *Node) arrange(ctx context.Context, tunnel *tunnelPath, direct []target) []target {
	snap := tunnel.snapshot()
	if !snap.usable {
		return n.raceDirect(ctx, direct)
	}

	if snap.preferred && !snap.relayed {
		return append(tunnelTarget(tunnel), direct...)
	}

	tunnel.kick()
	snap = tunnel.snapshot()

	addresses := make([]string, 0, len(direct))
	for _, t := range direct {
		addresses = append(addresses, t.via.address)
	}

	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	probed := make(chan string, 1)

	go func() {
		probed <- n.probeOf()(probeCtx, addresses)
	}()

	window := time.NewTimer(raceWindow)
	defer window.Stop()

	tunnelFirst := func() []target { return append(tunnelTarget(tunnel), direct...) }
	directFirst := func(winner string) []target {
		return append(promote(direct, winner), tunnelTarget(tunnel)...)
	}

	finished := snap.finished
	probeDone := false

	for {
		select {
		case winner := <-probed:
			probeDone = true

			if winner != "" {
				return directFirst(winner)
			}

			// Nothing direct answered, so the tunnel is the only thing left to
			// wait for, and it wins if it is up at all.
			if snap = tunnel.snapshot(); snap.up {
				return tunnelFirst()
			}

			if finished == nil {
				return directFirst("")
			}
		case <-finished:
			finished = nil

			snap = tunnel.snapshot()

			switch {
			case snap.up && snap.preferred && !snap.relayed:
				return tunnelFirst()
			case snap.up && probeDone:
				return tunnelFirst()
			case !snap.up && probeDone:
				return directFirst("")
			}
		case <-window.C:
			if snap = tunnel.snapshot(); snap.up && probeDone {
				return tunnelFirst()
			}

			return directFirst("")
		case <-ctx.Done():
			return directFirst("")
		}
	}
}

// raceDirect is the direct addresses alone, the one that answers first in
// front: what a call to a peer with no tunnel has always done.
func (n *Node) raceDirect(ctx context.Context, direct []target) []target {
	if len(direct) < 2 {
		return direct
	}

	addresses := make([]string, 0, len(direct))
	for _, t := range direct {
		addresses = append(addresses, t.via.address)
	}

	return promote(direct, n.probeOf()(ctx, addresses))
}

// promote moves the target for one address to the front, keeping the rest in
// order. An address that is not there changes nothing.
func promote(targets []target, address string) []target {
	if address == "" {
		return append([]target(nil), targets...)
	}

	out := make([]target, 0, len(targets))

	for _, t := range targets {
		if t.via.kind == pathDirect && t.via.address == address {
			out = append(out, t)
		}
	}

	for _, t := range targets {
		if t.via.kind != pathDirect || t.via.address != address {
			out = append(out, t)
		}
	}

	return out
}

// onPath orders the ways to try a peer while a path to it is established, by
// the precedence: the path in use first, unless the tunnel is up, punched and
// preferred and the path in use is direct TCP, which it outranks. Nothing is
// raced here, because the established path is the evidence a race would look
// for.
func onPath(current pathKind, tunnel *tunnelPath, direct []target) []target {
	snap := tunnel.snapshot()

	switch {
	case current == pathTunnel:
		return append(tunnelTarget(tunnel), direct...)
	case snap.preferred && !snap.relayed:
		return append(tunnelTarget(tunnel), direct...)
	case snap.usable:
		return append(direct, tunnelTarget(tunnel)...)
	default:
		return direct
	}
}
