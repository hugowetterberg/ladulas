// Package tunnel is the tunnel upgrade's tailcat half (docs/architecture.md §8,
// decisions AX and BA): the long-lived tailcat server, this instance's client
// key, and the allowlist of client keys the server admits.
//
// It is the only package that imports tailcat, and no other package under pkg/
// imports it. pkg/peer declares the Tunnel interface it needs, so that
// `tailscale.com`, gVisor and the pre-release pin are linked only by a binary
// that asks for them: the daemon binaries, through internal/tunnel's Factory,
// and a phone's core, which opens a client-only tunnel with Open (decision
// BA). It is public for that second reason; it used to be internal/tunnel,
// which kept the phone from carrying a tunnel at all.
//
// A build with the notailcat tag compiles the package without tailcat:
// Available is false, New and Open refuse, and the instance sends every peer
// the withdrawal form of the offer.
package tunnel

import (
	"errors"
	"log/slog"
)

// Version is the tunnel wire version this build offers (decision AX). It is
// ours and not tailcat's: bump it whenever the pinned tailcat changes its
// address format or its wire protocol incompatibly, so that a peer on an older
// build stays on the direct path rather than raising a tunnel that cannot
// come up.
const Version = 1

// Port is where the long-lived server listens inside the tunnel. It is the
// peer channel's own port, because what is served there is the peer channel.
const Port = 7373

// DefaultDERPMapURL is the DERP map the region is picked from when nobody has
// configured one: tailcat's, which lists Tailscale's public fleet. It is the
// default because the alternatives are worse — a tunnel that stays off until
// somebody runs a derper is one almost nobody turns on, and a relay of our own
// as the default is author-hosted infrastructure on the path, which §1 objects
// to most.
const DefaultDERPMapURL = "https://tailcat.dev/derpmap.json"

// ErrClientOnly is what a client-only tunnel says when asked for something only
// a server has: a listener, or a pairing server.
var ErrClientOnly = errors.New("tunnel: a client-only tunnel runs no server")

// Options configures a tunnel.
type Options struct {
	// The keys, raw: the server's node private key and pre-shared key, and the
	// client's node private key. The store generates them. The client key is
	// required; leaving out both server keys builds a client-only tunnel,
	// which raises clients to peers' servers and serves nothing (decision BA).
	ServerKey    []byte
	PresharedKey []byte
	ClientKey    []byte
	// Region is the persisted DERP region as tailcfg's JSON, empty before the
	// first start ever. A server with a region starts in it without fetching
	// any map; one without picks from DERPMapURL and hands the choice to
	// OnRegion to be persisted.
	Region     []byte
	DERPMapURL string
	OnRegion   func(region []byte) error
	Logger     *slog.Logger
}
