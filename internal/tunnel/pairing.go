//go:build !notailcat

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"

	"github.com/hugowetterberg/ladulas/pkg/peer"
	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// pairingPick bounds the pairing server's region pick. Past it the persisted
// region is used: a code on screen is not something to hold up on the DERP
// map's host (decision AZ).
const pairingPick = 4 * time.Second

// StartPairing implements peer.Tunnel: a second tailcat server for one
// pairing window (decision AZ).
//
// Its keys are made for it and never stored. Key and PresharedKey are left
// zero, which tailcat fills with ephemeral ones at Start, so nothing about it
// outlives the window: its address is a capability for as long as the window
// is open and for nothing afterwards. It shares no state with the long-lived
// server, which goes on admitting only the keys of trust records and pending
// pairings.
//
// The region is picked from the DERP map, the nearest by latency at the
// moment the code is shown, and is the long-lived server's persisted region
// when the map cannot be fetched or measured in time. The pick is not
// persisted: a pairing server's region is nobody's contract, since nothing
// records its address.
func (t *Tunnel) StartPairing(maxClients int32) (peer.PairingServer, error) {
	t.mu.Lock()
	closed := t.closed
	persisted := t.region
	t.mu.Unlock()

	if closed {
		return nil, errors.New("tunnel: closed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()

	region := persisted

	pickCtx, cancelPick := context.WithTimeout(ctx, pairingPick)
	picked, _, err := t.pick(pickCtx)

	cancelPick()

	switch {
	case err == nil:
		region = picked
	case persisted == nil:
		return nil, err
	default:
		t.log.Debug("the pairing server takes the persisted DERP region",
			"region", regionName(persisted), "error", err.Error())
	}

	allow := &cappedKeys{max: int(max(maxClients, 1)), log: t.log}

	server := &tailcat.Server{
		Region:      region,
		AllowClient: allow.admit,
		Logf: func(format string, args ...any) {
			t.log.Debug("tailcat pairing server: " + fmt.Sprintf(format, args...))
		},
		// The peer port only, as on the long-lived server.
		ServedTCPPorts: []filter.PortRange{},
		ServedUDPPorts: []filter.PortRange{},
	}

	if err := server.StartContext(ctx); err != nil {
		_ = server.Close()

		return nil, fmt.Errorf("tunnel: start the pairing server in DERP region %s: %w",
			regionName(region), err)
	}

	listener, err := server.Listen(ctx, "tcp", fmt.Sprintf(":%d", Port))
	if err != nil {
		_ = server.Close()

		return nil, fmt.Errorf("tunnel: the pairing server could not listen: %w", err)
	}

	return &pairingServer{server: server, listener: listener}, nil
}

// cappedKeys admits any client key, up to a number of distinct keys, and
// refuses every key after that (decision AZ).
//
// An empty KeySet would deny everybody, and nil would admit everybody without
// limit; every admitted key is a WireGuard peer in the process that signs, so
// the pairing server counts. A refused key is remembered, because a client
// tailcat refuses asks again about once a second.
type cappedKeys struct {
	max int
	log *slog.Logger

	mu      sync.Mutex
	seen    map[key.NodePublic]bool
	refused map[key.NodePublic]bool
}

func (c *cappedKeys) admit(k key.NodePublic) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.seen[k] {
		return true
	}

	if c.refused[k] {
		return false
	}

	if len(c.seen) >= c.max {
		if c.refused == nil {
			c.refused = map[key.NodePublic]bool{}
		}

		c.refused[k] = true

		c.log.Warn("the pairing server refused a client key past its cap",
			"cap", c.max)

		return false
	}

	if c.seen == nil {
		c.seen = map[key.NodePublic]bool{}
	}

	c.seen[k] = true

	return true
}

// pairingServer is a pairing tailcat server as peer.PairingServer.
type pairingServer struct {
	server   *tailcat.Server
	listener net.Listener
}

func (p *pairingServer) Address() string { return string(p.server.TailcatAddr()) }

func (p *pairingServer) Listener() transport.TunnelListener {
	return &pairingListener{listener: p.listener, server: p.server}
}

func (p *pairingServer) Close() error {
	if err := p.server.Close(); err != nil {
		return fmt.Errorf("tunnel: close the pairing server: %w", err)
	}

	return nil
}

// pairingListener hands out the pairing server's connections, each named for
// where it came from rather than for its in-netstack address.
type pairingListener struct {
	listener net.Listener
	server   *tailcat.Server
}

func (l *pairingListener) Accept() (transport.TunnelConn, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err //nolint:wrapcheck // net/http inspects this error
	}

	out := &tunnelConn{Conn: conn, path: peer.PairingServerPath}

	if client, ok := l.server.PeerKey(conn.RemoteAddr()); ok {
		out.key = client.AppendTo(nil)
	}

	return out, nil
}

func (l *pairingListener) Close() error {
	return l.listener.Close() //nolint:wrapcheck // net/http inspects this error
}
