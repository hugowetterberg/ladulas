package peer

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// The tunnel upgrade, this instance's half (§8, decision AX).
//
// Two paired instances that both have tailcat exchange tunnel credentials over
// an authenticated channel and can then reach each other's pinned TLS listener
// through a NAT traversal layer rather than only at a bound address. This file
// is everything that does not need tailcat itself: the offer that rides on the
// carriers decision AQ already has, the record of what each peer offered, the
// allowlist of client keys that is rebuilt from those records, the long-lived
// server's lifecycle, and the gate in front of the tunnel listener. The other
// half — raising a client to a peer's server, and choosing between it and the
// direct path — is decision AY's, in raise.go and route.go.
//
// The tunnel never authenticates an instance. Every connection through it runs
// the same TLS 1.3 handshake, pinned to the same identity key, as a direct
// connection does (decision A1); the tailcat keys decide who can reach that
// handshake and never who is on the far end of it. That is what lets the keys
// be exchanged at all: they arrive under a channel that has already
// authenticated, and nothing ever accepts one in place of the identity.

// Tunnel is the long-lived tailcat server and this instance's client key, as
// the node needs them.
//
// It is an interface because tailcat is not linked here. `tailscale.com`, its
// gVisor stack and its pre-release pin stay out of pkg/ — and so out of every
// phone build and every consumer of this module that does not want them — by
// living behind internal/tunnel, which only the daemon binaries wire in. A node
// without one is a build without tailcat or an instance with the upgrade
// switched off, and it sends the withdrawal form of the offer on every carrier.
//
// The signatures are strings, byte slices, integers, errors and the transport
// package's own tunnel interfaces, which is all `gomobile` binds (§21).
type Tunnel interface {
	// Version is the tunnel wire version this instance offers. It is ours, not
	// tailcat's, and is bumped whenever the pinned tailcat changes its address
	// or wire format incompatibly, so that a peer on an older build stays on
	// the direct path instead of failing to raise.
	Version() int32
	// Start raises the long-lived server in its persisted region and returns
	// its tailcat address. It does not re-pick a region that is already
	// persisted: an address embeds its region, and a pair with no direct path
	// has no way to hear about a new one.
	Start() (string, error)
	// ClientKey is this instance's tailcat client node public key, raw.
	ClientKey() []byte
	// Listen is the server's listener on the peer port, once started.
	Listen() (transport.TunnelListener, error)
	// Admit lets a client key reach the server; Revoke takes it back and drops
	// the client if it is connected.
	Admit(clientKey []byte)
	Revoke(clientKey []byte)
	// RelayRegion is every DERP region a peer's server address embeds, as the
	// JSON of a []relayRegion, so that the region rule can be applied here
	// without parsing a tailcat address here (checkRelayRegion). Every one,
	// because a client raised against the address connects to all of them.
	RelayRegion(serverAddress string) (string, error)
	// KnownRelays is this instance's own DERP map as far as it is known — at
	// least the region the server runs in — as the JSON of a []relayRegion.
	KnownRelays() string
	// Region names the region the server runs in, for a status line.
	Region() string
	// Raise builds a client to a peer's server address, with this instance's
	// client key (decision AY). It does not start it: the first Ping or Dial
	// does, and the client is a whole network stack of its own until Close.
	Raise(serverAddress string) (TunnelClient, error)
	// ClientPath is how the server sees one client key now: ClientPathDirect
	// for a punched UDP path, ClientPathRelayed — followed by a space and the
	// region when it is known — for a DERP relay, and "" for a client that is
	// not connected.
	ClientPath(clientKey []byte) string
	// Close closes the server and every client connection it holds.
	Close() error
}

// TunnelClient is one raised client: a tailcat client to one peer's server
// (decision AY). The deadlines are Unix nanoseconds, zero for none, because
// gomobile binds no context and no time.Time (§21).
type TunnelClient interface {
	// Ping starts the client if it has not started and waits for the server to
	// acknowledge it, which is the server admitting its key. A client that
	// pings has a tunnel; whether the far end is the peer is the pinned TLS's
	// to say, not this.
	Ping(deadlineUnixNano int64) error
	// Dial opens a TCP connection to the server's peer port.
	Dial(deadlineUnixNano int64) (transport.TunnelConn, error)
	// Close tears the client's stack down.
	Close() error
}

// What Tunnel.ClientPath answers.
const (
	ClientPathDirect  = "direct"
	ClientPathRelayed = "relayed"
)

// DefaultTunnelStale is how long a stored offer stays raisable without a beat
// re-confirming it. Long, because a laptop that was closed for a week is still
// the same laptop with the same keys; what it guards against is a peer that
// was reinstalled from a build that sends nothing at all, which would otherwise
// leave this instance raising a tunnel to keys nobody holds, for ever.
const DefaultTunnelStale = 14 * 24 * time.Hour

// tunnelContradictionGrace is how long a peer's beats have to keep carrying no
// offer at all before that contradicts the offer it made.
//
// An instance whose server is starting, or being replaced, sends nothing too:
// that is what "absent" is for, and its address will be the one it had. So
// one absent beat is not a contradiction, and the first version, which made it
// one, aged every peer's offer out on every unseal, every DERP-map retry and
// every re-save of the setting. What the rule is for — a peer reinstalled from
// a build that never sends the field — keeps sending nothing for ever, and is
// caught a few minutes later instead of at once.
const tunnelContradictionGrace = 10 * time.Minute

// tunnelState is the node's tunnel bookkeeping. Its own mutex, because the
// gate reads it during a handshake and must not wait on a link coming up.
type tunnelState struct {
	tunnelMu sync.Mutex
	// tunnel is the engine, nil when there is none; tunnelAddress is its server
	// address once started, and tunnelDetail why it is not running when it is
	// not.
	tunnel        Tunnel
	tunnelAddress string
	tunnelDetail  string
	tunnelStale   time.Duration
	// tunnelClosed is set once the node has closed its tunnel for good, at
	// seal or shutdown. From then on SetTunnel refuses, nothing starts, and
	// the offer says nothing rather than "withdrawn" (closeTunnel).
	tunnelClosed bool
	// tunnelSeen is when a beat last re-confirmed each peer's offer, and
	// tunnelContradicted when each peer's direct contacts started carrying no
	// offer at all, for as long as they have kept doing so. In memory, like
	// `seen`: a confirmation is worth nothing after a restart, which falls back
	// on the record's tunnel_updated_at.
	tunnelSeen         map[string]time.Time
	tunnelContradicted map[string]time.Time
	// observeTunnel is told about every tunnel event, for the metrics port.
	observeTunnel func(event string)
	// tunnelDwell is the hysteresis dwell and tunnelIdle the dialer's reap
	// age (decision AY), zero for the defaults; probe is the direct probe the
	// race runs, nil for the real one; and directClient builds the client a
	// link or the dialer takes the direct path with, nil for
	// transport.NewClient. Tests set them, so that the precedence between the
	// two paths can be exercised without a network.
	tunnelDwell  time.Duration
	tunnelIdle   time.Duration
	probe        probeFunc
	directClient func(transport.ClientOptions) (*transport.Client, error)
	// linked is told each time a link comes up — the transition that pushes
	// grant activity and logs "linked" — nil outside tests. It is how a test
	// holds a path change to the rule that it is not one of those.
	linked func(fingerprint string)
}

// newDirectClient is the client for the direct path to a peer.
func (n *Node) newDirectClient(opts transport.ClientOptions) (*transport.Client, error) {
	if n.directClient != nil {
		return n.directClient(opts)
	}

	return transport.NewClient(opts)
}

// TunnelStatus is the long-lived server as a status line reports it.
type TunnelStatus struct {
	// Configured is whether the node has a tunnel at all.
	Configured bool
	// Running is whether the server is up, Region where, and Detail why not.
	Running bool
	Region  string
	Detail  string
	Version int32
}

// TunnelStatus reports the long-lived server. A pointer, because gomobile
// binds structs by pointer only (§21).
func (n *Node) TunnelStatus() *TunnelStatus {
	n.tunnelMu.Lock()
	defer n.tunnelMu.Unlock()

	if n.tunnel == nil {
		return &TunnelStatus{}
	}

	status := &TunnelStatus{
		Configured: true,
		Running:    n.tunnelAddress != "",
		Detail:     n.tunnelDetail,
		Version:    n.tunnel.Version(),
	}

	if status.Running {
		status.Region = n.tunnel.Region()
	}

	return status
}

func (n *Node) observedTunnel(event string) {
	if n.observeTunnel != nil {
		n.observeTunnel(event)
	}
}

// SetTunnel gives the node a tunnel, replaces the one it has, or takes it away
// with nil, which is what turning the upgrade on and off at runtime does.
//
// The old one is closed first. Two servers with one node key would fight over
// the same DERP connection, and an instance that has just been told to stop
// being reachable through the tunnel should stop before anything else happens.
// The new one starts in the background when the node is already serving, and
// at the first Serve otherwise (Serve); either way nothing is offered until
// it is up.
//
// A node that has already closed its tunnel — sealed, or shutting down — takes
// no new one: it closes what it is handed. Otherwise a toggle racing a seal
// would start a server, holding the store's tunnel keys and a DERP presence,
// that nothing would ever close.
func (n *Node) SetTunnel(tunnel Tunnel) {
	n.tunnelMu.Lock()
	if n.tunnelClosed {
		n.tunnelMu.Unlock()

		if tunnel != nil {
			if err := tunnel.Close(); err != nil {
				n.log.Debug("could not close the tunnel", "error", err.Error())
			}
		}

		return
	}

	old := n.tunnel
	n.tunnel = tunnel
	n.tunnelAddress = ""
	n.tunnelDetail = ""
	n.tunnelMu.Unlock()

	if old != nil {
		if err := old.Close(); err != nil {
			n.log.Debug("could not close the tunnel", "error", err.Error())
		}
	}

	n.mu.Lock()
	serving := n.ctx != nil
	n.mu.Unlock()

	if tunnel != nil && serving {
		go n.raiseServer(tunnel)
	}

	// Whether this instance can raise a client at all has just changed, and
	// with it which peers are dialable and what every link's tunnel should be
	// doing (decision AY). Reconcile hands each link its record again, which
	// syncs its tunnel, and moves a tunnel-only peer between a link and an
	// inbox.
	//
	// The dialer's raised clients are dropped here rather than left to sync on
	// their next call: each is a whole tailcat stack with its DERP and
	// WireGuard sessions, and `ladulas tunnel off` is somebody ending a public
	// exposure (decision AX), who expects it to end now rather than at the
	// next dial-back or five idle minutes later. A dialer that wants a tunnel
	// again raises one against the new tunnel on its next call.
	n.resetDialerTunnels()

	if serving {
		n.Reconcile()
	}
}

// resetDialerTunnels drops every dialer's raised tunnel client.
func (n *Node) resetDialerTunnels() {
	n.dialMu.Lock()
	held := make([]*dialer, 0, len(n.dialers))

	for _, d := range n.dialers {
		held = append(held, d)
	}
	n.dialMu.Unlock()

	for _, d := range held {
		d.tunnelPath().reset()
	}
}

// raiseServer starts the long-lived server and keeps trying until it is up,
// the node stops, or the tunnel is replaced.
//
// A server that cannot start is not a node that cannot work: DERP being
// unreachable costs the tunnel and nothing else, since every peer still has
// whatever direct path it had. So it runs in the background — Serve does not
// wait for it, because a first region pick can take startTimeout and nothing
// else on the node should — and backs off between the presence loop's floor
// and ceiling, which means a desktop unsealed on a train is offering its
// tunnel within a minute of the network coming back.
func (n *Node) raiseServer(tunnel Tunnel) {
	ctx := n.lifetime()
	delay := n.floor

	for {
		if ctx.Err() != nil || !n.isTunnel(tunnel) || n.startServer(tunnel) {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}

		delay = min(delay*2, n.ceiling)
	}
}

// isTunnel reports whether a tunnel is still the node's, and the node has not
// closed it.
func (n *Node) isTunnel(tunnel Tunnel) bool {
	n.tunnelMu.Lock()
	defer n.tunnelMu.Unlock()

	return n.tunnel == tunnel && !n.tunnelClosed
}

// startServer runs one attempt at bringing the server up: start it, admit
// every key the store says should be admitted, and serve the peer handler on
// its listener behind the tunnel gate. It reports whether the server is up.
//
// The order is the lifecycle §3 requires: the server first, so its address is
// known; the allowlist from the records and pending pairings, which is the
// rebuild at unseal; and only then is the address published, by being what
// offer returns. Beats sent before that carry no offer, which peers read as no
// change, so no beat after an unseal carries a stale one.
func (n *Node) startServer(tunnel Tunnel) bool {
	if !n.isTunnel(tunnel) {
		return true
	}

	address, err := tunnel.Start()
	if err != nil {
		n.tunnelMu.Lock()
		if n.tunnel == tunnel {
			n.tunnelDetail = err.Error()
		}
		n.tunnelMu.Unlock()

		n.log.Warn("the tunnel server did not start", "error", err.Error())
		n.observedTunnel("server_failed")

		return false
	}

	listener, err := tunnel.Listen()
	if err != nil {
		n.tunnelMu.Lock()
		if n.tunnel == tunnel {
			n.tunnelDetail = err.Error()
		}
		n.tunnelMu.Unlock()

		n.log.Warn("the tunnel server could not listen", "error", err.Error())
		n.observedTunnel("server_failed")

		return false
	}

	n.admitAll(tunnel)

	n.tunnelMu.Lock()
	current := n.tunnel == tunnel
	if current {
		n.tunnelAddress = address
		n.tunnelDetail = ""
	}
	n.tunnelMu.Unlock()

	if !current {
		_ = listener.Close()

		return true
	}

	n.log.Info("the tunnel server is up", "region", tunnel.Region())
	n.observedTunnel("server_started")

	go func() {
		err := n.server.ServeTunnel(listener, tunnelGate{node: n})
		if err != nil && !errors.Is(err, transport.ErrTunnelClosed) {
			n.log.Warn("the tunnel listener stopped", "error", err.Error())
		}
	}()

	return true
}

// closeTunnel closes the server, which is what sealing does to it (§3). The
// links, which are the clients, have stopped before this is called.
//
// It marks the node closed before it lets go of the tunnel, and a closed node
// offers nothing rather than the withdrawal. Closing tailcat takes the engine,
// netstack and magicsock down and is not instant, and a carrier still running
// during it would otherwise tell every peer "withdrew its tunnel" — costing
// each of them a store write and this instance's allowlist entry — on every
// seal and every restart. Withdrawal is for the upgrade being turned off.
func (n *Node) closeTunnel() {
	n.tunnelMu.Lock()
	n.tunnelClosed = true
	tunnel := n.tunnel
	n.tunnel = nil
	n.tunnelAddress = ""
	n.tunnelMu.Unlock()

	if tunnel == nil {
		return
	}

	if err := tunnel.Close(); err != nil {
		n.log.Debug("could not close the tunnel", "error", err.Error())
	}
}

// tunnelVersion is the version this instance offers, zero when it has no
// tunnel.
func (n *Node) tunnelVersion() int32 {
	n.tunnelMu.Lock()
	defer n.tunnelMu.Unlock()

	if n.tunnel == nil {
		return 0
	}

	return max(n.tunnel.Version(), 0)
}

// offer is what this instance says about its tunnel on every carrier.
//
// Three answers. No tunnel — a build without tailcat, or the upgrade switched
// off — is the withdrawal form, so that a peer holding an old offer drops it
// rather than raising a tunnel that will never come up. A tunnel whose server
// has not started yet is nil, which says nothing: the address it will have is
// the address it had, since key and region are persisted, and a beat that said
// "withdrawn" while the server was still coming up would cost every peer its
// allowlist entry for nothing. And a running server is the offer.
//
// A node that has closed its tunnel, at seal or shutdown, also says nothing:
// it is going away, not turning the upgrade off (closeTunnel).
func (n *Node) offer() *ladulasv1.TunnelOffer {
	n.tunnelMu.Lock()
	defer n.tunnelMu.Unlock()

	if n.tunnelClosed {
		return nil
	}

	if n.tunnel == nil {
		return &ladulasv1.TunnelOffer{}
	}

	if n.tunnelAddress == "" {
		return nil
	}

	return &ladulasv1.TunnelOffer{
		Versions:      []uint32{uint32(max(n.tunnel.Version(), 0))},
		ServerAddress: n.tunnelAddress,
		ClientKey:     n.tunnel.ClientKey(),
	}
}

// admitAll rebuilds the allowlist from the store: the client keys of the trust
// records and of the pending pairings, which is the whole of what may reach the
// server (§8). The set belongs to the server instance, so this is every unseal
// and every restart of the server.
//
// It reads the store twice. The first read is what it admits; the second takes
// back anything the first admitted that is no longer there, because a
// revocation that ran in between read the tunnel's allowlist before this added
// its key back. The gate would still refuse that peer — the record is gone —
// but the allowlist would be holding a key nobody should hold.
func (n *Node) admitAll(tunnel Tunnel) {
	admitted := n.admissibleKeys()

	for key := range admitted {
		tunnel.Admit([]byte(key))
	}

	current := n.admissibleKeys()

	for key := range admitted {
		if !current[key] {
			tunnel.Revoke([]byte(key))
		}
	}
}

// admissibleKeys is every client key the store says may reach the server.
func (n *Node) admissibleKeys() map[string]bool {
	keys := map[string]bool{}

	for _, record := range n.trust.Peers() {
		if key := admissible(record.GetTunnel()); key != nil {
			keys[string(key)] = true
		}
	}

	for _, pending := range n.trust.PendingPairings() {
		if key := admissible(pending.GetTunnel()); key != nil {
			keys[string(key)] = true
		}
	}

	return keys
}

// admissible is the client key an offer asks to have admitted, or nil for an
// offer that is withdrawn or names none.
func admissible(offer *ladulasv1.TunnelOffer) []byte {
	if len(offer.GetVersions()) == 0 || len(offer.GetClientKey()) == 0 {
		return nil
	}

	return offer.GetClientKey()
}

// admitKey and revokeKey change the allowlist, when there is a tunnel to
// change it on. A key added while there is none is added by the next
// admitAll, which reads the same records.
func (n *Node) admitKey(key []byte) {
	if len(key) == 0 {
		return
	}

	n.tunnelMu.Lock()
	tunnel := n.tunnel
	n.tunnelMu.Unlock()

	if tunnel != nil {
		tunnel.Admit(key)
		n.observedTunnel("admitted")
	}
}

func (n *Node) revokeKey(key []byte) {
	if len(key) == 0 {
		return
	}

	n.tunnelMu.Lock()
	tunnel := n.tunnel
	n.tunnelMu.Unlock()

	if tunnel != nil {
		tunnel.Revoke(key)
		n.observedTunnel("revoked")
	}
}

// learnTunnel is what a peer's offer does to its trust record.
//
// It is learnAddresses' rule with the third state the tunnel needs: absent
// changes nothing, a withdrawal clears what is held and takes the client key
// off the allowlist, and an offer replaces what is held when it differs. The
// record is written only on a change, because an offer rides every beat.
//
// The peer is authenticated and can only change its own record, and what it
// can change is which client key reaches this instance's TLS handshake and
// which server this instance would raise a client to. Every connection either
// way is still pinned to the peer's identity, so the most a peer can do is
// send its own tunnel somewhere useless — except for the DERP region an
// address embeds, which this instance would connect to, and which is held to
// checkRelayRegion before it is written down.
func (n *Node) learnTunnel(fingerprint string, offer *ladulasv1.TunnelOffer) {
	record, ok := n.trust.Peer(fingerprint)
	if !ok {
		return
	}

	held := record.GetTunnel()

	if offer == nil {
		// Absent. An instance that offered before and keeps sending nothing at
		// all is one reinstalled from a build older than the offer, and its keys
		// are no longer anybody's (§8: stale offers age out). Keeps: one that
		// is starting its server sends nothing for a moment too, so only the
		// first absent beat is dated, and it contradicts the offer once the
		// grace has passed with no offer in between (tunnelStaleFor).
		if len(held.GetVersions()) > 0 {
			n.tunnelMu.Lock()
			if _, ok := n.tunnelContradicted[fingerprint]; !ok {
				n.tunnelContradicted[fingerprint] = time.Now()
			}
			n.tunnelMu.Unlock()
		}

		return
	}

	n.tunnelMu.Lock()
	delete(n.tunnelContradicted, fingerprint)

	if len(offer.GetVersions()) > 0 {
		n.tunnelSeen[fingerprint] = time.Now()
	}
	n.tunnelMu.Unlock()

	wanted := n.normalizeOffer(record.GetName(), offer)

	// A withdrawal from a peer that never offered is the ordinary beat of every
	// instance that has the upgrade off, and writing it down would turn "offers
	// no tunnel" into "withdrew its tunnel" for every one of them.
	if wanted != nil && len(wanted.GetVersions()) == 0 && len(held.GetVersions()) == 0 {
		return
	}

	if proto.Equal(held, wanted) {
		return
	}

	revised := proto.CloneOf(record)
	revised.Tunnel = wanted
	revised.TunnelUpdatedAt = timestamppb.Now()

	if err := n.trust.PutPeer(revised); err != nil {
		n.log.Error("could not record a peer's tunnel offer",
			"peer", record.GetName(), "error", err.Error())

		return
	}

	before, after := admissible(held), admissible(wanted)

	if !bytes.Equal(before, after) {
		n.revokeKey(before)
		n.admitKey(after)
	}

	if len(wanted.GetVersions()) == 0 {
		n.log.Info("a peer withdrew its tunnel", "peer", record.GetName())
		n.observedTunnel("offer_withdrawn")
	} else {
		n.log.Info("a peer offered its tunnel", "peer", record.GetName())
		n.observedTunnel("offer_received")
	}

	// The links work from the record they were built with, and Reconcile is
	// what hands them a new one — which re-raises or drops a link's tunnel —
	// and what moves a peer whose only way in is its tunnel between a link and
	// an inbox when it has just become, or stopped being, one this instance
	// can dial (trust.Dialable). In the background, because this runs on a
	// link's own presence loop, and a withdrawal from a tunnel-only peer
	// stops that very link, which waits for the loop to finish.
	go n.Reconcile()
}

// normalizeOffer is what of an offer is written down: the three fields, with
// a server address whose DERP region fails the region rule dropped, and a
// withdrawal reduced to the empty message.
func (n *Node) normalizeOffer(
	name string, offer *ladulasv1.TunnelOffer,
) *ladulasv1.TunnelOffer {
	if offer == nil {
		return nil
	}

	if len(offer.GetVersions()) == 0 {
		return &ladulasv1.TunnelOffer{}
	}

	wanted := &ladulasv1.TunnelOffer{
		Versions:      append([]uint32(nil), offer.GetVersions()...),
		ServerAddress: offer.GetServerAddress(),
		ClientKey:     append([]byte(nil), offer.GetClientKey()...),
	}

	if wanted.GetServerAddress() != "" {
		if refused := n.checkOfferRegion(wanted.GetServerAddress()); refused != "" {
			n.log.Warn("refused the DERP region a peer's tunnel address names",
				"peer", name, "reason", refused)
			n.observedTunnel("region_refused")

			wanted.ServerAddress = ""
		}
	}

	return wanted
}

// checkOfferRegion applies the region rule to a peer's server address, when
// this instance has a tunnel to parse it with. Without one nothing here will
// ever connect to the region, and the rule is applied again when a client is
// raised.
func (n *Node) checkOfferRegion(address string) string {
	n.tunnelMu.Lock()
	tunnel := n.tunnel
	n.tunnelMu.Unlock()

	if tunnel == nil {
		return ""
	}

	region, err := tunnel.RelayRegion(address)
	if err != nil {
		return "that tunnel address does not parse: " + err.Error()
	}

	return checkRelayRegionJSON(region, tunnel.KnownRelays())
}

// pendingOffer is the offer a pairing exchange carried, as a pending pairing
// stores it, admitted on the spot: the keys arrived inside a PIN exchange or
// over pinned TLS, bound to both identity keys, so "admitted only over an
// authenticated channel" holds (§8). A pending identity reaches nothing on the
// tunnel listener but SettlePairing for its own session (tunnelGate).
func (n *Node) pendingOffer(name string, offer *ladulasv1.TunnelOffer) *ladulasv1.TunnelOffer {
	wanted := n.normalizeOffer(name, offer)
	if len(wanted.GetVersions()) == 0 {
		// A withdrawal is how a pairing peer without the upgrade says so, and
		// a pending pairing has nothing to withdraw from.
		return nil
	}

	n.admitKey(admissible(wanted))

	return wanted
}

// forgetPendingTunnel takes a pending pairing's client key off the allowlist,
// when a pairing is declined, withdrawn or forgotten — unless the same identity
// has a trust record holding the same key, which is a re-pair of a peer that
// is still admitted for its own reasons.
func (n *Node) forgetPendingTunnel(pending *storepb.PendingPairing) {
	key := admissible(pending.GetTunnel())
	if key == nil {
		return
	}

	if record, ok := n.trust.Peer(pending.GetFingerprint()); ok &&
		bytes.Equal(admissible(record.GetTunnel()), key) {
		return
	}

	n.revokeKey(key)
}

// forgetRecordTunnel takes a revoked peer's client key off the allowlist and
// drops its client. Revocation does not depend on it — the record is gone, so
// the next handshake fails the gate whatever the allowlist says — but a peer
// that has been forgotten should not still be holding a WireGuard session.
func (n *Node) forgetRecordTunnel(record *storepb.TrustRecord) {
	n.revokeKey(admissible(record.GetTunnel()))

	n.tunnelMu.Lock()
	delete(n.tunnelSeen, record.GetFingerprint())
	delete(n.tunnelContradicted, record.GetFingerprint())
	n.tunnelMu.Unlock()
}

// tunnelStaleFor reports whether a peer's offer has aged out.
//
// An offer no beat has re-confirmed for the configured period, or one the
// peer's direct contacts have carried no offer at all for longer than
// tunnelContradictionGrace, stops being raised until the next offer arrives
// (§8). The exception is a peer with no direct address: its
// tunnel is the only carrier the next offer could arrive on, so ageing its
// offer out would strand the pair for good. Nothing else could replace it, so
// nothing is gained by refusing to try it.
func (n *Node) tunnelStaleFor(record *storepb.TrustRecord) bool {
	if len(record.GetAddresses()) == 0 {
		return false
	}

	n.tunnelMu.Lock()
	contradicted, absent := n.tunnelContradicted[record.GetFingerprint()]
	seen := n.tunnelSeen[record.GetFingerprint()]
	n.tunnelMu.Unlock()

	if absent && time.Since(contradicted) > tunnelContradictionGrace {
		return true
	}

	if updated := record.GetTunnelUpdatedAt().AsTime(); updated.After(seen) {
		seen = updated
	}

	return time.Since(seen) > n.tunnelStale
}

// describeTunnel is the tunnel's word for a peer's status (trust.DescribeTunnel):
// this instance's side, the path the peer is on and the direct address in use
// when it is direct, and what the raise is doing.
func (n *Node) describeTunnel(
	record *storepb.TrustRecord, path, address string, tunnel *tunnelPath,
) string {
	facts := &trust.TunnelFacts{
		Ours:    n.tunnelVersion(),
		Stale:   n.tunnelStaleFor(record),
		Path:    path,
		Address: address,
	}

	tunnel.facts(facts)

	return trust.DescribeTunnel(record, facts)
}

// tunnelGate is the long-lived tunnel listener's own door (§8, §16).
//
// It is narrower than the bound listener's gate in two ways and both are the
// point. It never admits an identity because a pairing window is open: that
// admission belongs to the bound listener and the pairing server, and a
// listener reachable from any DERP region that admitted strangers while a PIN
// was on screen would be a guessing surface open to the world. And it checks
// the tunnel client key a connection arrived with against the one that
// identity offered, so a leaked client key reaches nothing an unpaired
// identity could use, and a paired identity is admitted through its own tunnel
// only.
type tunnelGate struct {
	node *Node
}

var _ transport.TunnelGate = tunnelGate{}

// Admit lets in a paired identity, or one half way through a pairing written
// down here, arriving with the client key it offered.
func (g tunnelGate) Admit(fingerprint string, clientKey []byte) error {
	n := g.node

	if record, ok := n.trust.Peer(fingerprint); ok {
		return g.matches(record.GetName(), record.GetTunnel(), clientKey)
	}

	if pending, ok := n.trust.PendingPairing(fingerprint); ok &&
		pending.GetFingerprint() == fingerprint {
		return g.matches(pending.GetName(), pending.GetTunnel(), clientKey)
	}

	n.observedTunnel("refused")

	return fmt.Errorf("%w: %s is not paired, and the tunnel does not pair",
		errNotPaired, fingerprint)
}

func (g tunnelGate) matches(
	name string, offer *ladulasv1.TunnelOffer, clientKey []byte,
) error {
	held := admissible(offer)

	if held == nil || len(clientKey) == 0 || !bytes.Equal(held, clientKey) {
		g.node.observedTunnel("refused")

		return fmt.Errorf("%w: %q came through the tunnel with a client key "+
			"it has not offered", errNotPaired, name)
	}

	return nil
}

// settleProcedure is the one pairing RPC the tunnel listener answers, and the
// only RPC a pending identity reaches through it.
const settleProcedure = ladulasv1connect.PairingServiceSettlePairingProcedure

// Permit refuses the pairing RPCs to everybody, and everything but
// SettlePairing to an identity that is only pending. SettlePairing checks for
// itself that the session is the caller's own (settlePairingReply).
func (g tunnelGate) Permit(fingerprint, procedure string) error {
	if strings.HasPrefix(procedure, "/"+ladulasv1connect.PairingServiceName+"/") &&
		procedure != settleProcedure {
		return errors.New("the tunnel listener does not pair; " +
			"pair on the local network or with the full code")
	}

	if _, ok := g.node.trust.Peer(fingerprint); ok {
		return nil
	}

	if procedure == settleProcedure {
		return nil
	}

	return fmt.Errorf("%w: a pairing that is still pending reaches only "+
		"SettlePairing through the tunnel", errNotPaired)
}
