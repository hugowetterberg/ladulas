//go:build !notailcat

package tunnel

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"

	"github.com/hugowetterberg/ladulas/pkg/peer"
	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// Available says this build carries tailcat.
const Available = true

// startTimeout bounds one attempt at starting the server: fetching the DERP map
// and picking a region the first time, connecting to the region every time.
const startTimeout = 30 * time.Second

// Tunnel is the long-lived tailcat server and the client key, behind
// peer.Tunnel.
type Tunnel struct {
	opts      Options
	log       *slog.Logger
	clientPub key.NodePublic

	// allow is the allowlist. It is consulted on each new client's MEOW and is
	// safe to change at any time (tailcat's AllowClient hook, on main since
	// 2026-10-07): admitting and revoking a key costs nothing, and nothing
	// restarts the server.
	allow tailcat.KeySet

	mu     sync.Mutex
	server *tailcat.Server
	region *tailcfg.DERPRegion
	known  *tailcfg.DERPMap
	closed bool
}

var _ peer.Tunnel = (*Tunnel)(nil)

// New builds a tunnel. It does not start; the node does that, at the point in
// its lifecycle where the address is to be published.
func New(opts Options) (*Tunnel, error) {
	for name, raw := range map[string][]byte{
		"server key": opts.ServerKey, "client key": opts.ClientKey,
		"pre-shared key": opts.PresharedKey,
	} {
		if len(raw) != 32 {
			return nil, fmt.Errorf("tunnel: the %s is %d bytes, want 32", name, len(raw))
		}
	}

	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	client, err := nodePrivate(opts.ClientKey)
	if err != nil {
		return nil, err
	}

	t := &Tunnel{
		opts:      opts,
		log:       log,
		clientPub: client.Public(),
	}

	if len(opts.Region) > 0 {
		var region tailcfg.DERPRegion
		if err := json.Unmarshal(opts.Region, &region); err != nil {
			return nil, fmt.Errorf("tunnel: the persisted DERP region does not read: %w", err)
		}

		t.region = &region
	}

	return t, nil
}

// newTunnel is New as Factory needs it.
func newTunnel(opts Options) (peer.Tunnel, error) {
	built, err := New(opts)
	if err != nil {
		return nil, err
	}

	return built, nil
}

// Version implements peer.Tunnel.
func (t *Tunnel) Version() int32 { return Version }

// Start implements peer.Tunnel: the server in its persisted region, or in the
// region picked from the DERP map the first time, which is then persisted.
//
// The pick is made without holding t.mu. It fetches the map and measures
// latency for up to startTimeout, and Admit, Revoke and KnownRelays — which a
// revocation and every peer's beat call — take t.mu and should not wait on a
// network that may be refusing to answer.
func (t *Tunnel) Start() (string, error) {
	t.mu.Lock()

	if t.closed {
		t.mu.Unlock()

		return "", errors.New("tunnel: closed")
	}

	if t.server != nil {
		address := string(t.server.TailcatAddr())
		t.mu.Unlock()

		return address, nil
	}

	needPick := t.region == nil
	t.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()

	if needPick {
		if err := t.pickAndPersist(ctx); err != nil {
			return "", err
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return "", errors.New("tunnel: closed")
	}

	if t.server != nil {
		return string(t.server.TailcatAddr()), nil
	}

	var psk tailcat.PresharedKey
	copy(psk[:], t.opts.PresharedKey)

	serverKey, err := nodePrivate(t.opts.ServerKey)
	if err != nil {
		return "", err
	}

	server := &tailcat.Server{
		Key:          serverKey,
		PresharedKey: psk,
		// Never re-picked: with Region set the server starts in it and fetches
		// no map at all (§8, "the region is a contract").
		Region:      t.region,
		AllowClient: t.allow.Contains,
		Logf: func(format string, args ...any) {
			t.log.Debug("tailcat: " + fmt.Sprintf(format, args...))
		},
		// Only the peer port is served. A listener's port is admitted whatever
		// this says, so an empty list that is not nil is "nothing else": the
		// packet filter drops a connection to any other port before netstack
		// sees it, rather than answering it with OnTCP's RST. The same for
		// UDP, which nothing here serves.
		ServedTCPPorts: []filter.PortRange{},
		ServedUDPPorts: []filter.PortRange{},
	}

	if err := server.StartContext(ctx); err != nil {
		_ = server.Close()

		return "", fmt.Errorf("tunnel: start the server in DERP region %s: %w",
			regionName(t.region), err)
	}

	t.server = server

	return string(server.TailcatAddr()), nil
}

// pickAndPersist picks a region and records it, unless one was recorded while
// it was picking. Persisted before the server starts, so that an address that
// ever leaves this process names a region that will still be this one after
// the next unseal.
func (t *Tunnel) pickAndPersist(ctx context.Context) error {
	region, known, err := t.pick(ctx)
	if err != nil {
		return err
	}

	encoded, err := json.Marshal(region)
	if err != nil {
		return fmt.Errorf("tunnel: encode the DERP region: %w", err)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed || t.region != nil {
		return nil
	}

	if t.opts.OnRegion != nil {
		if err := t.opts.OnRegion(encoded); err != nil {
			return fmt.Errorf("tunnel: persist the DERP region: %w", err)
		}
	}

	t.region, t.known = region, known

	return nil
}

// pick fetches the DERP map and picks the region nearest by latency, falling
// back to a random region of the map when the latency check finds nothing,
// which is tailcat's own fallback.
func (t *Tunnel) pick(ctx context.Context) (*tailcfg.DERPRegion, *tailcfg.DERPMap, error) {
	url := t.opts.DERPMapURL
	if url == "" {
		url = DefaultDERPMapURL
	}

	known, err := tailcat.FetchDERPMap(ctx, tailcat.DERPMapURL(url), tailcat.ExpandForServer)
	if err != nil {
		return nil, nil, fmt.Errorf("tunnel: fetch the DERP map from %s: %w", url, err)
	}

	info := &tailcat.ConnInfo{RegionID: -1}
	if err := info.Expand(ctx, known); err != nil {
		return nil, nil, fmt.Errorf("tunnel: pick a DERP region: %w", err)
	}

	if len(info.Region) == 0 {
		return nil, nil, errors.New("tunnel: the DERP map has no regions")
	}

	return info.Region[0], known, nil
}

// ClientKey implements peer.Tunnel.
func (t *Tunnel) ClientKey() []byte {
	return t.clientPub.AppendTo(nil)
}

// nodePrivate turns a raw key from the store into tailscale's type. Through
// the text form, because the raw constructor is deprecated upstream for
// anything but a legacy cast; the store keeps raw bytes so that it does not
// depend on tailscale's spelling of a key.
func nodePrivate(raw []byte) (key.NodePrivate, error) {
	var out key.NodePrivate

	if err := out.UnmarshalText([]byte("privkey:" + hex.EncodeToString(raw))); err != nil {
		return key.NodePrivate{}, fmt.Errorf("tunnel: unusable node key: %w", err)
	}

	return out, nil
}

// Listen implements peer.Tunnel.
func (t *Tunnel) Listen() (transport.TunnelListener, error) {
	t.mu.Lock()
	server := t.server
	t.mu.Unlock()

	if server == nil {
		return nil, errors.New("tunnel: the server has not started")
	}

	listener, err := server.Listen(context.Background(), "tcp", fmt.Sprintf(":%d", Port))
	if err != nil {
		return nil, fmt.Errorf("tunnel: listen on the peer port: %w", err)
	}

	return &tunnelListener{listener: listener, tunnel: t, server: server}, nil
}

// Admit implements peer.Tunnel.
func (t *Tunnel) Admit(clientKey []byte) {
	if len(clientKey) != 32 {
		return
	}

	t.allow.Add(key.NodePublicFromRaw32(mem.B(clientKey)))
}

// Revoke implements peer.Tunnel: off the allowlist first, then disconnected,
// in the order DisconnectClient asks for, so the client cannot reconnect in
// between.
func (t *Tunnel) Revoke(clientKey []byte) {
	if len(clientKey) != 32 {
		return
	}

	public := key.NodePublicFromRaw32(mem.B(clientKey))
	t.allow.Remove(public)

	t.mu.Lock()
	server := t.server
	t.mu.Unlock()

	if server != nil {
		server.DisconnectClient(public)
	}
}

// relayRegion is pkg/peer's relayRegion, as JSON.
type relayRegion struct {
	ID    int         `json:"id,omitempty"`
	Nodes []relayNode `json:"nodes"`
}

// relayNode carries every field of a DERP node that decides where a client
// connects and what it accepts there: the host and the addresses beside it,
// both ports, the certificate name and the test mode. Leaving one out is
// leaving the rule blind to it.
type relayNode struct {
	Host     string `json:"host"`
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	DERPPort int    `json:"derp_port,omitempty"`
	STUNPort int    `json:"stun_port,omitempty"`
	CertName string `json:"cert_name,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
}

func relayOf(region *tailcfg.DERPRegion, id int) relayRegion {
	out := relayRegion{ID: id, Nodes: []relayNode{}}

	for _, node := range region.Nodes {
		if node.STUNOnly {
			continue
		}

		out.Nodes = append(out.Nodes, relayNode{
			Host:     node.HostName,
			IPv4:     node.IPv4,
			IPv6:     node.IPv6,
			DERPPort: node.DERPPort,
			STUNPort: node.STUNPort,
			CertName: node.CertName,
			Insecure: node.InsecureForTests,
		})
	}

	return out
}

// RelayRegion implements peer.Tunnel: every region the address embeds, as the
// JSON of a []relayRegion.
//
// Every one, not the first. An address carries a list, ParseAddr keeps all of
// it, and a client raised against it puts each region into its DERP map, so
// that netcheck and magicsock run STUN and DERP against all of them. A rule
// that looked at the first would pass an address whose second region pointed
// into this machine's own network.
//
// An address that names a region by id alone embeds none, and comes back as a
// single region with that id and no relays: the id is the only thing it says.
// An embedded region's id is not part of the address (ConnInfo.Addr zeroes it).
func (t *Tunnel) RelayRegion(serverAddress string) (string, error) {
	info, err := tailcat.ParseAddr(tailcat.Addr(serverAddress))
	if err != nil {
		return "", fmt.Errorf("tunnel: %w", err)
	}

	out := []relayRegion{{ID: int(info.RegionID), Nodes: []relayNode{}}}

	if len(info.Region) > 0 {
		out = make([]relayRegion, 0, len(info.Region))

		for _, region := range info.Region {
			if region == nil {
				continue
			}

			out = append(out, relayOf(region, 0))
		}
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("tunnel: encode the regions: %w", err)
	}

	return string(encoded), nil
}

// KnownRelays implements peer.Tunnel: the regions of the DERP map, when this
// process fetched one, and always the region the server runs in.
func (t *Tunnel) KnownRelays() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	var out []relayRegion

	if t.region != nil {
		out = append(out, relayOf(t.region, int(t.region.RegionID)))
	}

	if t.known != nil {
		for id, region := range t.known.Regions {
			out = append(out, relayOf(region, int(id)))
		}
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return ""
	}

	return string(encoded)
}

// Region implements peer.Tunnel.
func (t *Tunnel) Region() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	return regionName(t.region)
}

func regionName(region *tailcfg.DERPRegion) string {
	switch {
	case region == nil:
		return ""
	case region.RegionName != "":
		return region.RegionName
	case region.RegionCode != "":
		return region.RegionCode
	default:
		return fmt.Sprint(region.RegionID)
	}
}

// Close implements peer.Tunnel.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	server := t.server
	t.server = nil
	t.closed = true
	t.mu.Unlock()

	if server == nil {
		return nil
	}

	if err := server.Close(); err != nil {
		return fmt.Errorf("tunnel: close the server: %w", err)
	}

	return nil
}

// path is what a connection from a client came over, from the server's own
// view of that client (Server.Status, since tailcat v0.7.0): a current direct
// address is a punched path, and anything else is the relay.
func (t *Tunnel) path(server *tailcat.Server, client key.NodePublic) string {
	relayed := "tunnel, relayed via DERP " + t.Region()

	status := server.Status()
	if status == nil {
		return relayed
	}

	peer, ok := status.Peer[client]
	if !ok || peer == nil {
		return relayed
	}

	if peer.CurAddr != "" {
		return "tunnel, direct"
	}

	if peer.Relay != "" {
		return "tunnel, relayed via DERP " + peer.Relay
	}

	return relayed
}

// tunnelListener is the server's listener as transport.TunnelListener.
type tunnelListener struct {
	listener net.Listener
	tunnel   *Tunnel
	server   *tailcat.Server
}

func (l *tunnelListener) Accept() (transport.TunnelConn, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err //nolint:wrapcheck // net/http inspects this error
	}

	out := &tunnelConn{Conn: conn, path: "tunnel"}

	// The client key the connection came from is the one the allowlist
	// admitted; the gate holds it against the key the TLS identity offered.
	if client, ok := l.server.PeerKey(conn.RemoteAddr()); ok {
		out.key = client.AppendTo(nil)
		out.path = l.tunnel.path(l.server, client)
	}

	return out, nil
}

func (l *tunnelListener) Close() error {
	return l.listener.Close() //nolint:wrapcheck // net/http inspects this error
}

// tunnelConn is a connection through the tunnel as transport.TunnelConn.
type tunnelConn struct {
	net.Conn

	path string
	key  []byte
}

func (c *tunnelConn) SetDeadline(unixNano int64) error {
	return c.Conn.SetDeadline(deadline(unixNano)) //nolint:wrapcheck // as net.Conn
}

func (c *tunnelConn) SetReadDeadline(unixNano int64) error {
	return c.Conn.SetReadDeadline(deadline(unixNano)) //nolint:wrapcheck // as net.Conn
}

func (c *tunnelConn) SetWriteDeadline(unixNano int64) error {
	return c.Conn.SetWriteDeadline(deadline(unixNano)) //nolint:wrapcheck // as net.Conn
}

func (c *tunnelConn) Path() string { return c.path }

func (c *tunnelConn) ClientKey() []byte { return c.key }

func deadline(unixNano int64) time.Time {
	if unixNano == 0 {
		return time.Time{}
	}

	return time.Unix(0, unixNano)
}
