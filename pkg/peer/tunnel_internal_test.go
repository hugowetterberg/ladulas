package peer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// fakeTunnel stands in for tailcat, which cannot start without a DERP region.
// It records the allowlist the node keeps on it, which is the half of decision
// AX these tests are about.
type fakeTunnel struct {
	mu       sync.Mutex
	address  string
	client   []byte
	admitted map[string]bool
	started  int
	failures int
	region   string
	closed   chan struct{}
	once     sync.Once
	// fabric is what carries connections between fake tunnels, for the tests
	// of the dialling half (decision AY); nil where only the bookkeeping is
	// under test, and then nothing can be raised.
	fabric *fabric
}

func newFakeTunnel(address string, client byte) *fakeTunnel {
	return &fakeTunnel{
		address:  address,
		client:   bytes.Repeat([]byte{client}, 32),
		admitted: map[string]bool{},
		region:   `[{"nodes":[{"host":"derp.example.net"}]}]`,
		closed:   make(chan struct{}),
	}
}

func (f *fakeTunnel) Version() int32 { return 1 }

func (f *fakeTunnel) Start() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.failures > 0 {
		f.failures--

		return "", errors.New("DERP is unreachable")
	}

	f.started++

	return f.address, nil
}

func (f *fakeTunnel) ClientKey() []byte { return f.client }

func (f *fakeTunnel) Listen() (transport.TunnelListener, error) {
	if f.fabric != nil {
		return f.fabric.listen(f), nil
	}

	return &idleListener{closed: f.closed, once: &f.once}, nil
}

func (f *fakeTunnel) Raise(address string) (TunnelClient, error) {
	if f.fabric == nil {
		return nil, errors.New("no fabric to raise over")
	}

	return &fabricClient{fabric: f.fabric, address: address, key: f.client}, nil
}

func (f *fakeTunnel) ClientPath(key []byte) string {
	if f.fabric == nil {
		return ""
	}

	return f.fabric.clientPath(f.address, key)
}

func (f *fakeTunnel) Admit(key []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.admitted[string(key)] = true
}

func (f *fakeTunnel) Revoke(key []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.admitted, string(key))
}

func (f *fakeTunnel) admits(key []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.admitted[string(key)]
}

func (f *fakeTunnel) RelayRegion(address string) (string, error) {
	if !strings.HasPrefix(address, "tc") {
		return "", errors.New("not a tailcat address")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	return f.region, nil
}

func (f *fakeTunnel) KnownRelays() string {
	return `[{"nodes":[{"host":"derp.example.net"}]}]`
}

func (f *fakeTunnel) Region() string { return "test" }

func (f *fakeTunnel) Close() error {
	f.once.Do(func() { close(f.closed) })

	return nil
}

// idleListener accepts nothing until it is closed.
type idleListener struct {
	closed chan struct{}
	once   *sync.Once
}

func (l *idleListener) Accept() (transport.TunnelConn, error) {
	<-l.closed

	return nil, net.ErrClosed
}

func (l *idleListener) Close() error {
	l.once.Do(func() { close(l.closed) })

	return nil
}

// countingStore counts trust record writes, which is what write-on-change is
// a promise about.
type countingStore struct {
	*memoryStore

	puts int
}

func (c *countingStore) PutPeer(record *storepb.TrustRecord) error {
	c.puts++

	return c.memoryStore.PutPeer(record)
}

// tunnelNode is a node with nothing but a store and a tunnel, which is all the
// offer bookkeeping touches.
func tunnelNode(store Store, tunnel Tunnel) *Node {
	return &Node{
		trust: store,
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		links: map[string]*link{},
		tunnelState: tunnelState{
			tunnel:             tunnel,
			tunnelStale:        DefaultTunnelStale,
			tunnelSeen:         map[string]time.Time{},
			tunnelContradicted: map[string]time.Time{},
		},
	}
}

func offerFrom(address string, client byte) *ladulasv1.TunnelOffer {
	return &ladulasv1.TunnelOffer{
		Versions:      []uint32{1},
		ServerAddress: address,
		ClientKey:     bytes.Repeat([]byte{client}, 32),
	}
}

// The offer is written down once and then left alone however often it is
// repeated, because it rides every beat and a store write per heartbeat is the
// cost §7 already turned down for presence (decision AX).
func TestATunnelOfferIsWrittenOnChangeOnly(t *testing.T) {
	t.Parallel()

	store := &countingStore{memoryStore: &memoryStore{records: []*storepb.TrustRecord{{
		Fingerprint: "SHA256:laptop",
		Name:        "laptop",
		Addresses:   []string{"192.168.1.20:7373"},
	}}}}
	tunnel := newFakeTunnel("tcours", 9)
	n := tunnelNode(store, tunnel)
	n.tunnelAddress = tunnel.address

	offer := offerFrom("tctheirs", 1)

	for range 5 {
		n.learnTunnel("SHA256:laptop", offer)
	}

	if store.puts != 1 {
		t.Errorf("five identical offers wrote the record %d times, want once", store.puts)
	}

	record, _ := store.Peer("SHA256:laptop")
	if !proto.Equal(record.GetTunnel(), offer) {
		t.Errorf("stored %v, want %v", record.GetTunnel(), offer)
	}

	if record.GetTunnelUpdatedAt() == nil {
		t.Error("the change was not dated")
	}

	if !tunnel.admits(offer.GetClientKey()) {
		t.Error("the offered client key was not admitted")
	}

	// Absent changes nothing, and is not a write.
	n.learnTunnel("SHA256:laptop", nil)

	if store.puts != 1 {
		t.Error("an absent offer wrote the record")
	}

	// A rotated client key replaces the old one in the allowlist.
	rotated := offerFrom("tctheirs", 2)
	n.learnTunnel("SHA256:laptop", rotated)

	if store.puts != 2 {
		t.Errorf("a rotated key wrote the record %d times in all, want twice", store.puts)
	}

	if tunnel.admits(offer.GetClientKey()) || !tunnel.admits(rotated.GetClientKey()) {
		t.Error("a rotated client key did not replace the old one on the allowlist")
	}
}

// Empty versions withdraw: the stored fields are cleared, the client key comes
// off the allowlist, and the record says so. But a withdrawal from a peer that
// never offered is every upgrade-off instance's ordinary beat, and writing it
// down would turn "offers no tunnel" into "withdrew its tunnel" (decision AX).
func TestAWithdrawalClearsTheOfferAndTheAllowlist(t *testing.T) {
	t.Parallel()

	store := &countingStore{memoryStore: &memoryStore{records: []*storepb.TrustRecord{
		{Fingerprint: "SHA256:laptop", Name: "laptop", Addresses: []string{"192.168.1.20:7373"}},
		{Fingerprint: "SHA256:desk", Name: "desk", Addresses: []string{"192.168.1.30:7373"}},
	}}}
	tunnel := newFakeTunnel("tcours", 9)
	n := tunnelNode(store, tunnel)

	offer := offerFrom("tctheirs", 1)
	n.learnTunnel("SHA256:laptop", offer)
	n.learnTunnel("SHA256:laptop", &ladulasv1.TunnelOffer{})

	record, _ := store.Peer("SHA256:laptop")

	if record.GetTunnel() == nil || len(record.GetTunnel().GetVersions()) != 0 ||
		record.GetTunnel().GetServerAddress() != "" ||
		len(record.GetTunnel().GetClientKey()) != 0 {
		t.Errorf("after a withdrawal the record holds %v, want the empty offer",
			record.GetTunnel())
	}

	if tunnel.admits(offer.GetClientKey()) {
		t.Error("a withdrawn client key is still admitted")
	}

	if got := trust.DescribeTunnel(record, &trust.TunnelFacts{Ours: 1}); got != trust.TunnelWithdrawn {
		t.Errorf("a withdrawn tunnel reads %q", got)
	}

	puts := store.puts

	n.learnTunnel("SHA256:desk", &ladulasv1.TunnelOffer{})

	if store.puts != puts {
		t.Error("a withdrawal from a peer that never offered was written down")
	}

	desk, _ := store.Peer("SHA256:desk")
	if got := trust.DescribeTunnel(desk, &trust.TunnelFacts{Ours: 1}); got != trust.TunnelNoOffer {
		t.Errorf("a peer that never offered reads %q", got)
	}
}

// What the node offers is the withdrawal form without a tunnel, nothing while
// the server is coming up, and the server's address once it is up — never
// "withdrawn" because a server is slow to start, which would cost every peer
// its allowlist entry for nothing (decision AX).
func TestTheOfferFollowsTheServer(t *testing.T) {
	t.Parallel()

	n := tunnelNode(&memoryStore{}, nil)

	if got := n.offer(); got == nil || len(got.GetVersions()) != 0 {
		t.Errorf("without a tunnel the offer is %v, want the withdrawal form", got)
	}

	tunnel := newFakeTunnel("tcours", 9)
	n.tunnel = tunnel

	if got := n.offer(); got != nil {
		t.Errorf("before the server is up the offer is %v, want nothing", got)
	}

	n.tunnelAddress = tunnel.address

	got := n.offer()
	if got.GetServerAddress() != "tcours" ||
		!bytes.Equal(got.GetClientKey(), tunnel.client) ||
		len(got.GetVersions()) != 1 || got.GetVersions()[0] != 1 {
		t.Errorf("with the server up the offer is %v", got)
	}
}

// The allowlist is rebuilt from the store when the server starts: the client
// keys of the trust records and of the pending pairings, and nothing else
// (decision AX).
func TestStartingTheServerRebuildsTheAllowlist(t *testing.T) {
	t.Parallel()

	paired := offerFrom("tcpaired", 1)
	pending := offerFrom("tcpending", 2)
	withdrawn := &ladulasv1.TunnelOffer{}

	store := &memoryStore{
		records: []*storepb.TrustRecord{
			{Fingerprint: "SHA256:a", Tunnel: paired},
			{Fingerprint: "SHA256:b", Tunnel: withdrawn},
			{Fingerprint: "SHA256:c"},
		},
		pairings: []*storepb.PendingPairing{
			{SessionId: "s", Fingerprint: "SHA256:d", Tunnel: pending},
		},
	}

	tunnel := newFakeTunnel("tcours", 9)
	n := tunnelNode(store, tunnel)

	id, _, err := identity.Generate("desk")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	server, err := transport.NewServer(transport.ServerOptions{
		Identity: id,
		Listen:   transport.ListenNone,
		Handler:  http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	n.server = server

	t.Cleanup(func() {
		_ = server.Close()
	})

	if !n.startServer(tunnel) {
		t.Fatal("the server did not start")
	}

	if !tunnel.admits(paired.GetClientKey()) || !tunnel.admits(pending.GetClientKey()) {
		t.Error("a paired or pending client key was not admitted at start")
	}

	if len(tunnel.admitted) != 2 {
		t.Errorf("admitted %d keys, want 2", len(tunnel.admitted))
	}

	if n.offer().GetServerAddress() != "tcours" {
		t.Error("the address was not published once the server was up")
	}
}

// The tunnel listener's gate admits a paired identity, or a pending one, with
// the client key it offered and no other; never an identity because a pairing
// window is open; and lets a pending identity call SettlePairing and nothing
// else, while refusing the pairing RPCs to everybody (decision AX).
func TestTheTunnelGate(t *testing.T) {
	t.Parallel()

	paired := offerFrom("tcpaired", 1)
	pending := offerFrom("tcpending", 2)

	store := &memoryStore{
		records: []*storepb.TrustRecord{
			{Fingerprint: "SHA256:paired", Name: "paired", Tunnel: paired},
			{Fingerprint: "SHA256:keyless", Name: "keyless"},
		},
		pairings: []*storepb.PendingPairing{
			{SessionId: "s", Fingerprint: "SHA256:pending", Name: "pending", Tunnel: pending},
		},
	}

	n := tunnelNode(store, newFakeTunnel("tcours", 9))
	// An open window admits strangers at the bound listener. Not here.
	n.window = &pairingWindow{}
	gate := tunnelGate{node: n}

	for _, tc := range []struct {
		fingerprint string
		key         []byte
		admit       bool
	}{
		{"SHA256:paired", paired.GetClientKey(), true},
		{"SHA256:paired", pending.GetClientKey(), false},
		{"SHA256:paired", nil, false},
		{"SHA256:keyless", paired.GetClientKey(), false},
		{"SHA256:pending", pending.GetClientKey(), true},
		{"SHA256:pending", paired.GetClientKey(), false},
		{"SHA256:stranger", paired.GetClientKey(), false},
	} {
		err := gate.Admit(tc.fingerprint, tc.key)
		if (err == nil) != tc.admit {
			t.Errorf("Admit(%s, %x…) = %v, want admit=%v",
				tc.fingerprint, tc.key[:min(len(tc.key), 2)], err, tc.admit)
		}
	}

	settle := ladulasv1connect.PairingServiceSettlePairingProcedure
	pin := ladulasv1connect.PairingServicePairStartProcedure
	ping := ladulasv1connect.PresenceServicePingProcedure

	for _, tc := range []struct {
		fingerprint string
		procedure   string
		permit      bool
	}{
		{"SHA256:paired", ping, true},
		{"SHA256:paired", settle, true},
		{"SHA256:paired", pin, false},
		{"SHA256:pending", settle, true},
		{"SHA256:pending", ping, false},
		{"SHA256:pending", pin, false},
	} {
		err := gate.Permit(tc.fingerprint, tc.procedure)
		if (err == nil) != tc.permit {
			t.Errorf("Permit(%s, %s) = %v, want permit=%v",
				tc.fingerprint, tc.procedure, err, tc.permit)
		}
	}
}

// A tunnel offer makes a peer dialable only for an instance that can raise a
// client to it (decision AY): with the upgrade off here a collector that
// offers one stays a collector. And its offer never ages out, since nothing
// but its tunnel could carry the next one (decision AX).
func TestATunnelOnlyPeerIsDialableOnlyWithATunnelAndNeverStale(t *testing.T) {
	t.Parallel()

	tunnelOnly := &storepb.TrustRecord{
		Fingerprint: "SHA256:cafe",
		Tunnel:      offerFrom("tccafe", 1),
	}

	if tunnelNode(&memoryStore{}, nil).dialable(tunnelOnly) {
		t.Error("a peer with only a tunnel server address is dialable " +
			"by an instance that has no tunnel to raise with")
	}

	if !tunnelNode(&memoryStore{}, newFakeTunnel("tcours", 9)).dialable(tunnelOnly) {
		t.Error("a peer with only a tunnel server address is not dialable " +
			"by an instance that can raise a client to it")
	}

	if !trust.TunnelServes(tunnelOnly.GetTunnel()) {
		t.Error("an offer with versions and a server address does not serve")
	}

	for _, offer := range []*ladulasv1.TunnelOffer{
		{Versions: []uint32{1}, ClientKey: []byte{1}},
		{ServerAddress: "tcgone"},
	} {
		if trust.TunnelServes(offer) {
			t.Errorf("a client-only or withdrawn offer serves: %v", offer)
		}
	}

	n := tunnelNode(&memoryStore{}, newFakeTunnel("tcours", 9))

	if n.tunnelStaleFor(tunnelOnly) {
		t.Error("a tunnel-only peer's offer aged out")
	}

	direct := proto.CloneOf(tunnelOnly)
	direct.Addresses = []string{"192.168.1.20:7373"}

	if !n.tunnelStaleFor(direct) {
		t.Error("an offer nothing has confirmed is not stale for a peer with a direct path")
	}

	n.tunnelSeen[direct.GetFingerprint()] = time.Now()

	if n.tunnelStaleFor(direct) {
		t.Error("an offer a beat just confirmed is stale")
	}

	// One absent beat is a server starting, not a contradiction.
	n.tunnelContradicted[direct.GetFingerprint()] = time.Now()

	if n.tunnelStaleFor(direct) {
		t.Error("an offer is stale on the first absent beat")
	}

	n.tunnelContradicted[direct.GetFingerprint()] = time.Now().Add(-2 * tunnelContradictionGrace)

	if !n.tunnelStaleFor(direct) {
		t.Error("an offer absent from direct contacts for longer than the grace is not stale")
	}
}

// Absent beats are dated from the first, and an offer in between starts the
// count again (decision AX).
func TestAbsentBeatsContradictOnlyWhenTheyKeepComing(t *testing.T) {
	t.Parallel()

	store := &memoryStore{records: []*storepb.TrustRecord{{
		Fingerprint: "SHA256:laptop",
		Name:        "laptop",
		Addresses:   []string{"192.168.1.20:7373"},
	}}}
	n := tunnelNode(store, newFakeTunnel("tcours", 9))

	n.learnTunnel("SHA256:laptop", offerFrom("tctheirs", 1))
	n.learnTunnel("SHA256:laptop", nil)

	first := n.tunnelContradicted["SHA256:laptop"]
	if first.IsZero() {
		t.Fatal("an absent beat after an offer was not dated")
	}

	n.learnTunnel("SHA256:laptop", nil)

	if !n.tunnelContradicted["SHA256:laptop"].Equal(first) {
		t.Error("a second absent beat moved the date of the first")
	}

	n.learnTunnel("SHA256:laptop", offerFrom("tctheirs", 1))

	if _, ok := n.tunnelContradicted["SHA256:laptop"]; ok {
		t.Error("an offer did not clear the absent beats before it")
	}
}

// An approver that collects from an inbox, and has turned the tunnel on, still
// collects from a requester that has the upgrade off: its offer must not move
// it to a link nothing can connect over, which would leave its requester
// asking it nothing at all (decisions AX and AY).
func TestACollectorWithATunnelOfferKeepsItsInbox(t *testing.T) {
	phone := newPhone(t, "collector")
	requester := newInstance(t, "builder")

	scanQR(t, requester, phone)

	fingerprint := phone.identity.Fingerprint()

	// What the collector's beat would carry once its server is up. The
	// requester has no tunnel of its own, so the offer is stored unchecked.
	requester.node.learnTunnel(fingerprint, offerFrom("tccollector", 7))

	record, _ := requester.store.Peer(fingerprint)
	if record.GetTunnel().GetServerAddress() != "tccollector" {
		t.Fatalf("the offer was not recorded: %v", record.GetTunnel())
	}

	requester.node.Reconcile()

	requester.node.mu.Lock()
	_, inbox := requester.node.inboxes[fingerprint]
	_, link := requester.node.links[fingerprint]
	requester.node.mu.Unlock()

	if !inbox || link {
		t.Errorf("a collector with a tunnel offer has inbox=%v link=%v, "+
			"want its inbox and no link", inbox, link)
	}
}

// Revoking a peer, and declining or withdrawing a pending pairing, take the
// client key off the allowlist; completing a pairing does not, and neither does
// dropping a pending re-pair whose key the record still holds (decision AX).
func TestForgettingAPeerRevokesItsClientKey(t *testing.T) {
	approver := newInstance(t, "desk")
	requester := newInstance(t, "laptop")

	deskTunnel := newFakeTunnel("tcdesk", 1)
	laptopTunnel := newFakeTunnel("tclaptop", 2)

	approver.node.SetTunnel(deskTunnel)
	requester.node.SetTunnel(laptopTunnel)

	waitOffer(t, approver.node)
	waitOffer(t, requester.node)

	pair(t, approver, requester)
	waitPaired(t, approver, requester.identity.Fingerprint())
	waitPaired(t, requester, approver.identity.Fingerprint())

	if !deskTunnel.admits(laptopTunnel.client) {
		t.Fatal("completing the pairing did not leave the client key admitted")
	}

	// A pending re-pair of the same identity with the same key, dropped: the
	// record still holds the key, so it stays admitted.
	approver.node.dropPending(&storepb.PendingPairing{
		SessionId:   "re-pair",
		Fingerprint: requester.identity.Fingerprint(),
		Name:        "laptop",
		Tunnel:      offerFrom("tclaptop", 2),
	}, "declined")

	if !deskTunnel.admits(laptopTunnel.client) {
		t.Error("dropping a re-pair revoked a key the trust record still holds")
	}

	_, err := approver.node.RevokePeer(context.Background(),
		connect.NewRequest(&ladulasv1.RevokePeerRequest{
			Peer: requester.identity.Fingerprint(),
		}))
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if deskTunnel.admits(laptopTunnel.client) {
		t.Error("a revoked peer's client key is still admitted")
	}

	// A pending pairing that is declined or withdrawn: admitted when the
	// exchange carried it, revoked when it ends.
	for _, ending := range []string{"declined", "withdrawn"} {
		stranger := offerFrom("tcstranger", 5)

		pending := &storepb.PendingPairing{
			SessionId:   "s-" + ending,
			Fingerprint: "SHA256:stranger-" + ending,
			Name:        "stranger",
			Tunnel:      approver.node.pendingOffer("stranger", stranger),
		}

		if err := approver.store.PutPendingPairing(pending); err != nil {
			t.Fatalf("put pending: %v", err)
		}

		if !deskTunnel.admits(stranger.GetClientKey()) {
			t.Fatalf("a pending pairing's client key was not admitted (%s)", ending)
		}

		approver.node.dropPending(pending, ending)

		if deskTunnel.admits(stranger.GetClientKey()) {
			t.Errorf("a %s pairing's client key is still admitted", ending)
		}
	}
}

// A node that has closed its tunnel takes no new one and offers nothing, so a
// toggle racing a seal starts no server, and a closing node never tells its
// peers it withdrew (decision AX).
func TestAClosedNodeTakesNoTunnelAndOffersNothing(t *testing.T) {
	t.Parallel()

	tunnel := newFakeTunnel("tcours", 9)
	n := tunnelNode(&memoryStore{}, tunnel)
	n.tunnelAddress = tunnel.address

	n.closeTunnel()

	if got := n.offer(); got != nil {
		t.Errorf("a closed node offers %v, want nothing", got)
	}

	late := newFakeTunnel("tclate", 8)
	n.SetTunnel(late)

	select {
	case <-late.closed:
	default:
		t.Error("a tunnel handed to a closed node was not closed")
	}

	if n.startServer(late); late.started != 0 {
		t.Error("a closed node started a server")
	}

	if got := n.offer(); got != nil {
		t.Errorf("a closed node offers %v after SetTunnel, want nothing", got)
	}
}

// The DERP region a peer's tunnel address embeds is one this daemon would
// connect to, so it is held to the relay URL's rule: one of our own regions,
// or https to a public address (decision AX, §11, §16).
func TestPeerSuppliedRelayRegions(t *testing.T) {
	t.Parallel()

	ours := []relayRegion{{ID: 1, Nodes: []relayNode{
		{Host: "derp1.example.net", IPv4: "203.0.113.1"},
		{Host: "derp.lan", IPv4: "192.168.1.5"},
	}}}

	public := func(node relayNode) relayRegion {
		return relayRegion{Nodes: []relayNode{node}}
	}

	for _, tc := range []struct {
		name   string
		region relayRegion
		ok     bool
	}{
		{"a region of ours", public(relayNode{Host: "derp1.example.net", IPv4: "203.0.113.1"}), true},
		{"our private relay, because our map names it",
			public(relayNode{Host: "derp.lan", IPv4: "192.168.1.5"}), true},
		{"our host name at another address",
			public(relayNode{Host: "derp.lan", IPv4: "192.168.1.6"}), false},
		{"our host name on another DERP port",
			public(relayNode{Host: "derp.lan", IPv4: "192.168.1.5", DERPPort: 8443}), false},
		{"our host name with another STUN port",
			public(relayNode{Host: "derp.lan", IPv4: "192.168.1.5", STUNPort: 53}), false},
		{"a public relay we do not know",
			public(relayNode{Host: "derp.elsewhere.example", IPv4: "198.51.100.7", IPv6: "none"}), true},
		{"a public relay on the default ports, spelled out", public(relayNode{
			Host: "derp.elsewhere.example", IPv4: "198.51.100.7", IPv6: "none",
			DERPPort: 443, STUNPort: 3478}), true},
		{"a public relay with STUN off", public(relayNode{
			Host: "derp.elsewhere.example", IPv4: "198.51.100.7", IPv6: "none", STUNPort: -1}), true},
		{"a public literal for a host", public(relayNode{Host: "198.51.100.7"}), true},
		{"a region by id only", relayRegion{ID: 3}, true},
		{"a private address", public(relayNode{Host: "router.example", IPv4: "10.0.0.1", IPv6: "none"}), false},
		{"a private literal for a host", public(relayNode{Host: "192.168.1.1"}), false},
		{"loopback", public(relayNode{Host: "localhost"}), false},
		{"loopback with a trailing dot", public(relayNode{
			Host: "localhost.", IPv4: "198.51.100.7", IPv6: "none"}), false},
		{"a .localhost name", public(relayNode{
			Host: "derp.localhost", IPv4: "198.51.100.7", IPv6: "none"}), false},
		{"a bare name a search domain would complete", public(relayNode{
			Host: "intranet", IPv4: "198.51.100.7", IPv6: "none"}), false},
		{"a host name to be looked up", public(relayNode{Host: "intranet.corp.example"}), false},
		{"a host name with one family to be looked up", public(relayNode{
			Host: "intranet.corp.example", IPv4: "198.51.100.7"}), false},
		{"a host name with no address at all", public(relayNode{
			Host: "derp.example", IPv4: "none", IPv6: "none"}), false},
		{"an address that is not one", public(relayNode{
			Host: "derp.example", IPv4: "derp.example", IPv6: "none"}), false},
		{"another DERP port", public(relayNode{
			Host: "derp.example", IPv4: "198.51.100.7", IPv6: "none", DERPPort: 22}), false},
		{"another STUN port", public(relayNode{
			Host: "derp.example", IPv4: "198.51.100.7", IPv6: "none", STUNPort: 161}), false},
		{"a certificate name of its own", public(relayNode{
			Host: "derp.example", IPv4: "198.51.100.7", IPv6: "none", CertName: "other.example"}), false},
		{"link-local v6", public(relayNode{Host: "derp.example", IPv4: "none", IPv6: "fe80::1"}), false},
		{"a tailnet address", public(relayNode{
			Host: "derp.example", IPv4: "100.101.102.103", IPv6: "none"}), false},
		{"plain HTTP", public(relayNode{
			Host: "derp.example", IPv4: "198.51.100.7", IPv6: "none", Insecure: true}), false},
		{"no host", public(relayNode{IPv4: "198.51.100.7"}), false},
	} {
		refused := checkRelayRegion(tc.region, ours)
		if (refused == "") != tc.ok {
			t.Errorf("%s: refused=%q, want ok=%v", tc.name, refused, tc.ok)
		}
	}

	known, _ := json.Marshal(ours)

	if refused := checkRelayRegionJSON("not json", string(known)); refused == "" {
		t.Error("an unreadable region was accepted")
	}

	// Every region an address embeds is held to the rule, since a client
	// connects to all of them: a good first region does not carry a bad second.
	two, _ := json.Marshal([]relayRegion{
		ours[0],
		public(relayNode{Host: "metadata.example", IPv4: "169.254.169.254", IPv6: "none"}),
	})

	if refused := checkRelayRegionJSON(string(two), string(known)); refused == "" {
		t.Error("a bad second region was accepted behind a good first one")
	}

	one, _ := json.Marshal([]relayRegion{ours[0]})

	if refused := checkRelayRegionJSON(string(one), string(known)); refused != "" {
		t.Errorf("one of our own regions was refused: %s", refused)
	}
}

// An offer whose region fails the rule is kept without its server address, so
// the client key still reaches the allowlist and nothing here ever connects to
// the region — and the next identical offer is still not a write.
func TestARefusedRegionDropsTheServerAddress(t *testing.T) {
	t.Parallel()

	store := &countingStore{memoryStore: &memoryStore{records: []*storepb.TrustRecord{{
		Fingerprint: "SHA256:laptop",
		Name:        "laptop",
		Addresses:   []string{"192.168.1.20:7373"},
	}}}}
	tunnel := newFakeTunnel("tcours", 9)
	tunnel.region = `[{"nodes":[{"host":"10.0.0.1"}]}]`
	n := tunnelNode(store, tunnel)

	offer := offerFrom("tcevil", 1)
	n.learnTunnel("SHA256:laptop", offer)
	n.learnTunnel("SHA256:laptop", offer)

	record, _ := store.Peer("SHA256:laptop")

	if record.GetTunnel().GetServerAddress() != "" {
		t.Errorf("a refused region's address was stored: %v", record.GetTunnel())
	}

	if !tunnel.admits(offer.GetClientKey()) {
		t.Error("the client key of an offer with a refused region was not admitted")
	}

	if store.puts != 1 {
		t.Errorf("a refused region wrote the record %d times, want once", store.puts)
	}
}

// Pairing carries the offer from birth, both ways, and admits both keys once
// the code is spent; declining takes them off again (decision AX).
func TestPairingExchangesAndAdmitsTunnelOffers(t *testing.T) {
	approver := newInstance(t, "desk")
	requester := newInstance(t, "laptop")

	deskTunnel := newFakeTunnel("tcdesk", 1)
	laptopTunnel := newFakeTunnel("tclaptop", 2)

	approver.node.SetTunnel(deskTunnel)
	requester.node.SetTunnel(laptopTunnel)

	waitOffer(t, approver.node)
	waitOffer(t, requester.node)

	pair(t, approver, requester)

	theirs := waitPaired(t, approver, requester.identity.Fingerprint())
	if theirs.GetTunnel().GetServerAddress() != "tclaptop" {
		t.Errorf("the displaying side recorded %v", theirs.GetTunnel())
	}

	ours := waitPaired(t, requester, approver.identity.Fingerprint())
	if ours.GetTunnel().GetServerAddress() != "tcdesk" {
		t.Errorf("the joining side recorded %v", ours.GetTunnel())
	}

	if !deskTunnel.admits(laptopTunnel.client) || !laptopTunnel.admits(deskTunnel.client) {
		t.Error("the two client keys were not admitted on both sides")
	}

	if got := approver.node.describeTunnel(theirs, "", "", nil); got != trust.TunnelOffered {
		t.Errorf("the paired peer's tunnel reads %q", got)
	}
}

// waitOffer waits for a node's server to be up, which SetTunnel starts in the
// background on a node that is already serving.
func waitOffer(t *testing.T, n *Node) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		if n.offer().GetServerAddress() != "" {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("the tunnel server never came up")
}
