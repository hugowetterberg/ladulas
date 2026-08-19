// Package peer is an instance's half of the peer-to-peer world: it serves the
// peer RPCs to paired instances, keeps links to the peers that approve for it,
// and runs the pairing exchange (docs/architecture.md §7, §8, §9).
//
// The shape follows from one thing the engine already believed: local approval
// is an approver that happens to share the process. A paired peer is an
// approver that does not, and it registers with the same engine through the
// same interface. Everything else here is what it takes to make that true — a
// channel that authenticates, a trust record that authorizes, and a link that
// notices when the far end has gone.
package peer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// maxRequestBytes caps a peer submission. The commit object is tiny and the
// diff that travels with it is capped at a megabyte before it is sent; eight
// leaves room for the encoding and nothing else.
const maxRequestBytes = 8 << 20

// Store is what the node needs from the encrypted store: the trust records,
// and the changes the command line makes to them through a running instance,
// which have to go through here because they have consequences for live
// connections.
type Store interface {
	trust.Store

	SetPeerDirections(
		ref string, directions trust.Directions) (*storepb.TrustRecord, error)
	RenamePeer(ref, name string) (*storepb.TrustRecord, error)

	// The pairings that are under way. They live in the store beside the trust
	// records because an unanswered pairing has to survive a restart on either
	// side, and because who is trying to pair with this machine is the same map
	// the records are (§7).
	//
	// trust.Store's rule holds here as well, and for the same reason: **a
	// message that has been handed out is never written to again.** One pending
	// pairing is read in three places at once and none of them takes a lock —
	// the command that started the pairing is still holding the message it got
	// back, the reconciliation loop is reading the one the listing gave it, and
	// the confirmation on screen was built from a third. A change is made by
	// putting a new message in, not by reaching into one somebody is holding.
	PendingPairings() []*storepb.PendingPairing
	PendingPairing(ref string) (*storepb.PendingPairing, bool)
	PutPendingPairing(pending *storepb.PendingPairing) error
	RemovePendingPairing(ref string) (*storepb.PendingPairing, error)

	// The public halves of the keys paired peers offer, remembered so that a
	// holder that cannot be reached is still a holder this instance can say it
	// has keys on (§10, decision N). Public material only, and only ever used
	// to describe a key: a signature is still a call to the holder, decided by
	// the holder.
	BorrowedKeys() []*storepb.BorrowedKey
	SetBorrowedKeys(
		fingerprint string, keys []*ladulasv1.KeyRef, seen time.Time) error
	DropBorrowedKeys(fingerprint string) (int, error)

	// The publications are the record of what this instance publishes, which
	// lives in the same document as the trust records (§6).
	Publications() []*ladulasv1.Publication
	Publication(ref string) (*ladulasv1.Publication, bool)
	PutPublication(publication *ladulasv1.Publication) error
	RemovePublication(ref string) (*ladulasv1.Publication, error)

	// Whether a project this instance asks for a signature in is published on
	// the way past (decision Q). On unless somebody said otherwise.
	AutoPublish() bool
	SetAutoPublish(enabled bool) error
}

// Options configures a node.
type Options struct {
	// Identity is this instance's identity key. Required.
	Identity *identity.Identity
	// Trust holds the peer records. Required.
	Trust Store
	// Engine decides requests and is where remote approvers register. Required.
	Engine *approval.Engine
	// Keys is what this instance will sign with for the peers it has granted
	// key access to (§3). Optional: a keyless box has none, and answers a peer
	// that asks that it holds nothing to sign with.
	Keys KeyStore
	// Projects is what this instance has read of the projects its peers publish
	// (§6). Optional: an instance that keeps none reads everything afresh, and
	// reads nothing at all while it is offline.
	Projects *project.Cache
	// Delegations holds both halves of decision P: the standing permissions
	// approvers have granted this instance, and the record of the ones it has
	// granted. Optional; without it a TTL stays where it has always been, on
	// the approver.
	Delegations Delegations
	// Wakeups holds both halves of M9: the routes peers have announced for
	// themselves, and this instance's own. Optional, and optional all the way
	// down — an instance without one is the M6 instance, which polls (§11).
	Wakeups Wakeups
	// Handovers is both halves of decision S: the portable keys this instance
	// has promised a peer and not delivered, and the ones peers have handed it
	// and nobody has answered. Optional; an instance without one refuses to be
	// handed a key and has none to give.
	Handovers Handovers
	// Endorsements is both halves of decision AG: the promises other holders of
	// a key have made about a requester, and the retractions that take them
	// back. Optional; an instance without one endorses nothing, honours no
	// endorsement and asks about every borrowed signature, which is what every
	// instance did before decision AG.
	Endorsements Endorsements
	// Listen is the bind specification (decision H); AllowPublic opts in to
	// addresses reachable from outside the local network.
	Listen      string
	AllowPublic bool
	// Headless says this instance has no GUI of its own, which is worth
	// telling an approver that is being asked to answer for it.
	Headless bool
	// Heartbeat is how often a presence stream ticks. Defaults to
	// DefaultHeartbeat.
	Heartbeat time.Duration
	// RetryFloor and RetryCeiling bound the reconnection backoff.
	RetryFloor   time.Duration
	RetryCeiling time.Duration
	// PairingRetry is how often a pending pairing is taken to its peer.
	// Defaults to DefaultPairingRetry.
	PairingRetry time.Duration
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Reconnection and liveness defaults.
const (
	// DefaultHeartbeat is how often an approver tells a requester it is still
	// there. Often enough that a peer that went away is noticed within a
	// minute, rarely enough to be free.
	DefaultHeartbeat = 30 * time.Second

	// DefaultRetryFloor is the first reconnection delay, and
	// DefaultRetryCeiling is where the doubling stops. A desktop that has been
	// asleep all weekend should be reachable within a minute of waking, so the
	// ceiling is a minute rather than the several that a backoff would
	// otherwise reach.
	DefaultRetryFloor   = time.Second
	DefaultRetryCeiling = time.Minute
)

// Node is an instance's peer machinery.
type Node struct {
	identity     *identity.Identity
	trust        Store
	engine       *approval.Engine
	keys         KeyStore
	projects     *project.Cache
	delegations  Delegations
	wakeups      Wakeups
	handovers    Handovers
	endorsements Endorsements
	server       *transport.Server
	log          *slog.Logger
	headless     bool
	heartbeat    time.Duration
	floor        time.Duration
	ceiling      time.Duration
	retry        time.Duration

	// load caps how many decisions each peer can have in flight at once, which
	// bounds how many prompts one peer can raise before a human (M3).
	load *peerLoad

	// pairingMu serialises the transitions a pending pairing goes through, so
	// that an answer arriving from the peer and one arriving from the command
	// line cannot both decide that a pairing is complete. It is never held
	// across a network call.
	pairingMu sync.Mutex

	mu    sync.Mutex
	links map[string]*link
	// reached is what dialling a peer without keeping a link found, by
	// fingerprint. A phone never holds a link to the machine it approves for —
	// it collects from it and hangs up — so without this the only contact it
	// ever has with a peer is invisible to every surface that lists one, and a
	// peer being polled every second reads as "not tried yet".
	reached map[string]*reach
	// seen is when each peer last spoke to this instance, and collecting is how
	// many calls each is holding open right now.
	//
	// They are the other half of `reached`, and the half a phone actually has. A
	// device that advertises no address is never dialled, so nothing above ever
	// learns anything about it — but it comes here constantly: to collect what is
	// parked for it, to announce what keys it holds, to read a published
	// document. Every one of those is the peer being present, and until this
	// existed all of it was thrown away, so a phone somebody had just used read
	// as one that had never been heard from (§7, §11).
	//
	// In memory rather than in the store: presence is worth nothing after a
	// restart, and stamping the encrypted store on every poll would be a write a
	// second for a fact that expires.
	seen          map[string]time.Time
	collecting    map[string]int
	window        *pairingWindow
	confirmations map[string]chan *approval.Answer
	// prompts are the confirmation prompts currently raised for pending
	// pairings, by session id, so that a pairing withdrawn from either end
	// takes its card off whatever screen it is on.
	prompts map[string]context.CancelFunc
	// watchers are the pairing commands waiting to hear how a session ended.
	watchers map[string][]chan pairingEvent
	// attempted is when each pending pairing was last taken to its peer, so the
	// reconciliation loop paces itself.
	attempted map[string]time.Time
	// converge wakes that loop when there is a reason not to wait for the tick.
	converge chan struct{}
	// settled is the key handovers this instance has nothing left to do about
	// but has not told the sender so — a key it already held when the offer
	// arrived (decision S). Acknowledged on the next collection, and worth one
	// redelivery if this restarts first.
	settled map[string]bool
	// inboxes are the approvers that cannot be dialled and come to collect
	// instead; parked is what is waiting for them, and waiters releases the
	// calls that are long-polling for it (see inbox.go).
	inboxes map[string]func()
	parked  map[string]*parked
	// waiters is a set of channels per peer rather than one, so that a poll
	// which ends on its own — a timer, or a phone that was force-quit — can take
	// its own out without disturbing anybody else's. One shared channel could
	// only be removed by waking it, which is how a peer that had stopped
	// listening went on looking like one that was.
	waiters map[string]map[chan struct{}]bool
	// handled is every request this instance has picked out of an inbox and not
	// yet forgotten: what it decided, and whether the requester has heard it. A
	// request id is decided once, and a poll that arrives carrying one that has
	// already been answered is answered from here rather than by asking
	// somebody a second time (see collect.go).
	handled map[string]*handledRequest
	// inflight is the requests this instance currently has out to peers, so
	// that an approver looking at one can ask for the rest of its diff and
	// nobody can ask about anything else (see diff.go).
	inflight map[string]*outgoing
	// announced is what this instance last told each requester about being
	// woken, so that a poll loop running for an hour makes one announcement
	// rather than a hundred and twenty (see wakeup.go).
	announced map[string]announced
	// announcedKeys is the same for the key list a holder that cannot be dialled
	// announces instead of waiting to be asked (decision T, see announcekeys.go).
	announcedKeys map[string]announcedList
	// announceMu keeps one announcement sweep running at a time, since the
	// sweep is started from a poll round and the rounds overlap. The key list
	// gets its own, so that a slow requester in one sweep does not hold up the
	// other — the two are independent bookkeeping.
	announceMu     sync.Mutex
	announceKeysMu sync.Mutex
	// ctx is the lifetime the links run under. It is held rather than passed
	// because a link outlives the call that created it: pairing starts one from
	// inside an RPC, and it has to survive that RPC returning.
	ctx context.Context //nolint:containedctx // see above

	closeOnce sync.Once
}

// New creates a node. It does not listen; call Serve.
func New(opts Options) (*Node, error) {
	switch {
	case opts.Identity == nil:
		return nil, errors.New("peer: no instance identity")
	case opts.Trust == nil:
		return nil, errors.New("peer: no trust store")
	case opts.Engine == nil:
		return nil, errors.New("peer: no approval engine")
	}

	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	node := &Node{
		identity:      opts.Identity,
		trust:         opts.Trust,
		engine:        opts.Engine,
		keys:          opts.Keys,
		projects:      opts.Projects,
		delegations:   opts.Delegations,
		wakeups:       opts.Wakeups,
		handovers:     opts.Handovers,
		endorsements:  opts.Endorsements,
		log:           log,
		headless:      opts.Headless,
		heartbeat:     orDuration(opts.Heartbeat, DefaultHeartbeat),
		floor:         orDuration(opts.RetryFloor, DefaultRetryFloor),
		ceiling:       orDuration(opts.RetryCeiling, DefaultRetryCeiling),
		retry:         orDuration(opts.PairingRetry, DefaultPairingRetry),
		load:          newPeerLoad(),
		links:         map[string]*link{},
		reached:       map[string]*reach{},
		seen:          map[string]time.Time{},
		collecting:    map[string]int{},
		confirmations: map[string]chan *approval.Answer{},
		prompts:       map[string]context.CancelFunc{},
		watchers:      map[string][]chan pairingEvent{},
		attempted:     map[string]time.Time{},
		converge:      make(chan struct{}, 1),
		inflight:      map[string]*outgoing{},
		announced:     map[string]announced{},
		announcedKeys: map[string]announcedList{},
		inboxes:       map[string]func(){},
		parked:        map[string]*parked{},
		waiters:       map[string]map[chan struct{}]bool{},
		handled:       map[string]*handledRequest{},
	}

	server, err := transport.NewServer(transport.ServerOptions{
		Identity:    opts.Identity,
		Listen:      opts.Listen,
		AllowPublic: opts.AllowPublic,
		Handler:     node.handler(),
		Gate:        node.gate,
		Logger:      log,
	})
	if err != nil {
		return nil, err
	}

	node.server = server

	return node, nil
}

func orDuration(d, fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}

	return d
}

// Identity returns this instance's identity.
func (n *Node) Identity() *identity.Identity {
	return n.identity
}

// Addresses returns what the peer listener bound to, which is also what pairing
// advertises to a peer as the addresses to dial back on.
func (n *Node) Addresses() []string {
	return n.server.Addresses()
}

// Listen binds the peer listener without serving it, so that a caller can find
// out whether the address is available before anything else starts.
func (n *Node) Listen() error {
	return n.server.Listen()
}

// Serve runs the listener and the links until the context is done.
func (n *Node) Serve(ctx context.Context) error {
	n.mu.Lock()
	n.ctx = ctx
	n.mu.Unlock()

	// Links come up before the listener, because a headless box's whole reason
	// for existing is to reach its approver, and it should not have to wait for
	// its own door to open first.
	n.Reconcile()

	// A pairing that was under way when this instance last stopped is still
	// under way. The loop puts its confirmation back on screen and takes this
	// side's answer to the peer whenever the peer can be reached (§7).
	go n.runConvergence(ctx)

	defer n.stopLinks()

	return n.server.Serve(ctx)
}

// Close stops the listener and every link.
func (n *Node) Close() error {
	var err error

	n.closeOnce.Do(func() {
		n.stopLinks()

		err = n.server.Close()
	})

	return err
}

// handler builds the peer-facing RPC surface.
//
// Every service is mounted whether or not the caller may use it, and the
// authorization happens inside: a peer that has been paired in one direction
// only should be told it may not do the other thing, not that the thing does
// not exist.
func (n *Node) handler() http.Handler {
	mux := http.NewServeMux()

	service := &peerService{node: n}
	options := connect.WithReadMaxBytes(maxRequestBytes)

	mux.Handle(ladulasv1connect.NewApprovalServiceHandler(service, options))
	mux.Handle(ladulasv1connect.NewInboxServiceHandler(service, options))
	mux.Handle(ladulasv1connect.NewKeyServiceHandler(service, options))
	mux.Handle(ladulasv1connect.NewPairingServiceHandler(service, options))
	mux.Handle(ladulasv1connect.NewProjectServiceHandler(service,
		connect.WithReadMaxBytes(maxProjectBytes)))
	mux.Handle(ladulasv1connect.NewPresenceServiceHandler(service, options))
	mux.Handle(ladulasv1connect.NewWakeupServiceHandler(service, options))

	return mux
}

// gate is the outer door: an identity that is neither paired, nor arriving at
// an open pairing window, nor half way through a pairing this instance has
// written down does not get past the handshake (§15).
//
// Those three are the whole of the unauthenticated surface. A stranger who can
// reach the port gets a TLS handshake and a refusal; an unknown identity speaks
// only while somebody is deliberately pairing at this machine, and then only to
// the pairing service, and then only if it can prove it saw the code. The third
// condition is what that proof buys: once a code has been spent, the identity
// that spent it may come back — after a sleep, a restart, a week — to find out
// how the pairing ended, which is the whole of what makes a pairing resumable.
// It buys nothing else, because every other service checks for a trust record
// of its own accord and a pending pairing is not one.
//
// See transport.Gate for where a tailnet's same-user check would join this if
// it is ever built.
func (n *Node) gate(peer *transport.PeerIdentity) error {
	if _, ok := n.trust.Peer(peer.Fingerprint); ok {
		return nil
	}

	if n.openWindow() != nil {
		return nil
	}

	if pending, ok := n.trust.PendingPairing(peer.Fingerprint); ok &&
		pending.GetFingerprint() == peer.Fingerprint {
		return nil
	}

	return fmt.Errorf("%w: %s is not paired and no pairing is in progress",
		errNotPaired, peer.Fingerprint)
}

var errNotPaired = errors.New("peer: not paired")

// authorize turns an authenticated identity into the trust record that permits
// what it is asking for, or refuses.
//
// The identity comes from the channel and nothing else. A message field naming
// an instance is the caller's word for it, and is never what this looks at.
//
// There is only one direction to check here. Whether a peer may ask this
// instance to approve is this instance's decision and is checked here; whether
// this instance may ask that peer is the peer's decision, checked by the peer.
// Each side enforces the half it declared, which is what makes the two halves
// independent rather than negotiated.
func (n *Node) authorize(
	ctx context.Context,
) (*transport.PeerIdentity, *storepb.TrustRecord, error) {
	peer := transport.PeerFrom(ctx)
	if peer == nil {
		return nil, nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("the connection is not authenticated"))
	}

	record, ok := n.trust.Peer(peer.Fingerprint)
	if !ok {
		return nil, nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("%s is not a paired peer", peer.Fingerprint))
	}

	if !record.GetMayRequest() {
		return nil, nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("%q is paired, but %s",
				record.GetName(), trust.Describe(
					record.GetMayApprove(), record.GetMayRequest())))
	}

	n.saw(peer.Fingerprint)

	return peer, record, nil
}

// saw records that a peer has just spoken to this instance.
//
// Called from both authorisation chokepoints, which is what makes it complete:
// every call a peer makes goes through one of them, whichever direction of the
// pairing it is exercising.
func (n *Node) saw(fingerprint string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.seen[fingerprint] = time.Now()
}

// holding marks a call a peer is keeping open, and returns the function that
// says it has ended. A collector long-polls, so this is the closest thing to a
// link it has: while the count is above zero it is talking to this instance.
func (n *Node) holding(fingerprint string) func() {
	n.mu.Lock()
	n.collecting[fingerprint]++
	n.seen[fingerprint] = time.Now()
	n.mu.Unlock()

	return func() {
		n.mu.Lock()
		defer n.mu.Unlock()

		n.collecting[fingerprint]--
		if n.collecting[fingerprint] <= 0 {
			delete(n.collecting, fingerprint)
		}

		n.seen[fingerprint] = time.Now()
	}
}

// presence is what the inbound side knows about a peer: whether it is holding a
// call open, and when it last made one.
func (n *Node) presence(fingerprint string) (bool, time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.collecting[fingerprint] > 0, n.seen[fingerprint]
}

// Reconcile brings the approvers into agreement with the trust store: for every
// peer that may approve for this instance, a way of asking it, and for anybody
// else, none.
//
// There are two ways of asking, and which one a peer gets is decided by whether
// it advertised an address. One that did is dialled when there is something to
// decide; one that did not is a phone, and gets an inbox it collects from
// instead (§3, and inbox.go). Both are approvers in the same fan-out.
//
// It runs when the node starts, when a pairing completes, when a peer is
// revoked, and on the reload a SIGHUP triggers — so that changing a record on
// disk and telling the daemon to re-read it does what it looks like it does.
func (n *Node) Reconcile() {
	n.mu.Lock()

	ctx := n.ctx
	if ctx == nil {
		n.mu.Unlock()

		return
	}

	wanted := map[string]*storepb.TrustRecord{}
	collectors := map[string]*storepb.TrustRecord{}

	for _, record := range n.trust.Peers() {
		if !record.GetMayApprove() {
			continue
		}

		if len(record.GetAddresses()) > 0 {
			wanted[record.GetFingerprint()] = record

			continue
		}

		collectors[record.GetFingerprint()] = record
	}

	n.reconcileInboxes(collectors)

	var stopping []*link

	for fingerprint, existing := range n.links {
		if _, keep := wanted[fingerprint]; keep {
			continue
		}

		delete(n.links, fingerprint)
		stopping = append(stopping, existing)
	}

	var starting []*link

	for fingerprint, record := range wanted {
		if existing, ok := n.links[fingerprint]; ok {
			existing.update(record)

			continue
		}

		created, err := newLink(n, record)
		if err != nil {
			n.log.Error("could not set up a link to a peer",
				"peer", record.GetName(), "error", err.Error())

			continue
		}

		n.links[fingerprint] = created
		starting = append(starting, created)
	}

	n.mu.Unlock()

	for _, stopped := range stopping {
		stopped.stop()
	}

	for _, started := range starting {
		started.start(ctx)
	}
}

// reconcileInboxes registers an approver for every peer that has to collect,
// and unregisters the ones that no longer do. Callers hold the lock.
func (n *Node) reconcileInboxes(collectors map[string]*storepb.TrustRecord) {
	for fingerprint, unregister := range n.inboxes {
		if _, keep := collectors[fingerprint]; keep {
			continue
		}

		delete(n.inboxes, fingerprint)
		unregister()
	}

	for fingerprint, record := range collectors {
		if _, ok := n.inboxes[fingerprint]; ok {
			continue
		}

		n.inboxes[fingerprint] = n.engine.Register(n.inboxFor(record))
	}
}

// Disconnect drops everything holding a connection to an identity: the inbound
// connections the listener is holding, and the outbound link, if any.
//
// This is the other half of revocation. The authorization checks would refuse
// the peer's next call anyway, but a peer that has been forgotten should not
// still be holding a door open.
func (n *Node) Disconnect(fingerprint string) {
	dropped := n.server.Disconnect(fingerprint)

	n.mu.Lock()
	existing := n.links[fingerprint]
	delete(n.links, fingerprint)
	n.mu.Unlock()

	if existing != nil {
		existing.stop()
	}

	if dropped > 0 {
		n.log.Info("dropped connections from a forgotten peer",
			"peer", fingerprint, "connections", dropped)
	}
}

func (n *Node) stopLinks() {
	n.mu.Lock()
	links := make([]*link, 0, len(n.links))

	for fingerprint, existing := range n.links {
		links = append(links, existing)
		delete(n.links, fingerprint)
	}

	n.reconcileInboxes(nil)

	n.mu.Unlock()

	for _, stopped := range links {
		stopped.stop()
	}
}

// link returns the link to a peer, or nil.
func (n *Node) link(fingerprint string) *link {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.links[fingerprint]
}
