package peer

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/internal/cpace"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// pairingWindow is an open invitation on the listening side: a displayed code,
// the intent its user chose in advance, and the budget of attempts it will
// tolerate.
//
// One window at a time. Pairing is a thing a person does deliberately at a
// machine they are sitting at, and a second concurrent window would only make
// it ambiguous which screen a proof was supposed to have come from.
//
// The window is the short-lived half of a pairing and the only half with a
// clock on it: five minutes, single use, five attempts (§7). What it produces
// is a pending pairing, and the pending pairing does not expire.
//
// It holds two codes during the overlap release (decision AV): the PIN, which
// every current joiner proves with the CPace exchange, and an independent
// ten-character secret for older joiners, which they prove with the HMAC. One
// counter covers both, because two budgets would be ten attempts.
type pairingWindow struct {
	pin trust.PIN
	// secret is the older joiners' code. Empty refuses the older Pair
	// outright, which is how the overlap ends.
	secret  trust.Secret
	expires time.Time
	// intent is what this pairing is for, and it settles both sides' records
	// rather than only this one's (decision AD).
	intent trust.Intent
	// arrived carries the session id of the pending pairing a proof produced,
	// back to whoever is displaying the code.
	arrived chan string
	// attempted carries each failed attempt to whoever is displaying the code,
	// so the screen can say what knocked (decision AV). It is buffered and
	// never blocks: a screen that is not reading misses a line, never a
	// decision.
	attempted chan *ladulasv1.PairingAttempt
	// exhausted is closed when the attempts are spent and none is still in
	// flight, which is somebody guessing rather than the clock running out.
	exhausted chan struct{}
	// spent is closed when the code can produce no more pairings — claimed,
	// or out of attempts — and done when the window stops admitting anybody.
	// They are the two moments a pairing server cares about, and they are
	// different moments (decision AZ): spent refuses new exchanges at once,
	// but the exchange that spent it may still be writing its answer.
	spent chan struct{}
	done  chan struct{}

	mu sync.Mutex
	// charged is the attempts charged and not refunded, in flight included.
	// An attempt is charged when it starts — a PIN exchange's first round, an
	// older proof's arrival — and refunded only when it verifies. That is
	// what makes an exchange started and walked away from count: a PAKE in
	// which an attacker could learn whether its guess was right and then
	// leave before confirming would otherwise give it free guesses at a few
	// hundred a second. It also caps what is in flight at what is left.
	charged int
	// proving is older proofs being checked right now. They have no
	// exchange to sit in, and count as in flight for the same reason a taken
	// exchange does.
	proving   int
	failures  []*ladulasv1.PairingAttempt
	exchanges map[string]*pinExchange
	closed    bool
	settled   bool
	tired     bool
}

// pinExchange is a PIN exchange whose first round has been answered and whose
// second has not arrived.
type pinExchange struct {
	// fingerprint is the identity that started it. The second round has to
	// come from the same one: two rounds can arrive on two connections, and
	// this is what makes them one exchange.
	fingerprint string
	remote      string
	initiator   *cpace.Initiator
	timer       *time.Timer
	// taken is a second round being verified. It stays in the window's map
	// until it resolves, because an exchange being verified is still in
	// flight: a failure elsewhere must not find the map empty, decide the
	// window is exhausted, and close it under an answer that is about to be
	// right.
	taken bool
}

// The ways a window refuses an attempt before it is tried.
var (
	errPairingSpent     = errors.New("this pairing code has already been used")
	errPairingClosed    = errors.New("no pairing is in progress on this instance")
	errPairingExhausted = errors.New(
		"this pairing code has had all the attempts it allows")
	errNoExchange = errors.New(
		"that pairing exchange is not open here; start again")
	errExchangeOwner = errors.New(
		"that pairing exchange was started by another identity")
)

func newPairingWindow(
	pin trust.PIN, secret trust.Secret, intent trust.Intent,
) *pairingWindow {
	return &pairingWindow{
		pin:       pin,
		secret:    secret,
		expires:   time.Now().Add(trust.CodeValidity),
		intent:    intent,
		arrived:   make(chan string, 1),
		attempted: make(chan *ladulasv1.PairingAttempt, 4*trust.MaxAttempts),
		exhausted: make(chan struct{}),
		spent:     make(chan struct{}),
		done:      make(chan struct{}),
		exchanges: map[string]*pinExchange{},
	}
}

// settle reports the session once.
func (w *pairingWindow) settle(session string) {
	select {
	case w.arrived <- session:
	default:
	}
}

// admits says whether the window is still somebody's to knock on: open and
// in date, spent or not. A spent window keeps admitting until it would have
// expired anyway — after the screen that displayed it has gone, too — so that
// a joiner arriving late is told the code was used, or its attempts were,
// which is the loud message §7 wants, rather than refused at the handshake
// with nothing to say.
func (w *pairingWindow) admits(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	return !w.closed && now.Before(w.expires)
}

func (w *pairingWindow) close() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.closeLocked()
}

func (w *pairingWindow) closeLocked() {
	if !w.closed {
		close(w.done)
	}

	w.closed = true

	for _, exchange := range w.exchanges {
		exchange.timer.Stop()
	}
}

// chargeLocked charges one attempt, or says why it cannot be.
func (w *pairingWindow) chargeLocked() error {
	switch {
	case w.settled:
		return errPairingSpent
	case w.closed:
		return errPairingClosed
	case w.tired, w.charged >= trust.MaxAttempts:
		return errPairingExhausted
	}

	w.charged++

	return nil
}

// chargeProof charges an attempt that is decided in the same call, the older
// proof's. It is resolved by exactly one of failProof and passProof.
func (w *pairingWindow) chargeProof() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.chargeLocked(); err != nil {
		return err
	}

	w.proving++

	return nil
}

// failProof is an older proof that did not verify. Its attempt stays spent.
func (w *pairingWindow) failProof(source, outcome string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.proving--
	w.failLocked(source, outcome)
}

// passProof is an older proof that verified.
func (w *pairingWindow) passProof() bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.proving--

	return w.claimLocked()
}

// claimLocked gives back a verified attempt's charge and spends the code, and
// reports whether this caller was the one who did. A window is spent by the
// first proof that works, whatever happens to the pairing afterwards, and two
// joiners verifying at once must not both believe they won.
func (w *pairingWindow) claimLocked() bool {
	if w.charged > 0 {
		w.charged--
	}

	if w.settled || w.closed || w.tired {
		return false
	}

	w.settled = true

	close(w.spent)

	for _, exchange := range w.exchanges {
		exchange.timer.Stop()
	}

	return true
}

func (w *pairingWindow) failLocked(source, outcome string) {
	attempt := &ladulasv1.PairingAttempt{
		Source:  source,
		At:      timestamppb.Now(),
		Outcome: outcome,
	}

	w.failures = append(w.failures, attempt)

	select {
	case w.attempted <- attempt:
	default:
	}

	// Spent attempts with nothing in flight is a window that cannot produce a
	// pairing any more. It is marked tired here, and the screen is told, so
	// that it offers a new PIN rather than going quiet. Tired is not closed:
	// the window goes on admitting until it expires, so that a joiner who
	// arrives afterwards hears that the attempts were spent.
	if w.charged >= trust.MaxAttempts && len(w.exchanges) == 0 &&
		w.proving == 0 && !w.settled && !w.tired {
		w.tired = true

		close(w.exhausted)
		close(w.spent)
	}
}

// failedAttempts is what the confirmation card shows.
func (w *pairingWindow) failedAttempts() []*ladulasv1.PairingAttempt {
	w.mu.Lock()
	defer w.mu.Unlock()

	return append([]*ladulasv1.PairingAttempt(nil), w.failures...)
}

// startExchange charges an attempt to a PIN exchange's first round and holds
// its state for the second.
func (w *pairingWindow) startExchange(id string, exchange *pinExchange) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// One exchange per identity. A second first round from the same identity
	// is the first one abandoned, and it is written down as such: it was
	// charged when it started and stays charged.
	for other, existing := range w.exchanges {
		if existing.fingerprint == exchange.fingerprint && !existing.taken {
			existing.timer.Stop()
			delete(w.exchanges, other)
			w.failLocked(existing.remote, "started again before finishing")
		}
	}

	if err := w.chargeLocked(); err != nil {
		return err
	}

	exchange.timer = time.AfterFunc(pinExchangeTimeout, func() {
		w.abandon(id)
	})
	w.exchanges[id] = exchange

	return nil
}

// abandon is an exchange whose second round never came.
func (w *pairingWindow) abandon(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// A taken exchange belongs to failExchange or passExchange from then on.
	// The timer can fire just as the second round takes it, and its Stop
	// then comes too late to prevent this call; finding it taken is what
	// keeps an answer that is about to verify from being written down as
	// abandoned, and from tiring the window under it.
	exchange, ok := w.exchanges[id]
	if !ok || exchange.taken {
		return
	}

	delete(w.exchanges, id)
	w.failLocked(exchange.remote, "started and never finished")
}

// takeExchange hands a second round its first round's state, once, and only
// to the identity that started it. An identity that names somebody else's
// exchange gets nothing and leaves it where it was: it cannot have learned the
// id except by being told it, and refusing it is the whole check.
//
// What it hands out is resolved by exactly one of failExchange and
// passExchange.
func (w *pairingWindow) takeExchange(id, fingerprint string) (*pinExchange, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	exchange, ok := w.exchanges[id]
	if !ok || exchange.taken {
		return nil, errNoExchange
	}

	if exchange.fingerprint != fingerprint {
		return nil, errExchangeOwner
	}

	exchange.taken = true
	exchange.timer.Stop()

	return exchange, nil
}

// failExchange is a second round that did not verify. Its attempt stays
// spent.
func (w *pairingWindow) failExchange(id, source, outcome string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	delete(w.exchanges, id)
	w.failLocked(source, outcome)
}

// passExchange is a second round that verified: its attempt is given back,
// and the code is claimed by it if nobody has claimed it first.
func (w *pairingWindow) passExchange(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	delete(w.exchanges, id)

	return w.claimLocked()
}

// openWindow is the window, if one is still admitting anybody.
func (n *Node) openWindow() *pairingWindow {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.window == nil {
		return nil
	}

	if !n.window.admits(time.Now()) {
		n.window = nil

		return nil
	}

	return n.window
}

// ErrNoIntent is a pairing code asked for without saying what the pairing is
// for. It is the caller's omission rather than a failure here, and the surfaces
// answer it with a usage message (decision AD).
var ErrNoIntent = errors.New(
	"peer: say what the pairing is for: an approver for this instance, " +
		"an instance to approve for, or both")

// beginPairing opens the window and returns it with the older joiners' code.
//
// An intent is required rather than defaulted (decision AD). A code displayed
// without one would be an invitation to a pairing nobody had decided the shape
// of, and the shape is the only thing a pairing decides.
func (n *Node) beginPairing(
	intent trust.Intent,
) (*pairingWindow, trust.Secret, error) {
	if intent == trust.IntentUnspecified {
		return nil, "", ErrNoIntent
	}

	pin, err := trust.NewPIN()
	if err != nil {
		return nil, "", err
	}

	// Independent of the PIN, and drawn separately: nothing about one may say
	// anything about the other, or the older joiners' HMAC would be an HMAC
	// over the PIN after all (decision AV, invariant 1).
	secret, err := trust.NewSecret()
	if err != nil {
		return nil, "", err
	}

	window := newPairingWindow(pin, secret, intent)

	n.mu.Lock()
	previous := n.window
	n.window = window
	n.mu.Unlock()

	if previous != nil {
		previous.close()
	}

	return window, secret, nil
}

// closeWindow is the screen that displayed a window going away.
//
// A window nobody used stops admitting at once: nobody is looking at its code
// any more. A spent one — claimed, or out of attempts — stays registered until
// it would have expired (§7), because the screen going away is exactly what
// happens when its user rejects a card they did not expect, and the joiner
// who typed the PIN second is still owed "another machine used this code"
// rather than a refusal at the handshake. openWindow drops it at expiry.
func (n *Node) closeWindow(window *pairingWindow) {
	window.mu.Lock()
	spent := window.settled || window.tired

	if !spent {
		window.closeLocked()
	}
	window.mu.Unlock()

	if spent {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.window == window {
		n.window = nil
	}
}

// windowError turns a window's refusal into what the caller is told. The codes
// are the contract the joining side reads (pairByPIN): AlreadyExists is a code
// somebody else used, and is reported loudly.
func windowError(err error) error {
	switch {
	case errors.Is(err, errPairingSpent):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, errPairingExhausted):
		return connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, errExchangeOwner):
		return connect.NewError(connect.CodePermissionDenied, err)
	default:
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
}

// Pair is the older joiners' half of the exchange, kept for the overlap
// release (decision AV), and it answers immediately.
//
// It used to hold the call open while a human was asked, which meant the whole
// pairing lived inside one RPC and died with it. What it does now is spend the
// code, write down a pending pairing, and say so. The confirmation is raised
// behind it; the answer is reconciled afterwards, by whichever side can reach
// the other (§7).
//
// It proves the ten-character secret and never the PIN, and it draws on the
// same attempts as the PIN exchange.
func (s *peerService) Pair(
	ctx context.Context,
	req *connect.Request[ladulasv1.PairRequest],
) (*connect.Response[ladulasv1.PairResponse], error) {
	peer := transport.PeerFrom(ctx)
	if peer == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("the connection is not authenticated"))
	}

	window := s.node.openWindow()
	if window == nil {
		return nil, windowError(errPairingClosed)
	}

	// What the message says about the caller has to agree with what the channel
	// proved. It cannot be otherwise unless something is wrong, and neither
	// possibility is one to pair with.
	if claimed := req.Msg.GetIdentityPublicKey(); len(claimed) > 0 &&
		!bytes.Equal(claimed, peer.PublicKey.Marshal()) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the identity in the request is not the one on the connection"))
	}

	// A window without the older code is one that has left the overlap.
	if window.secret == "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this pairing takes the PIN; update the joining instance"))
	}

	if err := window.chargeProof(); err != nil {
		return nil, windowError(err)
	}

	ours := s.node.identity.PublicKey()

	if !trust.VerifyProof(window.secret, ours, peer.PublicKey, req.Msg.GetProof()) {
		window.failProof(peer.RemoteAddr, "refused an older ten-character code")

		s.node.log.Warn("refused a pairing proof", "peer", peer.Fingerprint,
			"from", peer.RemoteAddr)

		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("the pairing code does not match"))
	}

	// The code is single use, and this is where it is used. Claiming it here
	// rather than when the pairing settles is what keeps one displayed code
	// worth exactly one pending pairing, however long the pairing then takes.
	if !window.passProof() {
		return nil, windowError(errPairingSpent)
	}

	session, err := s.node.recordListened(window, peer,
		req.Msg.GetInstanceName(), req.Msg.GetListenAddresses(), req.Msg.GetTunnel())
	if err != nil {
		return nil, err
	}

	// The answer carries the intent as this side wrote it down, and the caller
	// records the mirror of it. That is the whole of how one answer on one
	// screen settles both records (decision AD).
	return connect.NewResponse(&ladulasv1.PairResponse{
		Accepted:          true,
		SessionId:         session,
		InstanceName:      s.node.identity.Name(),
		IdentityPublicKey: ours.Marshal(),
		MayApprove:        window.intent.PeerMayApprove(),
		MayRequest:        window.intent.PeerMayRequest(),
		ListenAddresses:   s.node.Advertised(),
		Confirmation:      trust.Confirmation(window.secret, ours, peer.PublicKey),
		Tunnel:            s.node.offer(),
	}), nil
}

// PairStart is the first round of the PIN exchange (decision AV): charge an
// attempt, mint a session id, answer with the listener's share.
//
// Nothing in the answer lets the caller test a guess — a CPace share is a
// random group element to anybody without the scalar — and the attempt is
// spent from here until a confirmation verifies.
func (s *peerService) PairStart(
	ctx context.Context,
	_ *connect.Request[ladulasv1.PairStartRequest],
) (*connect.Response[ladulasv1.PairStartResponse], error) {
	peer := transport.PeerFrom(ctx)
	if peer == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("the connection is not authenticated"))
	}

	window := s.node.openWindow()
	if window == nil {
		return nil, windowError(errPairingClosed)
	}

	sid, err := newPAKESessionID()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	initiator, err := cpace.NewInitiator(pinInputs(window.pin,
		peer.PublicKey, s.node.identity.PublicKey(), sid), []byte(adListener))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	err = window.startExchange(hex.EncodeToString(sid), &pinExchange{
		fingerprint: peer.Fingerprint,
		remote:      peer.RemoteAddr,
		initiator:   initiator,
	})
	if err != nil {
		return nil, windowError(err)
	}

	return connect.NewResponse(&ladulasv1.PairStartResponse{
		SessionId: sid,
		Share:     initiator.Share(),
	}), nil
}

// PairFinish is the second round: verify the joiner's tag, and only then act.
//
// The order inside is the security argument. Nothing the joiner sent is read —
// not its name, not its addresses — and nothing derived from the key is sent,
// until its tag has verified. A tag that does not verify is a refused PIN, and
// its attempt stays spent.
func (s *peerService) PairFinish(
	ctx context.Context,
	req *connect.Request[ladulasv1.PairFinishRequest],
) (*connect.Response[ladulasv1.PairFinishResponse], error) {
	peer := transport.PeerFrom(ctx)
	if peer == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("the connection is not authenticated"))
	}

	window := s.node.openWindow()
	if window == nil {
		return nil, windowError(errPairingClosed)
	}

	id := hex.EncodeToString(req.Msg.GetSessionId())

	exchange, err := window.takeExchange(id, peer.Fingerprint)
	if err != nil {
		return nil, windowError(err)
	}

	session, err := exchange.initiator.Finish(req.Msg.GetShare(), []byte(adJoiner))
	if err != nil {
		window.failExchange(id, peer.RemoteAddr,
			"sent a share that is not a group element")

		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	if !session.Verify(req.Msg.GetConfirmation()) {
		window.failExchange(id, peer.RemoteAddr, "refused PIN")

		s.node.log.Warn("refused a pairing PIN", "peer", peer.Fingerprint,
			"from", peer.RemoteAddr)

		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("the PIN does not match"))
	}

	// Verified. From here what the joiner said is believed, and this side's
	// own tag may go back — unless somebody else's verified first, in which
	// case this one is told so and nothing derived from the key leaves.
	if !window.passExchange(id) {
		return nil, windowError(errPairingSpent)
	}

	pairing, err := s.node.recordListened(window, peer,
		req.Msg.GetInstanceName(), req.Msg.GetListenAddresses(), req.Msg.GetTunnel())
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&ladulasv1.PairFinishResponse{
		Confirmation:    session.Confirmation(),
		SessionId:       pairing,
		InstanceName:    s.node.identity.Name(),
		MayApprove:      window.intent.PeerMayApprove(),
		MayRequest:      window.intent.PeerMayRequest(),
		ListenAddresses: s.node.Advertised(),
		Tunnel:          s.node.offer(),
	}), nil
}

// recordListened writes down the pending pairing a spent code produced on the
// listening side, and tells whoever is displaying the code.
//
// The joiner's tunnel offer is admitted here, once the code is spent and not
// before: its keys arrived in a message that is read only after the proof
// verified, bound to both identity keys (decision AX).
func (n *Node) recordListened(
	window *pairingWindow, peer *transport.PeerIdentity,
	name string, addresses []string, tunnel *ladulasv1.TunnelOffer,
) (string, error) {
	session := identity.NewRequestID()

	// What the joiner advertised is held to the same rule as everything else
	// written into an address list: direct host:port only (peerAddresses).
	pending := &storepb.PendingPairing{
		SessionId:         session,
		Fingerprint:       peer.Fingerprint,
		Name:              name,
		IdentityPublicKey: peer.PublicKey.Marshal(),
		Addresses:         trust.DirectAddresses(addresses),
		MayApprove:        window.intent.PeerMayApprove(),
		MayRequest:        window.intent.PeerMayRequest(),
		RemoteAddress:     peer.RemoteAddr,
		StartedAt:         timestamppb.Now(),
		FailedAttempts:    window.failedAttempts(),
		Tunnel:            n.pendingOffer(name, tunnel),
	}

	if err := n.recordPending(pending); err != nil {
		return "", connect.NewError(connect.CodeInternal, err)
	}

	window.settle(session)

	return session, nil
}

// SettlePairing reconciles one pending pairing, from either side, as often as
// anybody likes.
//
// It is the whole of how a pairing completes, and it is deliberately not a
// report of a decision that has to land in the moment: the caller says what its
// user has said so far, is told what this side's user has said so far, and both
// facts are already on disk. Calling it twice with the same answer changes
// nothing, and calling it after everything has been settled says so.
func (s *peerService) SettlePairing(
	ctx context.Context,
	req *connect.Request[ladulasv1.SettlePairingRequest],
) (*connect.Response[ladulasv1.SettlePairingResponse], error) {
	peer := transport.PeerFrom(ctx)
	if peer == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("the connection is not authenticated"))
	}

	resp, err := s.node.settlePairingReply(peer, req.Msg)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(resp), nil
}

// settlePairingReply is the server half of the reconciliation.
//
// Four answers. A session still pending here is settled against. One that
// completed here says so, so a peer that never heard the last word gets it. One
// this side refused while the peer could not be told is answered with that
// refusal and its reason, from the hold (refusal.go). And a session this
// instance has no memory of at all is reported as gone, and the asking side
// drops its half.
//
// The last used to be the whole of how a withdrawal propagated, with no
// tombstone kept — accepted on the reasoning that a phone could never be
// handed one and asking had to exist anyway. It never worked as well as that
// reads: the gates refuse an identity with nothing pending before this is
// reached, so the asker was turned away at the door rather than told. The hold
// is what lets it in. "Gone" with no answer is now what a peer hears only from
// an instance that has restarted or sealed since it refused, or that is older
// than the hold.
func (n *Node) settlePairingReply(
	peer *transport.PeerIdentity, msg *ladulasv1.SettlePairingRequest,
) (*ladulasv1.SettlePairingResponse, error) {
	n.pairingMu.Lock()
	defer n.pairingMu.Unlock()

	session := msg.GetSessionId()

	pending, ok := n.trust.PendingPairing(session)
	if ok && pending.GetSessionId() == session {
		if pending.GetFingerprint() != peer.Fingerprint {
			return nil, connect.NewError(connect.CodePermissionDenied,
				errors.New("that pairing belongs to another identity"))
		}

		return n.settleAgainst(pending, msg)
	}

	// A completed pairing still answers for the session it came out of, so a
	// peer that never heard the last word gets it rather than being told the
	// pairing is gone.
	if record, held := n.trust.Peer(peer.Fingerprint); held &&
		record.GetPairingSessionId() == session && session != "" {
		return &ladulasv1.SettlePairingResponse{
			State:  ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_PAIRED,
			Answer: ladulasv1.PairingAnswer_PAIRING_ANSWER_ACCEPTED,
			Reason: "already paired here",
		}, nil
	}

	// A pairing refused here while the peer could not be told: told now, in
	// the words it was refused in (refusal.go).
	if resp, held := n.answerHeldRefusal(peer.Fingerprint, session); held {
		return resp, nil
	}

	return &ladulasv1.SettlePairingResponse{
		State:  ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_GONE,
		Reason: "this instance has no record of that pairing",
	}, nil
}

func (n *Node) settleAgainst(
	pending *storepb.PendingPairing, msg *ladulasv1.SettlePairingRequest,
) (*ladulasv1.SettlePairingResponse, error) {
	ours := pending.GetOurAnswer()

	if answer := msg.GetAnswer(); answer !=
		ladulasv1.PairingAnswer_PAIRING_ANSWER_UNSPECIFIED {
		pending.TheirAnswer = answer
	}

	state, _, err := n.advance(pending, msg.GetReason(), false)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return &ladulasv1.SettlePairingResponse{
		State:  state,
		Answer: ours,
	}, nil
}

// PairWith is the joining side of the exchange, driven by the command line, the
// window and the phone.
//
// It reads as a sequence of refusals, which is what a pairing is: each step is
// a way for this not to be the machine whose screen the user is looking at. It
// stops short of the last one — the user saying so themselves — because that
// answer no longer belongs to this call. What it returns is a pending pairing,
// written down on both sides.
//
// It declares no directions of its own (decision AD). What the pairing is for
// was chosen on the screen the code is on, and this side learns it from the
// answer and records the mirror — so the user here confirms a pairing whose
// shape is already on the card, rather than choosing half of one blind.
//
// A code with a PIN in it is proved with the PIN exchange and nothing else.
// The older proof is used only when there is no PIN at all — a code from an
// older instance — and then only with the ten-character secret (decision AV).
func (n *Node) PairWith(
	ctx context.Context, address string, code *ladulasv1.PairingCode,
) (*storepb.PendingPairing, error) {
	var (
		pin    trust.PIN
		secret trust.Secret
		err    error
	)

	if code.GetPin() != "" {
		if pin, err = trust.ParsePIN(code.GetPin()); err != nil {
			return nil, err
		}
	} else if secret, err = trust.ParseSecret(code.GetSecret()); err != nil {
		return nil, err
	}

	expected, err := trust.CodeKey(code)
	if err != nil {
		return nil, err
	}

	reached, err := n.reachListener(ctx, address, code, expected)
	if err != nil {
		return nil, err
	}

	defer reached.close()

	client, peer := reached.client, reached.peer

	pairing := ladulasv1connect.NewPairingServiceClient(
		client.HTTP(), client.URL(reached.address))

	// What a refusal names, and what is written down as having worked: a
	// direct address that completed the handshake, or nothing at all for a
	// pairing server, whose address dies with the window (decision AZ).
	where, dialled := reached.address, reached.address
	if reached.raw != nil {
		where, dialled = "the machine through its pairing server", ""
	}

	var answer *joinAnswer

	if pin != "" {
		answer, err = n.pairByPIN(ctx, pairing, peer, pin, expected != nil)
	} else {
		answer, err = n.pairByProof(ctx, pairing, peer, secret)
	}

	if err != nil {
		return nil, fmt.Errorf("peer: pair with %s: %w", where, err)
	}

	if answer.session == "" {
		return nil, errors.New(
			"peer: the other instance named no pairing session")
	}

	// The intent as the other side wrote it down, mirrored into what this side
	// writes down. A pairing that says the peer may do nothing is one whose
	// shape was never chosen, and there is nothing to confirm about it.
	intent := trust.IntentOf(answer.mayApprove, answer.mayRequest).Mirror()

	if intent == trust.IntentUnspecified {
		return nil, errors.New(
			"peer: the other instance did not say what the pairing is for")
	}

	pending := &storepb.PendingPairing{
		SessionId:         answer.session,
		Fingerprint:       peer.Fingerprint,
		Name:              answer.name,
		IdentityPublicKey: peer.PublicKey.Marshal(),
		Addresses:         peerAddresses(answer.addresses, dialled),
		MayApprove:        intent.PeerMayApprove(),
		MayRequest:        intent.PeerMayRequest(),
		WeDialled:         true,
		KeyFromCode:       expected != nil,
		RemoteAddress:     peer.RemoteAddr,
		StartedAt:         timestamppb.Now(),
		// The listener's long-lived offer, never the address that was dialled
		// (decision AX): both sides admit the other's client key once the code
		// is spent, because either may settle and either may dial.
		Tunnel: n.pendingOffer(answer.name, answer.tunnel),
	}

	if err := n.recordPending(pending); err != nil {
		return nil, fmt.Errorf("peer: %w", err)
	}

	return pending, nil
}

// reachedListener is a listener a joiner has completed the pinned handshake
// with, and how: the client to make the pairing calls on, the identity it
// met, the address the calls go to, and the tunnel client under them when
// they go through a pairing server.
type reachedListener struct {
	client  *transport.Client
	peer    *transport.PeerIdentity
	address string
	raw     TunnelClient
}

func (r *reachedListener) close() {
	r.client.CloseIdle()

	closeRaw(r.raw)
}

// reachListener completes the handshake with the machine displaying a code,
// before anything else is sent to it.
//
// A typed address is dialled and nothing else. A full code's direct addresses
// are all tried at once, because each handshake is pinned to the key in the
// code and so cannot reach anybody else; the first that completes wins. When
// none does and the code carries a pairing server's address, the handshake
// goes through the tunnel to it instead, pinned the same way (decision AZ).
// Either way the PIN exchange starts only once the pin has held, so a wrong
// address — in the code, or answering at it — never receives a guess.
//
// The address dialled is the caller's to report and never to record: a
// pairing server's lives for one window, and what PairWith writes down are
// the direct addresses the listener advertises and the long-lived offer it
// sends (peerAddresses, pendingOffer).
func (n *Node) reachListener(
	ctx context.Context, address string, code *ladulasv1.PairingCode,
	expected ssh.PublicKey,
) (*reachedListener, error) {
	candidates := []string{address}

	if address == "" {
		candidates = code.GetAddresses()

		// Without the key to pin, every address but one would be a guess at a
		// machine the user did not pick.
		if expected == nil && len(candidates) > 1 {
			candidates = candidates[:1]
		}
	}

	tunnelled := address == "" && code.GetTunnelAddress() != "" && expected != nil

	if len(candidates) == 0 && !tunnelled {
		return nil, errors.New(
			"peer: no address to dial, and the code carries none")
	}

	var direct error

	if len(candidates) > 0 {
		// With a pairing server to fall back on, the direct phase is held to
		// directBeforeTunnel. Off the network the code was shown on, its
		// addresses are somebody else's LAN and silently dropped, and each
		// handshake would otherwise spend the whole DialTimeout before the
		// path that works was tried — ten seconds of a join the desktop gives
		// thirty in all, the tunnel's raise still to come.
		directCtx, cancel := ctx, context.CancelFunc(func() {})
		if tunnelled {
			directCtx, cancel = context.WithTimeout(ctx, directBeforeTunnel)
		}

		reached, err := n.handshakeFirst(directCtx, candidates, expected)

		cancel()

		if err == nil {
			return reached, nil
		}

		if !tunnelled {
			return nil, err
		}

		direct = err
	}

	reached, err := n.reachPairingServer(ctx, code, expected)
	if err != nil {
		if direct != nil {
			return nil, fmt.Errorf("%w; through the pairing server: %w", direct, err)
		}

		return nil, fmt.Errorf("peer: through the pairing server: %w", err)
	}

	return reached, nil
}

// directBeforeTunnel bounds the direct phase of a join whose code carries a
// pairing server (reachListener). A handshake on the network the code was
// shown on takes a fraction of it; one that has not completed by then is
// almost always an address that is not on this network at all.
const directBeforeTunnel = 3 * time.Second

// pairFinishTimeout bounds PairFinish once it has been sent, under a context
// the caller cannot cancel (pairByPIN).
const pairFinishTimeout = 15 * time.Second

// handshakeFirst handshakes with every candidate at once and keeps the first
// that completes. One client per address, because a client remembers the
// identity it met, and the losers' handshakes would otherwise write over the
// winner's.
func (n *Node) handshakeFirst(
	ctx context.Context, candidates []string, expected ssh.PublicKey,
) (*reachedListener, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		reached *reachedListener
		err     error
	}

	results := make(chan result, len(candidates))

	for _, candidate := range candidates {
		go func() {
			client, err := transport.NewClient(transport.ClientOptions{
				Identity: n.identity,
				Expect:   expected,
			})
			if err != nil {
				results <- result{err: err}

				return
			}

			peer, err := client.Handshake(ctx, candidate)
			if err != nil {
				client.CloseIdle()

				results <- result{err: fmt.Errorf("peer: reach %s: %w", candidate, err)}

				return
			}

			results <- result{reached: &reachedListener{
				client: client, peer: peer, address: candidate,
			}}
		}()
	}

	var first error

	for received := 1; received <= len(candidates); received++ {
		got := <-results
		if got.err == nil {
			// The rest are cancelled with ctx; what they reach anyway is
			// closed as it arrives.
			go func(remaining int) {
				for range remaining {
					if late := <-results; late.reached != nil {
						late.reached.close()
					}
				}
			}(len(candidates) - received)

			return got.reached, nil
		}

		if first == nil {
			first = got.err
		}
	}

	return nil, first
}

// joinAnswer is what either proof brings back from the listener, once it has
// been checked.
type joinAnswer struct {
	session    string
	name       string
	addresses  []string
	tunnel     *ladulasv1.TunnelOffer
	mayApprove bool
	mayRequest bool
}

// pairByPIN is the joining side of the PIN exchange (decision AV).
//
// It is one run per call: a refusal is reported, never retried with the same
// PIN, because each run is a guess the listener counts and a second one at
// another address would be a guess at a machine the user did not pick.
//
// And it never falls back. A listener that does not implement the exchange is
// not given the older proof instead — that would be an HMAC keyed with the
// PIN, handed to whoever answered, and twenty bits of HMAC is an offline search
// of milliseconds. It is reported as what it may be.
func (n *Node) pairByPIN(
	ctx context.Context, pairing ladulasv1connect.PairingServiceClient,
	peer *transport.PeerIdentity, pin trust.PIN, pinned bool,
) (*joinAnswer, error) {
	ours := n.identity.PublicKey()

	start, err := pairing.PairStart(ctx, connect.NewRequest(&ladulasv1.PairStartRequest{}))
	if err != nil {
		return nil, joinError(err, pinned)
	}

	share, session, err := cpace.Respond(
		pinInputs(pin, ours, peer.PublicKey, start.Msg.GetSessionId()),
		[]byte(adJoiner), start.Msg.GetShare(), []byte(adListener))
	if err != nil {
		return nil, fmt.Errorf("%w: it sent a share that is not a group element (%w)",
			ErrPossibleImpostor, err)
	}

	// The commitment: this side's share and tag, sent together, before
	// anything derived from the key has come back. Name and addresses ride
	// along and are read by the listener only once the tag has verified.
	//
	// Once this is sent the caller no longer gets to cancel it. The listener
	// writes its half of the pairing down as soon as the tag verifies, so a
	// join abandoned here — the desktop's wait running out on a slow relay, a
	// command line interrupted — would leave a pending pairing at the other
	// end with nothing here to settle it against. The call runs to its own
	// bound instead, and PairWith writes this side's half down with it.
	finishCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), pairFinishTimeout)
	defer cancel()

	finish, err := pairing.PairFinish(finishCtx, connect.NewRequest(&ladulasv1.PairFinishRequest{
		SessionId:       start.Msg.GetSessionId(),
		Share:           share,
		Confirmation:    session.Confirmation(),
		InstanceName:    n.identity.Name(),
		ListenAddresses: n.Advertised(),
		Tunnel:          n.offer(),
	}))
	if err != nil {
		return nil, joinError(err, pinned)
	}

	// The far end proves it knew the PIN too. A real listener only sends its
	// tag after verifying ours, so a tag that does not verify is something
	// that is not the machine displaying the PIN.
	if !session.Verify(finish.Msg.GetConfirmation()) {
		return nil, fmt.Errorf("%w: it accepted the PIN without proving it "+
			"knew it", ErrPossibleImpostor)
	}

	return &joinAnswer{
		session:    finish.Msg.GetSessionId(),
		name:       finish.Msg.GetInstanceName(),
		addresses:  finish.Msg.GetListenAddresses(),
		tunnel:     finish.Msg.GetTunnel(),
		mayApprove: finish.Msg.GetMayApprove(),
		mayRequest: finish.Msg.GetMayRequest(),
	}, nil
}

// joinError is what a refusal from the listener means to the person who typed
// the PIN.
func joinError(err error, pinned bool) error {
	switch connect.CodeOf(err) {
	case connect.CodeAlreadyExists:
		return ErrCodeSpent
	case connect.CodePermissionDenied:
		return ErrPINRefused
	case connect.CodeResourceExhausted:
		return ErrAttemptsSpent
	case connect.CodeUnimplemented:
		// With the key from a scanned or pasted code this is the real machine,
		// just an older one; with a typed PIN nothing says it is the machine at
		// all (decision AV, invariant 2).
		if pinned {
			return errors.New("that machine is too old to take a PIN; " +
				"update it, or pair from it with its ten-character code")
		}

		return fmt.Errorf("%w: it does not speak PIN pairing, which every "+
			"version that shows a PIN does — check the address, or use the "+
			"full code from the other screen", ErrPossibleImpostor)
	default:
		return err
	}
}

// pairByProof is the older joiners' proof (decision AV): an HMAC keyed with the
// ten-character secret, which only ever arrives here from a code an older
// instance displayed.
func (n *Node) pairByProof(
	ctx context.Context, pairing ladulasv1connect.PairingServiceClient,
	peer *transport.PeerIdentity, secret trust.Secret,
) (*joinAnswer, error) {
	ours := n.identity.PublicKey()

	resp, err := pairing.Pair(ctx, connect.NewRequest(&ladulasv1.PairRequest{
		Proof:             trust.Proof(secret, peer.PublicKey, ours),
		InstanceName:      n.identity.Name(),
		IdentityPublicKey: ours.Marshal(),
		ListenAddresses:   n.Advertised(),
		Tunnel:            n.offer(),
	}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeAlreadyExists {
			return nil, ErrCodeSpent
		}

		return nil, err
	}

	if !resp.Msg.GetAccepted() {
		reason := resp.Msg.GetReason()
		if reason == "" {
			reason = "the other side declined"
		}

		return nil, errors.New(reason)
	}

	// The far end proves it is the machine displaying the code. Without this a
	// mistyped address would show the user a stranger's fingerprint and ask
	// them to confirm it, which is the one moment a fingerprint cannot be
	// checked against anything.
	if !trust.VerifyConfirmation(
		secret, peer.PublicKey, ours, resp.Msg.GetConfirmation()) {
		return nil, errors.New(
			"the instance answered without knowing the pairing code; " +
				"check the address")
	}

	if claimed := resp.Msg.GetIdentityPublicKey(); len(claimed) > 0 &&
		!bytes.Equal(claimed, peer.PublicKey.Marshal()) {
		return nil, errors.New(
			"the identity in the answer is not the one on the connection")
	}

	return &joinAnswer{
		session:    resp.Msg.GetSessionId(),
		name:       resp.Msg.GetInstanceName(),
		addresses:  resp.Msg.GetListenAddresses(),
		tunnel:     resp.Msg.GetTunnel(),
		mayApprove: resp.Msg.GetMayApprove(),
		mayRequest: resp.Msg.GetMayRequest(),
	}, nil
}

// peerAddresses puts the address that actually worked first, since it demonstrably
// reaches the peer from here and the peer's own list is only its best guess.
//
// Only a direct address is recorded, dialled or advertised
// (trust.DirectAddresses). The joining side writes down what it dialled because
// a TCP connection to it worked, and that reasoning is about TCP: an address
// for a path that is not a direct dial — a pairing server's, whose address
// lives for the length of a pairing screen (decision AZ) — would be written
// into the list the direct dialler works from, first, and fail there every time
// for the life of the pairing. PairWith passes nothing as dialled for a
// pairing joined that way, and the filter here would refuse it anyway.
func peerAddresses(advertised []string, dialled string) []string {
	var out []string

	if trust.IsDirectAddress(dialled) {
		out = append(out, dialled)
	}

	for _, address := range trust.DirectAddresses(advertised) {
		if address != dialled {
			out = append(out, address)
		}
	}

	return out
}

// pendingConfirmation builds the prompt for a pending pairing.
//
// One function for both sides, because there is one pending pairing and it says
// which side dialled. What differs between the two prompts is a sentence, and
// it used to be two functions and two ways for them to drift.
func (n *Node) pendingConfirmation(
	pending *storepb.PendingPairing,
) *ladulasv1.ApprovalRequest {
	requester := &ladulasv1.RequesterInfo{
		InstanceId:    pending.GetFingerprint(),
		Name:          pending.GetName(),
		RemoteAddress: pending.GetRemoteAddress(),
	}

	if pending.GetWeDialled() {
		requester = &ladulasv1.RequesterInfo{
			InstanceId:    n.identity.Fingerprint(),
			Name:          n.identity.Name(),
			Local:         true,
			RemoteAddress: pending.GetRemoteAddress(),
		}
	}

	return &ladulasv1.ApprovalRequest{
		RequestId: identity.NewRequestID(),
		CreatedAt: timestamppb.Now(),
		Kind:      ladulasv1.RequestKind_REQUEST_KIND_PAIRING,
		Requester: requester,
		Operation: &ladulasv1.ApprovalRequest_Pairing{
			Pairing: &ladulasv1.PairingRequest{
				PeerName:         pending.GetName(),
				PeerFingerprint:  pending.GetFingerprint(),
				RemoteAddress:    pending.GetRemoteAddress(),
				PeerMayApprove:   pending.GetMayApprove(),
				PeerMayRequest:   pending.GetMayRequest(),
				LocalFingerprint: n.identity.Fingerprint(),
				LocalName:        n.identity.Name(),
				PeerAddresses:    pending.GetAddresses(),
				InitiatedLocally: pending.GetWeDialled(),
				KeyFromCode:      pending.GetKeyFromCode(),
				FailedAttempts:   pending.GetFailedAttempts(),
			},
		},
	}
}

// confirm puts a pairing in front of whoever can answer here.
//
// It goes through the engine, so it is subject to the hard rule that a pairing
// change always prompts and can reach the tray, a console, or the command line
// that started the pairing — whichever answers first. It is submitted as a peer
// request in the sense that matters: it is decided here and never passed on to
// another instance, because "should I trust this machine" is not a question to
// delegate.
//
// The response is handed back whole rather than reduced to a yes or a no,
// because the caller has to be able to tell a person's answer from the engine
// having given up on getting one. A pairing prompt has no deadline of its own
// (§9), so the ways it can end without an answer are all ways in which nothing
// should be written down.
func (n *Node) confirm(
	ctx context.Context, msg *ladulasv1.ApprovalRequest,
) (*ladulasv1.ApprovalResponse, error) {
	resp, _, err := n.engine.SubmitPeer(ctx, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("peer: confirm the pairing: %w", err)
	}

	return resp, nil
}
