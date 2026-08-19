package peer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// pairingWindow is an open invitation on the listening side: a displayed code,
// the intent its user chose in advance, and the budget of wrong answers it will
// tolerate.
//
// One window at a time. Pairing is a thing a person does deliberately at a
// machine they are sitting at, and a second concurrent window would only make
// it ambiguous which screen a proof was supposed to have come from.
//
// The window is the short-lived half of a pairing and the only half with a
// clock on it: five minutes, single use, five wrong answers (§7). What it
// produces is a pending pairing, and the pending pairing does not expire.
type pairingWindow struct {
	secret  trust.Secret
	expires time.Time
	// intent is what this pairing is for, and it settles both sides' records
	// rather than only this one's (decision AD).
	intent trust.Intent
	// arrived carries the session id of the pending pairing a proof produced,
	// back to whoever is displaying the code.
	arrived chan string

	mu       sync.Mutex
	attempts int
	closed   bool
	settled  bool
}

// settle reports the session once. A window is spent by the first proof that
// works, whatever happens to the pairing afterwards.
func (w *pairingWindow) settle(session string) {
	w.mu.Lock()

	if w.settled {
		w.mu.Unlock()

		return
	}

	w.settled = true
	w.mu.Unlock()

	select {
	case w.arrived <- session:
	default:
	}
}

func (w *pairingWindow) live(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	return !w.closed && now.Before(w.expires)
}

func (w *pairingWindow) close() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.closed = true
}

// spendAttempt records a wrong proof and reports whether the window survives.
//
// The cap is what turns fifty bits of secret into something an online attacker
// cannot work through: five wrong answers and the invitation is withdrawn, and
// the person who was actually pairing displays a new code.
func (w *pairingWindow) spendAttempt() bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.attempts++

	if w.attempts >= trust.MaxAttempts {
		w.closed = true
	}

	return !w.closed
}

func (n *Node) openWindow() *pairingWindow {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.window == nil {
		return nil
	}

	if !n.window.live(time.Now()) {
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

// beginPairing opens the window and returns the code to display.
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

	secret, err := trust.NewSecret()
	if err != nil {
		return nil, "", err
	}

	window := &pairingWindow{
		secret:  secret,
		expires: time.Now().Add(trust.CodeValidity),
		intent:  intent,
		arrived: make(chan string, 1),
	}

	n.mu.Lock()
	previous := n.window
	n.window = window
	n.mu.Unlock()

	if previous != nil {
		previous.close()
	}

	return window, secret, nil
}

func (n *Node) closeWindow(window *pairingWindow) {
	window.close()

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.window == window {
		n.window = nil
	}
}

// Pair is the listening side of the exchange, and it answers immediately.
//
// It used to hold the call open while a human was asked, which meant the whole
// pairing lived inside one RPC and died with it. What it does now is spend the
// code, write down a pending pairing, and say so. The confirmation is raised
// behind it; the answer is reconciled afterwards, by whichever side can reach
// the other (§7).
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
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("no pairing is in progress on this instance"))
	}

	// What the message says about the caller has to agree with what the channel
	// proved. It cannot be otherwise unless something is wrong, and neither
	// possibility is one to pair with.
	if claimed := req.Msg.GetIdentityPublicKey(); len(claimed) > 0 &&
		!bytes.Equal(claimed, peer.PublicKey.Marshal()) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the identity in the request is not the one on the connection"))
	}

	ours := s.node.identity.PublicKey()

	if !trust.VerifyProof(window.secret, ours, peer.PublicKey, req.Msg.GetProof()) {
		if !window.spendAttempt() {
			s.node.closeWindow(window)

			s.node.log.Warn("closed a pairing window after too many wrong codes",
				"peer", peer.Fingerprint)
		}

		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("the pairing code does not match"))
	}

	// The code is single use, and this is where it is used. Closing the window
	// here rather than when the pairing settles is what keeps one displayed code
	// worth exactly one pending pairing, however long the pairing then takes.
	s.node.closeWindow(window)

	session := identity.NewRequestID()

	pending := &storepb.PendingPairing{
		SessionId:         session,
		Fingerprint:       peer.Fingerprint,
		Name:              req.Msg.GetInstanceName(),
		IdentityPublicKey: peer.PublicKey.Marshal(),
		Addresses:         req.Msg.GetListenAddresses(),
		MayApprove:        window.intent.PeerMayApprove(),
		MayRequest:        window.intent.PeerMayRequest(),
		RemoteAddress:     peer.RemoteAddr,
		StartedAt:         timestamppb.Now(),
	}

	if err := s.node.recordPending(pending); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	window.settle(session)

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
		ListenAddresses:   s.node.Addresses(),
		Confirmation:      trust.Confirmation(window.secret, ours, peer.PublicKey),
	}), nil
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
// Three answers, and the third is the one worth explaining. A session this
// instance has no memory of is reported as gone, and the asking side drops its
// half — which is what makes withdrawal propagate without either side keeping a
// tombstone until it has been delivered. The cost is that "withdrawn here",
// "declined here" and "revoked here" all read as "gone" to a peer that was not
// reachable when it happened, and that is accepted rather than worked around:
// a phone advertises no address, so a tombstone could never be delivered to one
// at all, and the mechanism that has to exist anyway — the side still holding a
// pending entry asks — covers every case a tombstone would. The exact reason is
// delivered when the peer can be reached at the moment of the decision, which
// is most of the time and never load-bearing.
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

// PairWith is the dialling side of the exchange, driven by the command line and
// by the phone.
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
func (n *Node) PairWith(
	ctx context.Context, address string, code *ladulasv1.PairingCode,
) (*storepb.PendingPairing, error) {
	secret, err := trust.ParseSecret(code.GetSecret())
	if err != nil {
		return nil, err
	}

	expected, err := trust.CodeKey(code)
	if err != nil {
		return nil, err
	}

	if address == "" {
		if len(code.GetAddresses()) == 0 {
			return nil, errors.New(
				"peer: no address to dial, and the code carries none")
		}

		address = code.GetAddresses()[0]
	}

	client, err := transport.NewClient(transport.ClientOptions{
		Identity: n.identity,
		Expect:   expected,
	})
	if err != nil {
		return nil, err
	}

	defer client.CloseIdle()

	// The handshake first, on its own, because the proof has to be computed
	// over the key the far end actually presents. A code that carried the key
	// has already pinned it and this only confirms it; a typed code learns it
	// here, and everything after is pinned to what was learned.
	peer, err := client.Handshake(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("peer: reach %s: %w", address, err)
	}

	ours := n.identity.PublicKey()

	pairing := ladulasv1connect.NewPairingServiceClient(
		client.HTTP(), client.URL(address))

	resp, err := pairing.Pair(ctx, connect.NewRequest(&ladulasv1.PairRequest{
		Proof:             trust.Proof(secret, peer.PublicKey, ours),
		InstanceName:      n.identity.Name(),
		IdentityPublicKey: ours.Marshal(),
		ListenAddresses:   n.Addresses(),
	}))
	if err != nil {
		return nil, fmt.Errorf("peer: pair with %s: %w", address, err)
	}

	if !resp.Msg.GetAccepted() {
		reason := resp.Msg.GetReason()
		if reason == "" {
			reason = "the other side declined"
		}

		return nil, errors.New("peer: " + reason)
	}

	// The far end proves it is the machine displaying the code. Without this a
	// mistyped address would show the user a stranger's fingerprint and ask
	// them to confirm it, which is the one moment a fingerprint cannot be
	// checked against anything.
	if !trust.VerifyConfirmation(
		secret, peer.PublicKey, ours, resp.Msg.GetConfirmation()) {
		return nil, errors.New(
			"peer: the instance answered without knowing the pairing code; " +
				"check the address")
	}

	if claimed := resp.Msg.GetIdentityPublicKey(); len(claimed) > 0 &&
		!bytes.Equal(claimed, peer.PublicKey.Marshal()) {
		return nil, errors.New(
			"peer: the identity in the answer is not the one on the connection")
	}

	if resp.Msg.GetSessionId() == "" {
		return nil, errors.New(
			"peer: the other instance named no pairing session")
	}

	// The intent as the other side wrote it down, mirrored into what this side
	// writes down. A pairing that says the peer may do nothing is one whose
	// shape was never chosen, and there is nothing to confirm about it.
	intent := trust.IntentOf(
		resp.Msg.GetMayApprove(), resp.Msg.GetMayRequest()).Mirror()

	if intent == trust.IntentUnspecified {
		return nil, errors.New(
			"peer: the other instance did not say what the pairing is for")
	}

	pending := &storepb.PendingPairing{
		SessionId:         resp.Msg.GetSessionId(),
		Fingerprint:       peer.Fingerprint,
		Name:              resp.Msg.GetInstanceName(),
		IdentityPublicKey: peer.PublicKey.Marshal(),
		Addresses:         peerAddresses(resp.Msg.GetListenAddresses(), address),
		MayApprove:        intent.PeerMayApprove(),
		MayRequest:        intent.PeerMayRequest(),
		WeDialled:         true,
		KeyFromCode:       expected != nil,
		RemoteAddress:     peer.RemoteAddr,
		StartedAt:         timestamppb.Now(),
	}

	if err := n.recordPending(pending); err != nil {
		return nil, fmt.Errorf("peer: %w", err)
	}

	return pending, nil
}

// peerAddresses puts the address that actually worked first, since it demonstrably
// reaches the peer from here and the peer's own list is only its best guess.
func peerAddresses(advertised []string, dialled string) []string {
	out := []string{dialled}

	for _, address := range advertised {
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
