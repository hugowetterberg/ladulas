package peer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// The control service is how the command line drives a running instance.
//
// Pairing cannot be done behind the daemon's back. The exchange needs the
// listener the daemon owns, the confirmation has to reach whoever is driving
// it, and revoking a peer has to drop the connection it is holding — none of
// which a second process opening the same store could do. So `ladulas pair` is
// a thin client of the instance, and the confirmation it shows is the same
// approval request the tray would show, answered through the same engine.

// The node answers everything on the service except the lock-state calls,
// which internal/app answers itself — a sealed instance has no node, and
// Status and Unlock are exactly the calls that have to work then (§10, §14).

// Status reports what the instance is and which peers it can currently reach.
func (n *Node) Status(
	_ context.Context, _ *connect.Request[ladulasv1.StatusRequest],
) (*connect.Response[ladulasv1.StatusResponse], error) {
	resp := &ladulasv1.StatusResponse{
		InstanceName:    n.identity.Name(),
		Fingerprint:     n.identity.Fingerprint(),
		ListenAddresses: n.Addresses(),
	}

	resp.Peers = n.PeerStatuses()
	// Beside the per-peer offered keys, which say what is usable this second,
	// the whole borrowed set — including the keys on peers that are not there
	// (decision N).
	resp.BorrowedKeys = n.BorrowedKeys()

	return connect.NewResponse(resp), nil
}

// PeerStatuses is the peer list an embedder can show without going through the
// control socket, which is what the tray does — it is in the same process.
func (n *Node) PeerStatuses() []*ladulasv1.PeerStatus {
	records := n.trust.Peers()

	out := make([]*ladulasv1.PeerStatus, 0, len(records))
	for _, record := range records {
		out = append(out, n.peerStatus(record))
	}

	return out
}

// peerStatus joins a trust record to what the link knows about reaching it.
func (n *Node) peerStatus(record *storepb.TrustRecord) *ladulasv1.PeerStatus {
	status := &ladulasv1.PeerStatus{
		Name:        record.GetName(),
		Fingerprint: record.GetFingerprint(),
		Addresses:   record.GetAddresses(),
		MayApprove:  record.GetMayApprove(),
		MayRequest:  record.GetMayRequest(),
		AllowedKeys: record.GetAllowedKeyFingerprints(),
		AllKeys:     record.GetMayUseAllKeys(),
		PairedAt:    record.GetPairedAt(),
	}

	// A link reports its own state and is the better answer when there is one.
	// Without one, what is left is how the last dial went — which for an
	// instance that collects rather than listens is the only contact it has,
	// and is why a phone polling a machine every second used to describe it as
	// never having been tried.
	existing := n.link(record.GetFingerprint())
	if existing == nil {
		if state := n.reachOf(record.GetFingerprint()); state != nil {
			status.Online = state.online
			status.LastError = state.lastErr

			if !state.lastSeen.IsZero() {
				status.LastSeenAt = timestamppb.New(state.lastSeen)
			}
		}
	} else {
		online, lastErr, lastSeen := existing.State()

		status.Online = online
		status.LastError = lastErr
		// What the peer offers is only known while a link is up, which is exactly
		// the state in which a keyless box can actually use it.
		status.OfferedKeys = existing.offeredKeys()

		if !lastSeen.IsZero() {
			status.LastSeenAt = timestamppb.New(lastSeen)
		}
	}

	// And then what the peer did from its own side, which for a phone is
	// everything there is: it is never dialled, so nothing above ever hears
	// about it, while it collects, announces its keys and reads documentation
	// through the front door. A call it is holding open now is as connected as a
	// device that does not listen gets; the last call it made is the honest
	// answer to "when was it here" (§7).
	holding, lastCall := n.presence(record.GetFingerprint())

	if holding {
		status.Online = true
	}

	if !lastCall.IsZero() &&
		(status.GetLastSeenAt() == nil ||
			lastCall.After(status.GetLastSeenAt().AsTime())) {
		status.LastSeenAt = timestamppb.New(lastCall)
	}

	return status
}

// SetPeerDirections changes what a peer is allowed to do, and brings the links
// into line with the change.
func (n *Node) SetPeerDirections(
	_ context.Context, req *connect.Request[ladulasv1.SetPeerDirectionsRequest],
) (*connect.Response[ladulasv1.SetPeerDirectionsResponse], error) {
	record, err := n.trust.SetPeerDirections(req.Msg.GetPeer(), trust.Directions{
		MayApprove:  req.Msg.GetMayApprove(),
		MayRequest:  req.Msg.GetMayRequest(),
		AllowedKeys: req.Msg.GetAllowedKeys(),
		AllKeys:     req.Msg.GetAllKeys(),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	n.engine.LogLifecycle(fmt.Sprintf("%q now %s, and may use %s of this instance's keys",
		record.GetName(),
		trust.Describe(record.GetMayApprove(), record.GetMayRequest()),
		trust.DescribeKeys(record)))

	n.Reconcile()

	return connect.NewResponse(&ladulasv1.SetPeerDirectionsResponse{
		Peer: n.peerStatus(record),
	}), nil
}

// SetPeerKeyAccess grants or takes away a peer's use of this instance's keys,
// leaving the approval directions as they are.
//
// It exists because the phone had no way to say it (decision T): the permission
// is per peer and the phone's screens are per key and per pairing, and the whole
// of the setting a person wants there is "this machine may use my keys". A
// desktop says the same thing with `peers allow --all-keys`, through
// SetPeerDirections, which is what this is in terms of.
func (n *Node) SetPeerKeyAccess(fingerprint string, all bool) (*storepb.TrustRecord, error) {
	record, ok := n.trust.Peer(fingerprint)
	if !ok {
		return nil, fmt.Errorf("peer: no paired peer %q", fingerprint)
	}

	revised, err := n.trust.SetPeerDirections(fingerprint, trust.Directions{
		MayApprove: record.GetMayApprove(),
		MayRequest: record.GetMayRequest(),
		AllKeys:    all,
		// Taking away the blanket permission takes the list with it rather than
		// falling back to whatever was once listed there. A person turning this
		// off means "not my keys", and a remembered allowlist quietly surviving
		// that would be the opposite of what they said.
		AllowedKeys: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("peer: set what %q may use: %w", record.GetName(), err)
	}

	n.engine.LogLifecycle(fmt.Sprintf("%q may now use %s of this instance's keys",
		revised.GetName(), trust.DescribeKeys(revised)))

	return revised, nil
}

// RenamePeer changes the name this instance knows a peer by.
//
// The name is this side's own label. Two machines both called after their
// hostname can easily be the same word, and which one a prompt is talking about
// matters more than what either of them calls itself.
func (n *Node) RenamePeer(
	_ context.Context, req *connect.Request[ladulasv1.RenamePeerRequest],
) (*connect.Response[ladulasv1.RenamePeerResponse], error) {
	record, err := n.trust.RenamePeer(req.Msg.GetPeer(), req.Msg.GetName())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	n.Reconcile()

	return connect.NewResponse(&ladulasv1.RenamePeerResponse{
		Peer: n.peerStatus(record),
	}), nil
}

// RevokePeer forgets a peer and drops what it was holding.
//
// The two halves are both necessary and neither is sufficient. Forgetting the
// record is what stops the next call being authorized; dropping the connection
// is what stops the current one continuing. A revocation that only did the
// first would take effect at the peer's convenience.
func (n *Node) RevokePeer(
	_ context.Context, req *connect.Request[ladulasv1.RevokePeerRequest],
) (*connect.Response[ladulasv1.RevokePeerResponse], error) {
	record, _ := n.trust.Peer(req.Msg.GetPeer())

	fingerprint, err := n.trust.RemovePeer(req.Msg.GetPeer())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	if record != nil {
		n.dropPeerProjects(record)
		n.dropPeerKeys(record)
		n.dropPeerHandovers(record)
	}

	n.Disconnect(fingerprint)
	n.Reconcile()

	n.engine.LogLifecycle("revoked the pairing with " + fingerprint)

	return connect.NewResponse(&ladulasv1.RevokePeerResponse{
		Fingerprint: fingerprint,
	}), nil
}

// AnswerPairing settles a confirmation a pairing stream asked for.
func (n *Node) AnswerPairing(
	_ context.Context, req *connect.Request[ladulasv1.AnswerPairingRequest],
) (*connect.Response[ladulasv1.AnswerPairingResponse], error) {
	reason := req.Msg.GetReason()
	if reason == "" {
		reason = "answered at the command line"
	}

	answer := &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_DENY,
		Reason:   reason,
	}

	if req.Msg.GetAccepted() {
		answer.Decision = ladulasv1.Decision_DECISION_APPROVE
	}

	if !n.settleConfirmation(req.Msg.GetRequestId(), answer) {
		return nil, connect.NewError(connect.CodeNotFound,
			errors.New("that confirmation is no longer waiting"))
	}

	return connect.NewResponse(&ladulasv1.AnswerPairingResponse{}), nil
}

// BeginPairing displays a code and waits for somebody to use it.
//
// The code's five minutes are the only deadline in the command. What happens
// after somebody uses it is followed rather than waited for: the exchange is on
// disk by then, and the command can be interrupted, backgrounded or killed
// without costing anything (§7).
func (n *Node) BeginPairing(
	ctx context.Context,
	req *connect.Request[ladulasv1.BeginPairingRequest],
	stream *connect.ServerStream[ladulasv1.PairingProgress],
) error {
	session := n.newSession(stream)
	defer session.close()

	window, secret, err := n.beginPairing(
		req.Msg.GetPeerMayApprove(), req.Msg.GetPeerMayRequest())
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}

	defer n.closeWindow(window)

	addresses := n.Addresses()

	full, err := trust.EncodeCode(trust.NewCode(
		secret, n.identity.Name(), n.identity.PublicKey(),
		addresses, window.expires))
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}

	err = session.send(&ladulasv1.PairingProgress{
		Kind:            ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_CODE,
		Code:            secret.Display(),
		FullCode:        full,
		ExpiresAt:       timestamppb.New(window.expires),
		ListenAddresses: addresses,
	})
	if err != nil {
		return err
	}

	select {
	case pairing := <-window.arrived:
		return n.followPairing(ctx, session, pairing)
	case <-time.After(time.Until(window.expires)):
		return session.send(&ladulasv1.PairingProgress{
			Kind:    ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_FAILED,
			Message: "the pairing code expired before anybody used it",
		})
	case <-ctx.Done():
		return nil
	}
}

// PairWithPeer dials an instance that is displaying a code.
func (n *Node) PairWithPeer(
	ctx context.Context,
	req *connect.Request[ladulasv1.PairWithPeerRequest],
	stream *connect.ServerStream[ladulasv1.PairingProgress],
) error {
	session := n.newSession(stream)
	defer session.close()

	code, err := trust.DecodeCode(req.Msg.GetCode())
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}

	pending, err := n.PairWith(ctx, req.Msg.GetAddress(), code,
		req.Msg.GetPeerMayApprove(), req.Msg.GetPeerMayRequest())
	if err != nil {
		return session.send(&ladulasv1.PairingProgress{
			Kind:    ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_FAILED,
			Message: err.Error(),
		})
	}

	return n.followPairing(ctx, session, pending.GetSessionId())
}

// pairingHandover is how long a command waits for the other side after its own
// user has answered, before it says so and stops occupying a terminal.
//
// It settles nothing. The pairing is on disk on both sides and the daemon goes
// on reconciling it; this is only the point at which the person who has already
// done their part is told they can walk away.
const pairingHandover = 20 * time.Second

// followPairing reports a pending pairing until it is settled, this side has
// answered and the other side is taking its time, or the caller goes away.
func (n *Node) followPairing(
	ctx context.Context, session *pairingSession, id string,
) error {
	events := n.watchPairing(id)
	defer n.unwatchPairing(id, events)

	// The watcher is registered before the store is consulted, so a pairing
	// that settled while this was being set up is found here rather than waited
	// for indefinitely.
	if done, err := n.settledPairing(session, id); done || err != nil {
		return err
	}

	var handover <-chan time.Time

	for {
		select {
		case event := <-events:
			switch event.kind {
			case pairingCompleted:
				return session.send(&ladulasv1.PairingProgress{
					Kind: ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_DONE,
					Peer: n.peerStatus(event.record),
				})
			case pairingEnded:
				return session.send(&ladulasv1.PairingProgress{
					Kind:    ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_FAILED,
					Message: event.message,
				})
			case pairingAnswered:
				handover = time.After(pairingHandover)
			}
		case <-handover:
			return session.send(&ladulasv1.PairingProgress{
				Kind:    ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_WAITING,
				Message: "waiting for the other side to confirm",
			})
		case <-ctx.Done():
			return nil
		}
	}
}

// settledPairing reports a session that is already over, and says whether it
// was.
func (n *Node) settledPairing(
	session *pairingSession, id string,
) (bool, error) {
	if _, ok := n.trust.PendingPairing(id); ok {
		return false, nil
	}

	for _, record := range n.trust.Peers() {
		if record.GetPairingSessionId() != id {
			continue
		}

		return true, session.send(&ladulasv1.PairingProgress{
			Kind: ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_DONE,
			Peer: n.peerStatus(record),
		})
	}

	return true, session.send(&ladulasv1.PairingProgress{
		Kind:    ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_FAILED,
		Message: "the pairing is no longer on record here",
	})
}

// ListPendingPairings reports the pairings under way (§7, §14).
func (n *Node) ListPendingPairings(
	_ context.Context, _ *connect.Request[ladulasv1.ListPendingPairingsRequest],
) (*connect.Response[ladulasv1.ListPendingPairingsResponse], error) {
	resp := &ladulasv1.ListPendingPairingsResponse{}

	for _, pending := range n.trust.PendingPairings() {
		resp.Pairings = append(resp.Pairings, n.pendingStatus(pending))
	}

	return connect.NewResponse(resp), nil
}

// PendingPairingStatuses is the list an embedder can show without going through
// the control socket, which is what the tray and the phone shell do.
func (n *Node) PendingPairingStatuses() []*ladulasv1.PendingPairingStatus {
	pairings := n.trust.PendingPairings()

	out := make([]*ladulasv1.PendingPairingStatus, 0, len(pairings))
	for _, pending := range pairings {
		out = append(out, n.pendingStatus(pending))
	}

	return out
}

func (n *Node) pendingStatus(
	pending *storepb.PendingPairing,
) *ladulasv1.PendingPairingStatus {
	return &ladulasv1.PendingPairingStatus{
		SessionId:             pending.GetSessionId(),
		Name:                  pending.GetName(),
		Fingerprint:           pending.GetFingerprint(),
		Addresses:             pending.GetAddresses(),
		RemoteAddress:         pending.GetRemoteAddress(),
		MayApprove:            pending.GetMayApprove(),
		MayRequest:            pending.GetMayRequest(),
		WeDialled:             pending.GetWeDialled(),
		KeyFromCode:           pending.GetKeyFromCode(),
		OurAnswer:             pending.GetOurAnswer(),
		TheirAnswer:           pending.GetTheirAnswer(),
		StartedAt:             pending.GetStartedAt(),
		AnsweredAt:            pending.GetAnsweredAt(),
		LocalName:             n.identity.Name(),
		LocalFingerprint:      n.identity.Fingerprint(),
		ConfirmationRequestId: pending.GetConfirmationRequestId(),
	}
}

// AnswerPendingPairing records an answer whether or not the command that
// started the pairing is still running, and whether or not the peer is
// reachable (§7).
func (n *Node) AnswerPendingPairing(
	_ context.Context,
	req *connect.Request[ladulasv1.AnswerPendingPairingRequest],
) (*connect.Response[ladulasv1.AnswerPendingPairingResponse], error) {
	reason := req.Msg.GetReason()
	if reason == "" {
		reason = "answered at the management surface"
	}

	state, pending, record, err := n.AnswerPending(
		req.Msg.GetPairing(), req.Msg.GetAccepted(), reason)

	switch {
	case errors.Is(err, ErrNoPendingPairing):
		return nil, connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, ErrPairingAnswered):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &ladulasv1.AnswerPendingPairingResponse{
		State:   state,
		Message: pairingOutcomeMessage(state, req.Msg.GetAccepted()),
	}

	if record != nil {
		resp.Peer = n.peerStatus(record)
	}

	if state == ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_PENDING {
		resp.Pairing = n.pendingStatus(pending)
	}

	return connect.NewResponse(resp), nil
}

func pairingOutcomeMessage(
	state ladulasv1.PairingRecordState, accepted bool,
) string {
	switch state {
	case ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_PAIRED:
		return "both sides have agreed"
	case ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_GONE:
		if accepted {
			return "the other side had already ended it"
		}

		return "the attempt is over"
	case ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_PENDING,
		ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_UNSPECIFIED:
		return "recorded here; waiting for the other side"
	default:
		return "recorded here; waiting for the other side"
	}
}

// WithdrawPairing calls an attempt off on this side and tells the peer if it
// can be reached (§7).
func (n *Node) WithdrawPairing(
	ctx context.Context, req *connect.Request[ladulasv1.WithdrawPairingRequest],
) (*connect.Response[ladulasv1.WithdrawPairingResponse], error) {
	reason := req.Msg.GetReason()
	if reason == "" {
		reason = "called off at the management surface"
	}

	pending, told, err := n.Withdraw(ctx, req.Msg.GetPairing(), reason)
	if errors.Is(err, ErrNoPendingPairing) {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&ladulasv1.WithdrawPairingResponse{
		SessionId:   pending.GetSessionId(),
		Fingerprint: pending.GetFingerprint(),
		PeerTold:    told,
		Message:     withdrawalMessage(told, len(pending.GetAddresses()) > 0),
	}), nil
}

// withdrawalMessage says whether the other side knows yet, since the two cases
// want different things done about them: none, and nothing.
func withdrawalMessage(told, dialable bool) string {
	switch {
	case told:
		return "the other side has been told"
	case !dialable:
		return "the other side has no address to be told at, " +
			"and will find out when it next asks"
	default:
		return "the other side could not be reached, " +
			"and will find out when it next asks"
	}
}

// pairingSession is the approver a pairing command registers for as long as it
// is running.
//
// It answers pairing confirmations and nothing else, so a signing request that
// arrives while somebody is pairing is not sent to a terminal that is showing a
// fingerprint. It joins the engine's ordinary fan-out, which means a desktop
// that is also running a tray gets both: the prompt appears in the window and
// on the terminal, and whichever is answered first settles it.
type pairingSession struct {
	node   *Node
	stream *connect.ServerStream[ladulasv1.PairingProgress]

	sendMu     sync.Mutex
	closed     bool
	unregister func()
	closeOnce  sync.Once
}

var _ approval.Handler = (*pairingSession)(nil)

func (n *Node) newSession(
	stream *connect.ServerStream[ladulasv1.PairingProgress],
) *pairingSession {
	session := &pairingSession{node: n, stream: stream}
	session.unregister = n.engine.Register(session)

	return session
}

// close stops the session answering and stops it writing, in that order.
//
// The second half matters more than it looks. A pairing confirmation now
// outlives the call that raised it — it is raised on the node's own lifetime,
// because a pairing is not owned by a command any more (§7) — so a Decide can
// still be holding this stream when the handler that created it returns. The
// flag is what makes "the command has gone" a refusal rather than a write into
// a response somebody else is closing.
func (s *pairingSession) close() {
	s.sendMu.Lock()
	s.closed = true
	s.sendMu.Unlock()

	s.closeOnce.Do(s.unregister)
}

// errPairingSessionClosed is what a prompt gets when the command it would have
// been shown on is no longer there. The engine treats it as an approver that
// could not be reached, which is exactly what it is.
var errPairingSessionClosed = errors.New(
	"peer: the pairing command is no longer running")

// ID implements approval.Handler.
func (s *pairingSession) ID() string {
	return "pairing command"
}

// errNotPairing is what the session answers a request it has no business
// showing. The engine treats a handler that errors as one that is not there.
var errNotPairing = errors.New("peer: the pairing command only answers pairings")

// Decide implements approval.Handler.
func (s *pairingSession) Decide(
	ctx context.Context, req *approval.Request,
) (*approval.Answer, error) {
	if req.Msg.GetKind() != ladulasv1.RequestKind_REQUEST_KIND_PAIRING {
		return nil, errNotPairing
	}

	id := req.Msg.GetRequestId()

	waiting := s.node.awaitConfirmation(id)
	defer s.node.forgetConfirmation(id)

	err := s.send(&ladulasv1.PairingProgress{
		Kind:         ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_CONFIRM,
		Confirmation: req.Msg,
	})
	if err != nil {
		return nil, err
	}

	select {
	case answer := <-waiting:
		return answer, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// send serialises writes to the stream, which two goroutines reach: the one
// running the exchange and the one showing a confirmation.
func (s *pairingSession) send(progress *ladulasv1.PairingProgress) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	if s.closed {
		return errPairingSessionClosed
	}

	if err := s.stream.Send(progress); err != nil {
		return fmt.Errorf("peer: send pairing progress: %w", err)
	}

	return nil
}

func (n *Node) awaitConfirmation(id string) chan *approval.Answer {
	waiting := make(chan *approval.Answer, 1)

	n.mu.Lock()
	defer n.mu.Unlock()

	n.confirmations[id] = waiting

	return waiting
}

func (n *Node) forgetConfirmation(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	delete(n.confirmations, id)
}

func (n *Node) settleConfirmation(id string, answer *approval.Answer) bool {
	n.mu.Lock()
	waiting := n.confirmations[id]
	n.mu.Unlock()

	if waiting == nil {
		return false
	}

	select {
	case waiting <- answer:
		return true
	default:
		return false
	}
}
