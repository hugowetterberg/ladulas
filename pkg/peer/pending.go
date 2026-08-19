package peer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// A pairing has two halves that keep different time, and this file is the
// second one (§7).
//
// The first half is the pairing code: five minutes, single use, five wrong
// answers. That is a security property and nothing here touches it. What it
// buys is the right to write down a pending pairing on both sides, and from
// that point on nothing is bounded by a clock, because what remains is two
// people comparing two fingerprints and a person is not something an attacker
// can guess at ten thousand tries a second.
//
// So the state is on disk, each side records its own answer locally first, and
// the two sides reconcile whenever they can reach each other — idempotently,
// repeatedly, and driven from whichever end is able to dial. A pairing ends
// because somebody said no, because somebody called it off, or because the two
// sides cannot agree on who they are talking to. It never ends because time
// passed.

// DefaultPairingRetry is how often a pending pairing is taken to its peer.
//
// It is a network cadence rather than a deadline: nothing is decided when it
// elapses, and a peer that has been unreachable for a fortnight is asked again
// on the same schedule as one that was unreachable for a second. It is what
// covers the case neither side can shorten — a phone, which advertises no
// address and so can only ever be the side that asks.
const DefaultPairingRetry = 30 * time.Second

// maxConvergeTick is how often the loop looks at the pending set at all. Most
// of what it does is local — putting a confirmation back in front of an
// approver that has just appeared — so it runs more often than the retry.
const maxConvergeTick = 5 * time.Second

// settleTimeout bounds one reconciliation call. Nobody is thinking during it,
// so it is a network timeout and nothing else.
const settleTimeout = 15 * time.Second

// ErrNoPendingPairing is returned when nothing answers to a reference.
var ErrNoPendingPairing = errors.New("peer: no pairing is waiting under that name")

// ErrPairingAnswered is returned when an answer is given twice.
//
// The first one stands. Changing your mind about a pairing you have already
// approved is `pairings withdraw` while it is still pending, and `peers revoke`
// once it is not — both of which say plainly that something is being taken
// away, which a second answer would not.
var ErrPairingAnswered = errors.New(
	"peer: this pairing has already been answered here")

// pairingEventKind is what happened to a pending pairing.
type pairingEventKind int

const (
	// pairingAnswered is this side's user having answered, with the other side
	// not yet in.
	pairingAnswered pairingEventKind = iota
	// pairingCompleted is both sides having said yes.
	pairingCompleted
	// pairingEnded is the attempt being over without a pairing.
	pairingEnded
)

// pairingEvent is what a watcher is told.
type pairingEvent struct {
	kind    pairingEventKind
	record  *storepb.TrustRecord
	message string
}

// recordPending writes a pending pairing down and starts working on it.
//
// Writing it down is the point at which a pairing stops being able to be lost.
// Everything after this — the confirmation, the peer's answer, the completion —
// is recovery from a record rather than the continuation of a call.
func (n *Node) recordPending(pending *storepb.PendingPairing) error {
	if err := n.trust.PutPendingPairing(pending); err != nil {
		return fmt.Errorf("write down the pending pairing: %w", err)
	}

	n.log.Info("a pairing is waiting to be confirmed",
		"peer", pending.GetFingerprint(),
		"name", pending.GetName(),
		"session", pending.GetSessionId())

	n.raisePrompt(pending)
	n.pokeConvergence()

	return nil
}

// PendingPairings reports the pairings under way.
func (n *Node) PendingPairings() []*storepb.PendingPairing {
	return n.trust.PendingPairings()
}

// AnswerPending records this side's answer and reconciles what it can.
//
// The order is the whole design: the answer is written down here before
// anything is said to the peer, so an unreachable, asleep or restarting peer
// costs nothing but a delay. Telling it is the loop's job, and the loop keeps
// trying.
func (n *Node) AnswerPending(
	ref string, accepted bool, reason string,
) (ladulasv1.PairingRecordState, *storepb.PendingPairing, *storepb.TrustRecord, error) {
	answer := ladulasv1.PairingAnswer_PAIRING_ANSWER_DECLINED
	if accepted {
		answer = ladulasv1.PairingAnswer_PAIRING_ANSWER_ACCEPTED
	}

	state, pending, record, err := n.answerPending(ref, answer, reason)
	if err != nil {
		return state, nil, nil, err
	}

	// The peer is told now rather than at the next tick, so that two people
	// answering within a minute of each other see a pairing complete while they
	// are both still looking at it. Failing to reach it changes nothing: the
	// answer is already on disk and the loop keeps trying.
	n.nudgePeer(pending, reason)
	n.pokeConvergence()

	return state, pending, record, nil
}

// nudgePeer takes one pairing to its peer straight away, out of band of the
// loop's pacing.
func (n *Node) nudgePeer(pending *storepb.PendingPairing, reason string) {
	if len(pending.GetAddresses()) == 0 {
		return
	}

	n.mu.Lock()
	ctx := n.ctx
	n.mu.Unlock()

	if ctx == nil {
		return
	}

	go func() {
		callCtx, cancel := context.WithTimeout(ctx, settleTimeout)
		defer cancel()

		resp, err := n.callSettle(callCtx, pending, reason)
		if err != nil {
			n.log.Debug("could not tell the peer about a pairing answer",
				"session", pending.GetSessionId(), "error", err.Error())

			return
		}

		if err := n.applySettlement(pending.GetSessionId(), resp); err != nil {
			n.log.Error("could not apply what the peer said about a pairing",
				"session", pending.GetSessionId(), "error", err.Error())
		}
	}()
}

func (n *Node) answerPending(
	ref string, answer ladulasv1.PairingAnswer, reason string,
) (ladulasv1.PairingRecordState, *storepb.PendingPairing, *storepb.TrustRecord, error) {
	n.pairingMu.Lock()
	defer n.pairingMu.Unlock()

	pending, ok := n.trust.PendingPairing(ref)
	if !ok {
		return ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_GONE, nil, nil,
			fmt.Errorf("%w: %s", ErrNoPendingPairing, ref)
	}

	if pending.GetOurAnswer() != ladulasv1.PairingAnswer_PAIRING_ANSWER_UNSPECIFIED {
		return ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_PENDING, pending, nil,
			ErrPairingAnswered
	}

	pending.OurAnswer = answer
	pending.AnsweredAt = timestamppb.Now()

	state, record, err := n.advance(pending, reason, true)
	if err != nil {
		return state, nil, nil, err
	}

	return state, pending, record, nil
}

// advance is the whole of the state machine, and it is called from both ends:
// from the command line when somebody answers here, and from the RPC when the
// peer says what it decided. Callers hold pairingMu and hold no network call
// open.
func (n *Node) advance(
	pending *storepb.PendingPairing, reason string, answeredHere bool,
) (ladulasv1.PairingRecordState, *storepb.TrustRecord, error) {
	ours := pending.GetOurAnswer()
	theirs := pending.GetTheirAnswer()

	if refusal(ours) || refusal(theirs) {
		n.dropPending(pending, refusalMessage(ours, theirs, reason))

		return ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_GONE, nil, nil
	}

	if ours == ladulasv1.PairingAnswer_PAIRING_ANSWER_ACCEPTED &&
		theirs == ladulasv1.PairingAnswer_PAIRING_ANSWER_ACCEPTED {
		record, err := n.completePending(pending)
		if err != nil {
			return ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_PENDING, nil, err
		}

		return ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_PAIRED, record, nil
	}

	if err := n.trust.PutPendingPairing(pending); err != nil {
		return ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_PENDING, nil,
			fmt.Errorf("update the pending pairing: %w", err)
	}

	if answeredHere {
		n.notifyPairing(pending.GetSessionId(), pairingEvent{
			kind:    pairingAnswered,
			message: "waiting for the other side",
		})
	}

	return ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_PENDING, nil, nil
}

// completePending is the one place a pairing turns into a trust record.
func (n *Node) completePending(
	pending *storepb.PendingPairing,
) (*storepb.TrustRecord, error) {
	key, err := ssh.ParsePublicKey(pending.GetIdentityPublicKey())
	if err != nil {
		return nil, fmt.Errorf("read the peer's identity key: %w", err)
	}

	record := trust.NewRecord(
		pending.GetName(), key, pending.GetAddresses(),
		pending.GetMayApprove(), pending.GetMayRequest(), pending.GetWeDialled())

	// The session travels onto the record, so that a peer still holding the
	// pending half of this very pairing can be told that it completed here —
	// rather than being told only that nothing is pending, which is also what a
	// withdrawal looks like.
	record.PairingSessionId = pending.GetSessionId()

	if err := n.trust.PutPeer(record); err != nil {
		return nil, fmt.Errorf("store the trust record: %w", err)
	}

	if _, err := n.trust.RemovePendingPairing(pending.GetSessionId()); err != nil {
		n.log.Warn("a completed pairing left its pending entry behind",
			"session", pending.GetSessionId(), "error", err.Error())
	}

	n.cancelPrompt(pending.GetSessionId())

	n.engine.LogLifecycle(fmt.Sprintf("paired with %q, %s, which %s",
		record.GetName(), record.GetFingerprint(),
		trust.Describe(record.GetMayApprove(), record.GetMayRequest())))

	n.notifyPairing(pending.GetSessionId(), pairingEvent{
		kind:   pairingCompleted,
		record: record,
	})

	n.Reconcile()

	return record, nil
}

// dropPending forgets an attempt and tells everything that was watching it.
func (n *Node) dropPending(pending *storepb.PendingPairing, message string) {
	if _, err := n.trust.RemovePendingPairing(pending.GetSessionId()); err != nil {
		// Already gone is the ordinary case when both ends settle at once, and
		// there is nothing to do about any of the others either.
		n.log.Debug("a pending pairing was already gone when it ended",
			"session", pending.GetSessionId(), "error", err.Error())
	}

	n.cancelPrompt(pending.GetSessionId())

	n.engine.LogLifecycle(fmt.Sprintf("the pairing with %q, %s, ended: %s",
		pending.GetName(), pending.GetFingerprint(), message))

	n.notifyPairing(pending.GetSessionId(), pairingEvent{
		kind:    pairingEnded,
		message: message,
	})
}

func refusal(answer ladulasv1.PairingAnswer) bool {
	return answer == ladulasv1.PairingAnswer_PAIRING_ANSWER_DECLINED ||
		answer == ladulasv1.PairingAnswer_PAIRING_ANSWER_WITHDRAWN
}

// refusalMessage says which side ended it and how, in the words of whoever
// decided. "Declined" is not a synonym for "called off", and neither is a
// synonym for "nobody answered" — which is not a way for a pairing to end at
// all any more.
func refusalMessage(ours, theirs ladulasv1.PairingAnswer, reason string) string {
	var message string

	switch {
	case ours == ladulasv1.PairingAnswer_PAIRING_ANSWER_DECLINED:
		message = "declined here"
	case ours == ladulasv1.PairingAnswer_PAIRING_ANSWER_WITHDRAWN:
		message = "called off here"
	case theirs == ladulasv1.PairingAnswer_PAIRING_ANSWER_DECLINED:
		message = "declined at the other end"
	default:
		message = "called off at the other end"
	}

	if reason != "" {
		message += ": " + reason
	}

	return message
}

// Withdraw calls a pairing off. It is a manual operation and the only way a
// pending pairing leaves the list without being answered (§7).
//
// The peer is told if it can be reached, and finds out by asking if it cannot —
// see settlePairingReply for why that is enough, and for what it costs.
func (n *Node) Withdraw(
	ctx context.Context, ref, reason string,
) (*storepb.PendingPairing, bool, error) {
	n.pairingMu.Lock()

	pending, ok := n.trust.PendingPairing(ref)
	if !ok {
		n.pairingMu.Unlock()

		return nil, false, fmt.Errorf("%w: %s", ErrNoPendingPairing, ref)
	}

	pending.OurAnswer = ladulasv1.PairingAnswer_PAIRING_ANSWER_WITHDRAWN
	pending.AnsweredAt = timestamppb.Now()

	n.dropPending(pending, refusalMessage(pending.GetOurAnswer(),
		ladulasv1.PairingAnswer_PAIRING_ANSWER_UNSPECIFIED, reason))

	n.pairingMu.Unlock()

	told := n.tellPeer(ctx, pending, reason)

	return pending, told, nil
}

// tellPeer delivers an outcome that has already been decided here, so that the
// other side hears the exact reason rather than the general one it would get by
// asking later. It is best effort by construction: a peer that cannot be
// reached is not an error, and a phone cannot be reached at all.
func (n *Node) tellPeer(
	ctx context.Context, pending *storepb.PendingPairing, reason string,
) bool {
	if len(pending.GetAddresses()) == 0 {
		return false
	}

	ctx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), settleTimeout)
	defer cancel()

	if _, err := n.callSettle(ctx, pending, reason); err != nil {
		n.log.Info("the other side could not be told how a pairing ended",
			"session", pending.GetSessionId(), "error", err.Error())

		return false
	}

	return true
}

// callSettle takes this side's answer to the peer and brings its answer back.
// It holds no lock: it is the only part of a pairing that touches the network.
func (n *Node) callSettle(
	ctx context.Context, pending *storepb.PendingPairing, reason string,
) (*ladulasv1.SettlePairingResponse, error) {
	if len(pending.GetAddresses()) == 0 {
		return nil, ErrNoAddress
	}

	key, err := ssh.ParsePublicKey(pending.GetIdentityPublicKey())
	if err != nil {
		return nil, fmt.Errorf("read the peer's identity key: %w", err)
	}

	client, err := transport.NewClient(transport.ClientOptions{
		Identity: n.identity,
		Expect:   key,
	})
	if err != nil {
		return nil, err
	}

	defer client.CloseIdle()

	msg := &ladulasv1.SettlePairingRequest{
		SessionId: pending.GetSessionId(),
		Answer:    pending.GetOurAnswer(),
		Reason:    reason,
	}

	var last error

	for _, address := range pending.GetAddresses() {
		service := ladulasv1connect.NewPairingServiceClient(
			client.HTTP(), client.URL(address))

		resp, err := service.SettlePairing(ctx, connect.NewRequest(msg))
		if err == nil {
			return resp.Msg, nil
		}

		if ctx.Err() != nil {
			return nil, fmt.Errorf("settle the pairing with %s: %w", address, err)
		}

		last = fmt.Errorf("settle the pairing with %s: %w", address, err)
	}

	return nil, last
}

// applySettlement takes what the peer said and moves the pairing on.
func (n *Node) applySettlement(
	session string, resp *ladulasv1.SettlePairingResponse,
) error {
	n.pairingMu.Lock()
	defer n.pairingMu.Unlock()

	// The entry is re-read rather than reused: an answer may have been recorded
	// here while the call was out.
	pending, ok := n.trust.PendingPairing(session)
	if !ok || pending.GetSessionId() != session {
		return nil
	}

	switch resp.GetState() {
	case ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_PAIRED:
		pending.TheirAnswer = ladulasv1.PairingAnswer_PAIRING_ANSWER_ACCEPTED
	case ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_GONE:
		// The peer has no memory of this session. It was withdrawn, declined or
		// revoked there while this side could not be reached; either way there is
		// nothing left to converge on and nothing this side can do about it but
		// stop asking.
		n.dropPending(pending,
			"the other side has no record of this pairing")

		return nil
	case ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_PENDING,
		ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_UNSPECIFIED:
		if answer := resp.GetAnswer(); answer !=
			ladulasv1.PairingAnswer_PAIRING_ANSWER_UNSPECIFIED {
			pending.TheirAnswer = answer
		}
	}

	if _, _, err := n.advance(pending, resp.GetReason(), false); err != nil {
		return err
	}

	return nil
}

// runConvergence is the loop that makes a pairing resumable.
//
// It does two things, both of which are the answer to something that used to
// end a pairing for good: it puts a confirmation back in front of an approver
// that has appeared since — a tray that started, a phone that was opened, a
// daemon that restarted — and it takes this side's answer to the peer for as
// long as the peer is not reachable.
func (n *Node) runConvergence(ctx context.Context) {
	tick := maxConvergeTick
	if n.retry < tick {
		tick = n.retry
	}

	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	for {
		n.convergeOnce(ctx)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-n.converge:
		}
	}
}

func (n *Node) pokeConvergence() {
	select {
	case n.converge <- struct{}{}:
	default:
	}
}

func (n *Node) convergeOnce(ctx context.Context) {
	// A key queued for a peer that was not there is the same problem as an
	// answer to a pairing that was not there: something this side has decided,
	// waiting on somebody to be reachable (decision S).
	n.deliverQueuedKeys(ctx)

	for _, pending := range n.trust.PendingPairings() {
		if ctx.Err() != nil {
			return
		}

		if pending.GetOurAnswer() ==
			ladulasv1.PairingAnswer_PAIRING_ANSWER_UNSPECIFIED {
			n.raisePrompt(pending)
		}

		if !n.shouldSettle(pending) {
			continue
		}

		resp, err := n.settleWithin(ctx, pending)
		if err != nil {
			// Unreachable is not a failure of the pairing, and saying so at
			// anything above debug would fill a headless box's log with the fact
			// that a laptop is shut.
			n.log.Debug("could not reconcile a pairing with its peer",
				"session", pending.GetSessionId(), "error", err.Error())

			continue
		}

		if err := n.applySettlement(pending.GetSessionId(), resp); err != nil {
			n.log.Error("could not apply what the peer said about a pairing",
				"session", pending.GetSessionId(), "error", err.Error())
		}
	}
}

// settleWithin is one reconciliation call, bounded so that a peer that accepts
// a connection and then says nothing does not hold the loop up.
func (n *Node) settleWithin(
	ctx context.Context, pending *storepb.PendingPairing,
) (*ladulasv1.SettlePairingResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, settleTimeout)
	defer cancel()

	return n.callSettle(ctx, pending, "")
}

// shouldSettle paces the reconciliation. A peer with no address is never
// dialled at all: it is a phone, and the phone is the side that dials.
func (n *Node) shouldSettle(pending *storepb.PendingPairing) bool {
	if len(pending.GetAddresses()) == 0 {
		return false
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	last, seen := n.attempted[pending.GetSessionId()]
	if seen && time.Since(last) < n.retry {
		return false
	}

	n.attempted[pending.GetSessionId()] = time.Now()

	return true
}

// raisePrompt puts a pending pairing's confirmation in front of whoever can
// answer here, and does nothing at all when nobody can.
//
// Nothing being able to answer is an ordinary state — a headless box with no
// command running, a phone that is shut — and the old behaviour of asking
// anyway was what turned it into a denial. The entry stays where it is and the
// loop tries again, so an approver that appears an hour later gets the card.
func (n *Node) raisePrompt(pending *storepb.PendingPairing) {
	if !n.engine.HasLocalApprover() {
		return
	}

	session := pending.GetSessionId()

	n.mu.Lock()

	ctx := n.ctx
	_, raised := n.prompts[session]

	if ctx == nil || raised {
		n.mu.Unlock()

		return
	}

	promptCtx, cancel := context.WithCancel(ctx)
	n.prompts[session] = cancel

	n.mu.Unlock()

	go n.runPrompt(promptCtx, cancel, pending)
}

func (n *Node) runPrompt(
	ctx context.Context, cancel context.CancelFunc,
	pending *storepb.PendingPairing,
) {
	session := pending.GetSessionId()

	defer func() {
		cancel()

		n.mu.Lock()
		delete(n.prompts, session)
		n.mu.Unlock()
	}()

	msg := n.pendingConfirmation(pending)

	if err := n.noteConfirmation(session, msg.GetRequestId()); err != nil {
		n.log.Warn("could not record which prompt a pairing raised",
			"session", session, "error", err.Error())
	}

	resp, err := n.confirm(ctx, msg)
	if err != nil {
		n.log.Debug("a pairing confirmation could not be shown",
			"session", session, "error", err.Error())

		return
	}

	// Only a person's answer is an answer. Everything else the engine can
	// return here — nobody was there, the prompt was cancelled, the request was
	// withdrawn — leaves the pairing exactly where it was, which is the whole
	// point of writing it down.
	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_USER {
		n.log.Debug("a pairing confirmation ended without an answer",
			"session", session, "reason", resp.GetReason())

		return
	}

	accepted := resp.GetDecision() == ladulasv1.Decision_DECISION_APPROVE

	if _, _, _, err := n.AnswerPending(
		session, accepted, resp.GetReason()); err != nil &&
		!errors.Is(err, ErrPairingAnswered) &&
		!errors.Is(err, ErrNoPendingPairing) {
		n.log.Error("could not record a pairing answer",
			"session", session, "error", err.Error())
	}
}

// noteConfirmation records which prompt a pairing raised.
//
// It reads the entry and writes the copy it was given rather than writing into
// the message the prompt was raised from, and the two reasons are the same
// reason twice. The message belongs to whoever handed it over: `ladulas pair`
// is still holding the one it got back, the phone renders it, and a listing
// hands one to a loop that goes on reading it — none of which takes a lock, so
// a write from this goroutine is a race. And the entry may have moved on since
// that message was made, so writing it back whole would put a stale answer
// where a fresh one is.
func (n *Node) noteConfirmation(session, requestID string) error {
	n.pairingMu.Lock()
	defer n.pairingMu.Unlock()

	pending, ok := n.trust.PendingPairing(session)
	if !ok {
		// Answered, withdrawn or completed while the card was going up, which
		// is an ordinary thing for a pairing to do and nothing to record.
		return nil
	}

	pending.ConfirmationRequestId = requestID

	return n.trust.PutPendingPairing(pending)
}

func (n *Node) cancelPrompt(session string) {
	n.mu.Lock()
	cancel := n.prompts[session]
	delete(n.attempted, session)
	n.mu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// watchPairing registers interest in how a session ends, for a command that is
// following one.
func (n *Node) watchPairing(session string) chan pairingEvent {
	// Buffered, and written to without blocking: a watcher that has gone away
	// must not be able to hold up the state machine.
	events := make(chan pairingEvent, 4)

	n.mu.Lock()
	defer n.mu.Unlock()

	n.watchers[session] = append(n.watchers[session], events)

	return events
}

func (n *Node) unwatchPairing(session string, events chan pairingEvent) {
	n.mu.Lock()
	defer n.mu.Unlock()

	kept := n.watchers[session][:0]

	for _, existing := range n.watchers[session] {
		if existing != events {
			kept = append(kept, existing)
		}
	}

	if len(kept) == 0 {
		delete(n.watchers, session)

		return
	}

	n.watchers[session] = kept
}

func (n *Node) notifyPairing(session string, event pairingEvent) {
	n.mu.Lock()
	watchers := append([]chan pairingEvent(nil), n.watchers[session]...)
	n.mu.Unlock()

	for _, events := range watchers {
		select {
		case events <- event:
		default:
		}
	}
}
