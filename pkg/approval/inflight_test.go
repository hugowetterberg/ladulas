package approval_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Joining a request that is already waiting (decision AL).
//
// The engine used to settle the set of approvers when it fanned a request out,
// so the answer to "a signature is blocking my terminal, let me open something
// that can answer it" was that you had to have opened it first. What these
// check is that a late arrival is asked, that it cannot be asked about
// something that is over, and — the part worth being careful about — that the
// tally the NO_APPROVER denial is counted against moves with it. Decision AC is
// the bug that lived in that arithmetic.

// waitingHandler blocks until it is told what to answer, so that a test can
// hold a request in flight and do something else while it waits.
type waitingHandler struct {
	id string

	mu      sync.Mutex
	asked   int
	release chan *approval.Answer
	fail    chan error
}

func newWaitingHandler(id string) *waitingHandler {
	return &waitingHandler{
		id:      id,
		release: make(chan *approval.Answer, 1),
		fail:    make(chan error, 1),
	}
}

func (h *waitingHandler) ID() string {
	return h.id
}

func (h *waitingHandler) Decide(
	ctx context.Context, _ *approval.Request,
) (*approval.Answer, error) {
	h.mu.Lock()
	h.asked++
	h.mu.Unlock()

	select {
	case answer := <-h.release:
		return answer, nil
	case err := <-h.fail:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *waitingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.asked
}

// waitUntilAsked blocks until the handler has been put in front of a request,
// so a test does not race the goroutine the engine spawned.
func (h *waitingHandler) waitUntilAsked(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)

	for h.count() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%s was never asked", h.id)
		}

		time.Sleep(time.Millisecond)
	}
}

// localWaiting is a waitingHandler that draws on a screen at this instance,
// which is what a soft lock takes away.
type localWaiting struct {
	*waitingHandler
}

var _ approval.LocalPrompt = (*localWaiting)(nil)

func (h *localWaiting) LocalPrompt() {
}

// waitForWaiting blocks until the engine reports the expected number of
// requests out with approvers.
func waitForWaiting(t *testing.T, engine *approval.Engine, want int) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)

	for engine.Waiting() != want {
		if time.Now().After(deadline) {
			t.Fatalf("%d requests are waiting, want %d", engine.Waiting(), want)
		}

		time.Sleep(time.Millisecond)
	}
}

// TestAnApproverThatArrivesLateIsAskedAndCanAnswer: the whole point. A terminal
// started while a signature is blocking somebody's shell is asked about it and
// settles it, rather than showing an empty screen until the budget runs out.
func TestAnApproverThatArrivesLateIsAskedAndCanAnswer(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	first := newWaitingHandler("desktop")
	f.engine.Register(first)

	decided := make(chan *ladulasv1.ApprovalResponse, 1)

	go func() {
		resp, err := f.engine.Submit(context.Background(), gitSignRequest())
		if err != nil {
			decided <- nil

			return
		}

		decided <- resp
	}()

	first.waitUntilAsked(t)
	waitForWaiting(t, f.engine, 1)

	// The terminal, started after the request was raised.
	late := newWaitingHandler("terminal")
	f.engine.Register(late)
	late.waitUntilAsked(t)

	// No reason of its own, so the engine falls back to naming the approver —
	// which is the half of the log a read later cannot work out for itself.
	late.release <- &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
	}

	resp := <-decided
	if resp == nil {
		t.Fatal("the request ended in an error")
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Errorf("decision %v, want an approval", resp.GetDecision())
	}

	if !strings.Contains(resp.GetReason(), "terminal") {
		t.Errorf("the decision reads %q, and does not name who gave it",
			resp.GetReason())
	}
}

// TestALateApproverCountsTowardsTheNoApproverTally: the arithmetic. A request
// whose only approver has gone is denied — unless somebody arrived in the
// meantime, in which case denying it would be refusing a question at the moment
// somebody turned up to answer it, which is the shape decision AC's bug had.
func TestALateApproverCountsTowardsTheNoApproverTally(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	first := newWaitingHandler("desktop")
	f.engine.Register(first)

	decided := make(chan *ladulasv1.ApprovalResponse, 1)

	go func() {
		resp, err := f.engine.Submit(context.Background(), gitSignRequest())
		if err != nil {
			decided <- nil

			return
		}

		decided <- resp
	}()

	first.waitUntilAsked(t)
	waitForWaiting(t, f.engine, 1)

	late := newWaitingHandler("terminal")
	f.engine.Register(late)
	late.waitUntilAsked(t)

	// The first approver goes away. One of two has failed, so nothing is
	// settled: the request is still a question somebody can answer.
	first.fail <- errors.New("the stream dropped")

	select {
	case resp := <-decided:
		t.Fatalf("the request was settled as %v while an approver was still there",
			resp.GetDecision())
	case <-time.After(150 * time.Millisecond):
	}

	// And when the second goes too, it is denied — with the reason that says
	// nobody was reachable rather than that somebody refused.
	late.fail <- errors.New("the terminal was closed")

	resp := <-decided
	if resp == nil {
		t.Fatal("the request ended in an error")
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER {
		t.Errorf("source %v, want no-approver", resp.GetSource())
	}
}

// TestALateApproverIsNotAskedAboutASettledRequest: a card for a question that
// is over is worse than no card, because somebody would answer it.
func TestALateApproverIsNotAskedAboutASettledRequest(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	first := newWaitingHandler("desktop")
	f.engine.Register(first)

	decided := make(chan *ladulasv1.ApprovalResponse, 1)

	go func() {
		resp, err := f.engine.Submit(context.Background(), gitSignRequest())
		if err != nil {
			decided <- nil

			return
		}

		decided <- resp
	}()

	first.waitUntilAsked(t)
	first.release <- approveAnswer()

	if resp := <-decided; resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("decision %v", resp.GetDecision())
	}

	waitForWaiting(t, f.engine, 0)

	late := newWaitingHandler("terminal")
	f.engine.Register(late)

	// Nothing to be asked about, so nothing is asked. Given a moment, because
	// the failure being guarded against is a goroutine that would have raised a
	// prompt.
	time.Sleep(50 * time.Millisecond)

	if late.count() != 0 {
		t.Errorf("a settled request was put in front of a late approver %d times",
			late.count())
	}
}

// TestALateApproverInheritsTheRequestsDeadline: the budget belongs to the
// request (§9). An approver that restarted the clock by attaching would be an
// approver who could hold somebody's terminal open by opening a window.
func TestALateApproverInheritsTheRequestsDeadline(t *testing.T) {
	f := newEngine(t, approval.NewPolicy(&ladulasv1.PolicyDocument{
		Defaults: &ladulasv1.Defaults{
			SignTimeout: durationProto(250 * time.Millisecond),
		},
	}))

	first := newWaitingHandler("desktop")
	f.engine.Register(first)

	started := time.Now()
	decided := make(chan *ladulasv1.ApprovalResponse, 1)

	go func() {
		resp, err := f.engine.Submit(context.Background(), gitSignRequest())
		if err != nil {
			decided <- nil

			return
		}

		decided <- resp
	}()

	first.waitUntilAsked(t)

	late := newWaitingHandler("terminal")
	f.engine.Register(late)
	late.waitUntilAsked(t)

	resp := <-decided
	if resp == nil {
		t.Fatal("the request ended in an error")
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_TIMEOUT {
		t.Errorf("source %v, want a timeout", resp.GetSource())
	}

	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("the request waited %s, so attaching moved its deadline", elapsed)
	}
}

// TestASoftLockKeepsALocalPromptOutOfARequestAlreadyWaiting, and lifting it
// lets that prompt in: the soft lock is the claim that nobody is sitting here
// (§10), and it has to mean the same thing for a request that arrived a minute
// ago as for one arriving now.
func TestASoftLockKeepsALocalPromptOutOfARequestAlreadyWaiting(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	// A peer keeps the request alive while the screen here is suspended;
	// without one there would be no eligible approver and nothing to join.
	peer := &remoteStub{stubHandler: stubHandler{id: "phone"}}
	peer.delay = 5 * time.Second
	f.engine.Register(peer)

	f.engine.SuspendLocalPrompts(true)

	decided := make(chan *ladulasv1.ApprovalResponse, 1)

	go func() {
		resp, err := f.engine.Submit(context.Background(), gitSignRequest())
		if err != nil {
			decided <- nil

			return
		}

		decided <- resp
	}()

	waitForWaiting(t, f.engine, 1)

	here := &localWaiting{newWaitingHandler("gui")}
	f.engine.Register(here)

	time.Sleep(50 * time.Millisecond)

	if here.count() != 0 {
		t.Fatal("a locked instance put a waiting request on its own screen")
	}

	// Unlocking is the same event as an approver registering, so what was
	// waiting is offered now.
	f.engine.SuspendLocalPrompts(false)
	here.waitUntilAsked(t)

	here.release <- approveAnswer()

	resp := <-decided
	if resp == nil {
		t.Fatal("the request ended in an error")
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Errorf("decision %v, want an approval", resp.GetDecision())
	}
}

// TestARequestFromAPeerIsNotOfferedToAnotherPeer: passing one on would make
// this instance a relay for somebody else's decision, and that rule cannot have
// a hole in it for approvers that arrive late.
func TestARequestFromAPeerIsNotOfferedToAnotherPeer(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	here := &localWaiting{newWaitingHandler("gui")}
	f.engine.Register(here)

	decided := make(chan *ladulasv1.ApprovalResponse, 1)

	msg := gitSignRequest()

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal the request: %v", err)
	}

	go func() {
		resp, _, err := f.engine.SubmitPeerSigning(
			context.Background(), msg, body)
		if err != nil {
			decided <- nil

			return
		}

		decided <- resp
	}()

	here.waitUntilAsked(t)
	waitForWaiting(t, f.engine, 1)

	another := &remoteStub{stubHandler: stubHandler{
		id: "phone", answer: approveAnswer(),
	}}
	f.engine.Register(another)

	time.Sleep(50 * time.Millisecond)

	if another.promptCount() != 0 {
		t.Error("a request from a peer was offered to another peer")
	}

	here.release <- approveAnswer()

	if resp := <-decided; resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Errorf("decision %v", resp.GetDecision())
	}
}

// TestAnApproverIsNotAskedTwiceAboutOneRequest: registering is what offers, and
// a handler already in the fan-out is one that is already looking at it.
func TestAnApproverIsNotAskedTwiceAboutOneRequest(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	only := newWaitingHandler("desktop")
	remove := f.engine.Register(only)

	decided := make(chan *ladulasv1.ApprovalResponse, 1)

	go func() {
		resp, err := f.engine.Submit(context.Background(), gitSignRequest())
		if err != nil {
			decided <- nil

			return
		}

		decided <- resp
	}()

	only.waitUntilAsked(t)

	// Registering the same handler again is not a second approver.
	f.engine.Register(only)

	time.Sleep(50 * time.Millisecond)

	if only.count() != 1 {
		t.Errorf("the same approver was asked %d times", only.count())
	}

	remove()

	only.release <- approveAnswer()
	<-decided
}
