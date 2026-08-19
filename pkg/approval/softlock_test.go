package approval_test

import (
	"context"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The soft lock is §10's claim that nobody is sitting here, and nothing more
// than that: the key stays where it is, the promises made while somebody was
// here keep being kept, and the phone can still answer.

// localStub is a stubHandler that says it draws on a screen at this instance,
// which is what a soft lock takes away.
type localStub struct {
	stubHandler
}

var _ approval.LocalPrompt = (*localStub)(nil)

func (h *localStub) LocalPrompt() {
}

func TestSoftLockTakesTheLocalPromptOutOfTheSet(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	here := &localStub{stubHandler{id: "gui", answer: approveAnswer()}}
	f.engine.Register(here)

	f.engine.SuspendLocalPrompts(true)

	resp, err := f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Errorf("decision %v, want a denial", resp.GetDecision())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER {
		t.Errorf("source %v, want no-approver", resp.GetSource())
	}

	if here.promptCount() != 0 {
		t.Error("a locked instance put a request on its own screen")
	}

	if f.engine.HasLocalApprover() {
		t.Error("a locked instance told a peer somebody here could answer")
	}

	// And it comes back.
	f.engine.SuspendLocalPrompts(false)

	resp, err = f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Errorf("decision %v after unlocking", resp.GetDecision())
	}
}

// The whole point of the soft lock rather than a seal: §1's "desktop reached
// over SSH while away from it" has to keep working while the screen is locked.
func TestSoftLockKeepsRemoteApproval(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	here := &localStub{stubHandler{id: "gui", answer: denyAnswer()}}
	phone := &remoteStub{
		stubHandler: stubHandler{id: "phone", answer: approveAnswer()},
		peer:        "SHA256:phone",
	}

	f.engine.Register(here)
	f.engine.Register(phone)
	f.engine.SuspendLocalPrompts(true)

	resp, err := f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Errorf("decision %v, want the phone's approval", resp.GetDecision())
	}

	if here.promptCount() != 0 {
		t.Error("the locked screen was asked as well")
	}

	if phone.promptCount() != 1 {
		t.Errorf("the phone saw the request %d times", phone.promptCount())
	}
}

// A grant is the approver's prior promise, made while unlocked. It still fires
// while locked, and it still says that it did (§9, §10).
func TestSoftLockKeepsGrantsAndTheirNotifications(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	here := &localStub{stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		Reason:   "approved for an hour",
		GrantTTL: time.Hour,
	}}}

	f.engine.Register(here)

	if _, err := f.engine.Submit(context.Background(), gitSignRequest()); err != nil {
		t.Fatalf("submit: %v", err)
	}

	f.engine.SuspendLocalPrompts(true)

	resp, err := f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("decision %v, want the grant to cover it", resp.GetDecision())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		t.Errorf("source %v, want grant", resp.GetSource())
	}

	if here.promptCount() != 1 {
		t.Errorf("the screen was asked %d times, want only the first", here.promptCount())
	}

	if here.notifyCount() != 1 {
		t.Errorf("the spent promise was announced %d times, want 1", here.notifyCount())
	}
}

// A handler that is neither a screen here nor a peer keeps answering: what
// authorizes the pairing command is possession of the unix account, not the
// state of the store (§14).
func TestSoftLockLeavesTheCommandLineAlone(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	command := &stubHandler{id: "pairing command", answer: approveAnswer()}
	f.engine.Register(command)
	f.engine.SuspendLocalPrompts(true)

	resp, err := f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Errorf("decision %v", resp.GetDecision())
	}
}

// The soft lock is flipped from a logind signal while requests are in flight,
// so it is read and written from several goroutines by construction.
func TestSoftLockUnderConcurrency(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	f.engine.Register(&localStub{stubHandler{id: "gui", answer: approveAnswer()}})
	f.engine.Register(&remoteStub{
		stubHandler: stubHandler{id: "phone", answer: approveAnswer()},
		peer:        "SHA256:phone",
	})

	done := make(chan struct{})

	go func() {
		defer close(done)

		for i := range 200 {
			f.engine.SuspendLocalPrompts(i%2 == 0)
			f.engine.HasLocalApprover()
		}
	}()

	for range 40 {
		if _, err := f.engine.Submit(context.Background(), gitSignRequest()); err != nil {
			t.Errorf("submit: %v", err)
		}
	}

	<-done
}
