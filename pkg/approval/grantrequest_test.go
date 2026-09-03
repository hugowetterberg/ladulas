package approval_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// grantRequestFor builds what `ladulas ssh-grant` sends: the request a login to
// this destination would make, with nothing to sign (decision AO).
//
// It is deliberately built from the same helper the login tests use, because
// that is the property under test — the two have to derive the same scope, and
// a bespoke builder here would be testing that this file agrees with itself.
func grantRequestFor(destination, username string) *ladulasv1.ApprovalRequest {
	req := sshAuthRequest(destination, username, true, false)
	req.RequestId = "grant-req"
	req.GrantOnly = true

	return req
}

// The whole point of connecting to the server first: the promise a grant
// request mints has to cover the login it was asked about, without a second
// prompt. A scope is matched on strict equality, so this is the test that says
// the two paths derive the same one.
func TestGrantRequestCoversTheLoginItWasMadeFor(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	handler := &stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL: time.Hour,
	}}

	f.engine.Register(handler)

	resp, err := f.engine.Submit(context.Background(),
		grantRequestFor("bastion.example.net", "hugo"))
	if err != nil {
		t.Fatalf("submit the grant request: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("the grant request was not approved: %s", resp.GetReason())
	}

	if resp.GetGrant() == nil {
		t.Fatal("approved, but no promise was made")
	}

	// The login it was asked about, arriving the ordinary way.
	login, err := f.engine.Submit(context.Background(),
		sshAuthRequest("bastion.example.net", "hugo", true, false))
	if err != nil {
		t.Fatalf("submit the login: %v", err)
	}

	if login.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		t.Errorf("the login was decided by %s, want the grant to cover it",
			login.GetSource())
	}

	if handler.promptCount() != 1 {
		t.Errorf("the approver was prompted %d times, want 1 — the login "+
			"should have fallen under the promise", handler.promptCount())
	}
}

// The promise is no wider than an ordinary one. A grant request names one host,
// and a login somewhere else is still a question.
func TestGrantRequestDoesNotCoverAnotherHost(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	f.engine.Register(&stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL: time.Hour,
	}})

	if _, err := f.engine.Submit(context.Background(),
		grantRequestFor("bastion.example.net", "hugo")); err != nil {
		t.Fatalf("submit the grant request: %v", err)
	}

	elsewhere, err := f.engine.Submit(context.Background(),
		sshAuthRequest("other.example.net", "hugo", true, false))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if elsewhere.GetSource() == ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		t.Error("a promise about one host covered a login to another")
	}
}

// There is no plain yes to a grant request. Approving without a length would
// settle the card having authorized nothing, and the caller would be told it
// succeeded — so the engine refuses rather than inventing a length.
func TestGrantRequestApprovedWithoutLengthIsRefused(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	f.engine.Register(&stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
	}})

	resp, err := f.engine.Submit(context.Background(),
		grantRequestFor("bastion.example.net", "hugo"))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() == ladulasv1.Decision_DECISION_APPROVE {
		t.Fatal("a grant request was approved with no promise attached")
	}

	if !strings.Contains(resp.GetReason(), "length of time") {
		t.Errorf("the refusal does not say why: %q", resp.GetReason())
	}
}

// A grant request is a local verb. One arriving over the peer channel would be
// a peer naming a host key of its choosing to mint a promise over a key it
// borrows, and it is refused before anybody is asked.
func TestGrantRequestFromAPeerIsRefused(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	handler := &stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL: time.Hour,
	}}

	f.engine.Register(handler)

	resp, _, err := f.engine.SubmitPeer(context.Background(),
		grantRequestFor("bastion.example.net", "hugo"), nil)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() == ladulasv1.Decision_DECISION_APPROVE {
		t.Fatal("a peer minted a promise with a grant request")
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_HARD_RULE {
		t.Errorf("refused by %s, want a hard rule", resp.GetSource())
	}

	if handler.promptCount() != 0 {
		t.Error("somebody was asked about a request that cannot be granted")
	}
}

// The card has to say it is not a login happening now, because the answers
// differ: there is a length or there is nothing.
func TestGrantRequestPromptSaysWhatItIs(t *testing.T) {
	prompt := approval.RenderPrompt(grantRequestFor("bastion.example.net", "hugo"))

	if !strings.Contains(prompt.Title, "Allow SSH logins") {
		t.Errorf("the card reads %q, which does not say it is a promise",
			prompt.Title)
	}

	login := approval.RenderPrompt(
		sshAuthRequest("bastion.example.net", "hugo", true, false))
	if !strings.Contains(login.Title, "SSH login as") {
		t.Errorf("an ordinary login now reads %q", login.Title)
	}
}

// A length the caller asked for is put one tap away, and a length past the
// instance's own bound is dropped rather than clamped — a promise trimmed to
// fit is not the promise anybody asked for.
func TestRequestedLengthJoinsTheOffer(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	handler := &stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL: time.Hour,
	}}

	f.engine.Register(handler)

	req := grantRequestFor("bastion.example.net", "hugo")
	req.RequestedGrantTtl = durationpb.New(42 * time.Minute)

	if _, err := f.engine.Submit(context.Background(), req); err != nil {
		t.Fatalf("submit: %v", err)
	}

	offered := handler.lastRequest().GrantTTLs
	if !containsDuration(offered, 42*time.Minute) {
		t.Errorf("the asked-for length is not on the offer: %v", offered)
	}

	// Past the bound, and therefore not offered at all.
	f2 := newEngine(t, approval.DefaultPolicy())
	handler2 := &stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL: time.Hour,
	}}

	f2.engine.Register(handler2)

	tooLong := grantRequestFor("bastion.example.net", "hugo")
	tooLong.RequestedGrantTtl = durationpb.New(30 * 24 * time.Hour)

	if _, err := f2.engine.Submit(context.Background(), tooLong); err != nil {
		t.Fatalf("submit: %v", err)
	}

	if containsDuration(handler2.lastRequest().GrantTTLs, 30*24*time.Hour) {
		t.Error("a month was offered by an instance that promises hours")
	}
}

func containsDuration(list []time.Duration, want time.Duration) bool {
	for _, d := range list {
		if d == want {
			return true
		}
	}

	return false
}

// Asking again when a promise already covers the login is answered from the
// promise rather than with a second card — but it is not a use of it. Nothing
// was signed, and a ledger counting questions beside signatures is one nobody
// can read a number out of.
func TestAskingAgainIsAnsweredButNotCountedAsAUse(t *testing.T) {
	id, _, err := identity.Generate("test-desktop")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	uses := &recordingUses{}
	handler := &stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL: time.Hour,
	}}

	engine, err := approval.New(approval.Options{
		Identity:  id,
		Policy:    approval.DefaultPolicy(),
		Grants:    &memoryGrants{},
		GrantUses: uses,
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	engine.Register(handler)

	if _, err := engine.Submit(context.Background(),
		grantRequestFor("bastion.example.net", "hugo")); err != nil {
		t.Fatalf("submit: %v", err)
	}

	again, err := engine.Submit(context.Background(),
		grantRequestFor("bastion.example.net", "hugo"))
	if err != nil {
		t.Fatalf("submit again: %v", err)
	}

	if again.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		t.Errorf("asking again was decided by %s, want the existing promise",
			again.GetSource())
	}

	if handler.promptCount() != 1 {
		t.Errorf("the approver was asked %d times, want 1",
			handler.promptCount())
	}

	if got := uses.count(); got != 0 {
		t.Errorf("the promise recorded %d uses, want 0 — nothing was signed", got)
	}

	// A real login under the same promise is a use, which is what says the
	// check above is looking at a counter that moves.
	if _, err := engine.Submit(context.Background(),
		sshAuthRequest("bastion.example.net", "hugo", true, false)); err != nil {
		t.Fatalf("submit the login: %v", err)
	}

	if got := uses.count(); got != 1 {
		t.Errorf("a signature under the promise recorded %d uses, want 1", got)
	}
}

// recordingUses counts what the engine writes down as covered by a promise.
type recordingUses struct {
	mu   sync.Mutex
	uses []*ladulasv1.GrantUse
}

func (r *recordingUses) RecordGrantUses(uses []*ladulasv1.GrantUse) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.uses = append(r.uses, uses...)

	return nil
}

func (r *recordingUses) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.uses)
}

// The same rule on the delegation path, where it matters most: this ledger is
// an account owed to the approver and is reported back to the machine that made
// the promise. A grant request counted here would tell somebody's phone that
// this machine made a signature it never made — and an account that overstates
// what was done under a promise is worse than no account at all.
func TestAGrantRequestIsNotReportedToTheApproverAsAUse(t *testing.T) {
	approver, _, err := identity.Generate("iPhone")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	held := &memoryDelegations{}
	engine, id, _ := newDelegatedEngine(t, held)

	login := sshAuthRequest("github.com", "git", true, false)
	login.GetRequester().InstanceId = id.Fingerprint()

	held.held = append(held.held,
		delegationFor(t, approver, id.Fingerprint(), login, time.Hour))

	// Asking about a login the delegation already covers.
	ask := grantRequestFor("github.com", "git")
	ask.GetRequester().InstanceId = id.Fingerprint()

	resp, err := engine.Submit(context.Background(), ask)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		t.Fatalf("the question was decided by %s, want the delegation",
			resp.GetSource())
	}

	if got := len(held.recorded()); got != 0 {
		t.Errorf("the approver would be told about %d uses, want 0 — nothing "+
			"was signed", got)
	}

	// The login itself is a use, which is what says the counter moves at all.
	real := sshAuthRequest("github.com", "git", true, false)
	real.GetRequester().InstanceId = id.Fingerprint()

	if _, err := engine.Submit(context.Background(), real); err != nil {
		t.Fatalf("submit the login: %v", err)
	}

	if got := len(held.recorded()); got != 1 {
		t.Errorf("a real login recorded %d uses, want 1", got)
	}
}
