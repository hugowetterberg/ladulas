package approval_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// stubHandler answers with a canned answer after an optional delay.
type stubHandler struct {
	id     string
	answer *approval.Answer
	err    error
	delay  time.Duration
	// shown is the panel this handler claims to have drawn beside the prompt.
	shown *ladulasv1.PresentedProject

	mu       sync.Mutex
	prompts  []approval.Prompt
	requests []*approval.Request
	notified []*ladulasv1.ApprovalResponse
	blocked  bool
}

func (h *stubHandler) ID() string {
	return h.id
}

func (h *stubHandler) Decide(ctx context.Context, req *approval.Request) (*approval.Answer, error) {
	h.mu.Lock()
	h.prompts = append(h.prompts, req.Prompt)
	h.requests = append(h.requests, req)
	h.mu.Unlock()

	if h.shown != nil {
		req.Presented(h.shown)
	}

	if h.delay > 0 {
		select {
		case <-time.After(h.delay):
		case <-ctx.Done():
			h.mu.Lock()
			h.blocked = true
			h.mu.Unlock()

			return nil, ctx.Err()
		}
	}

	if h.err != nil {
		return nil, h.err
	}

	return h.answer, nil
}

func (h *stubHandler) Notify(_ *approval.Request, resp *ladulasv1.ApprovalResponse) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.notified = append(h.notified, resp)
}

// lastRequest is what the approver was actually handed, which is where the
// offer to promise anything lives.
func (h *stubHandler) lastRequest() *approval.Request {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.requests) == 0 {
		return nil
	}

	return h.requests[len(h.requests)-1]
}

func (h *stubHandler) promptCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(h.prompts)
}

func (h *stubHandler) notifyCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(h.notified)
}

func approveAnswer() *approval.Answer {
	return &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		Reason:   "the user said yes",
	}
}

func denyAnswer() *approval.Answer {
	return &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_DENY,
		Reason:   "the user said no",
	}
}

// memoryGrants is a GrantStore that keeps grants in memory.
type memoryGrants struct {
	mu     sync.Mutex
	grants []*ladulasv1.Grant
}

func (m *memoryGrants) Grants() ([]*ladulasv1.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]*ladulasv1.Grant, len(m.grants))
	copy(out, m.grants)

	return out, nil
}

func (m *memoryGrants) AddGrant(g *ladulasv1.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.grants = append(m.grants, g)

	return nil
}

// ReplaceGrant is how a promise gets more time on it: same identifier, same
// ledger, later expiry (decision V).
func (m *memoryGrants) ReplaceGrant(g *ladulasv1.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, existing := range m.grants {
		if existing.GetGrantId() == g.GetGrantId() {
			m.grants[i] = g

			return nil
		}
	}

	return errors.New("no such grant")
}

func (m *memoryGrants) RevokeGrant(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	kept := m.grants[:0]

	for _, g := range m.grants {
		if g.GetGrantId() != id {
			kept = append(kept, g)
		}
	}

	m.grants = kept

	return nil
}

type engineFixture struct {
	engine   *approval.Engine
	identity *identity.Identity
	grants   *memoryGrants
	auditLog string
}

func newEngine(t *testing.T, policy *approval.Policy) *engineFixture {
	t.Helper()

	id, _, err := identity.Generate("test-desktop")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	auditPath := t.TempDir() + "/audit.jsonl"

	log, err := approval.OpenAuditLog(auditPath)
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}

	t.Cleanup(func() {
		if err := log.Close(); err != nil {
			t.Errorf("close audit log: %v", err)
		}
	})

	grants := &memoryGrants{}

	engine, err := approval.New(approval.Options{
		Identity: id,
		Policy:   policy,
		Grants:   grants,
		Audit:    log,
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	return &engineFixture{
		engine:   engine,
		identity: id,
		grants:   grants,
		auditLog: auditPath,
	}
}

func TestEngineDeniesWithoutAnApprover(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	resp, err := f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Errorf("decision %v", resp.GetDecision())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER {
		t.Errorf("source %v", resp.GetSource())
	}
}

// An unclassifiable payload is denied whatever the policy says (§9).
func TestEngineDeniesOpaqueRequestsAgainstAnApprovingPolicy(t *testing.T) {
	f := newEngine(t, approval.NewPolicy(&ladulasv1.PolicyDocument{
		Rules: []*ladulasv1.Rule{
			{Name: "approve everything", Action: ladulasv1.Action_ACTION_APPROVE},
		},
	}))

	handler := &stubHandler{id: "gui", answer: approveAnswer()}
	f.engine.Register(handler)

	req := &ladulasv1.ApprovalRequest{
		Kind: ladulasv1.RequestKind_REQUEST_KIND_OPAQUE_SIGN,
		Key:  &ladulasv1.KeyRef{Fingerprint: "SHA256:workkey"},
		Operation: &ladulasv1.ApprovalRequest_OpaqueSign{
			OpaqueSign: &ladulasv1.OpaqueSignRequest{Reason: "random bytes"},
		},
	}

	resp, err := f.engine.Submit(context.Background(), req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Fatalf("decision %v", resp.GetDecision())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_HARD_RULE {
		t.Errorf("source %v", resp.GetSource())
	}

	if handler.promptCount() != 0 {
		t.Error("a hard denial still went to an approver")
	}
}

// Forwarded requests always prompt, whatever the policy says (§4, §9).
func TestEngineAlwaysPromptsForForwardedRequests(t *testing.T) {
	f := newEngine(t, approval.NewPolicy(&ladulasv1.PolicyDocument{
		Rules: []*ladulasv1.Rule{
			{Name: "approve everything", Action: ladulasv1.Action_ACTION_APPROVE},
		},
	}))

	handler := &stubHandler{id: "gui", answer: approveAnswer()}
	f.engine.Register(handler)

	resp, err := f.engine.Submit(context.Background(),
		sshAuthRequest("bastion.example.net", "hugo", true, true))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("decision %v", resp.GetDecision())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_USER {
		t.Errorf("source %v, want USER — the policy must not have decided this",
			resp.GetSource())
	}

	if handler.promptCount() != 1 {
		t.Fatalf("the approver was prompted %d times", handler.promptCount())
	}

	handler.mu.Lock()
	prompt := handler.prompts[0]
	handler.mu.Unlock()

	if !containsSubstring(prompt.Warnings, "forwarded") {
		t.Errorf("the prompt did not say the request was forwarded: %v", prompt.Warnings)
	}

	if !containsSubstring(prompt.Warnings, "policy would auto-approve") {
		t.Errorf("the prompt did not say the policy was overridden: %v", prompt.Warnings)
	}
}

func TestEngineAutoApprovesAndNotifies(t *testing.T) {
	f := newEngine(t, approval.NewPolicy(&ladulasv1.PolicyDocument{
		Rules: []*ladulasv1.Rule{{
			Name:   "git signing is fine",
			Action: ladulasv1.Action_ACTION_APPROVE,
			Match: &ladulasv1.Match{
				Kinds: []ladulasv1.RequestKind{ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN},
			},
		}},
	}))

	handler := &stubHandler{id: "gui", answer: denyAnswer()}
	f.engine.Register(handler)

	resp, err := f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("decision %v", resp.GetDecision())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_POLICY {
		t.Errorf("source %v", resp.GetSource())
	}

	if handler.promptCount() != 0 {
		t.Error("an auto-approved request still prompted")
	}

	if handler.notifyCount() != 1 {
		t.Errorf("the approver was notified %d times, want 1", handler.notifyCount())
	}
}

func TestEngineDeniesByPolicy(t *testing.T) {
	f := newEngine(t, approval.NewPolicy(&ladulasv1.PolicyDocument{
		Rules: []*ladulasv1.Rule{{
			Name:   "no signing from curl",
			Action: ladulasv1.Action_ACTION_DENY,
			Match:  &ladulasv1.Match{Executables: []string{"/usr/bin/ssh"}},
		}},
	}))

	handler := &stubHandler{id: "gui", answer: approveAnswer()}
	f.engine.Register(handler)

	resp, err := f.engine.Submit(context.Background(),
		sshAuthRequest("host", "hugo", true, false))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Errorf("decision %v", resp.GetDecision())
	}

	if handler.promptCount() != 0 {
		t.Error("a policy denial still prompted")
	}
}

// First response wins, and everyone else is cancelled (§9).
func TestEngineFirstResponseWins(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	fast := &stubHandler{id: "fast", answer: approveAnswer()}
	slow := &stubHandler{id: "slow", answer: denyAnswer(), delay: 5 * time.Second}

	f.engine.Register(fast)
	f.engine.Register(slow)

	start := time.Now()

	resp, err := f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the engine waited %s for the slow approver", elapsed)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Errorf("decision %v", resp.GetDecision())
	}

	// Give the cancelled handler a moment to notice.
	deadline := time.Now().Add(2 * time.Second)

	for time.Now().Before(deadline) {
		slow.mu.Lock()
		blocked := slow.blocked
		slow.mu.Unlock()

		if blocked {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Error("the losing approver was never cancelled")
}

func TestEngineTimesOut(t *testing.T) {
	policy := approval.NewPolicy(&ladulasv1.PolicyDocument{
		Defaults: &ladulasv1.Defaults{
			SignTimeout: durationProto(50 * time.Millisecond),
		},
	})

	f := newEngine(t, policy)
	f.engine.Register(&stubHandler{id: "slow", answer: approveAnswer(), delay: time.Minute})

	resp, err := f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Errorf("decision %v", resp.GetDecision())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_TIMEOUT {
		t.Errorf("source %v", resp.GetSource())
	}
}

// A handler that fails is skipped, not taken as a denial: the point of fan-out
// is that a broken approver does not settle anything.
func TestEngineSkipsFailingApprovers(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	f.engine.Register(&stubHandler{id: "broken", err: errors.New("no display")})
	f.engine.Register(&stubHandler{
		id: "working", answer: approveAnswer(), delay: 20 * time.Millisecond,
	})

	resp, err := f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Errorf("decision %v", resp.GetDecision())
	}
}

func TestEngineUnregister(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	unregister := f.engine.Register(&stubHandler{id: "gui", answer: approveAnswer()})
	unregister()

	resp, err := f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER {
		t.Errorf("source %v", resp.GetSource())
	}
}

func TestEngineGrantCoversLaterRequests(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	handler := &stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		Reason:   "approved for 3 hours",
		GrantTTL: 3 * time.Hour,
	}}

	f.engine.Register(handler)

	first, err := f.engine.Submit(context.Background(),
		sshAuthRequest("bastion.example.net", "hugo", true, false))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if first.GetGrant() == nil {
		t.Fatal("no grant was created")
	}

	if !strings.Contains(first.GetGrant().GetDescription(), "bastion.example.net") {
		t.Errorf("grant description %q", first.GetGrant().GetDescription())
	}

	// The same request again is covered by the grant, with no prompt.
	second, err := f.engine.Submit(context.Background(),
		sshAuthRequest("bastion.example.net", "hugo", true, false))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if second.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		t.Errorf("source %v, want GRANT", second.GetSource())
	}

	if handler.promptCount() != 1 {
		t.Errorf("the approver was prompted %d times, want 1", handler.promptCount())
	}

	if handler.notifyCount() != 1 {
		t.Errorf("the grant did not raise a passive notification")
	}
}

// The promise is made to the session the request came from, and kept there
// (decision U): the same login from another terminal window asks again.
func TestEngineGrantIsScopedToTheSession(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	handler := &stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL: time.Hour,
	}}

	f.engine.Register(handler)

	inEmacs := fromSession(
		sshAuthRequest("bastion.example.net", "hugo", true, false),
		46836, "/usr/bin/emacs", "")

	first, err := f.engine.Submit(context.Background(), inEmacs)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if first.GetGrant() == nil {
		t.Fatal("no grant was created")
	}

	// The button said who it was for, so the record has to say the same thing.
	if !strings.Contains(first.GetGrant().GetDescription(), "emacs") {
		t.Errorf("grant description %q", first.GetGrant().GetDescription())
	}

	again, err := f.engine.Submit(context.Background(), fromSession(
		sshAuthRequest("bastion.example.net", "hugo", true, false),
		46836, "/usr/bin/emacs", ""))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if again.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		t.Errorf("the same session was asked again: %v", again.GetSource())
	}

	// Another terminal window is another session, and is not covered.
	elsewhere, err := f.engine.Submit(context.Background(), fromSession(
		sshAuthRequest("bastion.example.net", "hugo", true, false),
		174776, "/usr/bin/zsh", "/usr/bin/kitty"))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if elsewhere.GetSource() == ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		t.Error("a promise made in one session was spent in another")
	}

	if handler.promptCount() != 2 {
		t.Errorf("the approver was prompted %d times, want 2", handler.promptCount())
	}
}

// The same promise, made to the machine instead (decision V): the approver said
// so, so the next window is covered rather than asked. The wider promise is a
// scope with no session in it, which is the shape a promise made where there was
// no session to name has always had — so what is being tested here is that the
// answer decides it, and not the requester.
func TestEngineGrantCanBeWidenedToTheMachine(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	handler := &stubHandler{id: "gui", answer: &approval.Answer{
		Decision:   ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL:   time.Hour,
		GrantReach: approval.GrantReachMachine,
	}}

	f.engine.Register(handler)

	first, err := f.engine.Submit(context.Background(), fromSession(
		sshAuthRequest("bastion.example.net", "hugo", true, false),
		46836, "/usr/bin/emacs", ""))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if first.GetGrant().GetScope().GetSessionId() != 0 {
		t.Errorf("the promise kept a session: %+v", first.GetGrant().GetScope())
	}

	// The record says who it was made to, and "emacs" is not who that was.
	description := first.GetGrant().GetDescription()

	if !strings.Contains(description, "anywhere on") {
		t.Errorf("grant description %q", description)
	}

	elsewhere, err := f.engine.Submit(context.Background(), fromSession(
		sshAuthRequest("bastion.example.net", "hugo", true, false),
		174776, "/usr/bin/zsh", "/usr/bin/kitty"))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if elsewhere.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		t.Errorf("another window was asked again: %v", elsewhere.GetSource())
	}

	if handler.promptCount() != 1 {
		t.Errorf("the approver was prompted %d times, want 1",
			handler.promptCount())
	}
}

// A promise kept here gets more time by being amended, and nothing else has to
// happen: the machine that asks is coming back here for every signature anyway
// (decision V).
func TestEngineExtendsAGrantItKeeps(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	f.engine.Register(&stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL: 15 * time.Minute,
	}})

	resp, err := f.engine.Submit(context.Background(),
		sshAuthRequest("bastion.example.net", "hugo", true, false))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	id := resp.GetGrant().GetGrantId()
	was := resp.GetGrant().GetExpiresAt().AsTime()

	amended, err := f.engine.ExtendGrant(context.Background(), id, 3*time.Hour)
	if err != nil {
		t.Fatalf("extend: %v", err)
	}

	if !amended.GetExpiresAt().AsTime().After(was) {
		t.Errorf("the promise still runs out at %s", amended.GetExpiresAt().AsTime())
	}

	// The sentence is re-rendered, or the list would go on saying "for 15
	// minutes" about a promise with three hours on it.
	if !strings.Contains(amended.GetDescription(), "3 hours") {
		t.Errorf("the promise still reads %q", amended.GetDescription())
	}

	// One promise, not two: the identifier and the ledger are the same.
	kept, err := f.grants.Grants()
	if err != nil {
		t.Fatalf("read the grants: %v", err)
	}

	if len(kept) != 1 || kept[0].GetGrantId() != id {
		t.Fatalf("the store holds %d promises", len(kept))
	}

	if kept[0].GetUseCount() != resp.GetGrant().GetUseCount() {
		t.Errorf("the account of what it covered changed: %d, was %d",
			kept[0].GetUseCount(), resp.GetGrant().GetUseCount())
	}
}

// The ceiling on making a promise is the ceiling on extending one, in both
// directions: nothing past the longest this instance offers, and nothing under
// a minute, which is a dialled zero.
func TestEngineRefusesAnExtensionPastTheBound(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	f.engine.Register(&stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL: 15 * time.Minute,
	}})

	resp, err := f.engine.Submit(context.Background(),
		sshAuthRequest("bastion.example.net", "hugo", true, false))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	id := resp.GetGrant().GetGrantId()

	for _, extra := range []time.Duration{9 * time.Hour, time.Second} {
		_, err := f.engine.ExtendGrant(context.Background(), id, extra)

		if !errors.Is(err, approval.ErrGrantTooLong) {
			t.Errorf("extending by %s said %v", extra, err)
		}
	}

	// And the promise is untouched by the refusal.
	kept, _ := f.grants.Grants()
	if len(kept) != 1 ||
		kept[0].GetExpiresAt().AsTime() != resp.GetGrant().GetExpiresAt().AsTime() {
		t.Error("a refused extension moved the expiry anyway")
	}
}

// Nothing to extend is one answer, whether the identifier is wrong or the
// promise has already run out: both mean there is nothing there to add to.
func TestEngineExtendsNothingThatIsNotRunning(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	_, err := f.engine.ExtendGrant(context.Background(), "nope", time.Hour)

	if !errors.Is(err, approval.ErrNoSuchGrant) {
		t.Errorf("extending a promise that is not there said %v", err)
	}
}

// A promise made where there is no session to name — a request from a peer that
// runs no local sockets — covers what it always covered. A grant already in a
// store must not change meaning because the code around it grew a field.
func TestEngineGrantWithoutASessionCoversTheInstance(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	handler := &stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL: time.Hour,
	}}

	f.engine.Register(handler)

	if _, err := f.engine.Submit(context.Background(),
		sshAuthRequest("bastion.example.net", "hugo", true, false)); err != nil {
		t.Fatalf("submit: %v", err)
	}

	covered, err := f.engine.Submit(context.Background(), fromSession(
		sshAuthRequest("bastion.example.net", "hugo", true, false),
		46836, "/usr/bin/emacs", ""))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if covered.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		t.Errorf("an unscoped grant did not cover a request: %v", covered.GetSource())
	}
}

// fromSession says which session a request came from, and what the walk up to it
// found: a leader, and the process that created the session when there is one.
func fromSession(
	req *ladulasv1.ApprovalRequest, session int32, leader, creator string,
) *ladulasv1.ApprovalRequest {
	proc := req.GetRequester().GetProcess()
	proc.SessionId = session
	proc.Ancestry = []*ladulasv1.ProcessAncestor{{
		Pid:           session,
		Executable:    leader,
		SessionLeader: true,
	}}

	if creator != "" {
		proc.Ancestry = append(proc.Ancestry, &ladulasv1.ProcessAncestor{
			Pid:            3901,
			Executable:     creator,
			StartedSession: true,
		})
	}

	return req
}

// A grant is scoped, and the scope has to be strict: a different destination,
// user or key is a different request.
func TestEngineGrantScopeIsStrict(t *testing.T) {
	for _, tc := range []struct {
		name string
		next *ladulasv1.ApprovalRequest
	}{
		{
			name: "different destination",
			next: sshAuthRequest("other.example.net", "hugo", true, false),
		},
		{
			name: "different user",
			next: sshAuthRequest("bastion.example.net", "root", true, false),
		},
		{
			name: "unbound",
			next: sshAuthRequest("", "hugo", false, false),
		},
		{
			name: "different kind",
			next: gitSignRequest(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newEngine(t, approval.DefaultPolicy())

			handler := &stubHandler{id: "gui", answer: &approval.Answer{
				Decision: ladulasv1.Decision_DECISION_APPROVE,
				GrantTTL: time.Hour,
			}}

			f.engine.Register(handler)

			if _, err := f.engine.Submit(context.Background(),
				sshAuthRequest("bastion.example.net", "hugo", true, false)); err != nil {
				t.Fatalf("submit: %v", err)
			}

			resp, err := f.engine.Submit(context.Background(), tc.next)
			if err != nil {
				t.Fatalf("submit: %v", err)
			}

			if resp.GetSource() == ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
				t.Error("the grant covered a request outside its scope")
			}

			if handler.promptCount() != 2 {
				t.Errorf("the approver was prompted %d times, want 2",
					handler.promptCount())
			}
		})
	}
}

// A grant is matched on the host proven in the signed payload, not on the label
// the requester attached to it (M2, decision X). A promise made for one host is
// not spent on another that merely wears the same name.
func TestGrantMatchesTheProvenHostNotItsLabel(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	handler := &stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL: time.Hour,
	}}

	f.engine.Register(handler)

	// A promise to log in to the real host, labelled "prod".
	if _, err := f.engine.Submit(context.Background(),
		sshAuthRequest("prod", "hugo", true, false)); err != nil {
		t.Fatalf("submit: %v", err)
	}

	// A login to a different host key, dressed in the very same label.
	impostor := sshAuthRequest("prod", "hugo", true, false)
	impostor.GetSshAuth().GetPayloadDestination().Fingerprint = "SHA256:host-evil"
	impostor.GetSshAuth().GetDestination().Fingerprint = "SHA256:host-evil"

	resp, err := f.engine.Submit(context.Background(), impostor)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetSource() == ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		t.Error("the grant was spent on a different host wearing the same label")
	}

	if handler.promptCount() != 2 {
		t.Errorf("the approver was prompted %d times, want 2", handler.promptCount())
	}
}

// Every decision is signed by the instance identity and lands in the log, which
// is what makes an approval an artifact rather than a message (§18).
func TestEngineWritesSignedAuditEntries(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())
	f.engine.Register(&stubHandler{
		id:     "gui",
		answer: approveAnswer(),
		shown: &ladulasv1.PresentedProject{
			ProjectId: "abcdefghij",
			Name:      "ladulas",
			Note:      "3 pages read here, at abc1234567.",
			Known:     true,
		},
	})

	resp, err := f.engine.Submit(context.Background(),
		sshAuthRequest("bastion.example.net", "hugo", true, false))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	entries, err := approval.ReadAuditLog(f.auditLog, 0)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}

	var decision *ladulasv1.AuditEntry

	for _, entry := range entries {
		if entry.GetEvent() == ladulasv1.AuditEvent_AUDIT_EVENT_DECISION {
			decision = entry
		}
	}

	if decision == nil {
		t.Fatalf("no decision entry in %d audit entries", len(entries))
	}

	if decision.GetRequestId() != resp.GetRequestId() {
		t.Error("the decision entry does not correlate with the response")
	}

	if !strings.Contains(decision.GetPromptShown(), "bastion.example.net") {
		t.Errorf("the log does not record what was shown: %q", decision.GetPromptShown())
	}

	// A host that drew more than the rendered prompt hands the rest back, and
	// the log keeps that too: it is the part of a card nobody can reconstruct
	// later, because it was this instance's own state at the time (§6).
	if decision.GetProjectShown().GetNote() != "3 pages read here, at abc1234567." {
		t.Errorf("the log records the panel as %+v", decision.GetProjectShown())
	}

	signed := decision.GetSignedApproval()
	if signed == nil {
		t.Fatal("the decision was not signed")
	}

	logged, pub, err := identity.VerifyApproval(signed)
	if err != nil {
		t.Fatalf("verify the logged approval: %v", err)
	}

	if pub.Type() != "ssh-ed25519" {
		t.Errorf("unexpected signing key type %s", pub.Type())
	}

	if logged.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Errorf("the logged decision is %v", logged.GetDecision())
	}

	if logged.GetApprover().GetInstanceId() != f.identity.Fingerprint() {
		t.Error("the logged approval names the wrong approver")
	}

	if len(logged.GetRequestDigest()) != 32 {
		t.Error("the logged approval carries no request digest")
	}
}

func TestEngineLogsSignatures(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	req := gitSignRequest()
	req.RequestId = "req-signed"

	f.engine.Signed(req, req.GetKey())

	entries, err := approval.ReadAuditLog(f.auditLog, 0)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}

	if entries[0].GetEvent() != ladulasv1.AuditEvent_AUDIT_EVENT_SIGNATURE {
		t.Errorf("event %v", entries[0].GetEvent())
	}

	if entries[0].GetKeyFingerprint() != req.GetKey().GetFingerprint() {
		t.Errorf("key fingerprint %q", entries[0].GetKeyFingerprint())
	}
}

func TestReadAuditLogLimit(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	for i := range 5 {
		f.engine.LogLifecycle(strings.Repeat("x", i+1))
	}

	entries, err := approval.ReadAuditLog(f.auditLog, 2)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}

	if entries[1].GetDetail() != strings.Repeat("x", 5) {
		t.Errorf("the newest entry is %q", entries[1].GetDetail())
	}
}

func containsSubstring(list []string, needle string) bool {
	for _, s := range list {
		if strings.Contains(s, needle) {
			return true
		}
	}

	return false
}
