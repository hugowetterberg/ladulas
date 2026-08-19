package approval_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// memoryDelegations is a requester's store of what it has been given.
type memoryDelegations struct {
	mu   sync.Mutex
	held []*ladulasv1.Delegation
	uses []*ladulasv1.GrantUse
}

func (m *memoryDelegations) UsableDelegations() ([]*ladulasv1.Delegation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.held, nil
}

func (m *memoryDelegations) RecordDelegationUse(use *ladulasv1.GrantUse) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.uses = append(m.uses, use)

	return nil
}

func (m *memoryDelegations) recorded() []*ladulasv1.GrantUse {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]*ladulasv1.GrantUse(nil), m.uses...)
}

// newDelegatedEngine builds an instance that keeps grants, and holds whatever
// delegations the test hands it.
//
// It takes no "does it hold the key" any more: what decides whether a promise
// is handed over is which door the request came through, so a test says that by
// choosing between Submit, SubmitPeer and SubmitPeerSigning (decision P).
func newDelegatedEngine(
	t *testing.T, delegations approval.DelegationStore,
) (*approval.Engine, *identity.Identity, *memoryGrants) {
	t.Helper()

	id, _, err := identity.Generate("test-instance")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	log, err := approval.OpenAuditLog(t.TempDir() + "/audit.jsonl")
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
		Identity:    id,
		Policy:      approval.DefaultPolicy(),
		Grants:      grants,
		Delegations: delegations,
		Audit:       log,
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	return engine, id, grants
}

// A TTL over a key the requester holds itself is handed over rather than kept:
// that is the whole of decision P, and it is what makes "approve for an hour"
// mean an hour rather than an hour of the approver being awake.
func TestApproverDelegatesAGrantOverTheRequestersOwnKey(t *testing.T) {
	// The peer asked only for a decision, which is a peer that holds the key
	// and will sign with it itself.
	engine, id, grants := newDelegatedEngine(t, nil)

	engine.Register(&stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		Reason:   "approved for 1 hour",
		GrantTTL: time.Hour,
	}})

	msg := sshAuthRequest("bastion.example.net", "hugo", true, false)
	msg.Requester = &ladulasv1.RequesterInfo{
		InstanceId: "SHA256:the-requester",
		Name:       "guppy",
	}

	resp, _, err := engine.SubmitPeer(context.Background(), msg, nil)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	signed := resp.GetDelegation()
	if signed == nil {
		t.Fatal("the approver kept the promise instead of handing it over")
	}

	d, _, err := identity.VerifyDelegation(signed)
	if err != nil {
		t.Fatalf("the delegation does not verify: %v", err)
	}

	if d.GetRequesterFingerprint() != "SHA256:the-requester" {
		t.Errorf("the delegation is addressed to %q", d.GetRequesterFingerprint())
	}

	if d.GetApproverFingerprint() != id.Fingerprint() {
		t.Errorf("the delegation names approver %q", d.GetApproverFingerprint())
	}

	if !strings.Contains(d.GetDescription(), "bastion.example.net") {
		t.Errorf("the delegation describes itself as %q", d.GetDescription())
	}

	// The approver keeps a record of it, or it could never be listed or taken
	// back. The two halves share an identifier, because they are one promise.
	kept, err := grants.Grants()
	if err != nil {
		t.Fatalf("read the grants: %v", err)
	}

	if len(kept) != 1 {
		t.Fatalf("the approver kept %d records of what it promised", len(kept))
	}

	if !kept[0].GetDelegated() {
		t.Error("the record does not say the promise was handed over")
	}

	if kept[0].GetGrantId() != d.GetDelegationId() {
		t.Errorf("the two halves have different identifiers: %q and %q",
			kept[0].GetGrantId(), d.GetDelegationId())
	}

	if kept[0].GetDelegateFingerprint() != "SHA256:the-requester" {
		t.Errorf("the record says it was handed to %q",
			kept[0].GetDelegateFingerprint())
	}
}

// A key the requester is borrowing cannot be delegated and is not. The private
// half never moves, so the requester has to come back for every signature
// whatever anybody decided — and on a phone the hardware demands presence per
// signature regardless.
//
// The request arrives through the signing door, which is what says so: it
// carried the bytes because the machine that sent them has no copy to sign
// with (decision T).
func TestApproverKeepsAGrantOverAKeyItSignsWith(t *testing.T) {
	engine, _, grants := newDelegatedEngine(t, nil)

	engine.Register(&stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		Reason:   "approved for 1 hour",
		GrantTTL: time.Hour,
	}})

	msg := sshAuthRequest("bastion.example.net", "hugo", true, false)
	msg.Requester = &ladulasv1.RequesterInfo{
		InstanceId: "SHA256:the-requester",
		Name:       "guppy",
	}

	resp, _, err := engine.SubmitPeerSigning(context.Background(), msg, nil)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDelegation() != nil {
		t.Fatal("a promise about a key held here was handed over")
	}

	if resp.GetGrant() == nil {
		t.Fatal("no grant was kept either")
	}

	if resp.GetGrant().GetDelegated() {
		t.Error("a grant kept here is marked as delegated")
	}

	kept, err := grants.Grants()
	if err != nil {
		t.Fatalf("read the grants: %v", err)
	}

	if len(kept) != 1 {
		t.Errorf("the approver kept %d grants", len(kept))
	}
}

// A key both machines hold is the requester's for this purpose, and a promise
// about it is handed over.
//
// This is the case that was wrong until 2026-08-13: the test used to be whether
// the approver held the key, as a stand-in for whether the requester did, and a
// portable key handed from a phone to a laptop (decision S) is held by both. So
// the phone kept every promise it made about it, and the laptop went on waking
// the phone for permission to use a key that was already in its own store — a
// grant that answered from the phone, per signature, with the phone's screen
// lighting up each time.
func TestAPromiseAboutAKeyBothHoldIsHandedOver(t *testing.T) {
	engine, _, _ := newDelegatedEngine(t, nil)

	engine.Register(&stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL: time.Hour,
	}})

	msg := sshAuthRequest("bastion.example.net", "hugo", true, false)
	msg.Requester = &ladulasv1.RequesterInfo{
		InstanceId: "SHA256:the-requester",
		Name:       "guppy",
	}

	// The approver holds this key too — it is the machine the copy came from —
	// and asks for a decision rather than a signature, because it has its own.
	resp, _, err := engine.SubmitPeer(context.Background(), msg, nil)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDelegation() == nil {
		t.Fatal("the promise stayed with the approver")
	}
}

// A request that started on this machine has no peer to delegate to, so the
// promise stays where it always was.
func TestALocalRequestNeverDelegates(t *testing.T) {
	engine, _, _ := newDelegatedEngine(t, nil)

	engine.Register(&stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL: time.Hour,
	}})

	resp, err := engine.Submit(context.Background(),
		sshAuthRequest("bastion.example.net", "hugo", true, false))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDelegation() != nil {
		t.Fatal("a local request produced a delegation")
	}

	if resp.GetGrant() == nil {
		t.Fatal("a local request produced no grant either")
	}
}

// The requester's half: a delegation answers a matching request with nobody
// asked, and the use is written down for the account it owes.
func TestADelegationAnswersWithoutAsking(t *testing.T) {
	approver, _, err := identity.Generate("phone")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	store := &memoryDelegations{}

	engine, requester, _ := newDelegatedEngine(t, store)

	// What the approver would have handed over for this request.
	msg := sshAuthRequest("bastion.example.net", "hugo", true, false)

	store.held = []*ladulasv1.Delegation{delegationFor(
		t, approver, requester.Fingerprint(), msg, time.Hour)}

	handler := &stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
	}}

	engine.Register(handler)

	resp, err := engine.Submit(context.Background(),
		sshAuthRequest("bastion.example.net", "hugo", true, false))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("the delegation did not answer: %v", resp.GetDecision())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		t.Errorf("source %v, want GRANT", resp.GetSource())
	}

	if handler.promptCount() != 0 {
		t.Errorf("somebody was asked %d times", handler.promptCount())
	}

	// Silent auto-approval is how approval fatigue turns into an unnoticed
	// compromise, so a delegation that answers still says it did (§9).
	if handler.notifyCount() != 1 {
		t.Errorf("the delegation raised %d notifications, want 1",
			handler.notifyCount())
	}

	uses := store.recorded()

	if len(uses) != 1 {
		t.Fatalf("%d uses were written down, want 1", len(uses))
	}

	if uses[0].GetGrantId() == "" {
		t.Error("the use does not say which promise it was under")
	}

	if uses[0].GetRequestId() != resp.GetRequestId() {
		t.Errorf("the use names request %q", uses[0].GetRequestId())
	}
}

// A promise widened to the machine is handed over widened (decision V). The two
// halves of decision P have to mean the same thing: an approver that said "any
// session on guppy" and then delegated the narrow version would have promised
// one thing and signed another.
func TestADelegationCarriesTheReachItWasGiven(t *testing.T) {
	engine, _, _ := newDelegatedEngine(t, nil)

	engine.Register(&stubHandler{id: "gui", answer: &approval.Answer{
		Decision:   ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL:   time.Hour,
		GrantReach: approval.GrantReachMachine,
	}})

	msg := fromSession(
		sshAuthRequest("bastion.example.net", "hugo", true, false),
		46836, "/usr/bin/emacs", "")
	msg.Requester = &ladulasv1.RequesterInfo{
		InstanceId: "SHA256:the-requester",
		Name:       "guppy",
		Process:    msg.GetRequester().GetProcess(),
	}

	resp, _, err := engine.SubmitPeer(context.Background(), msg, nil)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	signed := resp.GetDelegation()
	if signed == nil {
		t.Fatal("the approver kept the promise instead of handing it over")
	}

	d, _, err := identity.VerifyDelegation(signed)
	if err != nil {
		t.Fatalf("the delegation does not verify: %v", err)
	}

	if d.GetScope().GetSessionId() != 0 {
		t.Errorf("the handed-over promise kept a session: %+v", d.GetScope())
	}

	if !strings.Contains(d.GetDescription(), "anywhere on guppy") {
		t.Errorf("the delegation describes itself as %q", d.GetDescription())
	}
}

// Extending a promise that was handed over means re-signing it and getting it
// to the machine holding it — and the record here is amended only once that has
// happened (decision V).
//
// The order is the mirror of revoking's. An undelivered revocation leaves
// somebody signing who should have stopped; an undelivered extension would
// leave this list promising more than the machine acting on it will do. Both
// are a list that lies, and the order is what stops each.
func TestExtendingAHandedOverPromiseHasToReachItsHolder(t *testing.T) {
	engine, _, grants := newDelegatedEngine(t, nil)

	engine.Register(&stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		GrantTTL: 15 * time.Minute,
	}})

	msg := sshAuthRequest("bastion.example.net", "hugo", true, false)
	msg.Requester = &ladulasv1.RequesterInfo{
		InstanceId: "SHA256:the-requester",
		Name:       "guppy",
	}

	resp, _, err := engine.SubmitPeer(context.Background(), msg, nil)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	id := resp.GetGrant().GetGrantId()
	was := resp.GetGrant().GetExpiresAt().AsTime()

	// With no way to reach the holder, there is no extending it.
	if _, err := engine.ExtendGrant(
		context.Background(), id, 2*time.Hour); err == nil {
		t.Error("a promise was extended with no way to hand it over")
	}

	kept, _ := grants.Grants()
	if len(kept) != 1 || kept[0].GetExpiresAt().AsTime() != was {
		t.Fatal("the record was amended anyway")
	}

	// With one, the holder gets the promise re-signed under the same
	// identifier, and only then does the record here move.
	var handed *ladulasv1.SignedDelegation

	engine.RenewDelegations(func(
		_ context.Context, holder string, signed *ladulasv1.SignedDelegation,
	) error {
		if holder != "SHA256:the-requester" {
			t.Errorf("the promise was handed to %q", holder)
		}

		handed = signed

		return nil
	})

	amended, err := engine.ExtendGrant(context.Background(), id, 2*time.Hour)
	if err != nil {
		t.Fatalf("extend: %v", err)
	}

	if handed == nil {
		t.Fatal("nothing was handed over")
	}

	d, _, err := identity.VerifyDelegation(handed)
	if err != nil {
		t.Fatalf("the re-issued delegation does not verify: %v", err)
	}

	if d.GetDelegationId() != id {
		t.Errorf("the re-issued promise has a new identifier: %q",
			d.GetDelegationId())
	}

	if !d.GetExpiresAt().AsTime().Equal(amended.GetExpiresAt().AsTime()) {
		t.Errorf("the artifact runs to %s and the record to %s",
			d.GetExpiresAt().AsTime(), amended.GetExpiresAt().AsTime())
	}

	if !strings.Contains(d.GetDescription(), "2 hours") {
		t.Errorf("the re-issued promise reads %q", d.GetDescription())
	}
}

// The scope is matched exactly as an approver-side grant's is. A delegation for
// one destination is not a delegation for another, which is what keeps the
// programs at the agent socket gated by the promise that was actually made.
func TestADelegationIsScoped(t *testing.T) {
	approver, _, err := identity.Generate("phone")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	store := &memoryDelegations{}

	engine, requester, _ := newDelegatedEngine(t, store)

	store.held = []*ladulasv1.Delegation{delegationFor(
		t, approver, requester.Fingerprint(),
		sshAuthRequest("bastion.example.net", "hugo", true, false), time.Hour)}

	handler := &stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
	}}

	engine.Register(handler)

	if _, err := engine.Submit(context.Background(),
		sshAuthRequest("other.example.net", "hugo", true, false)); err != nil {
		t.Fatalf("submit: %v", err)
	}

	if handler.promptCount() != 1 {
		t.Errorf("a different destination was answered by the delegation")
	}
}

// An expired delegation answers nothing. The expiry is what bounds the whole
// arrangement — revocation is best-effort by design, and this is not.
func TestAnExpiredDelegationAnswersNothing(t *testing.T) {
	approver, _, err := identity.Generate("phone")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	store := &memoryDelegations{}

	engine, requester, _ := newDelegatedEngine(t, store)

	store.held = []*ladulasv1.Delegation{delegationFor(
		t, approver, requester.Fingerprint(),
		sshAuthRequest("bastion.example.net", "hugo", true, false),
		-time.Minute)}

	handler := &stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
	}}

	engine.Register(handler)

	if _, err := engine.Submit(context.Background(),
		sshAuthRequest("bastion.example.net", "hugo", true, false)); err != nil {
		t.Fatalf("submit: %v", err)
	}

	if handler.promptCount() != 1 {
		t.Error("an expired delegation answered a request")
	}

	if len(store.recorded()) != 0 {
		t.Error("an expired delegation was recorded as used")
	}
}

// A request that arrived from a peer is that peer's to answer. Applying a
// permission granted to this instance would be lending out a promise that was
// never made about the machine asking.
func TestADelegationDoesNotAnswerForAPeer(t *testing.T) {
	approver, _, err := identity.Generate("phone")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	store := &memoryDelegations{}

	engine, requester, _ := newDelegatedEngine(t, store)

	msg := sshAuthRequest("bastion.example.net", "hugo", true, false)

	store.held = []*ladulasv1.Delegation{delegationFor(
		t, approver, requester.Fingerprint(), msg, time.Hour)}

	handler := &stubHandler{id: "gui", answer: &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
	}}

	engine.Register(handler)

	fromPeer := sshAuthRequest("bastion.example.net", "hugo", true, false)
	fromPeer.Requester = &ladulasv1.RequesterInfo{
		InstanceId: "SHA256:somebody-else",
		Name:       "another-machine",
	}

	if _, _, err := engine.SubmitPeer(
		context.Background(), fromPeer, nil); err != nil {
		t.Fatalf("submit: %v", err)
	}

	if handler.promptCount() != 1 {
		t.Error("a peer's request was answered by this instance's delegation")
	}

	if len(store.recorded()) != 0 {
		t.Error("a peer's request was recorded against this instance's promise")
	}
}

// delegationFor builds and signs what an approver would have handed over for a
// request, so the requester-side tests are exercising the real artifact.
func delegationFor(
	t *testing.T,
	approver *identity.Identity,
	requesterFingerprint string,
	msg *ladulasv1.ApprovalRequest,
	ttl time.Duration,
) *ladulasv1.Delegation {
	t.Helper()

	d := approval.DelegationForTest(approver, msg, requesterFingerprint, ttl)

	if _, err := approver.SignDelegation(d); err != nil {
		t.Fatalf("sign the delegation: %v", err)
	}

	return d
}
