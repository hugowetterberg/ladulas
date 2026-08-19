// Package approval is the approval engine: policy evaluation, TTL grants,
// fan-out to approvers, and the audit log (docs/architecture.md §9).
//
// There is one engine, and local GUI approval is simply an approver that
// happens to share the process. A remote peer (M3) plugs into the same
// Handler interface, and the fan-out that picks the first answer is already
// the shape that "first response wins" needs.
package approval

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/gitctx"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Request is what an approver is shown: the request itself, the rendered
// prompt, and the grant options the policy offers.
type Request struct {
	Msg    *ladulasv1.ApprovalRequest
	Prompt Prompt
	// GrantTTLs are the lengths worth one tap. They are suggestions rather than
	// the whole of what may be agreed to (decision V): the length itself is
	// chosen, and GrantMaxTTL is as far as it may go.
	GrantTTLs []time.Duration
	// GrantMaxTTL is the longest promise this instance will make.
	GrantMaxTTL time.Duration
	// GrantSubject is who a session-wide promise would be made to, worded for a
	// button: "emacs", or "this kitty window" (decision U). Empty when the
	// request names no session, and then there is only one promise to make and
	// it covers the requesting instance as it always did.
	GrantSubject string
	// GrantMachine is who a machine-wide promise would be made to: the name of
	// the machine that asked (decision V).
	GrantMachine string
	// Origin says where the request came from, which decides who may be asked
	// about it.
	Origin Origin
	// Body is the exact serialization the digest of this request covers. A
	// handler that sends the request somewhere else sends these bytes, so that
	// the digest in the answer it gets back is over material both ends had.
	Body []byte

	// shown is what the host that drew the card added to the prompt this
	// package rendered. See Presented.
	shownMu sync.Mutex
	shown   *ladulasv1.PresentedProject
}

// Presented is a host telling the log what it put on screen beyond the rendered
// prompt (§9, §18).
//
// The engine renders the prompt and can therefore record it, which is most of
// what the promise "the log says what was actually shown" needs. The rest is
// the documentation panel: it is drawn out of this instance's own state — the
// pages it holds of the requester's project and the commit they were read at —
// which the engine does not have and which will not be the same state later.
// So the host that drew it hands it back, and a host that drew no such panel
// hands back nothing.
//
// It is safe to call from whichever goroutine drew the card; the engine reads it
// once the request has been answered.
func (r *Request) Presented(project *ladulasv1.PresentedProject) {
	r.shownMu.Lock()
	defer r.shownMu.Unlock()

	r.shown = project
}

// Shown is what Presented recorded, for the audit entry.
func (r *Request) Shown() *ladulasv1.PresentedProject {
	r.shownMu.Lock()
	defer r.shownMu.Unlock()

	return r.shown
}

// Origin says where a request came from, and — for the two that came from a
// peer — which side is going to produce the signature.
//
// That second half is not bookkeeping. It is the whole of what decides whether
// a promise can be handed over (decision P): a peer that asks only for a
// decision is a peer that holds the key and will sign with it itself, and a
// peer that sends the bytes along is one that cannot. Nothing else on a request
// distinguishes them — the key, the requester and the kind read the same either
// way — and the door it arrived through is the only place the difference is
// known.
type Origin int

const (
	// OriginLocal is a request that started on this machine: the agent socket,
	// the signing socket, the instance's own commands.
	OriginLocal Origin = iota
	// OriginPeer is a request a paired peer sent over the channel for a
	// decision, holding the key and meaning to sign with it itself.
	OriginPeer
	// OriginPeerSigning is a peer borrowing a key of this instance's: it sent
	// the bytes because it has no copy, and the signature is made here
	// (decision T). A promise about such a key stays here, because the
	// requester has to come back for every signature whatever anyone decided.
	OriginPeerSigning
)

// Answer is an approver's response to a prompt.
type Answer struct {
	Decision ladulasv1.Decision
	// Reason is free text shown in the log; the approver's own words.
	Reason string
	// GrantTTL, when positive and the decision is an approval, creates a TTL
	// grant scoped to this request (§9).
	//
	// A remote approver never sets it. Grants live on the approver that made
	// the promise (§18), so the grant a peer created is the peer's and the
	// requester keeps no copy it could later extend.
	GrantTTL time.Duration
	// GrantReach is how far that grant carries (decision V). The zero value is
	// the session the request came from, which is the narrower of the two.
	GrantReach GrantReach
	// Approver identifies who answered, when it was not somebody at this
	// instance.
	Approver *ladulasv1.ApproverInfo
	// Source overrides how the decision is attributed. A peer that answered
	// from a standing grant of its own says so, and the requester's log should
	// not record a human having been asked when none was (§9).
	Source ladulasv1.DecisionSource
	// Signed is the approver's own signed artifact, when a peer answered. It is
	// what turns the requester's audit log from its own account of events into
	// evidence: it cannot be forged without the approver's identity key.
	Signed *ladulasv1.SignedApproval
}

// Handler is an approver — something that can answer a prompt. The tray app is
// one, a console prompt is one, and a paired peer is one.
//
// Decide blocks until it has an answer or the context is done. A handler that
// returns an error is skipped; the engine waits for the others, and gives up at
// once when they have all failed.
type Handler interface {
	// ID identifies the approver in logs.
	ID() string
	Decide(ctx context.Context, req *Request) (*Answer, error)
}

// RemoteHandler marks a Handler that asks a paired peer rather than a human
// here.
//
// The engine uses it for one rule: a request that arrived from a peer is
// decided at this instance and is never passed on. Without it a pair of
// instances that each named the other as an approver would bounce a request
// between them until it timed out, and a longer ring would do the same more
// slowly. The rule is also the honest one — an approver is a human who has
// agreed to answer for a requester, not a router.
type RemoteHandler interface {
	Handler

	// Peer is the fingerprint of the peer this handler asks.
	Peer() string
}

// LocalPrompt marks a Handler that asks a human sitting at this instance — the
// tray window, the terminal. It is what a soft lock takes away (§10).
//
// The distinction the engine needs is not "in this process" but "answered by
// somebody who is here": a soft lock is the claim that nobody is, and the
// screen it would draw on is behind a lock screen anyway. Handlers that are
// neither this nor a RemoteHandler — the pairing command's session, say — keep
// answering, because what authorizes those is possession of the unix account
// rather than the state of the store (§14).
type LocalPrompt interface {
	Handler

	// LocalPrompt is a marker; it does nothing.
	LocalPrompt()
}

// Notifier is an optional Handler capability: a passive notification for
// requests that were auto-approved without a prompt (§9). Silent auto-approval
// is how approval fatigue turns into an unnoticed compromise, so a rule that
// approves still tells you it did.
type Notifier interface {
	Notify(req *Request, resp *ladulasv1.ApprovalResponse)
}

// Options configures an engine.
type Options struct {
	// Identity signs approval responses. Required.
	Identity *identity.Identity
	// Policy defaults to DefaultPolicy.
	Policy *Policy
	// Grants persists TTL grants. Optional; without one, grants are refused.
	Grants GrantStore
	// Delegations holds the standing permissions paired approvers have given
	// this instance (decision P). Optional; without one, this instance simply
	// asks every time, which is what it did before delegations existed.
	Delegations DelegationStore
	// Endorsements holds the promises other holders of a key have made about a
	// requester (decision AG). Optional; without one this instance asks about
	// every borrowed signature, which is what it did before endorsements
	// existed.
	Endorsements EndorsementStore
	// KeySigner is how a promise about a key gets signed with that key, which
	// is what lets the other holders check it (decision AG). Optional; without
	// one a promise is kept here and endorsed to nobody.
	KeySigner KeySigner
	// GrantUses is where an approver writes down what its promises covered.
	// Optional; keystore.Vault implements it, and without one a grant's count
	// stays at nothing.
	GrantUses GrantUses
	// Audit receives every decision. Optional but strongly recommended.
	Audit *AuditLog
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Now defaults to time.Now, and exists so tests can control expiry.
	Now func() time.Time
}

// Engine decides requests.
type Engine struct {
	identity     *identity.Identity
	grants       GrantStore
	delegations  DelegationStore
	endorsements EndorsementStore
	keySigner    KeySigner
	grantUses    GrantUses
	// reportUse is how a requester tells an approver it can reach what it has
	// just done under a delegation, and renewDelegation is how an approver
	// hands over a promise it has extended. Both are set after construction,
	// because the thing that can reach a peer is built after the engine that
	// decides.
	reportUse       func(approverFingerprint string)
	renewDelegation func(ctx context.Context, holder string,
		signed *ladulasv1.SignedDelegation) error
	// publishEndorsement tells the other holders of a key about a promise made
	// here, and is set after construction for the same reason (decision AG).
	publishEndorsement func(ctx context.Context, signed *ladulasv1.SignedEndorsement)

	audit *AuditLog
	log   *slog.Logger
	now   func() time.Time

	mu       sync.RWMutex
	policy   *Policy
	handlers []Handler
	// softLocked suspends local approval authority (§10). Set through
	// SuspendLocalPrompts.
	softLocked bool
}

// New creates an engine.
func New(opts Options) (*Engine, error) {
	if opts.Identity == nil {
		return nil, errors.New("approval: no instance identity to sign decisions with")
	}

	policy := opts.Policy
	if policy == nil {
		policy = DefaultPolicy()
	}

	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	return &Engine{
		identity:     opts.Identity,
		grants:       opts.Grants,
		delegations:  opts.Delegations,
		endorsements: opts.Endorsements,
		keySigner:    opts.KeySigner,
		grantUses:    opts.GrantUses,
		audit:        opts.Audit,
		log:          log,
		now:          now,
		policy:       policy,
	}, nil
}

// Register adds an approver and returns a function that removes it again. The
// tray app registers when it starts and unregisters when it quits, which is
// what makes "no approver is reachable" a real state rather than a hang.
func (e *Engine) Register(h Handler) func() {
	e.mu.Lock()
	e.handlers = append(e.handlers, h)
	e.mu.Unlock()

	var once sync.Once

	return func() {
		once.Do(func() {
			e.mu.Lock()
			defer e.mu.Unlock()

			for i, existing := range e.handlers {
				if existing == h {
					e.handlers = append(e.handlers[:i], e.handlers[i+1:]...)

					break
				}
			}
		})
	}
}

// HasLocalApprover reports whether a human at this instance could be asked
// something.
//
// It is what an instance tells a peer that is deciding whether to bother with a
// wake-up, and what "can prompt" means in a status listing. Remote approvers do
// not count: a chain of instances each of which would forward the question is
// not somewhere a question can be answered. Neither does a soft-locked
// instance, which is the same statement about a screen nobody is looking at.
func (e *Engine) HasLocalApprover() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.softLocked {
		return false
	}

	for _, h := range e.handlers {
		if _, remote := h.(RemoteHandler); !remote {
			return true
		}
	}

	return false
}

// SuspendLocalPrompts is the soft lock (§10): the prompts at this instance
// leave the eligible-approver set, so every request that needs a decision goes
// to a remote approver or waits.
//
// It deliberately stops short of everything else. The data encryption key stays
// where it is, so a peer that approves can still have a key used; grants and
// auto-approve rules still fire, because they are promises this instance made
// while somebody was here to make them.
func (e *Engine) SuspendLocalPrompts(suspended bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.softLocked = suspended
}

// LocalPromptsSuspended reports whether the soft lock is on.
func (e *Engine) LocalPromptsSuspended() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.softLocked
}

// SetPolicy replaces the policy.
func (e *Engine) SetPolicy(p *Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.policy = p
}

// Policy returns the current policy.
func (e *Engine) Policy() *Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.policy
}

// Submit decides a request. It never returns an error for an ordinary denial —
// a denial is a decision. An error means the engine itself failed, and the
// caller should treat that as a refusal too.
func (e *Engine) Submit(
	ctx context.Context, msg *ladulasv1.ApprovalRequest,
) (*ladulasv1.ApprovalResponse, error) {
	resp, _, err := e.SubmitSigned(ctx, msg)

	return resp, err
}

// SubmitSigned decides a request and also hands back the signed artifact.
//
// Callers that keep an account of what happened want it: ladulas-sign records
// the approver's signature over the decision in its own log, so that the
// requester's history holds evidence rather than its own word (§18).
func (e *Engine) SubmitSigned(
	ctx context.Context, msg *ladulasv1.ApprovalRequest,
) (*ladulasv1.ApprovalResponse, *ladulasv1.SignedApproval, error) {
	return e.submit(ctx, msg, nil, OriginLocal)
}

// SubmitPeer decides a request that arrived from a paired peer, digesting the
// exact bytes that crossed the channel rather than a re-serialization of them.
//
// Both ends have to agree on what the response commits to, and protobuf
// serialization is not promised to be reproducible — so the approver signs over
// what it received, and the requester checks against what it sent. Anything
// else would leave the binding between a request and its answer resting on an
// encoder's good behaviour.
func (e *Engine) SubmitPeer(
	ctx context.Context, msg *ladulasv1.ApprovalRequest, body []byte,
) (*ladulasv1.ApprovalResponse, *ladulasv1.SignedApproval, error) {
	return e.submit(ctx, msg, body, OriginPeer)
}

// SubmitPeerSigning decides a request whose signature this instance is going to
// make, because the peer that asked holds no copy of the key (decision T).
//
// It is the same decision in every other respect. What it changes is that a TTL
// agreed to here cannot be handed over: the requester will be back for the next
// signature no matter what was promised, so the promise stays where the key is
// (decision P).
func (e *Engine) SubmitPeerSigning(
	ctx context.Context, msg *ladulasv1.ApprovalRequest, body []byte,
) (*ladulasv1.ApprovalResponse, *ladulasv1.SignedApproval, error) {
	return e.submit(ctx, msg, body, OriginPeerSigning)
}

func (e *Engine) submit(
	ctx context.Context,
	msg *ladulasv1.ApprovalRequest,
	body []byte,
	origin Origin,
) (*ladulasv1.ApprovalResponse, *ladulasv1.SignedApproval, error) {
	if msg == nil {
		return nil, nil, errors.New("approval: nil request")
	}

	if msg.GetRequestId() == "" {
		msg.RequestId = identity.NewRequestID()
	}

	if msg.GetCreatedAt() == nil {
		msg.CreatedAt = timestamppb.New(e.now())
	}

	// Checking the git context against the payload happens before the request is
	// serialized, so that the verdict is part of the bytes the approval response
	// commits to: an approver's signature has to cover whether the commit it was
	// shown was the commit being signed (§5).
	contextProblem := gitctx.VerifyRequest(msg)

	// The digest binds a response to the exact request bytes the approver saw,
	// so a response cannot be replayed against a different request even though
	// it travels separately from it. A request that arrived over the channel
	// brought its own bytes and keeps them.
	if body == nil {
		serialized, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
		if err != nil {
			return nil, nil, fmt.Errorf("serialize request: %w", err)
		}

		body = serialized
	}

	policy := e.Policy()

	req := &Request{
		Msg:          msg,
		Prompt:       RenderPrompt(msg),
		GrantSubject: GrantSubject(msg),
		GrantMachine: GrantMachine(msg),
		Origin:       origin,
		Body:         body,
	}

	// A kind that can be promised for carries the offer, and a kind that
	// cannot carries none — which is what stops a surface offering it (§9).
	if grantable(msg.GetKind()) {
		req.GrantTTLs = policy.GrantTTLs()
		req.GrantMaxTTL = policy.MaxGrantTTL()
	}

	e.logEntry(&ladulasv1.AuditEntry{
		Event:     ladulasv1.AuditEvent_AUDIT_EVENT_REQUEST,
		RequestId: msg.GetRequestId(),
		Request:   msg,
	})

	resp, remote := e.decide(ctx, req, policy, contextProblem)
	resp.RequestId = msg.GetRequestId()
	resp.RequestDigest = identity.Digest(body)

	// A decision a peer made keeps the peer's name on it. The signature below
	// is still this instance's, and says "this is the answer I acted on"; the
	// peer's own artifact travels beside it in the log.
	if resp.GetApprover() == nil {
		resp.Approver = e.identity.ApproverInfo(true)
	}

	if resp.GetDecidedAt() == nil {
		resp.DecidedAt = timestamppb.New(e.now())
	}

	signed, err := e.identity.SignApproval(resp)
	if err != nil {
		// A decision we cannot sign is a decision we cannot account for, so it
		// does not get to be an approval.
		e.log.Error("could not sign the approval response",
			"request_id", msg.GetRequestId(), "error", err.Error())

		resp = deny(ladulasv1.DecisionSource_DECISION_SOURCE_ERROR,
			"the decision could not be signed")
		resp.RequestId = msg.GetRequestId()
		resp.RequestDigest = identity.Digest(body)
		resp.Approver = e.identity.ApproverInfo(true)
		resp.DecidedAt = timestamppb.New(e.now())
		remote = nil
	}

	e.logEntry(&ladulasv1.AuditEntry{
		Event:          ladulasv1.AuditEvent_AUDIT_EVENT_DECISION,
		RequestId:      msg.GetRequestId(),
		Request:        msg,
		Response:       resp,
		SignedApproval: signed,
		RemoteApproval: remote,
		PromptShown:    req.Prompt.Text(),
		ProjectShown:   req.Shown(),
	})

	e.log.Info("decided",
		"request_id", msg.GetRequestId(),
		"kind", msg.GetKind().String(),
		"decision", resp.GetDecision().String(),
		"source", resp.GetSource().String(),
		"approver", resp.GetApprover().GetName(),
		"reason", resp.GetReason())

	return resp, signed, nil
}

// decide applies the hard rules, the policy, the grants and finally the
// approvers, in that order.
//
// The second return is the answering peer's own signed artifact, when a peer
// answered. It is not part of the decision; it is the evidence that goes into
// the log beside it.
func (e *Engine) decide(
	ctx context.Context, req *Request, policy *Policy, contextProblem string,
) (*ladulasv1.ApprovalResponse, *ladulasv1.SignedApproval) {
	msg := req.Msg

	// Hard rules first. Nothing below can override these (§9).
	if msg.GetKind() == ladulasv1.RequestKind_REQUEST_KIND_OPAQUE_SIGN {
		return deny(ladulasv1.DecisionSource_DECISION_SOURCE_HARD_RULE,
			"the payload is neither an SSH authentication blob "+
				"nor an SSHSIG signature"), nil
	}

	// A request whose context describes a different commit from the one it would
	// sign is the compromised-requester attack of §15, caught here rather than
	// left for a human to spot in a prompt that is lying to them. It runs on a
	// request that arrived over the channel exactly as it runs on a local one:
	// the machine we distrust is the requesting one, which is precisely the
	// remote case.
	if contextProblem != "" {
		return deny(
			ladulasv1.DecisionSource_DECISION_SOURCE_HARD_RULE, contextProblem), nil
	}

	// A forwarded agent socket is held by a machine we do not control, and a
	// pairing change is the root of all later trust — both always ask.
	mustPrompt := ""

	switch {
	case msg.GetSshAuth().GetForwarded():
		mustPrompt = "requests through a forwarded agent always ask"
	case msg.GetKind() == ladulasv1.RequestKind_REQUEST_KIND_PAIRING:
		mustPrompt = "pairing changes always ask"
	}

	eval := policy.Evaluate(msg)

	if eval.Action == ladulasv1.Action_ACTION_DENY {
		return deny(ladulasv1.DecisionSource_DECISION_SOURCE_POLICY, eval.Rule), nil
	}

	if mustPrompt == "" {
		if eval.Action == ladulasv1.Action_ACTION_APPROVE {
			resp := approve(ladulasv1.DecisionSource_DECISION_SOURCE_POLICY, eval.Rule)
			resp.NotifyOnly = eval.Notify

			e.notify(req, resp)

			return resp, nil
		}

		// A grant is this instance's own promise, so it answers a peer's request
		// here without the peer being told anything but the answer — and the
		// human here still gets the passive notification that says a promise was
		// spent (§9, §18).
		if grant := e.matchGrant(msg); grant != nil {
			resp := approve(ladulasv1.DecisionSource_DECISION_SOURCE_GRANT,
				grant.GetDescription())
			resp.NotifyOnly = true

			e.recordOwnUse(grant.GetGrantId(), msg)
			e.notify(req, resp)

			return resp, nil
		}

		// A delegation is somebody else's promise, kept here (decision P). It
		// only ever answers this instance's own requests — a request that
		// arrived from a peer is that peer's to answer, and passing it through
		// a permission granted to this one would be lending out a promise that
		// was not made about it.
		if req.Origin == OriginLocal {
			if d := e.matchDelegation(msg); d != nil {
				resp := approve(
					ladulasv1.DecisionSource_DECISION_SOURCE_GRANT,
					d.GetDescription())
				resp.NotifyOnly = true

				e.recordDelegatedUse(msg, d)
				e.notify(req, resp)

				return resp, nil
			}
		}

		// An endorsement is a promise another holder of this key made about the
		// machine that is asking (decision AG). It only ever answers a borrowed
		// signature: a request that came for a decision belongs to a peer that
		// holds the key itself, and one made here is this instance's own to
		// decide from its own grants.
		if req.Origin == OriginPeerSigning {
			if en := e.matchEndorsement(req, policy); en != nil {
				resp := approve(
					ladulasv1.DecisionSource_DECISION_SOURCE_GRANT,
					en.GetDescription())
				resp.NotifyOnly = true

				e.recordEndorsedUse(msg, en)
				e.notify(req, resp)

				return resp, nil
			}
		}
	} else if eval.Action == ladulasv1.Action_ACTION_APPROVE {
		req.Prompt.Warnings = append(req.Prompt.Warnings,
			fmt.Sprintf("policy would auto-approve this, but %s", mustPrompt))
	}

	return e.prompt(ctx, req, policy)
}

// grantable reports whether "approve for a while" means anything for this kind
// of request.
//
// A promise is a scope and a clock over signing with a key (§9). A pairing has
// no key, happens once, and is a hard rule that always prompts — so a promise
// about one could never be spent, and the offer was three buttons and a clock
// under a question whose whole content is "is this the machine on the other
// screen". It was there because the offer was sized from the policy for every
// kind alike, and it read as an invitation to leave the door open for an hour.
//
// A key listing is the same shape of nothing: no key, no bytes, and nothing a
// later request could match against.
func grantable(kind ladulasv1.RequestKind) bool {
	switch kind {
	case ladulasv1.RequestKind_REQUEST_KIND_PAIRING,
		ladulasv1.RequestKind_REQUEST_KIND_KEY_LIST:
		return false
	case ladulasv1.RequestKind_REQUEST_KIND_UNSPECIFIED,
		ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH,
		ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
		ladulasv1.RequestKind_REQUEST_KIND_SSHSIG,
		ladulasv1.RequestKind_REQUEST_KIND_OPAQUE_SIGN:
	}

	return true
}

func (e *Engine) matchGrant(msg *ladulasv1.ApprovalRequest) *ladulasv1.Grant {
	if e.grants == nil {
		return nil
	}

	grants, err := e.grants.Grants()
	if err != nil {
		e.log.Error("could not read grants", "error", err.Error())

		return nil
	}

	return findGrant(grants, msg, e.now())
}

// prompt fans a request out to every eligible approver and takes the first
// decision: the local GUI, a console, and every paired peer that may approve
// for this instance, all at once.
//
// The first *decision*, and not simply the first thing that comes back — see
// declined, which is the difference between a peer answering and a peer saying
// it has nobody to ask.
//
// A request that arrived from a peer is not passed on to another peer. See
// RemoteHandler for why.
func (e *Engine) prompt(
	ctx context.Context, req *Request, policy *Policy,
) (*ladulasv1.ApprovalResponse, *ladulasv1.SignedApproval) {
	handlers := e.eligible(req.Origin)

	if len(handlers) == 0 {
		reason := "no approver is available to answer"
		if e.LocalPromptsSuspended() {
			reason = "this instance is locked and no paired approver could answer"
		}

		return deny(
			ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER, reason), nil
	}

	timeout := policy.Timeout(req.Msg.GetKind())
	if requested := req.Msg.GetTimeout(); requested != nil && requested.AsDuration() > 0 {
		timeout = requested.AsDuration()
	}

	// A kind with no budget waits on the caller's context alone: it ends when
	// somebody answers, when another approver wins the race, or when whatever
	// raised it goes away. Pairings are the case (§7).
	ctx, cancel := withOptionalTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		handler Handler
		answer  *Answer
	}

	results := make(chan result, len(handlers))
	failures := make(chan struct{}, len(handlers))

	for _, h := range handlers {
		go func() {
			answer, err := h.Decide(ctx, req)
			if err != nil {
				if ctx.Err() == nil {
					e.log.Warn("approver failed",
						"approver", h.ID(),
						"request_id", req.Msg.GetRequestId(),
						"error", err.Error())
				}

				failures <- struct{}{}

				return
			}

			results <- result{handler: h, answer: answer}
		}()
	}

	var failed int

	for {
		select {
		case r := <-results:
			// A peer with nobody to ask has reported on itself rather than
			// decided anything, and it does it instantly — so it goes on the
			// same path as an approver that could not be reached at all
			// (decision AC).
			if declined(r.handler, r.answer) {
				failed++

				if failed == len(handlers) {
					return deny(
						ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER,
						"no approver could be reached"), nil
				}

				continue
			}

			// Cancelling here is what tells the other approvers to drop their
			// prompts: first decision wins.
			cancel()

			return e.answerToResponse(req, r.handler, r.answer)
		case <-failures:
			failed++

			// Every approver that could have answered has gone. Waiting out the
			// timeout would tell the user nothing they do not already know, and
			// the difference between "the desktop said no" and "the desktop was
			// not there" is worth having in the log and on the terminal.
			if failed == len(handlers) {
				return deny(ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER,
					"no approver could be reached"), nil
			}
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return deny(ladulasv1.DecisionSource_DECISION_SOURCE_TIMEOUT,
					fmt.Sprintf("nobody answered within %s", timeout)), nil
			}

			return deny(ladulasv1.DecisionSource_DECISION_SOURCE_CANCELLED,
				"the request was withdrawn"), nil
		}
	}
}

// declined reports whether what came back from a peer is a report about the
// peer rather than a decision about the request — decision AC.
//
// A peer runs the same engine, and a peer with no approver of its own denies
// with NO_APPROVER the instant it is asked, because nothing was asked of
// anybody. That travels back as a perfectly well-formed answer, and "first
// response wins" then hands it the race against a desktop prompt waiting on a
// human to look at a window — every time, because one of them takes a
// millisecond and the other takes as long as a person takes. Pairing an
// instance that cannot approve stopped being a second way to get an answer and
// became a veto on the first.
//
// So the rule is that first *decision* wins, and this is not one. The engine
// already tells an answer apart from the absence of one — handlers that error
// go to failures and the request is denied only when every one of them has gone
// — and this belongs on that path.
//
// Only NO_APPROVER, and only from a peer. A timeout means somebody was asked
// and did not answer, which is a fact about the request; a peer's policy
// denial, hard rule or human saying no are all decisions. And a local prompt
// that reports NO_APPROVER is this instance's own engine, which cannot happen
// and would be a bug to paper over here.
//
// An approval is never discarded whatever it says about its source: the source
// is how a decision was reached, and an answer that approves has been decided.
func declined(h Handler, answer *Answer) bool {
	if _, remote := h.(RemoteHandler); !remote {
		return false
	}

	return answer != nil &&
		answer.Decision != ladulasv1.Decision_DECISION_APPROVE &&
		answer.Source == ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER
}

// withOptionalTimeout applies a deadline when there is one to apply.
func withOptionalTimeout(
	ctx context.Context, timeout time.Duration,
) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}

	return context.WithTimeout(ctx, timeout)
}

// eligible is the set of approvers a request of this origin may be shown to.
func (e *Engine) eligible(origin Origin) []Handler {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := make([]Handler, 0, len(e.handlers))

	for _, h := range e.handlers {
		// Any request that came from a peer stops here, whichever door it came
		// through: passing one on would make this instance a relay for somebody
		// else's decision. See RemoteHandler.
		if _, remote := h.(RemoteHandler); remote && origin != OriginLocal {
			continue
		}

		if _, local := h.(LocalPrompt); local && e.softLocked {
			continue
		}

		out = append(out, h)
	}

	return out
}

func (e *Engine) answerToResponse(
	req *Request, handler Handler, answer *Answer,
) (*ladulasv1.ApprovalResponse, *ladulasv1.SignedApproval) {
	if answer == nil {
		return deny(ladulasv1.DecisionSource_DECISION_SOURCE_ERROR,
			"the approver returned nothing"), nil
	}

	reason := answer.Reason
	if reason == "" {
		reason = "answered by " + handler.ID()
	}

	source := answer.Source
	if source == ladulasv1.DecisionSource_DECISION_SOURCE_UNSPECIFIED {
		source = ladulasv1.DecisionSource_DECISION_SOURCE_USER
	}

	if answer.Decision != ladulasv1.Decision_DECISION_APPROVE {
		resp := deny(source, reason)
		resp.Approver = answer.Approver

		return resp, answer.Signed
	}

	resp := approve(source, reason)
	resp.Approver = answer.Approver

	// Where the promise goes follows the key it is about (decision P). One over
	// a key this instance holds is kept here, because the requester has to come
	// back for every signature anyway. One over a key the requester holds
	// itself is handed over signed, because keeping it here would only mean the
	// requester waiting for this instance to be awake — and the daemon it is
	// handed to could already sign with that key unasked.
	//
	// And only where a promise was offered at all: a request with no offer on
	// it is one nothing can be promised about (grantable), and an answer that
	// asks for one anyway is answering a question it was not shown.
	if answer.GrantTTL > 0 && req.GrantMaxTTL > 0 {
		if e.shouldDelegate(req) {
			resp.Delegation, resp.Grant = e.delegate(
				req.Msg, answer.GrantTTL, answer.GrantReach)
		} else {
			resp.Grant = e.createGrant(
				req.Msg, answer.GrantTTL, answer.GrantReach)

			// A promise about a portable key is also written down for the other
			// machines that hold it, so that the requester does not have to come
			// back to this one for every signature (decision AG). It is an
			// addition to the grant rather than an alternative to it: this
			// instance holds the key too and goes on answering from the record
			// exactly as before.
			if e.shouldEndorse(req) {
				resp.Endorsement = e.endorse(req.Msg, resp.Grant)
			}
		}
	}

	return resp, answer.Signed
}

// ReportDelegatedUse installs the way a requester tells an approver what it has
// done under a delegation, as soon as it does it.
//
// It is set after construction rather than passed in, because what can reach a
// peer is the peer node and the node is built around the engine. Without one
// nothing is lost: the use stays in the ledger and is collected (decision P).
func (e *Engine) ReportDelegatedUse(report func(approverFingerprint string)) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.reportUse = report
}

func (e *Engine) useReporter() func(string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.reportUse
}

// RenewDelegations installs the way an extended promise reaches the machine
// holding it (decision V), and is set after construction for the same reason
// the use reporter is: what can reach a peer is the peer node, and the node is
// built around the engine.
//
// Without one, extending a handed-over promise fails rather than quietly
// amending the record here — see ExtendGrant for why that order is the whole of
// it.
func (e *Engine) RenewDelegations(
	renew func(ctx context.Context, holder string,
		signed *ladulasv1.SignedDelegation) error,
) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.renewDelegation = renew
}

func (e *Engine) delegationRenewer() func(
	context.Context, string, *ladulasv1.SignedDelegation,
) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.renewDelegation
}

// ExtendGrant gives a promise that is still running more time, counted from now
// (decision V).
//
// One that was handed over is re-signed and delivered to the machine holding it
// **before** the record here is amended, which is the mirror of how revoking is
// ordered and rests on the same fact: a delegation is honoured by its holder
// without asking anybody, so what this store says about it is a description and
// not the thing itself. An undelivered revocation would leave somebody signing
// who should have stopped; an undelivered extension would leave this list
// promising more than the machine acting on it will do. Both are a list that
// lies, and the order is what stops each of them.
//
// A promise this instance keeps needs no delivery: the machine that asks comes
// back here for every signature anyway.
func (e *Engine) ExtendGrant(
	ctx context.Context, id string, extra time.Duration,
) (*ladulasv1.Grant, error) {
	if e.grants == nil {
		return nil, errors.New("this instance keeps no grants")
	}

	grants, err := e.grants.Grants()
	if err != nil {
		return nil, fmt.Errorf("read the grants: %w", err)
	}

	now := e.now()

	var grant *ladulasv1.Grant

	for _, candidate := range grants {
		if candidate.GetGrantId() != id {
			continue
		}

		if candidate.GetExpiresAt().AsTime().After(now) {
			grant = candidate
		}

		break
	}

	if grant == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchGrant, id)
	}

	// A promise somebody has already taken back is not one to top up. Its
	// holder has not been told yet — that is the whole of what pending means —
	// and adding time to it would be arguing with the person who revoked it.
	if grant.GetRevokePending() {
		return nil, errors.New("this promise has been revoked and is waiting " +
			"to be taken back from the machine holding it")
	}

	amended, signed, err := e.extendPromise(
		grant, extra, e.Policy().MaxGrantTTL(), now)
	if err != nil {
		return nil, err
	}

	if signed != nil {
		renew := e.delegationRenewer()
		if renew == nil {
			return nil, errors.New("this promise is held by another machine " +
				"and there is no way to reach it from here")
		}

		if err := renew(
			ctx, grant.GetDelegateFingerprint(), signed); err != nil {
			return nil, fmt.Errorf("hand over the extended promise: %w", err)
		}
	}

	if err := e.grants.ReplaceGrant(amended); err != nil {
		return nil, fmt.Errorf("store the extended promise: %w", err)
	}

	e.logEntry(&ladulasv1.AuditEntry{
		Event:     ladulasv1.AuditEvent_AUDIT_EVENT_GRANT,
		RequestId: grant.GetOriginRequestId(),
		Grant:     amended,
		Detail:    "extended to run for " + HumanDuration(extra) + " from now",
	})

	return amended, nil
}

// ErrNoSuchGrant is what extending something that is not running says. A
// mistyped identifier and an expired promise are the same answer on purpose:
// both mean there is nothing there to add time to.
var ErrNoSuchGrant = errors.New("approval: no live grant with that id")

// ErrGrantTooLong is a length this instance will not promise anything for
// (decision V), in either direction: past the ceiling, or under a minute, which
// is a dialled zero rather than a promise.
var ErrGrantTooLong = errors.New("approval: not a length this instance promises")

func (e *Engine) createGrant(
	msg *ladulasv1.ApprovalRequest, ttl time.Duration, reach GrantReach,
) *ladulasv1.Grant {
	if e.grants == nil {
		e.log.Warn("a grant was asked for but there is nowhere to keep it",
			"request_id", msg.GetRequestId())

		return nil
	}

	grant := newGrant(msg, ttl, reach, e.now())

	if err := e.grants.AddGrant(grant); err != nil {
		e.log.Error("could not store the grant",
			"request_id", msg.GetRequestId(), "error", err.Error())

		return nil
	}

	e.logEntry(&ladulasv1.AuditEntry{
		Event:     ladulasv1.AuditEvent_AUDIT_EVENT_GRANT,
		RequestId: msg.GetRequestId(),
		Grant:     grant,
		Detail:    grant.GetDescription(),
	})

	// The request that produced the promise is the first thing it covered.
	e.recordOwnUse(grant.GetGrantId(), msg)

	return grant
}

// Signed records that a signature was actually produced. The agent calls this
// after signing, so the log distinguishes "approved" from "approved and used".
func (e *Engine) Signed(msg *ladulasv1.ApprovalRequest, key *ladulasv1.KeyRef) {
	e.logEntry(&ladulasv1.AuditEntry{
		Event:          ladulasv1.AuditEvent_AUDIT_EVENT_SIGNATURE,
		RequestId:      msg.GetRequestId(),
		KeyFingerprint: key.GetFingerprint(),
		Detail:         msg.GetKind().String(),
	})
}

// Delegated records a request that was decided, and acted on, somewhere else.
//
// A keyless requester does not decide its own signatures. The key lives on a
// paired holder, and it is the holder's engine that applies the hard rules, the
// policy, the grants and the prompt — asking here as well would put the same
// commit in front of two people and let the wrong one settle it (§8).
//
// What is left for this instance is its half of the account: the request as it
// went out, the answer that came back, and the holder's own signature over that
// answer, which is evidence rather than this instance's word for it (§18). The
// local signature beside it says only "this is the answer I acted on".
func (e *Engine) Delegated(
	msg *ladulasv1.ApprovalRequest,
	resp *ladulasv1.ApprovalResponse,
	remote *ladulasv1.SignedApproval,
) {
	e.logEntry(&ladulasv1.AuditEntry{
		Event:     ladulasv1.AuditEvent_AUDIT_EVENT_REQUEST,
		RequestId: msg.GetRequestId(),
		Request:   msg,
	})

	signed, err := e.identity.SignApproval(resp)
	if err != nil {
		e.log.Error("could not countersign a delegated decision",
			"request_id", msg.GetRequestId(), "error", err.Error())
	}

	e.logEntry(&ladulasv1.AuditEntry{
		Event:          ladulasv1.AuditEvent_AUDIT_EVENT_DECISION,
		RequestId:      msg.GetRequestId(),
		Request:        msg,
		Response:       resp,
		SignedApproval: signed,
		RemoteApproval: remote,
		PromptShown:    RenderPrompt(msg).Text(),
	})

	e.log.Info("decided elsewhere",
		"request_id", msg.GetRequestId(),
		"kind", msg.GetKind().String(),
		"decision", resp.GetDecision().String(),
		"source", resp.GetSource().String(),
		"approver", resp.GetApprover().GetName(),
		"reason", resp.GetReason())
}

// LogLifecycle records something worth knowing that is not a request: the store
// being unlocked, a key being imported, the agent starting.
func (e *Engine) LogLifecycle(detail string) {
	e.logEntry(&ladulasv1.AuditEntry{
		Event:  ladulasv1.AuditEvent_AUDIT_EVENT_LIFECYCLE,
		Detail: detail,
	})
}

// LogKeyTransfer records a portable key changing machines (decision S): sent,
// arrived, accepted or refused. It is separate from LogLifecycle because it is
// the one entry somebody will go looking for after losing a device.
func (e *Engine) LogKeyTransfer(detail, fingerprint string) {
	e.logEntry(&ladulasv1.AuditEntry{
		Event:          ladulasv1.AuditEvent_AUDIT_EVENT_KEY_TRANSFER,
		Detail:         detail,
		KeyFingerprint: fingerprint,
	})
}

func (e *Engine) notify(req *Request, resp *ladulasv1.ApprovalResponse) {
	if !resp.GetNotifyOnly() {
		return
	}

	e.mu.RLock()
	handlers := make([]Handler, len(e.handlers))
	copy(handlers, e.handlers)
	e.mu.RUnlock()

	for _, h := range handlers {
		if notifier, ok := h.(Notifier); ok {
			notifier.Notify(req, resp)
		}
	}
}

func (e *Engine) logEntry(entry *ladulasv1.AuditEntry) {
	if err := e.audit.Append(entry); err != nil {
		e.log.Error("could not write to the audit log", "error", err.Error())
	}
}

func approve(source ladulasv1.DecisionSource, reason string) *ladulasv1.ApprovalResponse {
	return &ladulasv1.ApprovalResponse{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		Source:   source,
		Reason:   reason,
	}
}

func deny(source ladulasv1.DecisionSource, reason string) *ladulasv1.ApprovalResponse {
	return &ladulasv1.ApprovalResponse{
		Decision: ladulasv1.Decision_DECISION_DENY,
		Source:   source,
		Reason:   reason,
	}
}
