package approval

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The requester's half of decision P.
//
// A grant over a key this instance holds itself is handed over rather than kept
// by the approver: a signed, scoped, expiring statement that until some time,
// within some scope, this instance may answer for itself. It is what makes
// "approve for an hour" mean an hour rather than an hour of the approver being
// awake.
//
// What it does not do is widen anything. The scope is the same GrantScope an
// approver-side grant uses and is matched the same strict way, so a delegation
// answers exactly the requests the promise was made about — and the programs
// coming to the agent socket are gated by that scope exactly as they were when
// the grant lived on the approver. The party that gains is the daemon holding
// the key, which could already sign anything it liked.

// DelegationStore holds the standing permissions paired approvers have given
// this instance.
type DelegationStore interface {
	// UsableDelegations returns the ones that may still be applied: live, and
	// from a peer this instance still trusts to approve for it.
	//
	// The signature was checked when each arrived, and whether the approver is
	// still trusted is a question about trust records rather than about
	// approvals — so both are settled before the engine ever sees one, and what
	// is left here is matching a scope.
	UsableDelegations() ([]*ladulasv1.Delegation, error)
	// RecordDelegationUse writes down that one answered a request, for the
	// account this instance owes its approver (decision P).
	RecordDelegationUse(use *ladulasv1.GrantUse) error
}

// matchDelegation returns the delegation covering a request, if any.
func (e *Engine) matchDelegation(msg *ladulasv1.ApprovalRequest) *ladulasv1.Delegation {
	if e.delegations == nil {
		return nil
	}

	held, err := e.delegations.UsableDelegations()
	if err != nil {
		e.log.Error("could not read delegations", "error", err.Error())

		return nil
	}

	return findDelegation(held, msg, e.now())
}

func findDelegation(
	held []*ladulasv1.Delegation, msg *ladulasv1.ApprovalRequest, now time.Time,
) *ladulasv1.Delegation {
	for _, d := range held {
		if !d.GetExpiresAt().AsTime().After(now) {
			continue
		}

		if covers(d.GetScope(), msg) {
			return d
		}
	}

	return nil
}

// grantUse describes one thing a promise covered, in the words the prompt would
// have used for it.
func (e *Engine) grantUse(
	grantID string, msg *ladulasv1.ApprovalRequest,
) *ladulasv1.GrantUse {
	return &ladulasv1.GrantUse{
		GrantId:   grantID,
		RequestId: msg.GetRequestId(),
		UsedAt:    timestamppb.New(e.now()),
		Kind:      msg.GetKind(),
		Subject:   RenderPrompt(msg).Subject,
	}
}

// recordDelegatedUse adds one line to the account this instance owes.
//
// A failure here is logged and does not stop the request. The alternative is
// refusing to sign something an approver has already agreed to because the
// bookkeeping about it could not be written, which trades a promise kept for a
// promise recorded.
func (e *Engine) recordDelegatedUse(
	msg *ladulasv1.ApprovalRequest, d *ladulasv1.Delegation,
) {
	use := e.grantUse(d.GetDelegationId(), msg)

	if err := e.delegations.RecordDelegationUse(use); err != nil {
		e.log.Error("could not record the use of a delegation",
			"request_id", msg.GetRequestId(),
			"delegation_id", d.GetDelegationId(),
			"error", err.Error())

		return
	}

	// Tell the approver now if it can be reached. Between two desktops that is
	// the ordinary case and makes the account immediate; when the approver is a
	// phone there is nothing to dial, and the entry waits in the ledger to be
	// collected (decision P).
	if report := e.useReporter(); report != nil {
		report(d.GetApproverFingerprint())
	}
}

// recordOwnUse writes down that a promise this instance keeps covered
// something.
//
// A grant that never says what it did is a grant nobody can audit. Both kinds
// record: this one straight into the grant, because the promise and the thing
// it covered are both here, and a delegated one through the ledger above.
func (e *Engine) recordOwnUse(grantID string, msg *ladulasv1.ApprovalRequest) {
	if e.grantUses == nil {
		return
	}

	err := e.grantUses.RecordGrantUses(
		[]*ladulasv1.GrantUse{e.grantUse(grantID, msg)})
	if err != nil {
		e.log.Error("could not record what a grant covered",
			"request_id", msg.GetRequestId(),
			"grant_id", grantID, "error", err.Error())
	}
}

// GrantUses is where an approver writes down what its promises have covered:
// its own auto-approvals, and the accounts its delegates send it.
type GrantUses interface {
	RecordGrantUses(uses []*ladulasv1.GrantUse) error
}

// delegate turns a TTL somebody agreed to into an artifact for the requester to
// keep, plus this instance's own record of having promised it.
//
// The two halves share an identifier, because they are one promise: the
// requester reports what it did against that id, and revoking the record here
// is what tells the requester to stop.
func (e *Engine) delegate(
	msg *ladulasv1.ApprovalRequest, ttl time.Duration, reach GrantReach,
) (*ladulasv1.SignedDelegation, *ladulasv1.Grant) {
	scope := grantScopeFor(msg, reach)
	promise := GrantPromise(msg, reach)
	now := e.now()
	id := identity.NewRequestID()

	d := &ladulasv1.Delegation{
		DelegationId:         id,
		Scope:                scope,
		CreatedAt:            timestamppb.New(now),
		ExpiresAt:            timestamppb.New(now.Add(ttl)),
		OriginRequestId:      msg.GetRequestId(),
		Description:          DescribeScope(scope, promise, ttl),
		ApproverFingerprint:  e.identity.Fingerprint(),
		ApproverName:         e.identity.Name(),
		RequesterFingerprint: msg.GetRequester().GetInstanceId(),
	}

	signed, err := e.identity.SignDelegation(d)
	if err != nil {
		e.log.Error("could not sign a delegation",
			"request_id", msg.GetRequestId(), "error", err.Error())

		return nil, nil
	}

	// The record kept here is a grant like any other, marked as handed over so
	// that every surface listing promises lists this one — a promise that could
	// not be seen could not be taken back.
	grant := &ladulasv1.Grant{
		GrantId:             id,
		Scope:               scope,
		CreatedAt:           timestamppb.New(now),
		ExpiresAt:           timestamppb.New(now.Add(ttl)),
		OriginRequestId:     msg.GetRequestId(),
		Description:         d.GetDescription(),
		PromiseSubject:      promise,
		Delegated:           true,
		DelegateFingerprint: msg.GetRequester().GetInstanceId(),
		DelegateName:        msg.GetRequester().GetName(),
	}

	if e.grants == nil {
		e.log.Warn("a delegation was granted but there is nowhere to record it",
			"request_id", msg.GetRequestId())

		return signed, nil
	}

	if err := e.grants.AddGrant(grant); err != nil {
		e.log.Error("could not record a delegation",
			"request_id", msg.GetRequestId(), "error", err.Error())

		return signed, nil
	}

	e.logEntry(&ladulasv1.AuditEntry{
		Event:     ladulasv1.AuditEvent_AUDIT_EVENT_GRANT,
		RequestId: msg.GetRequestId(),
		Grant:     grant,
		Detail:    "delegated to " + msg.GetRequester().GetName(),
	})

	// The request that produced the promise is the first thing it covered.
	// Somebody who says "approve, and for the next hour as well" has approved
	// this one too, and a list that started at the second would be missing the
	// only entry anybody actually looked at.
	e.recordOwnUse(id, msg)

	return signed, grant
}

// shouldDelegate decides which kind of promise a TTL becomes (decision P).
//
// It comes down to one question: who is going to make the next signature. A
// requester that makes its own could already sign unasked, so keeping the
// promise here buys nothing and costs it an approver that has to be awake. A
// requester that has to come back for every signature gets nothing from a
// promise it cannot apply, and the promise stays with the key.
//
// The origin is what answers that, because the two arrive through two doors: a
// peer asking only for a decision holds the key, and a peer that sent the bytes
// with it does not (decision T).
//
// It used to ask whether *this* instance held the key, as a stand-in for the
// same question — and that reading was wrong for the case both machines hold a
// portable key (decision S), which is the ordinary case for a key handed from a
// phone to a laptop. The phone held a copy, so it kept every promise it made
// about that key, and the laptop went on waking it for permission to use a key
// already in its own store. **Do not put the holds-it test back**: a key being
// here says nothing about whether it is also there.
func (e *Engine) shouldDelegate(req *Request) bool {
	if req.Origin != OriginPeer {
		return false
	}

	// A delegation is addressed to an instance. Without a fingerprint to
	// address it to there is nobody to hand it to, and nothing that could
	// later report what it did with it.
	return req.Msg.GetRequester().GetInstanceId() != ""
}
