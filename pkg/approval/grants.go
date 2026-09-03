package approval

import (
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// GrantStore persists TTL grants. Grants live on the approver (§18): the grant
// is the approver's promise, requests still travel to it, and a compromised
// requester cannot self-extend one. keystore.Vault implements this.
type GrantStore interface {
	// Grants returns the live grants, having dropped expired ones.
	Grants() ([]*ladulasv1.Grant, error)
	AddGrant(*ladulasv1.Grant) error
	RevokeGrant(id string) error
	// ReplaceGrant puts an amended promise in place of the one it was made
	// from, keeping the ledger: it is how one gets more time on it
	// (decision V).
	ReplaceGrant(*ladulasv1.Grant) error
}

// GrantReach is how far a timed approval carries: the session it was made in,
// or the whole machine that asked (decision V).
//
// Both were always representable — a promise made where there was no session to
// name has covered a whole machine since before decision U existed — and what
// this adds is the approver being asked which one they mean rather than the
// answer following from what the requester happened to send.
type GrantReach int

const (
	// GrantReachSession keeps the promise to the session the request came from:
	// the editor, or the terminal window (decision U). It is the zero value
	// because it is the narrower of the two, and an approver that did not say
	// which it meant must not get the wider one.
	GrantReachSession GrantReach = iota
	// GrantReachMachine widens it to every session on the requesting machine.
	GrantReachMachine
)

// scopeFor derives the scope a request falls under. A grant created from a
// prompt gets exactly this scope, and a later request is covered only when its
// own derived scope matches.
//
// Matching is strict equality rather than "an empty field means any", because
// an SSH authentication request that could not be tied to a destination derives
// an empty destination — and a grant that treated empty as a wildcard would
// then cover every host on the internet. The session is the one exception, for
// the reason written on the field itself (decision U).
func scopeFor(req *ladulasv1.ApprovalRequest) *ladulasv1.GrantScope {
	scope := &ladulasv1.GrantScope{
		KeyFingerprint:      req.GetKey().GetFingerprint(),
		Kind:                req.GetKind(),
		RequesterInstanceId: req.GetRequester().GetInstanceId(),
		SessionId:           req.GetRequester().GetProcess().GetSessionId(),
	}

	if auth := req.GetSshAuth(); auth != nil {
		scope.Username = auth.GetUsername()

		// A grant is matched on the host proven in the signed payload — the
		// hostbound key the signature itself covers — and never on the Bound flag
		// or the label, both the requester's to choose (M2, decision X). Keying
		// on the label let a promise made for one host be spent on another
		// wearing the same name, and gating on Bound let a hostbound login claim
		// to be unbound and fall under an unbound promise. A login whose payload
		// named no host keeps an empty destination, covered only by a grant
		// equally without one; the label rides along for the sentence, not the
		// match.
		if payload := auth.GetPayloadDestination(); payload != nil {
			scope.DestinationFingerprint = payload.GetFingerprint()

			scope.Destination = auth.GetDestinationLabel()
			if scope.Destination == "" {
				scope.Destination = payload.GetFingerprint()
			}
		}
	}

	if git := req.GetSshsig().GetGitContext(); git != nil {
		scope.Repository = git.GetRepositoryPath()
	}

	return scope
}

// AssertedScope names the requester-asserted facts a grant made for this
// request would pin — today, the repository a commit says it belongs to. Those
// are the requesting machine's word (§5): a human at the prompt sees them
// labelled and weighs them, but a timed promise takes them on faith for as long
// as it runs, answering a later request that carries the same claim without
// asking again (decision X). It returns nothing when a promise here would rest
// only on proven scope — the key, the kind, the username parsed from the signed
// blob, and, for a bound login, the host key named in the payload — because then
// there is no unverified word for the promise to lean on. A bound login's
// destination label is left out on purpose: the scope pins it, but the host key
// behind it is proven against the payload, so it is not the peer's word in the
// way a repository is.
func AssertedScope(req *ladulasv1.ApprovalRequest) []Detail {
	var facts []Detail

	if repo := req.GetSshsig().GetGitContext().GetRepositoryPath(); repo != "" {
		facts = append(facts, Detail{
			Label:    "Repository",
			Value:    repo,
			Asserted: true,
		})
	}

	// A grant request's host key is asserted too — nothing has been signed, so
	// it is this machine's word rather than a fact proven inside a payload
	// (decision AO). It is not listed here, and the reason is worth writing
	// down: this function feeds the note shown when a promise would rest on
	// *another* machine's word, and a grant request only ever comes from this
	// one. The card says where the host key came from in its own row, which is
	// where somebody deciding will read it.
	return facts
}

// withRequestedTTL puts a requester's asked-for length among the ones the
// prompt offers as a single tap, sorted so the list still reads as a scale.
//
// Over the instance's bound it is dropped rather than clamped, and in silence:
// a length nobody offered must not appear on a card, and a length trimmed to
// fit is a different promise from the one that was asked for. The requester
// hears about it the way it hears about everything else — in what was actually
// granted.
func withRequestedTTL(
	ttls []time.Duration, requested, maxTTL time.Duration,
) []time.Duration {
	if requested <= 0 || requested > maxTTL {
		return ttls
	}

	if slices.Contains(ttls, requested) {
		return ttls
	}

	out := append(slices.Clone(ttls), requested)
	slices.Sort(out)

	return out
}

// covers reports whether a promise made under one scope answers a request.
//
// It is not symmetric, and the asymmetry is the whole of decision U: a promise
// made to a session is kept for that session and nowhere else, and a promise
// made where there was no session to speak of — before this existed, or to a
// requester that named no process — goes on covering whatever the rest of the
// scope allows. That is what "approve for an hour" used to mean, and a stored
// grant should not change meaning because the code around it grew a field.
func covers(scope *ladulasv1.GrantScope, req *ladulasv1.ApprovalRequest) bool {
	want := scopeFor(req)

	if scope.GetKeyFingerprint() != want.GetKeyFingerprint() ||
		scope.GetKind() != want.GetKind() ||
		scope.GetDestinationFingerprint() != want.GetDestinationFingerprint() ||
		scope.GetRepository() != want.GetRepository() ||
		scope.GetRequesterInstanceId() != want.GetRequesterInstanceId() ||
		scope.GetUsername() != want.GetUsername() {
		return false
	}

	if scope.GetSessionId() == 0 {
		return true
	}

	return scope.GetSessionId() == want.GetSessionId()
}

// findGrant returns the live grant covering a request, if any.
func findGrant(
	grants []*ladulasv1.Grant, req *ladulasv1.ApprovalRequest, now time.Time,
) *ladulasv1.Grant {
	for _, grant := range grants {
		if !grant.GetExpiresAt().AsTime().After(now) {
			continue
		}

		if covers(grant.GetScope(), req) {
			return grant
		}
	}

	return nil
}

// grantScopeFor is the scope a promise of this reach is made under.
//
// A machine-wide promise is the request's scope with the session taken out of
// it, which is exactly the shape covers() has always read as "any session on
// that machine". So widening a promise reuses the meaning grants had before
// decision U rather than introducing a second one, and a delegate running older
// code applies it correctly without being told anything new.
func grantScopeFor(
	req *ladulasv1.ApprovalRequest, reach GrantReach,
) *ladulasv1.GrantScope {
	scope := scopeFor(req)

	if reach == GrantReachMachine {
		scope.SessionId = 0
	}

	return scope
}

// newGrant builds the grant a prompt asked for.
func newGrant(
	req *ladulasv1.ApprovalRequest, ttl time.Duration, reach GrantReach,
	now time.Time,
) *ladulasv1.Grant {
	scope := grantScopeFor(req, reach)
	promise := GrantPromise(req, reach)

	return &ladulasv1.Grant{
		GrantId:         identity.NewRequestID(),
		Scope:           scope,
		CreatedAt:       timestamppb.New(now),
		ExpiresAt:       timestamppb.New(now.Add(ttl)),
		OriginRequestId: req.GetRequestId(),
		Description:     DescribeScope(scope, promise, ttl),
		PromiseSubject:  promise,
	}
}

// extendPromise works out what a promise with more time on it looks like: the
// amended record, and — when the promise was handed over — the artifact that
// has to reach its holder for the extension to mean anything (decision P).
func (e *Engine) extendPromise(
	grant *ladulasv1.Grant, extra, max time.Duration, now time.Time,
) (*ladulasv1.Grant, *ladulasv1.SignedDelegation, error) {
	// The same bound as making one, and here for the same reason (decision V):
	// an extension is a promise being made, and "extend" is not a word that
	// should reach past what "approve for a while" can.
	if extra < time.Minute {
		return nil, nil, fmt.Errorf(
			"%w: a promise is at least a minute long", ErrGrantTooLong)
	}

	if max > 0 && extra > max {
		return nil, nil, fmt.Errorf("%w: %s is the longest",
			ErrGrantTooLong, HumanDuration(max))
	}

	amended := extendedGrant(grant, extra, now)

	if !grant.GetDelegated() {
		return amended, nil, nil
	}

	// The same identifier, so that the requester replaces what it holds rather
	// than keeping two records of one promise, and so that everything already
	// reported against it goes on belonging to it.
	d := &ladulasv1.Delegation{
		DelegationId:         grant.GetGrantId(),
		Scope:                grant.GetScope(),
		CreatedAt:            grant.GetCreatedAt(),
		ExpiresAt:            amended.GetExpiresAt(),
		OriginRequestId:      grant.GetOriginRequestId(),
		Description:          amended.GetDescription(),
		ApproverFingerprint:  e.identity.Fingerprint(),
		ApproverName:         e.identity.Name(),
		RequesterFingerprint: grant.GetDelegateFingerprint(),
	}

	signed, err := e.identity.SignDelegation(d)
	if err != nil {
		return nil, nil, fmt.Errorf("sign the extended delegation: %w", err)
	}

	return amended, signed, nil
}

// extendedGrant is a promise with more time on it: the same promise, the same
// identifier, the same ledger, running until later.
//
// The length is from now rather than added to what was left, because that is
// what somebody dialling a clock means by it — "keep this going for another
// two hours" — and because it is what lets the same bound apply to extending
// as to granting. An extension can top a promise back up to the longest this
// instance makes and never past it (decision V).
//
// The sentence is re-rendered, which is the whole reason a grant remembers who
// it was promised to: a row reading "for 1 hour" on a promise that now runs
// three is exactly the kind of quiet untruth a list of standing permissions
// cannot afford. An older grant that remembers no subject loses the phrase
// rather than keeping a stale one.
func extendedGrant(
	grant *ladulasv1.Grant, extra time.Duration, now time.Time,
) *ladulasv1.Grant {
	out := proto.CloneOf(grant)

	out.ExpiresAt = timestamppb.New(now.Add(extra))
	out.Description = DescribeScope(
		grant.GetScope(), grant.GetPromiseSubject(), extra)

	return out
}

// DescribeScope renders a grant scope the way it was offered on the prompt, so
// the audit log and any later listing say the same thing the user agreed to.
//
// The subject is who the promise was made to — the editor or the terminal window
// the request came from (decision U) — and is passed in rather than read off the
// scope, because it is a name and the scope holds an identifier. A name that
// changed later must not stop a promise matching, and a promise that has expired
// must still read as the sentence somebody agreed to.
func DescribeScope(
	scope *ladulasv1.GrantScope, subject string, ttl time.Duration,
) string {
	what := "requests"

	switch scope.GetKind() {
	case ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH:
		if scope.GetDestinationFingerprint() != "" {
			what = fmt.Sprintf("SSH logins as %s to %s",
				scope.GetUsername(), scope.GetDestination())
		} else {
			what = "SSH logins to unidentified destinations"
		}
	case ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN:
		if scope.GetRepository() != "" {
			what = "git signing in " + scope.GetRepository()
		} else {
			what = "git signing"
		}
	case ladulasv1.RequestKind_REQUEST_KIND_SSHSIG:
		what = "SSHSIG signing"
	case ladulasv1.RequestKind_REQUEST_KIND_UNSPECIFIED,
		ladulasv1.RequestKind_REQUEST_KIND_OPAQUE_SIGN,
		ladulasv1.RequestKind_REQUEST_KIND_KEY_LIST,
		ladulasv1.RequestKind_REQUEST_KIND_PAIRING:
	}

	if subject != "" {
		return fmt.Sprintf("%s with this key from %s, for %s",
			what, subject, HumanDuration(ttl))
	}

	return fmt.Sprintf("%s with this key, for %s", what, HumanDuration(ttl))
}

// HumanDuration renders a promise's length the way somebody agreeing to it
// would say it.
//
// It spells the hours and the minutes both, because a length is now chosen on a
// clock rather than picked off a list of four (decision V): "90 minutes" was a
// fine rendering of an option nobody could type, and a poor one of an hour and a
// half somebody dialled themselves.
func HumanDuration(d time.Duration) string {
	if d < time.Minute {
		return d.String()
	}

	hours := int(d / time.Hour)
	minutes := int(d%time.Hour) / int(time.Minute)

	switch {
	case hours == 0:
		return plural(int32(minutes), "minute", "minutes")
	case minutes == 0:
		return plural(int32(hours), "hour", "hours")
	default:
		return plural(int32(hours), "hour", "hours") + " " +
			plural(int32(minutes), "minute", "minutes")
	}
}
