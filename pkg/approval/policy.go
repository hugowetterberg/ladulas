package approval

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Default timeouts (§9). SSH authentication is bounded by the far server's
// LoginGraceTime, typically 120 seconds, so 90 leaves room to answer and still
// complete the handshake.
//
// Signing is bounded by nothing: git and ssh-keygen block happily, and the two
// costs are not symmetric. A request that waits too long costs a terminal
// somebody has walked away from. A request that gives up too early costs the
// commit: git aborts, whatever was in the middle of being done is started
// again, and the person answering is punished for having been in another room.
//
// It was five minutes, which is long enough to walk to the kitchen and not
// long enough to be in a meeting, so the failure it produced was the ordinary
// one: the phone was in a pocket and the answer arrived to a request that had
// already given up. An hour covers being away from the desk without being a
// length anybody would plan around, and it leaves room to actually read the
// diff on the prompt, which is what the rich prompt is for (§5).
const (
	DefaultSSHAuthTimeout = 90 * time.Second
	DefaultSignTimeout    = time.Hour
)

// MinSignTimeout and MaxSignTimeout bound what a surface may set the signing
// budget to.
//
// They are not a bound on the policy document. A hand-edited policy.json is the
// escape hatch and stays unbounded, because somebody editing the file has said
// what they mean; these are what a settings screen may offer and what the
// control socket accepts from one, which is the same division the grant offer
// draws between the lengths a prompt shows and the length the engine will
// honour (decision V).
//
// The floor is not zero because zero already means something else — a kind with
// no budget waits on its caller's context alone — and a budget of seconds fails
// every request that needs a person. The ceiling is a day because a signing
// request is something somebody is blocked on: past that it is not a budget,
// it is a promise never to give up, and the terminal holding the commit would
// hold it until the machine went down.
const (
	MinSignTimeout = 30 * time.Second
	MaxSignTimeout = 24 * time.Hour
)

// DefaultGrantTTLs are the "approve for a while" options offered on a prompt.
var DefaultGrantTTLs = []time.Duration{
	15 * time.Minute,
	time.Hour,
	3 * time.Hour,
	8 * time.Hour,
}

// Policy is a loaded policy document with the evaluation logic over it.
//
// Rules are evaluated in order and the first match wins, so specific denials
// belong above general approvals. Nothing a policy says can override the hard
// rules in the engine (§9).
type Policy struct {
	doc *ladulasv1.PolicyDocument
}

// DefaultPolicy prompts for everything. It is what a fresh install gets, and
// what a missing policy file falls back to.
func DefaultPolicy() *Policy {
	return &Policy{doc: &ladulasv1.PolicyDocument{
		Version: 1,
		Defaults: &ladulasv1.Defaults{
			UnboundSshAuth: ladulasv1.Action_ACTION_PROMPT,
			Fallback:       ladulasv1.Action_ACTION_PROMPT,
		},
	}}
}

// NewPolicy wraps a policy document.
func NewPolicy(doc *ladulasv1.PolicyDocument) *Policy {
	if doc == nil {
		return DefaultPolicy()
	}

	return &Policy{doc: doc}
}

// LoadPolicy reads a policy from a protojson file. A missing file is not an
// error; it yields DefaultPolicy.
func LoadPolicy(path string) (*Policy, error) {
	body, err := os.ReadFile(path) //nolint:gosec // the path is configuration
	if errors.Is(err, os.ErrNotExist) {
		return DefaultPolicy(), nil
	}

	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}

	var doc ladulasv1.PolicyDocument

	unmarshal := protojson.UnmarshalOptions{DiscardUnknown: false}

	if err := unmarshal.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}

	return NewPolicy(&doc), nil
}

// Save writes the policy back as indented protojson, which is what makes it
// hand-editable.
func (p *Policy) Save(path string) error {
	body, err := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}.Marshal(p.doc)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}

	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		return fmt.Errorf("write policy: %w", err)
	}

	return nil
}

// SetSignTimeout changes the signing budget in the document, so that saving it
// writes the new value and an engine given this policy applies it.
//
// A zero or negative length is refused rather than read as "no budget at all":
// the kinds that wait forever do so because of what they are (§9), and a
// signing request typed into a settings box is not one of them.
func (p *Policy) SetSignTimeout(d time.Duration) error {
	if d < MinSignTimeout || d > MaxSignTimeout {
		return fmt.Errorf(
			"a signing request waits for at least %s and at most %s",
			HumanDuration(MinSignTimeout), HumanDuration(MaxSignTimeout))
	}

	if p.doc.GetDefaults() == nil {
		p.doc.Defaults = &ladulasv1.Defaults{}
	}

	p.doc.Defaults.SignTimeout = durationpb.New(d)

	return nil
}

// Document returns the underlying document.
func (p *Policy) Document() *ladulasv1.PolicyDocument {
	return p.doc
}

// Timeout is how long to wait for an answer to a request of this kind. Zero
// means there is no deadline at all.
//
// A pairing has none. Everything else here is waited for by something that
// cannot wait — an SSH handshake with a grace period, a git command holding a
// terminal — and giving up is the kindest thing to do to it. A pairing
// confirmation is waited for by a record on disk, and the whole of what it
// asks is whether two fingerprints on two screens match, which is a question
// a person can answer tomorrow without it being any less true. The clock that
// does bound a pairing is trust.CodeValidity, and it has already run by the
// time this confirmation exists (§7).
// GrantRequestTimeout is how long to wait for an answer to a request that asks
// for a promise and nothing else (decision AO).
//
// It is the signing budget rather than the SSH one, and that is the whole
// reason the request kind exists. An ordinary login gets ninety seconds because
// the far server's LoginGraceTime is counting and an answer that arrives after
// it is a login that failed anyway. Nothing is counting here: `ssh-grant` holds
// no handshake open, it blocks a command the way git blocks on a commit
// signature, and the cost of giving up early is the same — the person answering
// is punished for having been in another room.
//
// It takes no argument so that it stays bindable (§21); the caller knows it is
// asking about a grant request.
func (p *Policy) GrantRequestTimeout() time.Duration {
	return durationOr(
		p.doc.GetDefaults().GetSignTimeout(), DefaultSignTimeout)
}

func (p *Policy) Timeout(kind ladulasv1.RequestKind) time.Duration {
	defaults := p.doc.GetDefaults()

	switch kind {
	case ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH:
		return durationOr(defaults.GetSshAuthTimeout(), DefaultSSHAuthTimeout)
	case ladulasv1.RequestKind_REQUEST_KIND_PAIRING:
		return 0
	default:
		return durationOr(defaults.GetSignTimeout(), DefaultSignTimeout)
	}
}

// MaxGrantTTL is the longest promise this instance will make.
//
// It is the longest of the offered lengths rather than a setting of its own,
// because that is what the list already meant: an approver who picks a length
// on a clock (decision V) is choosing inside the same bound as one who picked
// the last button, and there is nothing for a policy to configure twice. What
// it is for is the surfaces — a picker stops there, and the bridge refuses
// anything past it, which is what keeps "a length somebody chose" from becoming
// "any length anything that can reach the bridge asks for".
func (p *Policy) MaxGrantTTL() time.Duration {
	var longest time.Duration

	for _, ttl := range p.GrantTTLs() {
		if ttl > longest {
			longest = ttl
		}
	}

	if longest <= 0 {
		return DefaultGrantTTLs[len(DefaultGrantTTLs)-1]
	}

	return longest
}

// GrantTTLs are the TTL options a prompt should offer.
func (p *Policy) GrantTTLs() []time.Duration {
	options := p.doc.GetDefaults().GetGrantTtlOptions()
	if len(options) == 0 {
		return DefaultGrantTTLs
	}

	out := make([]time.Duration, 0, len(options))
	for _, d := range options {
		out = append(out, d.AsDuration())
	}

	return out
}

func durationOr(d *durationpb.Duration, fallback time.Duration) time.Duration {
	if d == nil || d.AsDuration() <= 0 {
		return fallback
	}

	return d.AsDuration()
}

// Evaluation is what the policy has to say about a request.
type Evaluation struct {
	Action ladulasv1.Action
	// Rule is the name of the rule that matched, or a description of the
	// default that applied.
	Rule string
	// Notify says whether an auto-approval should still raise a passive
	// notification on the approver's devices (§9).
	Notify bool
}

// Evaluate runs the policy over a request.
func (p *Policy) Evaluate(req *ladulasv1.ApprovalRequest) Evaluation {
	facts := factsFor(req)

	for _, rule := range p.doc.GetRules() {
		if !matches(rule.GetMatch(), facts) {
			continue
		}

		name := rule.GetName()
		if name == "" {
			name = "unnamed rule"
		}

		return Evaluation{
			Action: rule.GetAction(),
			Rule:   name,
			Notify: rule.GetNotify() || rule.Notify == nil,
		}
	}

	defaults := p.doc.GetDefaults()

	if req.GetKind() == ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH &&
		!req.GetSshAuth().GetBound() {
		return Evaluation{
			Action: actionOr(defaults.GetUnboundSshAuth(), ladulasv1.Action_ACTION_PROMPT),
			Rule:   "default for unbound SSH authentication",
			Notify: true,
		}
	}

	return Evaluation{
		Action: actionOr(defaults.GetFallback(), ladulasv1.Action_ACTION_PROMPT),
		Rule:   "default",
		Notify: true,
	}
}

func actionOr(action, fallback ladulasv1.Action) ladulasv1.Action {
	if action == ladulasv1.Action_ACTION_UNSPECIFIED {
		return fallback
	}

	return action
}

// facts are the request attributes rules match against, pulled out once so the
// matcher does not have to know the shape of every operation type.
type facts struct {
	kind              ladulasv1.RequestKind
	keyFingerprint    string
	keyLabel          string
	destination       []string
	username          string
	repository        []string
	namespace         string
	requesterInstance string
	executable        string
	forwarded         bool
	bound             bool
	local             bool
}

func factsFor(req *ladulasv1.ApprovalRequest) facts {
	f := facts{
		kind:              req.GetKind(),
		keyFingerprint:    req.GetKey().GetFingerprint(),
		keyLabel:          req.GetKey().GetLabel(),
		requesterInstance: req.GetRequester().GetInstanceId(),
		executable:        req.GetRequester().GetProcess().GetExecutable(),
		local:             req.GetRequester().GetLocal(),
	}

	if auth := req.GetSshAuth(); auth != nil {
		f.username = auth.GetUsername()
		f.forwarded = auth.GetForwarded()
		f.bound = auth.GetBound()

		if label := auth.GetDestinationLabel(); label != "" && auth.GetBound() {
			f.destination = append(f.destination, label)
		}

		if host := auth.GetDestination(); host != nil {
			f.destination = append(f.destination, host.GetKnownHostsNames()...)
			f.destination = append(f.destination, host.GetFingerprint())
		}
	}

	if sig := req.GetSshsig(); sig != nil {
		f.namespace = sig.GetNamespace()

		if git := sig.GetGitContext(); git != nil {
			if path := git.GetRepositoryPath(); path != "" {
				f.repository = append(f.repository, path)
			}

			if origin := git.GetOriginUrl(); origin != "" {
				f.repository = append(f.repository, origin)
			}
		}
	}

	return f
}

func matches(m *ladulasv1.Match, f facts) bool {
	if m == nil {
		return true
	}

	if kinds := m.GetKinds(); len(kinds) > 0 {
		found := false

		for _, kind := range kinds {
			if kind == f.kind {
				found = true

				break
			}
		}

		if !found {
			return false
		}
	}

	checks := []struct {
		patterns []string
		values   []string
		fold     bool
	}{
		{m.GetKeyFingerprints(), []string{f.keyFingerprint}, false},
		{m.GetKeyLabels(), []string{f.keyLabel}, true},
		{m.GetDestinations(), f.destination, true},
		{m.GetUsernames(), []string{f.username}, false},
		{m.GetRepositories(), f.repository, false},
		{m.GetNamespaces(), []string{f.namespace}, false},
		{m.GetRequesterInstances(), []string{f.requesterInstance}, false},
		{m.GetExecutables(), []string{f.executable}, false},
	}

	for _, check := range checks {
		if len(check.patterns) == 0 {
			continue
		}

		if !anyMatch(check.patterns, check.values, check.fold) {
			return false
		}
	}

	tristates := []struct {
		want  ladulasv1.Tristate
		value bool
	}{
		{m.GetForwarded(), f.forwarded},
		{m.GetBound(), f.bound},
		{m.GetLocal(), f.local},
	}

	for _, t := range tristates {
		if !tristateMatches(t.want, t.value) {
			return false
		}
	}

	return true
}

func tristateMatches(want ladulasv1.Tristate, value bool) bool {
	switch want {
	case ladulasv1.Tristate_TRISTATE_TRUE:
		return value
	case ladulasv1.Tristate_TRISTATE_FALSE:
		return !value
	case ladulasv1.Tristate_TRISTATE_ANY:
		return true
	default:
		return true
	}
}

func anyMatch(patterns, values []string, fold bool) bool {
	for _, pattern := range patterns {
		for _, value := range values {
			if value == "" {
				continue
			}

			if globMatch(pattern, value, fold) {
				return true
			}
		}
	}

	return false
}

// globMatch is a plain glob: * matches any run of characters including
// separators, ? matches one. path.Match is not used because its refusal to let
// * cross a / makes repository path patterns behave surprisingly.
func globMatch(pattern, value string, fold bool) bool {
	if fold {
		pattern = strings.ToLower(pattern)
		value = strings.ToLower(value)
	}

	return globMatchBytes(pattern, value)
}

func globMatchBytes(pattern, value string) bool {
	// Iterative backtracking: linear in the common case, and bounded even for
	// patterns full of stars.
	var (
		p, v         int
		star         = -1
		valueAtStar  int
		patternRunes = []rune(pattern)
		valueRunes   = []rune(value)
	)

	for v < len(valueRunes) {
		switch {
		case p < len(patternRunes) && (patternRunes[p] == '?' || patternRunes[p] == valueRunes[v]):
			p++
			v++
		case p < len(patternRunes) && patternRunes[p] == '*':
			star = p
			valueAtStar = v
			p++
		case star >= 0:
			p = star + 1
			valueAtStar++
			v = valueAtStar
		default:
			return false
		}
	}

	for p < len(patternRunes) && patternRunes[p] == '*' {
		p++
	}

	return p == len(patternRunes)
}
