// Package bridge is the contract between the shared viewer bundle and the Go
// core: an http.Handler serving the bundle and a small JSON API beside it
// (docs/architecture.md §12, open question 5).
//
// It deliberately depends on nothing platform-specific. The desktop hands this
// handler to Wails as its asset handler; a WKWebView hands it a request from a
// URL scheme handler and an Android WebView from shouldInterceptRequest, both
// through Call below. One contract, and the hosts differ only in how a method,
// a path and a body reach it — which is the whole of what a webview can do
// anyway.
//
// The other half of the contract is the Presenter: the bridge knows that a
// request needs a human, and the host knows what showing a human something
// means on its platform. A window on the desktop, a view controller on iOS, a
// notification with actions on Android.
package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/avatar"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/viewer"
)

// maxRecent bounds the activity list.
const maxRecent = 50

// ErrNoSuchRequest is returned when answering something that is not waiting.
var ErrNoSuchRequest = errors.New("bridge: no such pending request")

// ErrNoSuchGrant is what a host wraps when the identifier is the problem, as
// opposed to the machine holding the grant being unreachable. The two are
// different answers: one means nothing needed to happen, the other means
// something needed to and did not.
var ErrNoSuchGrant = errors.New("bridge: no such grant")

// ErrGrantTooLong is what a host wraps when an extension asks for longer than
// this instance promises anything for (decision V). It is the caller's mistake
// rather than a failure to reach anybody, and the surfaces say so differently.
var ErrGrantTooLong = errors.New("bridge: longer than this instance promises")

// ExtendFailure turns what the engine says about an extension into what a
// host's option is documented to return, so that the two hosts do not each
// invent their own mapping of the same three answers.
func ExtendFailure(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, approval.ErrNoSuchGrant):
		return fmt.Errorf("%w: %w", ErrNoSuchGrant, err)
	case errors.Is(err, approval.ErrGrantTooLong):
		return fmt.Errorf("%w: %w", ErrGrantTooLong, err)
	default:
		return err
	}
}

// Presenter is the host's half of the contract: it puts a request in front of
// a human, and takes it away again when it has been settled or withdrawn.
type Presenter interface {
	// Present is called from the goroutine deciding the request. It must not
	// block waiting for the answer — the bridge does that.
	Present(req *PendingRequest)
	// Dismiss is called once, whatever the outcome.
	Dismiss(id string)
}

// Announcer is an optional Presenter capability: the passive notification an
// auto-approved request still gets (§9).
type Announcer interface {
	Announce(activity ActivityView)
}

// PendingRequest is a request on screen.
type PendingRequest struct {
	ID      string
	Request *approval.Request
	// Since is when it started waiting.
	Since time.Time
	// URL is where a host should point a webview to show it.
	URL string

	answer chan *approval.Answer
	once   sync.Once
}

func (p *PendingRequest) settle(answer *approval.Answer) {
	p.once.Do(func() {
		p.answer <- answer
	})
}

// Location is one "this lives here" row of the status pane.
type Location struct {
	Label string
	Path  string
}

// Delegation is one standing permission this instance holds and applies itself
// (decision P), as a host reports it.
//
// It is a type of this package's own rather than the store's document, because
// a host may be a front end that has never opened a store: what reaches it over
// a socket is an account of a delegation, and the view was reading four fields
// of one anyway. The signed artifact is not among them — a listing answers
// which promise is being acted on, not what the bytes were (§14).
type Delegation struct {
	Delegation *ladulasv1.Delegation
	// ReceivedAt is when it arrived. Zero when nobody recorded that.
	ReceivedAt time.Time
	// UseCount is everything self-approved under it, and Unreported how much of
	// that the approver has not been told about yet. The second is a machine
	// that has been out of touch rather than a fault, and reads as one.
	UseCount   int
	Unreported int
}

// Options configure a session.
type Options struct {
	// Name and Fingerprint identify the instance in the status pane.
	Name        string
	Fingerprint string
	// Locations are the paths worth showing: the sockets, the policy, the log.
	Locations []Location
	// Keys lists the keys the instance holds. Optional.
	Keys func() []*ladulasv1.KeyRef
	// Borrowed lists the keys paired instances offer, reachable or not (§10,
	// decision N). Optional: an instance with peering off borrows nothing.
	Borrowed func() []*ladulasv1.BorrowedKeyStatus
	// Grants lists the live TTL grants, and RevokeGrant takes one back (§9).
	// Both optional, and optional separately: a host can show what it has
	// promised without being the place the promise is withdrawn.
	//
	// RevokeGrant is expected to report a grant that is not live as an error
	// rather than as a success. Revoking is idempotent in the store, which
	// makes a stale identifier look like it worked, and somebody taking a
	// promise back wants to be told they took back the one they meant.
	Grants func() ([]*ladulasv1.Grant, error)
	// RevokeGrant takes a context because revoking a delegated grant is a call
	// to the machine holding it, and one that is allowed to fail: the local
	// record is the smaller half of a promise somebody else acts on alone. A
	// host wraps ErrNoSuchGrant when the identifier is the problem, so that
	// "there is no such grant" and "it could not be taken back" are not the
	// same answer.
	RevokeGrant func(ctx context.Context, id string) error
	// ExtendGrant gives a promise more time, counted from now (decision V).
	// Optional beside RevokeGrant: a host can show what it promised and end it
	// without being the place it is topped back up.
	//
	// It takes a context for the same reason revoking does — a promise that was
	// handed over has to reach its holder before the record here may say
	// anything longer — and reports ErrNoSuchGrant the same way.
	ExtendGrant func(ctx context.Context, id string, extra time.Duration) error
	// Delegations lists the standing permissions this instance was given and
	// applies itself (decision P). Optional, and there is no revoking one from
	// here: a promise made elsewhere is stopped where it was made.
	Delegations func() ([]Delegation, error)
	// Peers lists the paired instances and whether they can be reached.
	// Optional: an instance with peering off has none to list.
	Peers func() []PeerView
	// Pairings lists the pairings under way, and Withdraw calls one off (§7).
	// Optional together: a host without them shows no pairings section, which
	// is right for an instance with no peer channel.
	//
	// Answering one is not here, because answering one is a card and a card is
	// a request like any other. What is here is the half a card cannot show:
	// the pairing this side has already agreed to and the other side has not.
	Pairings func() []PairingSummaryView
	Withdraw func(session string) error
	// Projects is the documentation paired instances have published here (§6).
	// Optional.
	Projects Projects
	// FetchDiff asks the requester for the rest of a diff the caps cut short
	// (§5). Optional; without it the viewer does not offer to.
	FetchDiff func(
		ctx context.Context, req *approval.Request, path string,
	) (*ladulasv1.GitDiff, error)
	// History is what this instance has decided, from a record that outlives
	// the process — the audit log. Optional, and without it the activity list
	// is only what happened since the app started, and has nothing to open.
	//
	// It hands back the entries rather than the rendered rows because the rows
	// are not all of it: an entry is also the card that was in front of somebody
	// when they decided, which is what makes an activity row worth tapping.
	History func(limit int) ([]*ladulasv1.AuditEntry, error)
	// Reload re-reads the store and policy, for the viewer's reload action.
	// Optional.
	Reload func() error
	// Lock is the store's lock state and the way to change it (§10). Optional:
	// without one the viewer shows no unlock panel.
	Lock Lock
	// Presenter is the host. Without one the session answers nothing, which is
	// the right behaviour for a host that has not started yet.
	Presenter Presenter
	// ID names this approver in the audit log. Defaults to "desktop".
	ID string
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

// Session is a viewer host's connection to the approval engine. It is an
// approval.Handler, so registering it is what makes a front end an approver.
type Session struct {
	opts Options
	id   string
	log  *slog.Logger
	now  func() time.Time

	mu          sync.Mutex
	name        string
	fingerprint string
	locations   []Location
	presenter   Presenter
	pending     map[string]*PendingRequest
	recent      []ActivityView
}

var (
	_ approval.Handler     = (*Session)(nil)
	_ approval.Notifier    = (*Session)(nil)
	_ approval.LocalPrompt = (*Session)(nil)
)

// NewSession creates a session.
func NewSession(opts Options) *Session {
	if opts.ID == "" {
		opts.ID = "desktop"
	}

	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	if opts.Now == nil {
		opts.Now = time.Now
	}

	return &Session{
		opts:        opts,
		id:          opts.ID,
		log:         opts.Logger,
		now:         opts.Now,
		name:        opts.Name,
		fingerprint: opts.Fingerprint,
		locations:   opts.Locations,
		presenter:   opts.Presenter,
		pending:     map[string]*PendingRequest{},
	}
}

// SetLocations replaces the paths the status pane shows.
//
// It is SetInstance's neighbour and exists for the same reason: a host that is
// not the instance learns where the files are from the instance, and only once
// it has found one (decision Z). Where a daemon keeps its store is the daemon's
// answer to give — a front end started from a menu was not started with the
// unit's environment, so working it out here would show paths that are right
// only by luck.
func (s *Session) SetLocations(locations []Location) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.locations = locations
}

func (s *Session) locationList() []Location {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.locations
}

// SetInstance names the instance in the status pane.
//
// A desktop knows both at construction, because the tray is built after the
// store has been opened at least once. A phone starts locked and learns its own
// fingerprint when somebody unlocks it, and the status pane should say so
// rather than showing a blank where an identity goes.
func (s *Session) SetInstance(name, fingerprint string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.name = name
	s.fingerprint = fingerprint
}

func (s *Session) instance() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.name, s.fingerprint
}

// SetPresenter installs, or replaces, the host.
//
// The desktop has no use for it: Wails is built around the session and the
// session around Wails in one call. A phone shell is the other order — the
// webview that draws the prompt is loaded from this very handler, so the host
// cannot exist until the session does (§12). A session with no host answers
// nothing, which is the right behaviour for a core whose UI has not started.
func (s *Session) SetPresenter(presenter Presenter) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.presenter = presenter
}

func (s *Session) host() Presenter {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.presenter
}

// ID implements approval.Handler.
func (s *Session) ID() string {
	return s.id
}

// LocalPrompt implements approval.LocalPrompt: a viewer host draws on a screen
// somebody has to be in front of, which is exactly what a soft lock says is not
// the case (§10).
func (s *Session) LocalPrompt() {
}

// Decide implements approval.Handler: it puts the request in front of the host
// and waits.
//
// A context that finishes first — another approver answered, or the requester
// gave up — is not an answer, so it returns an error rather than a denial. The
// engine has already settled the request by then.
func (s *Session) Decide(
	ctx context.Context, req *approval.Request,
) (*approval.Answer, error) {
	host := s.host()
	if host == nil {
		return nil, errors.New("bridge: no host to show the request on")
	}

	id := req.Msg.GetRequestId()

	pending := &PendingRequest{
		ID:      id,
		Request: req,
		Since:   s.now(),
		URL:     "/?request=" + id,
		answer:  make(chan *approval.Answer, 1),
	}

	s.mu.Lock()
	s.pending[id] = pending
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()

		host.Dismiss(id)
	}()

	host.Present(pending)

	select {
	case answer := <-pending.answer:
		s.record(req, describeAnswer(answer))

		return answer, nil
	case <-ctx.Done():
		s.record(req, unansweredOutcome(ctx.Err()))

		return nil, ctx.Err() //nolint:wrapcheck // the engine matches on it
	}
}

// unansweredOutcome names the way a request ended with nobody having answered
// it.
//
// The engine already draws the distinction when it denies (§9) and it is the
// whole of what the person who did not answer needs to know: "nobody answered
// in time" is the instruction to be quicker, and "withdrawn" is the statement
// that somebody else settled it or the requester gave up. Recording both as
// withdrawn made a card that timed out look like one that had been called off.
func unansweredOutcome(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "not answered in time"
	}

	return "withdrawn"
}

// Notify implements approval.Notifier.
func (s *Session) Notify(req *approval.Request, resp *ladulasv1.ApprovalResponse) {
	outcome := "auto-approved"
	if resp.GetSource() == ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		outcome = "covered by a grant"
	}

	activity := s.record(req, outcome)

	if announcer, ok := s.host().(Announcer); ok {
		announcer.Announce(activity)
	}
}

// Answer settles a pending request. The viewer calls it through the API; a host
// can call it directly for a notification action button.
func (s *Session) Answer(id string, answer *approval.Answer) error {
	s.mu.Lock()
	pending := s.pending[id]
	s.mu.Unlock()

	if pending == nil {
		return ErrNoSuchRequest
	}

	pending.settle(answer)

	return nil
}

// Deny settles a request as a refusal, which is what a host does when its
// window is closed without an answer. Anything else would mean a stray click
// could approve.
func (s *Session) Deny(id, reason string) {
	_ = s.Answer(id, &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_DENY,
		Reason:   reason,
	})
}

// Pending returns the requests still waiting, oldest first.
func (s *Session) Pending() []*PendingRequest {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]*PendingRequest, 0, len(s.pending))
	for _, pending := range s.pending {
		out = append(out, pending)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Since.Before(out[j].Since)
	})

	return out
}

func (s *Session) lookup(id string) *PendingRequest {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.pending[id]
}

func (s *Session) record(req *approval.Request, outcome string) ActivityView {
	title := req.Prompt.Title
	if req.Prompt.Subject != "" {
		title += " — " + req.Prompt.Subject
	}

	now := s.now()

	activity := ActivityView{
		When:    now.Format("15:04:05"),
		WhenAt:  now.Format(time.RFC3339),
		Title:   title,
		Outcome: outcome,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.recent = append(s.recent, activity)

	if len(s.recent) > maxRecent {
		s.recent = s.recent[len(s.recent)-maxRecent:]
	}

	return activity
}

// Recent returns the activity list, newest first.
//
// It prefers the host's persisted history, because the alternative — the list
// this session has built up since it started — is gone the moment the process
// is. On a desktop that is rare enough to have gone unnoticed; on a phone the
// process is killed whenever iOS wants the memory, so "what have I approved"
// answered nothing an hour after answering it.
//
// The in-memory list stays as the fallback for a host that keeps no log, and
// for the moment between a decision being made and its entry being written.
func (s *Session) Recent() []ActivityView {
	if entries, err := s.history(maxRecent); err != nil {
		s.log.Warn("could not read the activity history", "error", err.Error())
	} else if history := activityFromAudit(entries); len(history) > 0 {
		return history
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]ActivityView, len(s.recent))

	for i, item := range s.recent {
		out[len(s.recent)-1-i] = item
	}

	return out
}

// activityFromAudit renders persisted audit entries as the activity list,
// newest first.
//
// It is here rather than in the hosts so that a decision made a minute ago and
// one read back from the log a week later are described in the same words: both
// go through approval.RenderPrompt, which is the same function that worded the
// card at the time.
func activityFromAudit(entries []*ladulasv1.AuditEntry) []ActivityView {
	out := make([]ActivityView, 0, len(entries))

	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]

		if entry.GetEvent() != ladulasv1.AuditEvent_AUDIT_EVENT_DECISION {
			continue
		}

		out = append(out, activityView(entry))
	}

	return out
}

func activityView(entry *ladulasv1.AuditEntry) ActivityView {
	prompt := approval.RenderPrompt(entry.GetRequest())

	title := prompt.Title
	if prompt.Subject != "" {
		title += " — " + prompt.Subject
	}

	at := entry.GetTimestamp().AsTime()

	return ActivityView{
		ID:      entry.GetEntryId(),
		When:    at.Local().Format("15:04:05"),
		WhenAt:  at.Format(time.RFC3339),
		Title:   title,
		Outcome: describeDecision(entry.GetResponse()),
	}
}

// history reads the log, or says there is none to read.
func (s *Session) history(limit int) ([]*ladulasv1.AuditEntry, error) {
	if s.opts.History == nil {
		return nil, nil
	}

	return s.opts.History(limit)
}

// handleActivity is one past decision, opened again (§18).
//
// A row in the activity list is worth tapping because the log kept more than
// the row: it kept the request as it was evaluated and the panel the host drew
// beside it, so the card can be put back on screen as it stood rather than
// summarised after the fact. What it does not get back are the buttons — this
// was decided, and the decision is part of what is shown.
func (s *Session) handleActivity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	entries, err := s.history(maxRecent * auditLinesPerDecision)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())

		return
	}

	for _, entry := range entries {
		if entry.GetEntryId() != id ||
			entry.GetEvent() != ladulasv1.AuditEvent_AUDIT_EVENT_DECISION {
			continue
		}

		writeJSON(w, http.StatusOK, s.activityDetail(entry))

		return
	}

	writeError(w, http.StatusNotFound,
		"this instance's log does not go back to that decision")
}

// auditLinesPerDecision is how many lines the log holds around one decision, so
// that looking for one among the last maxRecent asks for enough of them: the
// request, the decision, usually a signature, sometimes an error.
const auditLinesPerDecision = 4

func (s *Session) activityDetail(entry *ladulasv1.AuditEntry) ActivityDetailView {
	msg := entry.GetRequest()

	// The card is rendered from the request the way it was rendered then —
	// RenderPrompt is the same function — and carries no grant options, because
	// the offer to approve for an hour was made once and is not being made again.
	request := requestView(&approval.Request{
		Msg:    msg,
		Prompt: approval.RenderPrompt(msg),
	})

	request.Project = projectShown(entry.GetProjectShown())

	return ActivityDetailView{
		ActivityView: activityView(entry),
		Request:      request,
		Decided:      describeDecider(entry.GetResponse()),
		Reason:       entry.GetResponse().GetReason(),
		Prompt:       entry.GetPromptShown(),
	}
}

// describeDecider says who answered and on what footing, which is the question
// an activity row raises that the outcome does not: "approved" by somebody
// looking at it, by a promise made earlier, or by a rule, are three different
// things to have happened (§9).
func describeDecider(resp *ladulasv1.ApprovalResponse) string {
	who := resp.GetApprover().GetName()
	if who == "" {
		who = "this instance"
	}

	switch resp.GetSource() {
	case ladulasv1.DecisionSource_DECISION_SOURCE_GRANT:
		return "Covered by a standing grant at " + who
	case ladulasv1.DecisionSource_DECISION_SOURCE_POLICY:
		return "Decided by policy at " + who
	case ladulasv1.DecisionSource_DECISION_SOURCE_HARD_RULE:
		return "Refused by a rule nothing overrides"
	case ladulasv1.DecisionSource_DECISION_SOURCE_TIMEOUT:
		return "Nobody answered in time"
	case ladulasv1.DecisionSource_DECISION_SOURCE_CANCELLED:
		return "Called off before it was answered"
	case ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER:
		return "There was nobody to ask"
	case ladulasv1.DecisionSource_DECISION_SOURCE_ERROR:
		return "Something went wrong before anybody was asked"
	case ladulasv1.DecisionSource_DECISION_SOURCE_USER,
		ladulasv1.DecisionSource_DECISION_SOURCE_UNSPECIFIED:
	}

	return "Answered at " + who
}

func describeDecision(response *ladulasv1.ApprovalResponse) string {
	if response.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		return "denied"
	}

	// A grant on the response is an answer that covered more than the one
	// request, and its length is the difference between the two timestamps it
	// was written with rather than a field of its own.
	if grant := response.GetGrant(); grant != nil {
		ttl := grant.GetExpiresAt().AsTime().Sub(grant.GetCreatedAt().AsTime())
		if ttl > 0 {
			return "approved for " + HumanDuration(ttl)
		}
	}

	return "approved"
}

func describeAnswer(answer *approval.Answer) string {
	if answer == nil || answer.Decision != ladulasv1.Decision_DECISION_APPROVE {
		return "denied"
	}

	if answer.GrantTTL > 0 {
		return "approved for " + HumanDuration(answer.GrantTTL)
	}

	return "approved"
}

// Handler is the whole bridge: the viewer bundle, and the JSON API under
// /api/v1 that it talks to.
func (s *Session) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/instance", s.handleInstance)
	mux.HandleFunc("POST /api/v1/reload", s.handleReload)
	mux.HandleFunc("GET /api/v1/lock", s.handleLockState)
	mux.HandleFunc("POST /api/v1/lock/unlock", s.handleUnlock)
	mux.HandleFunc("POST /api/v1/lock/lock", s.handleLock)
	mux.HandleFunc("GET /api/v1/requests", s.handleRequests)
	mux.HandleFunc("GET /api/v1/requests/{id}", s.handleRequest)
	mux.HandleFunc("POST /api/v1/requests/{id}/answer", s.handleAnswer)
	mux.HandleFunc("POST /api/v1/requests/{id}/diff", s.handleRequestDiff)
	mux.HandleFunc("GET /api/v1/activity/{id}", s.handleActivity)
	mux.HandleFunc("POST /api/v1/pairings/{session}/withdraw", s.handleWithdraw)
	mux.HandleFunc("POST /api/v1/grants/{id}/revoke", s.handleRevokeGrant)
	mux.HandleFunc("POST /api/v1/grants/{id}/extend", s.handleExtendGrant)
	mux.HandleFunc("GET /api/v1/avatar", s.handleAvatar)
	// The browsing calls name a project by peer and project id in the query
	// rather than in the path (§6): a fingerprint carries slashes, and a path
	// segment that has to be escaped to hold one is a trap for whichever host
	// forgets to.
	mux.HandleFunc("GET /api/v1/projects", s.handleProjects)
	mux.HandleFunc("GET /api/v1/projects/one", s.handleProject)
	mux.HandleFunc("GET /api/v1/projects/directory", s.handleProjectDirectory)
	mux.HandleFunc("GET /api/v1/projects/search", s.handleProjectSearch)
	mux.HandleFunc("GET /api/v1/projects/file", s.handleProjectFile)

	// Anything that is not the API is the bundle, including the paths the
	// viewer's own routing uses.
	mux.Handle("/", viewer.Handler())

	return mux
}

func (s *Session) handleRequests(w http.ResponseWriter, _ *http.Request) {
	pending := s.Pending()

	views := make([]PendingView, 0, len(pending))

	for _, item := range pending {
		views = append(views, pendingView(item))
	}

	writeJSON(w, http.StatusOK, views)
}

// pendingView is the one place a waiting request is described, so that the
// status pane and a shell restoring a card after a trip to the home screen are
// looking at the same thing.
func pendingView(item *PendingRequest) PendingView {
	return PendingView{
		ID:      item.ID,
		Kind:    kindName(item.Request.Msg.GetKind()),
		Title:   item.Request.Prompt.Title,
		Subject: item.Request.Prompt.Subject,
		Since:   item.Since.Format(time.RFC3339),
		URL:     item.URL,
	}
}

func (s *Session) handleRequest(w http.ResponseWriter, r *http.Request) {
	pending := s.lookup(r.PathValue("id"))
	if pending == nil {
		writeError(w, http.StatusNotFound, "this request is no longer waiting")

		return
	}

	view := requestView(pending.Request)
	view.Project = s.requestProject(pending.Request)

	// The log keeps what was drawn, not what could be worked out again later.
	// The documentation panel is the one part of a card that is this instance's
	// own state rather than a rendering of the request, so it is handed to the
	// engine now, while it still says what it said (§6, §18).
	pending.Request.Presented(presentedProject(view.Project))

	writeJSON(w, http.StatusOK, view)
}

// answerBody is what a surface sends back: the decision, and the promise that
// goes with it when there is one.
type answerBody struct {
	Decision     string `json:"decision"`
	GrantSeconds int64  `json:"grantSeconds"`
	// GrantScope is how far the promise reaches: "session" (the default, and
	// the narrower) or "machine" (decision V).
	GrantScope string `json:"grantScope"`
}

func (s *Session) handleAnswer(w http.ResponseWriter, r *http.Request) {
	var body answerBody

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "the answer could not be read")

		return
	}

	id := r.PathValue("id")

	pending := s.lookup(id)
	if pending == nil {
		writeError(w, http.StatusNotFound, "this request is no longer waiting")

		return
	}

	answer := &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_DENY,
		Reason:   "denied at the " + s.id,
	}

	if strings.EqualFold(body.Decision, "approve") {
		answer.Decision = ladulasv1.Decision_DECISION_APPROVE
		answer.Reason = "approved at the " + s.id

		if body.GrantSeconds > 0 {
			ttl, reach, err := grantAsked(pending.Request, body)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())

				return
			}

			answer.GrantTTL = ttl
			answer.GrantReach = reach
			answer.Reason = fmt.Sprintf("approved at the %s for %s",
				s.id, HumanDuration(ttl))

			// A promise with somebody to name says who it was made to, because
			// that half of it is the half a log read later cannot work out.
			if promise := approval.GrantPromise(
				pending.Request.Msg, reach); promise != "" {
				answer.Reason = fmt.Sprintf("approved at the %s for %s, for %s",
					s.id, promise, HumanDuration(ttl))
			}
		}
	}

	if err := s.Answer(id, answer); err != nil {
		writeError(w, http.StatusNotFound, "this request is no longer waiting")

		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// minGrantTTL is the shortest promise worth making. The surfaces choose a
// length in hours and minutes (decision V), so anything under a minute is a
// dialled zero rather than a promise.
const minGrantTTL = time.Minute

// grantAsked reads the promise an answer asked for, and refuses one this
// instance did not offer.
//
// The length no longer has to be one of four the prompt named, because the
// prompt no longer names four — but it is still bounded, and for the same
// reason it was bounded before: the bridge is reachable by everything in the
// app, and a duration taken straight from a caller would let any of it mint a
// promise of its own length. What changed is that the bound is a maximum
// instead of a list.
func grantAsked(
	req *approval.Request, body answerBody,
) (time.Duration, approval.GrantReach, error) {
	var reach approval.GrantReach

	switch strings.ToLower(body.GrantScope) {
	case "", "session":
		reach = approval.GrantReachSession
	case "machine":
		reach = approval.GrantReachMachine
	default:
		return 0, 0, errors.New("that is not a scope a promise can have")
	}

	ttl := time.Duration(body.GrantSeconds) * time.Second

	if ttl < minGrantTTL {
		return 0, 0, errors.New("a promise is at least a minute long")
	}

	// A prompt that offered no bound offered no promise either, and the answer
	// to "how long may this run" is not a value to fall back on when it is
	// missing.
	if req.GrantMaxTTL <= 0 {
		return 0, 0, errors.New("this request cannot be approved for a while")
	}

	if ttl > req.GrantMaxTTL {
		return 0, 0, errors.New(
			"this instance does not promise anything for longer than " +
				HumanDuration(req.GrantMaxTTL))
	}

	return ttl, reach, nil
}

func (s *Session) handleInstance(w http.ResponseWriter, _ *http.Request) {
	name, fingerprint := s.instance()

	view := InstanceView{
		Name:        name,
		Fingerprint: fingerprint,
		Recent:      s.Recent(),
	}

	if s.opts.Lock != nil {
		state := s.opts.Lock.State()
		view.Lock = &state
	}

	for _, location := range s.locationList() {
		view.Locations = append(view.Locations, LocationView(location))
	}

	if s.opts.Keys != nil {
		for _, key := range s.opts.Keys() {
			view.Keys = append(view.Keys, KeyView{
				Label:       key.GetLabel(),
				Fingerprint: key.GetFingerprint(),
				Algorithm:   key.GetAlgorithm(),
				Comment:     key.GetComment(),
			})
		}
	}

	if s.opts.Borrowed != nil {
		for _, key := range s.opts.Borrowed() {
			view.Borrowed = append(view.Borrowed, borrowedKeyView(key))
		}
	}

	if s.opts.Grants != nil {
		grants, err := s.opts.Grants()
		if err != nil {
			view.Error = err.Error()
		}

		for _, grant := range grants {
			view.Grants = append(view.Grants, grantSummary(grant))
		}
	}

	if s.opts.Delegations != nil {
		held, err := s.opts.Delegations()
		if err != nil {
			view.Error = err.Error()
		}

		for _, item := range held {
			view.Delegations = append(
				view.Delegations, delegationSummary(item))
		}
	}

	if s.opts.Peers != nil {
		view.Peers = s.opts.Peers()
	}

	if s.opts.Pairings != nil {
		view.Pairings = s.opts.Pairings()
	}

	for _, pending := range s.Pending() {
		view.Pending = append(view.Pending, pendingView(pending))
	}

	writeJSON(w, http.StatusOK, view)
}

// handleWithdraw calls a pairing off from the viewer.
//
// It is the one destructive thing the pairings section can do, and it is
// deliberately the only one: a pairing leaves the list by being answered, by
// being completed, or by somebody here saying they no longer want it (§7).
func (s *Session) handleWithdraw(w http.ResponseWriter, r *http.Request) {
	if s.opts.Withdraw == nil {
		writeError(w, http.StatusNotImplemented,
			"this host cannot call a pairing off")

		return
	}

	if err := s.opts.Withdraw(r.PathValue("session")); err != nil {
		writeError(w, http.StatusNotFound, err.Error())

		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleRevokeGrant takes back an "approve for a while".
//
// A grant is the one thing on the status pane that goes on saying yes after
// the person who said it has stopped looking, so the surface that lists them
// is the surface that has to be able to end one.
func (s *Session) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	if s.opts.RevokeGrant == nil {
		writeError(w, http.StatusNotImplemented,
			"this host cannot revoke a grant")

		return
	}

	if err := s.opts.RevokeGrant(r.Context(), r.PathValue("id")); err != nil {
		// Two different failures, and telling them apart is the point. A
		// stale identifier is the caller's mistake and nothing has changed.
		// A holder that could not be reached means the revoke did not happen
		// and the other machine is still signing, which is not a 404 and must
		// not close as though it worked.
		status := http.StatusBadGateway
		if errors.Is(err, ErrNoSuchGrant) {
			status = http.StatusNotFound
		}

		writeError(w, status, err.Error())

		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleExtendGrant gives a promise more time.
//
// The failures are the revoke handler's, in the same three shapes and for the
// same reasons: a stale identifier is a 404 and nothing has changed, a length
// this instance will not promise is the caller's mistake, and a holder that
// could not be reached means the extension did not happen — which must not
// close as though it did, because the machine acting on the promise will still
// stop at the old time.
func (s *Session) handleExtendGrant(w http.ResponseWriter, r *http.Request) {
	if s.opts.ExtendGrant == nil {
		writeError(w, http.StatusNotImplemented,
			"this host cannot extend a grant")

		return
	}

	var body struct {
		Seconds int64 `json:"seconds"`
	}

	if err := json.NewDecoder(
		http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "the request could not be read")

		return
	}

	err := s.opts.ExtendGrant(r.Context(), r.PathValue("id"),
		time.Duration(body.Seconds)*time.Second)
	if err != nil {
		status := http.StatusBadGateway

		switch {
		case errors.Is(err, ErrNoSuchGrant):
			status = http.StatusNotFound
		case errors.Is(err, ErrGrantTooLong):
			status = http.StatusBadRequest
		}

		writeError(w, status, err.Error())

		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleAvatar draws the picture that goes beside a fingerprint (§7).
//
// It takes the seed from the query string rather than looking a peer up,
// because it draws seeds and not peers: the same route serves this instance's
// own fingerprint, a peer's, and one belonging to a pairing that has not
// finished and so is not a peer yet.
//
// The drawing is a pure function of the seed and never changes, which is what
// lets a caller cache one forever and why this is the one response here that
// says so.
func (s *Session) handleAvatar(w http.ResponseWriter, r *http.Request) {
	seed := r.URL.Query().Get("seed")
	if seed == "" {
		writeError(w, http.StatusBadRequest, "no seed to draw")

		return
	}

	drawn, err := avatar.SVG(seed)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())

		return
	}

	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.WriteHeader(http.StatusOK)

	_, _ = w.Write([]byte(drawn))
}

func (s *Session) handleReload(w http.ResponseWriter, _ *http.Request) {
	if s.opts.Reload == nil {
		writeError(w, http.StatusNotImplemented, "this host cannot reload")

		return
	}

	if err := s.opts.Reload(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())

		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
