package bridge_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/bridge"
	"github.com/hugowetterberg/ladulas/pkg/gitctx"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const commitObject = "tree e95bc8444bcd06692c882451e807e45dfe27b5ba\n" +
	"parent 937fa9137d03e1ca64111b86264e78dc907127e7\n" +
	"author A U Thor <author@example.test> 1786209283 +0200\n" +
	"committer C O Mitter <committer@example.test> 1786209290 +0200\n" +
	"\n" +
	"tighten the socket permissions\n" +
	"\n" +
	"The agent socket was 0644, which meant anything on the box could ask.\n"

// presenter records what the host was told to show.
type presenter struct {
	mu        sync.Mutex
	presented []*bridge.PendingRequest
	dismissed []string
	announced []bridge.ActivityView
}

func (p *presenter) Present(req *bridge.PendingRequest) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.presented = append(p.presented, req)
}

func (p *presenter) Dismiss(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.dismissed = append(p.dismissed, id)
}

func (p *presenter) Announce(activity bridge.ActivityView) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.announced = append(p.announced, activity)
}

func (p *presenter) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.presented)
}

// gitRequest builds the request ladulas-sign produces, already verified the way
// the engine would have verified it.
func gitRequest(t *testing.T, id string) *approval.Request {
	t.Helper()

	digest, err := sshsig.Hash(sshsig.HashSHA512, []byte(commitObject))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	msg := &ladulasv1.ApprovalRequest{
		RequestId: id,
		Kind:      ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
		Key: &ladulasv1.KeyRef{
			Label:       "work",
			Fingerprint: "SHA256:workkey",
			Algorithm:   "ssh-ed25519",
			Comment:     "work@example.test",
		},
		Requester: &ladulasv1.RequesterInfo{
			Name:  "desktop",
			Local: true,
			Process: &ladulasv1.ClientProcess{
				Pid: 4242, Executable: "/usr/bin/ladulas-sign",
			},
		},
		Operation: &ladulasv1.ApprovalRequest_Sshsig{
			Sshsig: &ladulasv1.SshsigRequest{
				Namespace:     "git",
				HashAlgorithm: sshsig.HashSHA512,
				MessageDigest: digest,
				GitContext: &ladulasv1.GitContext{
					RepositoryPath: "/home/hugo/Projects/ladulas",
					OriginUrl:      "git@github.com:example/ladulas.git",
					Branch:         "main",
					Operation:      "commit",
					Object:         []byte(commitObject),
					Diff: &ladulasv1.GitDiff{
						FilesChanged: 1,
						Insertions:   1,
						Deletions:    1,
						Range:        "937fa9137d..e95bc8444b",
						Files: []*ladulasv1.GitDiffFile{{
							OldPath:    "agent/server.go",
							NewPath:    "agent/server.go",
							Status:     "modified",
							Insertions: 1,
							Deletions:  1,
							Hunks: []*ladulasv1.GitDiffHunk{{
								Header: "@@ -150,3 +150,3 @@ func listen() {",
								Lines: []*ladulasv1.GitDiffLine{
									{Kind: ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_CONTEXT, Text: "\tlistener, err := net.Listen(...)"},
									{Kind: ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_REMOVED, Text: "\tos.Chmod(path, 0o644)"},
									{Kind: ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_ADDED, Text: "\tos.Chmod(path, 0o600)"},
								},
							}},
						}},
					},
				},
			},
		},
	}

	if problem := gitctx.VerifyRequest(msg); problem != "" {
		t.Fatalf("the fixture does not verify: %s", problem)
	}

	return &approval.Request{
		Msg:          msg,
		Prompt:       approval.RenderPrompt(msg),
		GrantTTLs:    []time.Duration{15 * time.Minute, time.Hour},
		GrantMaxTTL:  time.Hour,
		GrantSubject: approval.GrantSubject(msg),
		GrantMachine: approval.GrantMachine(msg),
	}
}

type fixture struct {
	session   *bridge.Session
	presenter *presenter
	server    *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	host := &presenter{}

	session := bridge.NewSession(bridge.Options{
		Name:        "workstation",
		Fingerprint: "SHA256:instance",
		Locations: []bridge.Location{
			{Label: "Agent socket", Path: "/run/user/1000/ladulas/agent.sock"},
		},
		Keys: func() []*ladulasv1.KeyRef {
			return []*ladulasv1.KeyRef{{
				Label: "work", Fingerprint: "SHA256:workkey", Algorithm: "ssh-ed25519",
			}}
		},
		Grants: func() ([]*ladulasv1.Grant, error) {
			return nil, nil
		},
		Delegations: func() ([]bridge.Delegation, error) {
			return []bridge.Delegation{{
				Delegation: &ladulasv1.Delegation{
					DelegationId: "del-1",
					Description:  "git signing in ~/src/ladulas with this key",
					ApproverName: "iPhone",
					ExpiresAt: timestamppb.New(
						time.Now().Add(time.Hour)),
				},
				UseCount:   3,
				Unreported: 1,
			}}, nil
		},
		Presenter: host,
	})

	server := httptest.NewServer(session.Handler())
	t.Cleanup(server.Close)

	return &fixture{session: session, presenter: host, server: server}
}

// decide runs a request through the session in the background and returns a
// channel with the answer.
func (f *fixture) decide(t *testing.T, req *approval.Request) chan *approval.Answer {
	t.Helper()

	// What this waits for is one *more* request on screen, not the first one.
	//
	// It waited for `count() == 0` to stop being true, and the presenter's
	// count never goes down — so on a fixture that decides twice the second
	// call went straight through the wait and returned before the deciding
	// goroutine had registered anything. Every read after that raced the
	// registration, and losing the race is a 404 from
	// `/api/v1/requests/{id}` saying the request is no longer waiting. It lost
	// it on a loaded CI runner and took a release with it, having passed
	// thirty runs in a row on a quiet machine.
	before := f.presenter.count()

	answers := make(chan *approval.Answer, 1)

	go func() {
		answer, err := f.session.Decide(context.Background(), req)
		if err != nil {
			answers <- nil

			return
		}

		answers <- answer
	}()

	deadline := time.Now().Add(2 * time.Second)
	for f.presenter.count() == before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	if f.presenter.count() == before {
		t.Fatal("the request was never presented")
	}

	return answers
}

func (f *fixture) get(t *testing.T, path string) (int, []byte) {
	t.Helper()

	resp, err := f.server.Client().Get(f.server.URL + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return resp.StatusCode, body
}

func TestRequestViewCarriesTheWholeCommit(t *testing.T) {
	f := newFixture(t)
	req := gitRequest(t, "req-1")

	answers := f.decide(t, req)

	status, body := f.get(t, "/api/v1/requests/req-1")
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	var view bridge.RequestView

	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	if view.Kind != "git-sign" {
		t.Errorf("kind is %q", view.Kind)
	}

	if view.Git == nil {
		t.Fatal("the view carries no git card")
	}

	if !view.Git.Verified {
		t.Error("the card does not say the commit was verified")
	}

	if view.Git.Subject != "tighten the socket permissions" {
		t.Errorf("subject is %q", view.Git.Subject)
	}

	if !strings.Contains(view.Git.Message, "anything on the box could ask") {
		t.Errorf("the message did not survive: %q", view.Git.Message)
	}

	// The body is the message without the line the subject already is, so a
	// card that has shown the subject can show the rest without repeating it
	// and without deciding for itself where the subject ends (decision W).
	if view.Git.Body != "The agent socket was 0644, which meant anything on "+
		"the box could ask." {
		t.Errorf("the body is %q", view.Git.Body)
	}

	if view.Git.Author.Email != "author@example.test" {
		t.Errorf("author is %+v", view.Git.Author)
	}

	if view.Git.Committer.Email != "committer@example.test" {
		t.Errorf("committer is %+v", view.Git.Committer)
	}

	if view.Git.Branch != "main" || view.Git.Repository == "" {
		t.Errorf("the asserted environment is %+v", view.Git)
	}

	if view.Git.Diff == nil || len(view.Git.Diff.Files) != 1 {
		t.Fatalf("the diff is %+v", view.Git.Diff)
	}

	lines := view.Git.Diff.Files[0].Hunks[0].Lines

	if len(lines) != 3 {
		t.Fatalf("got %d lines", len(lines))
	}

	// The +/- is resolved server side, so the viewer never has to look at the
	// first character of a line an attacker chose.
	if lines[1].Kind != "removed" || lines[2].Kind != "added" {
		t.Errorf("line kinds are %q and %q", lines[1].Kind, lines[2].Kind)
	}

	if strings.HasPrefix(lines[2].Text, "+") {
		t.Errorf("the marker is still on the text: %q", lines[2].Text)
	}

	if view.Key == nil || view.Key.Label != "work" {
		t.Errorf("key is %+v", view.Key)
	}

	if view.Requester == nil || !strings.Contains(view.Requester.Program, "ladulas-sign") {
		t.Errorf("requester is %+v", view.Requester)
	}

	// The promise is an offer to be filled in rather than four ready-made
	// buttons: how far it may reach, how long it may run, and the lengths worth
	// one tap (decision V).
	if view.Grant == nil || view.Grant.MaxSeconds != 3600 ||
		len(view.Grant.Suggestions) != 2 || view.Grant.Suggestions[1] != 3600 {
		t.Errorf("the grant offer is %+v", view.Grant)
	}

	if view.Grant != nil && view.Grant.Machine == "" {
		t.Errorf("the offer names no machine: %+v", view.Grant)
	}

	if view.Grant != nil && view.Grant.Trust != nil {
		t.Errorf("a local request should carry no trust note: %+v", view.Grant.Trust)
	}

	f.session.Deny("req-1", "test over")
	<-answers
}

// A timed promise made to answer another machine's borrowed-key request reuses
// a judgement about that machine's word for the repository, so the offer says
// what it would take on trust before it is made (decision X).
func TestGrantOfferDisclosesWhatItTrustsARemoteRequesterFor(t *testing.T) {
	f := newFixture(t)

	req := gitRequest(t, "req-remote")
	req.Msg.GetRequester().Name = "iPhone"
	req.Msg.GetRequester().Local = false
	req.Msg.GetRequester().Process = nil
	req.GrantSubject = approval.GrantSubject(req.Msg)
	req.GrantMachine = approval.GrantMachine(req.Msg)

	answers := f.decide(t, req)

	_, body := f.get(t, "/api/v1/requests/req-remote")

	var view bridge.RequestView

	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	if view.Grant == nil || view.Grant.Trust == nil {
		t.Fatalf("the offer carries no trust note: %+v", view.Grant)
	}

	trust := view.Grant.Trust

	if len(trust.Facts) != 1 || trust.Facts[0].Label != "Repository" ||
		!trust.Facts[0].Asserted {
		t.Errorf("the trusted facts are %+v", trust.Facts)
	}

	if !strings.Contains(trust.Note, "iPhone") {
		t.Errorf("the note does not name the requester: %q", trust.Note)
	}

	if trust.Detail == "" {
		t.Error("the note has no fuller explanation to disclose")
	}

	f.session.Deny("req-remote", "test over")
	<-answers
}

// A context that did not verify has to reach the viewer as a danger, not as a
// missing field: the point of the card is that it says where its facts came
// from.
func TestUnverifiedContextIsMarkedDangerous(t *testing.T) {
	f := newFixture(t)
	req := gitRequest(t, "req-2")

	git := req.Msg.GetSshsig().GetGitContext()
	git.VerifiedAgainstPayload = false
	git.VerificationError = "the commit shown is not the one that would be signed"

	answers := f.decide(t, req)

	_, body := f.get(t, "/api/v1/requests/req-2")

	var view bridge.RequestView

	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !view.Danger {
		t.Error("the request is not marked dangerous")
	}

	if view.Git.Verified {
		t.Error("the card claims the commit was verified")
	}

	if view.Git.VerificationError == "" {
		t.Error("the card does not say what went wrong")
	}

	f.session.Deny("req-2", "test over")
	<-answers
}

func TestAnswerApproves(t *testing.T) {
	f := newFixture(t)
	answers := f.decide(t, gitRequest(t, "req-3"))

	post(t, f, "/api/v1/requests/req-3/answer", `{"decision":"approve"}`, http.StatusOK)

	answer := <-answers

	if answer == nil || answer.Decision != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("answer is %+v", answer)
	}

	if answer.GrantTTL != 0 {
		t.Errorf("a plain approval created a grant of %s", answer.GrantTTL)
	}

	if len(f.presenter.dismissed) != 1 {
		t.Errorf("the host was told to dismiss %d times", len(f.presenter.dismissed))
	}
}

// A length is chosen rather than picked off a list (decision V), so a duration
// no button ever offered is a perfectly good answer as long as it is inside the
// bound — and it arrives scoped to the session unless the answer says otherwise.
func TestAnswerCreatesAGrantOfAChosenLength(t *testing.T) {
	f := newFixture(t)
	answers := f.decide(t, gitRequest(t, "req-4"))

	post(t, f, "/api/v1/requests/req-4/answer",
		`{"decision":"approve","grantSeconds":2700}`, http.StatusOK)

	answer := <-answers

	if answer.GrantTTL != 45*time.Minute {
		t.Errorf("grant is %s, want 45 minutes", answer.GrantTTL)
	}

	if answer.GrantReach != approval.GrantReachSession {
		t.Errorf("an answer that said nothing about reach got %v",
			answer.GrantReach)
	}
}

// Widening a promise to the whole machine is something the answer has to say,
// because the narrower one is what an answer that says nothing means.
func TestAnswerWidensAGrantToTheMachine(t *testing.T) {
	f := newFixture(t)
	answers := f.decide(t, gitRequest(t, "req-4b"))

	post(t, f, "/api/v1/requests/req-4b/answer",
		`{"decision":"approve","grantSeconds":3600,"grantScope":"machine"}`,
		http.StatusOK)

	answer := <-answers

	if answer.GrantReach != approval.GrantReachMachine {
		t.Errorf("the promise stayed at %v", answer.GrantReach)
	}
}

// The bound is what stops anything that can reach the bridge minting a promise
// of its own length, and a request past it is refused rather than quietly
// approved without the promise: an answer that is not the answer somebody gave
// must not be the one that gets acted on. The request stays waiting, which is
// the state it can still be answered from.
func TestAnswerRefusesAGrantPastTheBound(t *testing.T) {
	f := newFixture(t)
	answers := f.decide(t, gitRequest(t, "req-5"))

	post(t, f, "/api/v1/requests/req-5/answer",
		`{"decision":"approve","grantSeconds":31536000}`,
		http.StatusBadRequest)

	post(t, f, "/api/v1/requests/req-5/answer",
		`{"decision":"approve","grantSeconds":900}`, http.StatusOK)

	answer := <-answers

	if answer.GrantTTL != 15*time.Minute {
		t.Errorf("the second answer granted %s", answer.GrantTTL)
	}
}

// A scope nobody defined is not a scope to guess at.
func TestAnswerRefusesAnUnknownScope(t *testing.T) {
	f := newFixture(t)
	answers := f.decide(t, gitRequest(t, "req-5b"))

	post(t, f, "/api/v1/requests/req-5b/answer",
		`{"decision":"approve","grantSeconds":900,"grantScope":"everything"}`,
		http.StatusBadRequest)

	f.session.Deny("req-5b", "test over")
	<-answers
}

func TestAnswerDenies(t *testing.T) {
	f := newFixture(t)
	answers := f.decide(t, gitRequest(t, "req-6"))

	post(t, f, "/api/v1/requests/req-6/answer", `{"decision":"deny"}`, http.StatusOK)

	if answer := <-answers; answer.Decision != ladulasv1.Decision_DECISION_DENY {
		t.Errorf("answer is %+v", answer)
	}
}

// Anything that is not the word approve is a refusal. A typo must never be an
// approval.
func TestUnknownDecisionIsARefusal(t *testing.T) {
	f := newFixture(t)
	answers := f.decide(t, gitRequest(t, "req-7"))

	post(t, f, "/api/v1/requests/req-7/answer", `{"decision":"aprove"}`, http.StatusOK)

	if answer := <-answers; answer.Decision != ladulasv1.Decision_DECISION_DENY {
		t.Errorf("answer is %+v", answer)
	}
}

func TestUnknownRequestIsNotFound(t *testing.T) {
	f := newFixture(t)

	if status, _ := f.get(t, "/api/v1/requests/nothing"); status != http.StatusNotFound {
		t.Errorf("status is %d", status)
	}

	post(t, f, "/api/v1/requests/nothing/answer",
		`{"decision":"approve"}`, http.StatusNotFound)
}

func TestWithdrawnRequestDismissesTheHost(t *testing.T) {
	f := newFixture(t)
	req := gitRequest(t, "req-8")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		_, err := f.session.Decide(ctx, req)
		done <- err
	}()

	deadline := time.Now().Add(2 * time.Second)
	for f.presenter.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	cancel()

	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("error is %v, want context.Canceled", err)
	}

	if len(f.presenter.dismissed) != 1 {
		t.Errorf("the host was told to dismiss %d times", len(f.presenter.dismissed))
	}

	if len(f.session.Pending()) != 0 {
		t.Error("a withdrawn request is still pending")
	}

	if recent := f.session.Recent(); len(recent) != 1 ||
		recent[0].Outcome != "withdrawn" {
		t.Errorf("the activity list says %+v", recent)
	}
}

// A card nobody answered in time is not a card somebody called off, and the
// activity list has to say which happened: one of them means answer faster and
// the other means look for what settled it.
func TestARequestThatRanOutOfTimeSaysSo(t *testing.T) {
	f := newFixture(t)
	req := gitRequest(t, "req-8b")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := f.session.Decide(ctx, req)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error is %v, want context.DeadlineExceeded", err)
	}

	if recent := f.session.Recent(); len(recent) != 1 ||
		recent[0].Outcome != "not answered in time" {
		t.Errorf("the activity list says %+v", recent)
	}
}

func TestNotifyAnnouncesAndRecords(t *testing.T) {
	f := newFixture(t)
	req := gitRequest(t, "req-9")

	f.session.Notify(req, &ladulasv1.ApprovalResponse{
		Decision:   ladulasv1.Decision_DECISION_APPROVE,
		Source:     ladulasv1.DecisionSource_DECISION_SOURCE_POLICY,
		NotifyOnly: true,
	})

	if len(f.presenter.announced) != 1 {
		t.Fatalf("the host was announced to %d times", len(f.presenter.announced))
	}

	if f.presenter.announced[0].Outcome != "auto-approved" {
		t.Errorf("outcome is %q", f.presenter.announced[0].Outcome)
	}

	_, body := f.get(t, "/api/v1/instance")

	var view bridge.InstanceView

	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(view.Recent) != 1 {
		t.Errorf("the activity list has %d entries", len(view.Recent))
	}

	if view.Name != "workstation" || len(view.Keys) != 1 || len(view.Locations) != 1 {
		t.Errorf("instance view is %+v", view)
	}
}

// The promises somebody else made about this instance are their own list: a
// machine that self-approves under a standing permission has to be able to say
// which one, and `grants` is the promises it made rather than the ones it was
// given (decision P).
func TestInstanceViewListsDelegationsSeparately(t *testing.T) {
	f := newFixture(t)

	_, body := f.get(t, "/api/v1/instance")

	var view bridge.InstanceView

	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(view.Grants) != 0 {
		t.Errorf("a delegation turned up among the grants: %+v", view.Grants)
	}

	if len(view.Delegations) != 1 {
		t.Fatalf("the instance holds %d delegations", len(view.Delegations))
	}

	held := view.Delegations[0]

	if held.ID != "del-1" || held.Approver != "iPhone" {
		t.Errorf("the delegation reads %+v", held)
	}

	// What it has done under it, and what it still owes an account of.
	if held.UseCount != 3 || held.Unreported != 1 {
		t.Errorf("the counts are %d used, %d unreported",
			held.UseCount, held.Unreported)
	}
}

// The three answers extending can give, each with its own status, because a
// surface has to tell them apart: nothing there, a length this instance will
// not promise, and a holder that could not be reached — and the last one means
// the promise was not extended (decision V).
func TestExtendGrantReportsWhichFailureItWas(t *testing.T) {
	var asked []time.Duration

	host := &presenter{}
	session := bridge.NewSession(bridge.Options{
		Name: "workstation",
		ExtendGrant: func(
			_ context.Context, id string, extra time.Duration,
		) error {
			asked = append(asked, extra)

			switch id {
			case "gone":
				return bridge.ErrNoSuchGrant
			case "too-long":
				return bridge.ErrGrantTooLong
			case "unreachable":
				return errors.New("the machine holding it did not answer")
			default:
				return nil
			}
		},
		Presenter: host,
	})

	server := httptest.NewServer(session.Handler())
	t.Cleanup(server.Close)

	for _, tc := range []struct {
		id     string
		status int
	}{
		{"live", http.StatusOK},
		{"gone", http.StatusNotFound},
		{"too-long", http.StatusBadRequest},
		{"unreachable", http.StatusBadGateway},
	} {
		resp, err := server.Client().Post(
			server.URL+"/api/v1/grants/"+tc.id+"/extend",
			"application/json", strings.NewReader(`{"seconds":7200}`))
		if err != nil {
			t.Fatalf("post %s: %v", tc.id, err)
		}

		_ = resp.Body.Close()

		if resp.StatusCode != tc.status {
			t.Errorf("extending %q: status %d, want %d",
				tc.id, resp.StatusCode, tc.status)
		}
	}

	// The length crosses as seconds and reaches the host as a duration.
	if len(asked) != 4 || asked[0] != 2*time.Hour {
		t.Errorf("the host was asked for %v", asked)
	}
}

func TestPendingList(t *testing.T) {
	f := newFixture(t)
	answers := f.decide(t, gitRequest(t, "req-10"))

	_, body := f.get(t, "/api/v1/requests")

	var views []bridge.PendingView

	if err := json.Unmarshal(body, &views); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(views) != 1 || views[0].ID != "req-10" {
		t.Errorf("pending list is %+v", views)
	}

	// The list says where to go to answer each of them. It is what makes a card
	// somebody navigated away from reachable again, and a phone coming back to
	// the foreground has nothing else to go on.
	if views[0].URL != "/?request=req-10" {
		t.Errorf("the pending request points at %q", views[0].URL)
	}

	f.session.Deny("req-10", "test over")
	<-answers
}

// The bundle has to be served with the policy that makes it safe to render
// somebody else's diff in it.
func TestBundleIsServedUnderTheContentSecurityPolicy(t *testing.T) {
	f := newFixture(t)

	for _, path := range []string{"/", "/app.js", "/?request=req-1"} {
		resp, err := f.server.Client().Get(f.server.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}

		body, _ := io.ReadAll(resp.Body)

		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d", path, resp.StatusCode)
		}

		policy := resp.Header.Get("Content-Security-Policy")

		for _, want := range []string{
			"default-src 'none'", "script-src 'self'", "connect-src 'self'",
		} {
			if !strings.Contains(policy, want) {
				t.Errorf("%s: the policy %q does not contain %q", path, policy, want)
			}
		}

		if len(body) == 0 {
			t.Errorf("%s: served nothing", path)
		}
	}
}

// A path that is not a file in the bundle serves the page, because the viewer
// routes on its query string and a host can only open URLs.
func TestUnknownPathServesThePage(t *testing.T) {
	f := newFixture(t)

	status, body := f.get(t, "/prompt")

	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}

	if !strings.Contains(string(body), "app.js") {
		t.Errorf("the page was not served:\n%s", body)
	}
}

// The same handler has to answer identically whether it is reached over HTTP —
// as Wails does — or through Call, which is what a WKWebView scheme handler or
// an Android shouldInterceptRequest has to use. That equivalence is the whole
// of open question 5.
func TestCallMatchesTheHTTPServer(t *testing.T) {
	f := newFixture(t)
	answers := f.decide(t, gitRequest(t, "req-11"))

	handler := f.session.Handler()

	overHTTP := func(path string) (int, string) {
		status, body := f.get(t, path)

		return status, string(body)
	}

	for _, path := range []string{
		"/api/v1/instance",
		"/api/v1/requests",
		"/api/v1/requests/req-11",
		"/api/v1/requests/nothing",
		"/app.css",
	} {
		wantStatus, wantBody := overHTTP(path)

		got := bridge.Call(handler, &bridge.CallRequest{
			Method: http.MethodGet,
			Path:   path,
		})

		if got.Status != wantStatus {
			t.Errorf("%s: Call returned %d, the server %d",
				path, got.Status, wantStatus)
		}

		if string(got.Body) != wantBody {
			t.Errorf("%s: Call and the server disagree:\n%s\n%s",
				path, got.Body, wantBody)
		}
	}

	// And a write works the same way round.
	answered := bridge.Call(handler, &bridge.CallRequest{
		Method:      http.MethodPost,
		Path:        "/api/v1/requests/req-11/answer",
		ContentType: "application/json",
		Body:        []byte(`{"decision":"approve","grantSeconds":900}`),
	})

	if answered.Status != http.StatusOK {
		t.Fatalf("Call could not answer: %d %s", answered.Status, answered.Body)
	}

	answer := <-answers

	if answer.Decision != ladulasv1.Decision_DECISION_APPROVE ||
		answer.GrantTTL != 15*time.Minute {
		t.Errorf("the answer that came through Call is %+v", answer)
	}
}

func TestSessionWithoutAHostAnswersNothing(t *testing.T) {
	session := bridge.NewSession(bridge.Options{Name: "headless"})

	_, err := session.Decide(context.Background(), gitRequest(t, "req-12"))
	if err == nil {
		t.Error("a session with no host answered a request")
	}
}

func post(t *testing.T, f *fixture, path, body string, wantStatus int) {
	t.Helper()

	resp, err := f.server.Client().Post(
		f.server.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != wantStatus {
		out, _ := io.ReadAll(resp.Body)

		t.Fatalf("post %s: status %d, want %d: %s",
			path, resp.StatusCode, wantStatus, out)
	}
}

// TestPairingViewShowsBothFingerprints: the integrity of a trust-on-first-use
// pairing is that the two machines display the same pair of fingerprints and
// their users agree they match, so a card that showed only the other side's
// would be asking for a confirmation with nothing to confirm against (§7).
func TestPairingViewShowsBothFingerprints(t *testing.T) {
	f := newFixture(t)

	req := &approval.Request{
		Msg: &ladulasv1.ApprovalRequest{
			RequestId: "pair-1",
			Kind:      ladulasv1.RequestKind_REQUEST_KIND_PAIRING,
			Operation: &ladulasv1.ApprovalRequest_Pairing{
				Pairing: &ladulasv1.PairingRequest{
					PeerName:         "builder",
					PeerFingerprint:  "SHA256:thepeer",
					RemoteAddress:    "100.64.0.9:52104",
					PeerMayApprove:   false,
					PeerMayRequest:   true,
					LocalName:        "desktop",
					LocalFingerprint: "SHA256:ourselves",
					PeerAddresses:    []string{"100.64.0.9:7373"},
				},
			},
		},
	}

	req.Prompt = approval.RenderPrompt(req.Msg)

	answers := f.decide(t, req)

	status, body := f.get(t, "/api/v1/requests/pair-1")
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	var view bridge.RequestView

	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	if view.Pairing == nil {
		t.Fatal("the view carries no pairing card")
	}

	if view.Pairing.Fingerprint != "SHA256:thepeer" {
		t.Errorf("the peer's fingerprint is %q", view.Pairing.Fingerprint)
	}

	if view.Pairing.LocalFingerprint != "SHA256:ourselves" {
		t.Errorf("this instance's fingerprint is %q", view.Pairing.LocalFingerprint)
	}

	if view.Pairing.LocalName != "desktop" {
		t.Errorf("this instance is named %q", view.Pairing.LocalName)
	}

	if !view.Pairing.MayRequest || view.Pairing.MayApprove {
		t.Errorf("the directions are approve=%v request=%v",
			view.Pairing.MayApprove, view.Pairing.MayRequest)
	}

	f.session.Deny("pair-1", "not now")

	if answer := <-answers; answer.Decision != ladulasv1.Decision_DECISION_DENY {
		t.Errorf("the answer was %v", answer.Decision)
	}
}

// TestStatusListsPeers: a user wondering why nothing is being approved should
// be able to see who this instance is paired with and whether it is there.
func TestStatusListsPeers(t *testing.T) {
	session := bridge.NewSession(bridge.Options{
		Name:        "desktop",
		Fingerprint: "SHA256:ourselves",
		Peers: func() []bridge.PeerView {
			return []bridge.PeerView{{
				Name:        "builder",
				Fingerprint: "SHA256:thepeer",
				Direction:   "asks us",
				State:       "listening",
			}}
		},
	})

	server := httptest.NewServer(session.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/api/v1/instance")
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	var view bridge.InstanceView

	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(view.Peers) != 1 || view.Peers[0].Name != "builder" {
		t.Fatalf("the status pane lists %+v", view.Peers)
	}

	if view.Peers[0].State != "listening" {
		t.Errorf("the peer's state is %q", view.Peers[0].State)
	}
}

// TestPairingsSectionShowsWhatHasNoCard: a pairing this side has already agreed
// to has no confirmation to answer and is waiting on somebody at the other
// machine, so the only way to see it — or to call it off — is the pairings
// section of the status pane (§7).
func TestPairingsSectionShowsWhatHasNoCard(t *testing.T) {
	host := &presenter{}
	withdrawn := make(chan string, 1)

	session := bridge.NewSession(bridge.Options{
		Name:        "workstation",
		Fingerprint: "SHA256:instance",
		Pairings: func() []bridge.PairingSummaryView {
			return bridge.PairingSummaries([]*ladulasv1.PendingPairingStatus{
				{
					SessionId:        "session-mine",
					Name:             "phone",
					Fingerprint:      "SHA256:phone",
					LocalFingerprint: "SHA256:instance",
					MayApprove:       true,
					OurAnswer:        ladulasv1.PairingAnswer_PAIRING_ANSWER_ACCEPTED,
				},
				{
					SessionId:             "session-theirs",
					Name:                  "laptop",
					Fingerprint:           "SHA256:laptop",
					LocalFingerprint:      "SHA256:instance",
					MayRequest:            true,
					ConfirmationRequestId: "req-pair",
				},
			})
		},
		Withdraw: func(session string) error {
			withdrawn <- session

			return nil
		},
		Presenter: host,
	})

	server := httptest.NewServer(session.Handler())
	t.Cleanup(server.Close)

	f := &fixture{session: session, presenter: host, server: server}

	_, body := f.get(t, "/api/v1/instance")

	var view bridge.InstanceView

	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(view.Pairings) != 2 {
		t.Fatalf("the status pane lists %d pairings", len(view.Pairings))
	}

	// The one this side has answered says so and offers no card, because there
	// is none: what it is waiting for is a person at the other machine.
	if view.Pairings[0].State != "waiting for the other side" ||
		view.Pairings[0].URL != "" {
		t.Errorf("the answered pairing reads %+v", view.Pairings[0])
	}

	// The one this side has not answered points at the card that answers it,
	// which is what makes a confirmation navigated away from reachable again.
	if view.Pairings[1].State != "waiting for you" ||
		view.Pairings[1].URL != "/?request=req-pair" {
		t.Errorf("the unanswered pairing reads %+v", view.Pairings[1])
	}

	post(t, f, "/api/v1/pairings/session-mine/withdraw", "", http.StatusOK)

	select {
	case session := <-withdrawn:
		if session != "session-mine" {
			t.Errorf("called off %q", session)
		}
	default:
		t.Error("nothing was called off")
	}
}

// A key a paired machine handed this instance is listed as waiting rather than
// as held, and answering it is the one thing this end can do about a handover
// (decision S).
func TestKeyOffersAreListedAndAnswered(t *testing.T) {
	arrived := time.Date(2026, 8, 19, 9, 30, 0, 0, time.UTC)

	type answer struct {
		id     string
		accept bool
		label  string
	}

	var answers []answer

	session := bridge.NewSession(bridge.Options{
		Name: "workstation",
		KeyOffers: func() []*ladulasv1.KeyOfferInfo {
			return []*ladulasv1.KeyOfferInfo{{
				Id:              "offer-1",
				PeerFingerprint: "SHA256:phone",
				PeerName:        "iPhone",
				Label:           "github",
				Algorithm:       "ssh-ed25519",
				Fingerprint:     "SHA256:portable",
				ReceivedAt:      timestamppb.New(arrived),
			}}
		},
		AnswerKeyOffer: func(
			_ context.Context, id string, accept bool, label string,
		) error {
			answers = append(answers, answer{id, accept, label})

			if id != "offer-1" {
				return errors.New("no such offer")
			}

			return nil
		},
		Presenter: &presenter{},
	})

	server := httptest.NewServer(session.Handler())
	t.Cleanup(server.Close)

	resp, err := server.Client().Get(server.URL + "/api/v1/instance")
	if err != nil {
		t.Fatalf("get the instance: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the instance: %v", err)
	}

	_ = resp.Body.Close()

	var view bridge.InstanceView

	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Waiting, not held: an offer that turned up among the keys would be a
	// window saying the store holds something it does not.
	if len(view.Keys) != 0 {
		t.Errorf("an offer turned up among the keys: %+v", view.Keys)
	}

	if len(view.Offers) != 1 {
		t.Fatalf("the instance lists %d offers", len(view.Offers))
	}

	offer := view.Offers[0]

	if offer.ID != "offer-1" || offer.Peer != "iPhone" ||
		offer.Fingerprint != "SHA256:portable" {
		t.Errorf("the offer reads %+v", offer)
	}

	// When it arrived, twice: a sentence for the card and a stamp for the
	// shell's own clock.
	if offer.Received == "" {
		t.Error("the offer does not say when it arrived")
	}

	if _, err := time.Parse(time.RFC3339, offer.ReceivedAt); err != nil {
		t.Errorf("receivedAt is not a timestamp: %q", offer.ReceivedAt)
	}

	for _, tc := range []struct {
		id     string
		body   string
		status int
	}{
		{"offer-1", `{"accept":true,"label":"  work  "}`, http.StatusOK},
		{"offer-1", `{"accept":false}`, http.StatusOK},
		{"gone", `{"accept":true}`, http.StatusBadRequest},
	} {
		resp, err := server.Client().Post(
			server.URL+"/api/v1/keys/offers/"+tc.id+"/answer",
			"application/json", strings.NewReader(tc.body))
		if err != nil {
			t.Fatalf("answer %s: %v", tc.id, err)
		}

		_ = resp.Body.Close()

		if resp.StatusCode != tc.status {
			t.Errorf("answering %q: status %d, want %d",
				tc.id, resp.StatusCode, tc.status)
		}
	}

	want := []answer{
		{"offer-1", true, "work"},
		{"offer-1", false, ""},
		{"gone", true, ""},
	}

	if len(answers) != len(want) {
		t.Fatalf("the host was asked %d times: %+v", len(answers), answers)
	}

	for i, got := range answers {
		if got != want[i] {
			t.Errorf("answer %d was %+v, want %+v", i, got, want[i])
		}
	}
}
