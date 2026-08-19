package bridge_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/bridge"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// What a past decision can be asked about afterwards (§18).
//
// The promise the log makes is that it records what was in front of somebody,
// and the promise is only worth something if it can be read back. These are the
// two halves of that: the card was captured, and the card comes back.

// TestTheCardIsCapturedWhenItIsDrawn: the documentation panel is written down
// at the moment it is shown, because it is the one part of a card that cannot
// be worked out again (§6).
func TestTheCardIsCapturedWhenItIsDrawn(t *testing.T) {
	f := newProjectFixture(t)

	if status, body := f.get(t, browse("file", map[string]string{
		"path": "README.md",
	})); status != http.StatusOK {
		t.Fatalf("read the README: %d %s", status, body)
	}

	req := remoteGitRequest(t, "req-kept", published, publishedCommit)
	answers := f.decide(t, req)

	// Nothing is captured until a host draws the card. A request answered from
	// a notification action showed nobody a documentation panel, and claiming
	// one in the log would be inventing it.
	if shown := req.Shown(); shown != nil {
		t.Errorf("a card nobody fetched recorded %+v", shown)
	}

	view := f.requestView(t, "req-kept")

	shown := req.Shown()
	if shown == nil {
		t.Fatal("the card was drawn and nothing was recorded")
	}

	if shown.GetNote() != view.Project.Note {
		t.Errorf("the log recorded %q, the card said %q",
			shown.GetNote(), view.Project.Note)
	}

	if shown.GetProjectId() != published || !shown.GetKnown() {
		t.Errorf("the recorded panel is %+v", shown)
	}

	f.session.Deny("req-kept", "done")
	<-answers
}

// TestAPastDecisionOpensAsItStood: an activity row is a way back to the card,
// not a summary of one.
func TestAPastDecisionOpensAsItStood(t *testing.T) {
	entry := &ladulasv1.AuditEntry{
		EntryId:   "audit-1",
		Event:     ladulasv1.AuditEvent_AUDIT_EVENT_DECISION,
		RequestId: "req-past",
		Request:   remoteGitRequest(t, "req-past", published, publishedCommit).Msg,
		Response: &ladulasv1.ApprovalResponse{
			Decision: ladulasv1.Decision_DECISION_APPROVE,
			Source:   ladulasv1.DecisionSource_DECISION_SOURCE_USER,
			Reason:   "approved at the phone",
			Approver: &ladulasv1.ApproverInfo{Name: "iPhone"},
		},
		PromptShown: "Sign a commit\ntighten the socket permissions\n",
		ProjectShown: &ladulasv1.PresentedProject{
			PeerFingerprint: publisher,
			ProjectId:       published,
			Name:            "ladulas",
			Note: "1 page read here on 9 Aug 09:00, at 937fa9137d, which is " +
				"the commit this change is built on.",
			Known: true,
		},
	}

	session := bridge.NewSession(bridge.Options{
		Name: "phone",
		History: func(_ int) ([]*ladulasv1.AuditEntry, error) {
			return []*ladulasv1.AuditEntry{entry}, nil
		},
	})

	handler := session.Handler()

	recent := session.Recent()
	if len(recent) != 1 || recent[0].ID != "audit-1" {
		t.Fatalf("the activity list is %+v", recent)
	}

	var detail bridge.ActivityDetailView

	getJSON(t, handler, "/api/v1/activity/audit-1", &detail)

	if detail.Outcome != "approved" || detail.Decided != "Answered at iPhone" {
		t.Errorf("the decision reads %q / %q", detail.Outcome, detail.Decided)
	}

	if detail.Reason != "approved at the phone" {
		t.Errorf("the reason is %q", detail.Reason)
	}

	// The card, rendered from the request the log kept — and worded by the same
	// renderer that worded it on the day.
	if !strings.Contains(detail.Request.Subject, "tighten the socket") {
		t.Errorf("the card reads %q / %q",
			detail.Request.Title, detail.Request.Subject)
	}

	if detail.Request.Kind != "git-sign" || detail.Request.Git == nil {
		t.Errorf("the commit card did not come back: %+v", detail.Request)
	}

	// No buttons. The offer to approve for a while was made once.
	if detail.Request.Grant != nil {
		t.Errorf("a decided request still offers %+v", detail.Request.Grant)
	}

	// And the documentation panel is the sentence that was shown, not one
	// worked out now against a cache that has moved on.
	if detail.Request.Project == nil ||
		!strings.Contains(detail.Request.Project.Note, "9 Aug 09:00") {
		t.Errorf("the documentation panel is %+v", detail.Request.Project)
	}

	// A decision the log no longer goes back to is a plain answer rather than
	// an empty screen.
	resp := getFrom(t, handler, "/api/v1/activity/audit-404")
	if resp.Code != http.StatusNotFound {
		t.Errorf("an unknown decision answered with %d", resp.Code)
	}
}

// A host that keeps no log has nothing to open, and says so rather than
// pretending the row is missing.
func TestActivityWithoutALogHasNothingToOpen(t *testing.T) {
	session := bridge.NewSession(bridge.Options{Name: "desktop"})

	resp := getFrom(t, session.Handler(), "/api/v1/activity/whatever")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("status %d", resp.Code)
	}

	var body map[string]string

	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !strings.Contains(body["error"], "does not go back") {
		t.Errorf("the answer is %q", body["error"])
	}
}
