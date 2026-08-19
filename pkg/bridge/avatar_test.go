package bridge_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/bridge"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The picture beside a fingerprint is served by the bridge rather than drawn by
// whatever is displaying it, so that a phone drawing it natively and a viewer
// drawing it in a page are looking at the same thing (§7).
func TestAvatarIsDrawnForASeed(t *testing.T) {
	f := newFixture(t)

	resp := f.request(t, http.MethodGet,
		"/api/v1/avatar?seed=SHA256:instance", "")

	if resp.Code != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Code, resp.Body.String())
	}

	if got := resp.Header().Get("Content-Type"); !strings.HasPrefix(got, "image/svg+xml") {
		t.Errorf("content type is %q", got)
	}

	// A drawing is a pure function of its seed and never changes, and the
	// caller's cache is what makes a list of peers cheap. Saying so is the
	// whole reason this response has a caching header when nothing else here
	// does.
	if got := resp.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Errorf("cache control is %q", got)
	}

	if !strings.HasPrefix(resp.Body.String(), "<svg") {
		t.Errorf("the body does not start with a drawing: %.60s",
			resp.Body.String())
	}
}

func TestAvatarNeedsASeed(t *testing.T) {
	f := newFixture(t)

	resp := f.request(t, http.MethodGet, "/api/v1/avatar", "")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want %d", resp.Code, http.StatusBadRequest)
	}
}

// request calls the handler directly rather than over the test server, because
// the headers are the point here and the helpers above only return a body.
func (f *fixture) request(
	t *testing.T, method, path, body string,
) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	recorder := httptest.NewRecorder()
	f.session.Handler().ServeHTTP(recorder, req)

	return recorder
}

// TestGrantIsRevokedFromTheViewer: a grant goes on saying yes after the person
// who said it has stopped looking, so the surface that lists them has to be
// able to end one (§9).
func TestGrantIsRevokedFromTheViewer(t *testing.T) {
	revoked := make(chan string, 1)

	session := bridge.NewSession(bridge.Options{
		Name:        "workstation",
		Fingerprint: "SHA256:instance",
		RevokeGrant: func(_ context.Context, id string) error {
			if id != "grant-1" {
				return fmt.Errorf("%w: %s", bridge.ErrNoSuchGrant, id)
			}

			revoked <- id

			return nil
		},
	})

	server := httptest.NewServer(session.Handler())
	t.Cleanup(server.Close)

	f := &fixture{session: session, server: server}

	post(t, f, "/api/v1/grants/grant-1/revoke", "", http.StatusOK)

	select {
	case id := <-revoked:
		if id != "grant-1" {
			t.Errorf("revoked %q", id)
		}
	default:
		t.Fatal("nothing was revoked")
	}

	// One that is not live is a 404 rather than a success. Revoking is
	// idempotent in the store, and a typo that reports success is a grant still
	// running.
	post(t, f, "/api/v1/grants/grant-2/revoke", "", http.StatusNotFound)
}

// A host that cannot revoke says so, rather than swallowing the call. The
// pairings section already works this way, and the two are the same shape of
// optional capability.
func TestGrantRevocationNeedsAHostThatCan(t *testing.T) {
	f := newFixture(t)

	post(t, f, "/api/v1/grants/grant-1/revoke", "", http.StatusNotImplemented)
}

// TestActivitySurvivesTheSession: the activity list used to be a slice on the
// session, so it was gone the moment the process was. On a desktop that is a
// restart; on a phone iOS kills the app whenever it wants the memory, and
// "what have I approved" answered nothing an hour after answering it.
func TestActivitySurvivesTheSession(t *testing.T) {
	entries := []*ladulasv1.AuditEntry{
		{
			Event:     ladulasv1.AuditEvent_AUDIT_EVENT_REQUEST,
			Timestamp: timestamppb.New(time.Date(2026, 8, 10, 9, 0, 0, 0, time.Local)),
		},
		{
			Event:     ladulasv1.AuditEvent_AUDIT_EVENT_DECISION,
			Timestamp: timestamppb.New(time.Date(2026, 8, 10, 9, 0, 1, 0, time.Local)),
			Request: &ladulasv1.ApprovalRequest{
				Kind: ladulasv1.RequestKind_REQUEST_KIND_SSHSIG,
				Operation: &ladulasv1.ApprovalRequest_Sshsig{
					Sshsig: &ladulasv1.SshsigRequest{Namespace: "file"},
				},
			},
			Response: &ladulasv1.ApprovalResponse{
				Decision: ladulasv1.Decision_DECISION_APPROVE,
			},
		},
		{
			Event:     ladulasv1.AuditEvent_AUDIT_EVENT_DECISION,
			Timestamp: timestamppb.New(time.Date(2026, 8, 10, 9, 5, 0, 0, time.Local)),
			Request: &ladulasv1.ApprovalRequest{
				Kind: ladulasv1.RequestKind_REQUEST_KIND_SSHSIG,
				Operation: &ladulasv1.ApprovalRequest_Sshsig{
					Sshsig: &ladulasv1.SshsigRequest{Namespace: "git"},
				},
			},
			Response: &ladulasv1.ApprovalResponse{
				Decision: ladulasv1.Decision_DECISION_APPROVE,
				Grant: &ladulasv1.Grant{
					CreatedAt: timestamppb.New(time.Date(2026, 8, 10, 9, 5, 0, 0, time.Local)),
					ExpiresAt: timestamppb.New(time.Date(2026, 8, 10, 10, 5, 0, 0, time.Local)),
				},
			},
		},
	}

	// A session that has decided nothing at all still knows what this instance
	// decided before it started, which is the whole point.
	session := bridge.NewSession(bridge.Options{
		Name:        "phone",
		Fingerprint: "SHA256:instance",
		History: func(_ int) ([]*ladulasv1.AuditEntry, error) {
			return entries, nil
		},
	})

	recent := session.Recent()

	if len(recent) != 2 {
		t.Fatalf("the activity list has %d entries: %+v", len(recent), recent)
	}

	// Newest first, and only decisions — a request being received is not
	// something that happened to anybody.
	if recent[0].When != "09:05:00" {
		t.Errorf("the newest entry is at %q", recent[0].When)
	}

	if recent[0].Outcome != "approved for 1 hour" {
		t.Errorf("the grant is described as %q", recent[0].Outcome)
	}

	if recent[1].Outcome != "approved" {
		t.Errorf("the plain approval is described as %q", recent[1].Outcome)
	}

	// The wording comes from the same renderer that worded the card at the
	// time, so a decision read back a week later reads as it did on the day.
	if !strings.Contains(recent[0].Title, "git") {
		t.Errorf("the title lost its subject: %q", recent[0].Title)
	}
}

// A host that keeps no log still gets the list it has always had, and a log
// that cannot be read is a warning rather than an empty screen.
func TestActivityFallsBackToTheSession(t *testing.T) {
	session := bridge.NewSession(bridge.Options{
		Name:        "phone",
		Fingerprint: "SHA256:instance",
		History: func(_ int) ([]*ladulasv1.AuditEntry, error) {
			return nil, errors.New("the log could not be read")
		},
	})

	if recent := session.Recent(); len(recent) != 0 {
		t.Fatalf("a session that decided nothing lists %d entries", len(recent))
	}
}
