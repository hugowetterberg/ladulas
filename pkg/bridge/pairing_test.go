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

	"github.com/hugowetterberg/ladulas/pkg/bridge"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// What a window can do about pairing and keys, which until this existed was
// nothing: it listed what was under way and could call one off, and starting a
// pairing or making a key meant a terminal on a machine whose whole point is
// that somebody is sitting at a window.

// pairingHost is a host that displays codes and makes keys.
type pairingHost struct {
	mu      sync.Mutex
	live    *bridge.Invitation
	stopped int
	asked   []trust.Intent
}

func (h *pairingHost) Invite(
	_ context.Context, intent trust.Intent,
) (bridge.Invitation, error) {
	if intent == trust.IntentUnspecified {
		return bridge.Invitation{}, bridge.ErrNoIntent
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.asked = append(h.asked, intent)

	invitation := bridge.Invitation{
		Code:      "k7n41-9qra0",
		FullCode:  "ladulas-pair-v1.AAAA",
		Addresses: []string{"guppy:7373", "100.64.0.2:7373"},
		Expires:   time.Now().Add(5 * time.Minute),
		Intent:    intent,
	}

	h.live = &invitation

	return invitation, nil
}

func (h *pairingHost) Invitation() (bridge.Invitation, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.live == nil {
		return bridge.Invitation{}, false
	}

	return *h.live, true
}

func (h *pairingHost) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.stopped++
	h.live = nil
}

func newPairingFixture(t *testing.T) (*httptest.Server, *pairingHost) {
	t.Helper()

	host := &pairingHost{}

	session := bridge.NewSession(bridge.Options{
		Name:    "workstation",
		Pairing: host,
		GenerateKey: func(
			_ context.Context, label, comment string,
		) (*ladulasv1.KeyRef, error) {
			if label == "" {
				return nil, errors.New("a key needs a name")
			}

			return &ladulasv1.KeyRef{
				Label:       label,
				Comment:     comment,
				Fingerprint: "SHA256:made",
				Algorithm:   "ssh-ed25519",
			}, nil
		},
	})

	server := httptest.NewServer(session.Handler())
	t.Cleanup(server.Close)

	return server, host
}

func send(
	t *testing.T, server *httptest.Server, method, path, body string,
) (int, []byte) {
	t.Helper()

	req, err := http.NewRequestWithContext(
		t.Context(), method, server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s: %v", method, path, err)
	}

	return resp.StatusCode, out
}

// TestAnInvitationCarriesEveryWayIn: one secret, three kinds of machine. A
// terminal types the command, another window pastes the full code, a phone
// points a camera at the picture — and the screen has to hand over all three,
// because which is easiest depends on what the person is holding.
func TestAnInvitationCarriesEveryWayIn(t *testing.T) {
	server, host := newPairingFixture(t)

	status, body := send(t, server, http.MethodPost,
		"/api/v1/pairings/invite", `{"intent":"approver"}`)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	var view bridge.InvitationView

	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	if view.Code != "k7n41-9qra0" {
		t.Errorf("the code is %q", view.Code)
	}

	if !strings.Contains(view.Join, "guppy:7373") ||
		!strings.Contains(view.Join, view.Code) {
		t.Errorf("the command to run elsewhere is %q", view.Join)
	}

	// The command carries no direction of its own: what the pairing is for was
	// settled here, and a flag on the other side would be a second answer to a
	// question that has one.
	if strings.Contains(view.Join, "--intent") ||
		strings.Contains(view.Join, "--role") {
		t.Errorf("the command asks the other side to choose as well: %q", view.Join)
	}

	if view.Intent != "approver" || view.Direction == "" {
		t.Errorf("the intent reads %q / %q", view.Intent, view.Direction)
	}

	if view.QR == "" {
		t.Fatal("no picture for a camera")
	}

	// And the picture is one, drawn here rather than left to a command line
	// somebody has to know about.
	status, drawn := send(t, server, http.MethodGet, view.QR, "")
	if status != http.StatusOK {
		t.Fatalf("the QR would not draw: %d %s", status, drawn)
	}

	if !strings.HasPrefix(string(drawn), "<svg") {
		t.Errorf("the QR is not a drawing: %.40s", drawn)
	}

	if len(host.asked) != 1 || host.asked[0] != trust.IntentPeerApproves {
		t.Errorf("the host was asked for %v", host.asked)
	}
}

// A code already on display is handed back rather than replaced: a code is
// single use and five minutes long, and two of them on two screens is one
// somebody will type the wrong one of.
func TestAWindowReopenedShowsTheCodeAlreadyOnDisplay(t *testing.T) {
	server, host := newPairingFixture(t)

	status, _ := send(t, server, http.MethodGet, "/api/v1/pairings/invitation", "")
	if status != http.StatusNotFound {
		t.Errorf("status %d with nothing on display, want 404", status)
	}

	send(t, server, http.MethodPost,
		"/api/v1/pairings/invite", `{"intent":"mutual"}`)

	status, body := send(t, server, http.MethodGet,
		"/api/v1/pairings/invitation", "")
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	status, _ = send(t, server, http.MethodPost, "/api/v1/pairings/stop", "")
	if status != http.StatusOK {
		t.Errorf("stopping said %d", status)
	}

	if host.stopped != 1 {
		t.Errorf("the host was told to stop %d times", host.stopped)
	}

	status, _ = send(t, server, http.MethodGet, "/api/v1/pairings/invitation", "")
	if status != http.StatusNotFound {
		t.Errorf("status %d after stopping, want 404", status)
	}
}

// An invitation with no intent is refused, and refused as the question rather
// than as a failure: what a pairing is for is the thing a pairing decides.
func TestAPairingWithoutAnIntentIsRefused(t *testing.T) {
	server, host := newPairingFixture(t)

	for _, body := range []string{`{}`, `{"intent":""}`, `{"intent":"sideways"}`} {
		status, out := send(t, server, http.MethodPost,
			"/api/v1/pairings/invite", body)
		if status != http.StatusBadRequest {
			t.Errorf("%s said %d: %s", body, status, out)
		}
	}

	if len(host.asked) != 0 {
		t.Errorf("a code was spent anyway: %v", host.asked)
	}
}

// The peer is named in the body and not in the path, because a fingerprint
// carries slashes — the same reason the browsing calls put it in the query.
func TestAPairingIsRevokedByFingerprint(t *testing.T) {
	var forgotten []string

	session := bridge.NewSession(bridge.Options{
		Name: "workstation",
		RevokePeer: func(_ context.Context, peer string) error {
			if peer != "SHA256:a/b+c=" {
				return errors.New("no such peer")
			}

			forgotten = append(forgotten, peer)

			return nil
		},
	})

	server := httptest.NewServer(session.Handler())
	t.Cleanup(server.Close)

	status, body := send(t, server, http.MethodPost, "/api/v1/peers/revoke",
		`{"peer":"SHA256:a/b+c="}`)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	if len(forgotten) != 1 {
		t.Fatalf("the host was asked to forget %v", forgotten)
	}

	status, _ = send(t, server, http.MethodPost, "/api/v1/peers/revoke", `{}`)
	if status != http.StatusBadRequest {
		t.Errorf("forgetting nothing said %d", status)
	}

	status, _ = send(t, server, http.MethodPost, "/api/v1/peers/revoke",
		`{"peer":"SHA256:somebody-else"}`)
	if status != http.StatusNotFound {
		t.Errorf("forgetting a stranger said %d", status)
	}
}

func TestAKeyIsMadeInTheDaemonsStore(t *testing.T) {
	server, _ := newPairingFixture(t)

	status, body := send(t, server, http.MethodPost, "/api/v1/keys",
		`{"label":"work","comment":"hugo@guppy"}`)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	var key bridge.KeyView

	if err := json.Unmarshal(body, &key); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	if key.Label != "work" || key.Fingerprint != "SHA256:made" {
		t.Errorf("the key came back as %+v", key)
	}

	// A key with no name is refused where the name is asked for, rather than
	// arriving in a store as an untitled row.
	status, _ = send(t, server, http.MethodPost, "/api/v1/keys", `{"label":"  "}`)
	if status != http.StatusBadRequest {
		t.Errorf("an unnamed key said %d", status)
	}
}
