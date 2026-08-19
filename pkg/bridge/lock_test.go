package bridge_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/bridge"
)

// The unlock panel's half of the contract. Nobody has seen the window it is
// drawn in — there is no display here and no StatusNotifier host — but what the
// window talks to is this, and this is exercisable.

// fakeLock is a store as the viewer can see it.
type fakeLock struct {
	mu         sync.Mutex
	state      string
	passphrase string
	enrolled   bool
	seen       [][]byte
	// buffer is the slice the handler was given, kept so the test can check
	// that it was wiped afterwards.
	buffer []byte
	sealed bool
	locked bool
}

func (l *fakeLock) State() bridge.LockView {
	l.mu.Lock()
	defer l.mu.Unlock()

	return bridge.LockView{
		State:           l.state,
		Passphrase:      true,
		KeyringEnrolled: l.enrolled,
	}
}

func (l *fakeLock) Unlock(passphrase []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Keeping a copy is the point: the test checks that the buffer the handler
	// was given is wiped, and a copy is the only way to know what it held.
	kept := make([]byte, len(passphrase))
	copy(kept, passphrase)
	l.seen = append(l.seen, kept)
	l.buffer = passphrase

	if string(passphrase) != l.passphrase {
		return errors.New("that is not the passphrase")
	}

	l.state = "unlocked"

	return nil
}

func (l *fakeLock) Lock(seal bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if seal {
		l.sealed = true
		l.state = "sealed"

		return nil
	}

	l.locked = true
	l.state = "locked"

	return nil
}

func lockSession(lock bridge.Lock) *bridge.Session {
	return bridge.NewSession(bridge.Options{
		Name:      "desktop",
		Lock:      lock,
		Presenter: &presenter{},
	})
}

func TestUnlockThroughTheViewer(t *testing.T) {
	lock := &fakeLock{state: "sealed", passphrase: "correct horse"}
	handler := lockSession(lock).Handler()

	var state bridge.LockView

	getJSON(t, handler, "/api/v1/lock", &state)

	if state.State != "sealed" {
		t.Fatalf("state %q", state.State)
	}

	// The wrong passphrase is a refusal rather than a failure of the page.
	resp := postTo(t, handler, "/api/v1/lock/unlock",
		`{"passphrase":"`+base64Of("hunter2")+`"}`)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("wrong passphrase: %d %s", resp.Code, resp.Body.String())
	}

	resp = postTo(t, handler, "/api/v1/lock/unlock",
		`{"passphrase":"`+base64Of("correct horse")+`"}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("unlock: %d %s", resp.Code, resp.Body.String())
	}

	var after bridge.LockView

	if err := json.Unmarshal(resp.Body.Bytes(), &after); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if after.State != "unlocked" {
		t.Errorf("state %q after unlocking", after.State)
	}

	lock.mu.Lock()
	defer lock.mu.Unlock()

	if len(lock.seen) != 2 || string(lock.seen[1]) != "correct horse" {
		t.Errorf("the store was handed %q", lock.seen)
	}

	// And the buffer it arrived in is not left holding it (§14).
	for i, b := range lock.buffer {
		if b != 0 {
			t.Fatalf("byte %d of the passphrase survived the handler: %q", i, b)
		}
	}
}

func TestLockAndSealThroughTheViewer(t *testing.T) {
	lock := &fakeLock{state: "unlocked"}
	handler := lockSession(lock).Handler()

	if resp := postTo(t, handler, "/api/v1/lock/lock", `{"seal":false}`); resp.Code != http.StatusOK {
		t.Fatalf("lock: %d %s", resp.Code, resp.Body.String())
	}

	lock.mu.Lock()
	softLocked := lock.locked && !lock.sealed
	lock.mu.Unlock()

	if !softLocked {
		t.Error("the plain lock sealed the store")
	}

	if resp := postTo(t, handler, "/api/v1/lock/lock", `{"seal":true}`); resp.Code != http.StatusOK {
		t.Fatalf("seal: %d %s", resp.Code, resp.Body.String())
	}

	lock.mu.Lock()
	defer lock.mu.Unlock()

	if !lock.sealed {
		t.Error("the store was not sealed")
	}
}

// The status pane carries the lock state, which is what puts "locked — the
// session was locked" in front of somebody wondering why nothing is being
// signed.
func TestInstanceViewCarriesTheLockState(t *testing.T) {
	handler := lockSession(&fakeLock{state: "locked"}).Handler()

	var view bridge.InstanceView

	getJSON(t, handler, "/api/v1/instance", &view)

	if view.Lock == nil || view.Lock.State != "locked" {
		t.Errorf("the status pane does not carry the lock state: %+v", view.Lock)
	}
}

// A host that does not manage a store — a phone, where the keys are in the
// secure element — says so rather than pretending to have unlocked something.
func TestHostWithoutALockSaysSo(t *testing.T) {
	handler := bridge.NewSession(bridge.Options{Name: "phone"}).Handler()

	if resp := getFrom(t, handler, "/api/v1/lock"); resp.Code != http.StatusNotImplemented {
		t.Errorf("lock state: %d", resp.Code)
	}

	if resp := postTo(t, handler, "/api/v1/lock/unlock", `{}`); resp.Code != http.StatusNotImplemented {
		t.Errorf("unlock: %d", resp.Code)
	}
}

func getFrom(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))

	return recorder
}

func getJSON(t *testing.T, handler http.Handler, path string, into any) {
	t.Helper()

	resp := getFrom(t, handler, path)
	if resp.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, resp.Code, resp.Body.String())
	}

	if err := json.Unmarshal(resp.Body.Bytes(), into); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func postTo(
	t *testing.T, handler http.Handler, path, body string,
) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(recorder, req)

	return recorder
}

// base64Of is what the viewer's encodePassphrase produces, and what a Go []byte
// field expects.
func base64Of(text string) string {
	return base64.StdEncoding.EncodeToString([]byte(text))
}
