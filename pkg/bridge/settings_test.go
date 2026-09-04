package bridge_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/bridge"
)

// The settings a surface may change (§9).
//
// There is one of them and it is a number, which is the whole of the design:
// the policy decides what is approved without asking, so a screen that could
// write rules would be an auto-approve rule one mis-click away. These check
// that the one number can be read and written, and that a host which cannot
// write it is a host whose screen offers nothing rather than one that appears
// to work.

type settingsHost struct {
	mu      sync.Mutex
	timeout time.Duration
	refuse  error
	writes  []time.Duration
}

func (h *settingsHost) view() (bridge.SettingsView, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	return bridge.SettingsView{
		SignTimeoutSeconds:        int64(h.timeout / time.Second),
		DefaultSignTimeoutSeconds: int64(approval.DefaultSignTimeout / time.Second),
		MinSignTimeoutSeconds:     int64(approval.MinSignTimeout / time.Second),
		MaxSignTimeoutSeconds:     int64(approval.MaxSignTimeout / time.Second),
		PolicyPath:                "/home/hugo/.config/ladulas/policy.json",
		MaxGrantSeconds:           8 * 3600,
	}, nil
}

func (h *settingsHost) set(d time.Duration) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.writes = append(h.writes, d)

	if h.refuse != nil {
		return h.refuse
	}

	h.timeout = d

	return nil
}

func newSettingsFixture(
	_ *testing.T, host *settingsHost, writable bool,
) http.Handler {
	opts := bridge.Options{
		Name:      "workstation",
		Presenter: &presenter{},
	}

	if host != nil {
		opts.Settings = host.view
	}

	if writable {
		opts.SetSignTimeout = host.set
	}

	return bridge.NewSession(opts).Handler()
}

// TestTheSigningBudgetIsOnTheInstanceView: a settings screen is drawn from one
// call, so the value it shows arrives with everything else on that screen
// rather than in a second request that can be a moment out of date.
func TestTheSigningBudgetIsOnTheInstanceView(t *testing.T) {
	host := &settingsHost{timeout: time.Hour}
	handler := newSettingsFixture(t, host, true)

	var view bridge.InstanceView

	getJSON(t, handler, "/api/v1/instance", &view)

	if view.Settings == nil {
		t.Fatal("the instance view carries no settings")
	}

	if view.Settings.SignTimeoutSeconds != 3600 {
		t.Errorf("the budget is %ds", view.Settings.SignTimeoutSeconds)
	}

	if view.Settings.DefaultSignTimeoutSeconds !=
		int64(approval.DefaultSignTimeout/time.Second) {
		t.Errorf("the default is %ds, which is not the core's",
			view.Settings.DefaultSignTimeoutSeconds)
	}

	// A screen offers nothing past the bound and the daemon refuses anything
	// past it, so the bound has to reach the screen (decision V).
	if view.Settings.MaxSignTimeoutSeconds <= view.Settings.MinSignTimeoutSeconds {
		t.Errorf("the bounds are %d..%d",
			view.Settings.MinSignTimeoutSeconds,
			view.Settings.MaxSignTimeoutSeconds)
	}

	// The same for the clock that extends a grant: it stops where a grant
	// offer's does, and the number is the instance's.
	if view.Settings.MaxGrantSeconds != 8*3600 {
		t.Errorf("the longest promise is %ds", view.Settings.MaxGrantSeconds)
	}
}

// TestSettingTheBudgetAnswersWithWhatAReadWouldSay: the write's answer is the
// new state, so a screen redraws from the reply instead of polling to find out
// whether its own write took.
func TestSettingTheBudgetAnswersWithWhatAReadWouldSay(t *testing.T) {
	host := &settingsHost{timeout: time.Hour}
	handler := newSettingsFixture(t, host, true)

	resp := postTo(t, handler,
		"/api/v1/settings/sign-timeout", `{"seconds":5400}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("set the budget: %d %s", resp.Code, resp.Body.String())
	}

	var answered bridge.SettingsView

	if err := json.Unmarshal(resp.Body.Bytes(), &answered); err != nil {
		t.Fatalf("read the answer: %v", err)
	}

	if answered.SignTimeoutSeconds != 5400 {
		t.Errorf("the write answered %ds", answered.SignTimeoutSeconds)
	}

	if len(host.writes) != 1 || host.writes[0] != 90*time.Minute {
		t.Errorf("the host was asked for %v", host.writes)
	}
}

// TestABudgetTheInstanceRefusesIsReportedRatherThanTrimmed: the bound belongs
// to the instance, and a value past it comes back as the sentence saying so.
// Trimming it would be a setting somebody thinks they made.
func TestABudgetTheInstanceRefusesIsReportedRatherThanTrimmed(t *testing.T) {
	host := &settingsHost{timeout: time.Hour, refuse: errRefused}
	handler := newSettingsFixture(t, host, true)

	resp := postTo(t, handler,
		"/api/v1/settings/sign-timeout", `{"seconds":999999}`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("a refused budget answered %d %s", resp.Code, resp.Body.String())
	}

	if !strings.Contains(resp.Body.String(), errRefused.Error()) {
		t.Errorf("the refusal reads %s", resp.Body.String())
	}

	if host.timeout != time.Hour {
		t.Errorf("a refused write changed it to %s", host.timeout)
	}
}

// TestABudgetWithNoLengthIsRefused: a missing field and a deliberate zero read
// alike in JSON, and one of them is a signing budget of nothing.
func TestABudgetWithNoLengthIsRefused(t *testing.T) {
	host := &settingsHost{timeout: time.Hour}
	handler := newSettingsFixture(t, host, true)

	resp := postTo(t, handler, "/api/v1/settings/sign-timeout", `{}`)
	if resp.Code != http.StatusBadRequest {
		t.Errorf("a request with no length answered %d", resp.Code)
	}

	if len(host.writes) != 0 {
		t.Errorf("the host was asked for %v", host.writes)
	}
}

// TestAHostThatCannotWriteTheBudgetSaysSo: a phone shell that can read the
// policy and not write it is a real host, and it gets a screen that shows the
// value with no way to change it rather than a button that fails.
func TestAHostThatCannotWriteTheBudgetSaysSo(t *testing.T) {
	host := &settingsHost{timeout: time.Hour}
	handler := newSettingsFixture(t, host, false)

	var view bridge.SettingsView

	getJSON(t, handler, "/api/v1/settings", &view)

	if view.SignTimeoutSeconds != 3600 {
		t.Errorf("the readable budget is %ds", view.SignTimeoutSeconds)
	}

	resp := postTo(t, handler,
		"/api/v1/settings/sign-timeout", `{"seconds":600}`)
	if resp.Code != http.StatusNotImplemented {
		t.Errorf("a host that cannot write answered %d", resp.Code)
	}
}

// TestAHostWithNoSettingsDrawsNone: and a host with neither draws neither, so
// the screen simply has no such section.
func TestAHostWithNoSettingsDrawsNone(t *testing.T) {
	handler := newSettingsFixture(t, nil, false)

	var view bridge.InstanceView

	getJSON(t, handler, "/api/v1/instance", &view)

	if view.Settings != nil {
		t.Errorf("a host with no settings offered %+v", view.Settings)
	}

	resp := getFrom(t, handler, "/api/v1/settings")
	if resp.Code != http.StatusNotImplemented {
		t.Errorf("asking a host with no settings answered %d", resp.Code)
	}
}

var errRefused = errorString(
	"a signing request waits for at least 30s and at most 24 hours")

type errorString string

func (e errorString) Error() string {
	return string(e)
}
