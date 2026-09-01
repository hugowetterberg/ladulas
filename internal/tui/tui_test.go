package tui

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/hugowetterberg/ladulas/pkg/bridge"
)

// What the terminal has to get right.
//
// It is a surface for answering signing requests, so the things worth asserting
// are the things that would make somebody approve the wrong thing or fail to
// refuse the right one: that the card says what the request is, that the diff
// is there to be read, that the answer keys are on screen whatever is scrolled
// where, and that what goes back to the instance is what was pressed.

// stub is the bridge as this program sees it: a handler that answers the three
// calls the terminal makes, and remembers what it was told.
type stub struct {
	mu sync.Mutex

	view    bridge.RequestView
	answers []answerBody
	refuse  string
	full    bridge.DiffView
}

func (s *stub) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/requests/{id}", func(
		w http.ResponseWriter, _ *http.Request,
	) {
		s.mu.Lock()
		defer s.mu.Unlock()

		_ = json.NewEncoder(w).Encode(s.view)
	})

	mux.HandleFunc("POST /api/v1/requests/{id}/answer", func(
		w http.ResponseWriter, r *http.Request,
	) {
		var body answerBody

		_ = json.NewDecoder(r.Body).Decode(&body)

		s.mu.Lock()
		defer s.mu.Unlock()

		s.answers = append(s.answers, body)

		if s.refuse != "" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": s.refuse})

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /api/v1/requests/{id}/diff", func(
		w http.ResponseWriter, _ *http.Request,
	) {
		s.mu.Lock()
		defer s.mu.Unlock()

		_ = json.NewEncoder(w).Encode(s.full)
	})

	mux.HandleFunc("GET /api/v1/settings", func(
		w http.ResponseWriter, _ *http.Request,
	) {
		_ = json.NewEncoder(w).Encode(bridge.SettingsView{
			SignTimeoutSeconds:        3600,
			DefaultSignTimeoutSeconds: 3600,
			MinSignTimeoutSeconds:     30,
			MaxSignTimeoutSeconds:     86400,
		})
	})

	return mux
}

func (s *stub) sent() []answerBody {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]answerBody(nil), s.answers...)
}

// gitView is an ordinary commit signature: the thing this program exists for.
func gitView() bridge.RequestView {
	return bridge.RequestView{
		ID:      "req-1",
		Kind:    "git-sign",
		Title:   "Git signature",
		Subject: "a listener that binds one tier",
		Key: &bridge.KeyView{
			Label:       "work",
			Fingerprint: "SHA256:workkey",
			Algorithm:   "ssh-ed25519",
		},
		Requester: &bridge.RequesterView{
			Local:   true,
			Program: "/usr/bin/git",
			Asker:   "this kitty window",
			Chain:   "git ← zsh ← kitty",
		},
		Grant: &bridge.GrantOffer{
			Session:     "this kitty window",
			Machine:     "guppy",
			MaxSeconds:  8 * 3600,
			Suggestions: []int64{900, 3600, 3 * 3600, 8 * 3600},
		},
		Git: &bridge.GitView{
			Verified:   true,
			ObjectType: "commit",
			Repository: "/home/hugo/Projects/ladulas",
			Branch:     "main",
			Subject:    "a listener that binds one tier",
			Message:    "a listener that binds one tier\n\nand an address that was our own.",
			Author: &bridge.IdentityView{
				Name:  "Hugo Wetterberg",
				Email: "hugo@example.com",
				Time:  "2026-09-01 09:12:00",
			},
			Diff: &bridge.DiffView{
				FilesChanged: 1,
				Insertions:   1,
				Deletions:    1,
				Truncated:    true,
				Files: []bridge.DiffFileView{{
					OldPath:    "agent/server.go",
					NewPath:    "agent/server.go",
					Status:     "modified",
					Insertions: 1,
					Deletions:  1,
					Hunks: []bridge.DiffHunkView{{
						Header: "@@ -150,3 +150,3 @@ func listen() {",
						Lines: []bridge.DiffLineView{
							{Kind: "context", Text: "\tlistener, err := net.Listen(...)"},
							{Kind: "removed", Text: "\tos.Chmod(path, 0o644)"},
							{Kind: "added", Text: "\tos.Chmod(path, 0o600)"},
						},
					}},
				}},
			},
		},
	}
}

// fixture is a model with a request already on screen, which is the state every
// one of these is about.
func fixture(t *testing.T) (*model, *stub) {
	t.Helper()

	host := &stub{view: gitView()}
	m := newModel(&api{handler: host.handler()}, "/run/user/1000/ladulas/control.sock")

	m.width = 100
	m.height = 40
	m.attached = true

	m.present(presentMsg{
		id:    "req-1",
		since: time.Now(),
		view:  host.view,
	})

	return m, host
}

// keystroke is one key as the program will read it. The names are the ones
// Key.String() produces, which is what the key tables in this package match on,
// so a test presses the key a person presses.
func keystroke(name string) tea.KeyMsg {
	switch name {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(name)}
	}
}

// press feeds a key and runs whatever command came back, so that a test sees
// what the program does rather than what it intends to do.
func press(t *testing.T, m *model, keys ...string) {
	t.Helper()

	for _, key := range keys {
		_, cmd := m.Update(keystroke(key))

		for cmd != nil {
			msg := cmd()
			if msg == nil {
				break
			}

			_, cmd = m.Update(msg)
		}
	}
}

// TestTheCardSaysWhatIsBeingSigned: the four facts decision W says a card leads
// with — what is being asked, on what, by which program, with which key.
func TestTheCardSaysWhatIsBeingSigned(t *testing.T) {
	m, _ := fixture(t)

	screen := m.View()

	for _, want := range []string{
		"Git signature",
		"a listener that binds one tier",
		"/home/hugo/Projects/ladulas",
		"Hugo Wetterberg",
		"SHA256:workkey",
		"this kitty window",
	} {
		if !strings.Contains(screen, want) {
			t.Errorf("the card does not say %q", want)
		}
	}

	// The provenance line is what keeps the whole rich prompt honest (§5): it
	// says which half of the card is derived from the bytes being signed.
	if !strings.Contains(screen, "checked against the bytes") {
		t.Error("the card does not say what was checked against the payload")
	}
}

// TestTheAnswerKeysAreAlwaysOnScreen: buttons underneath the diff meant
// scrolling past the whole change before you could refuse it, which the window
// learned and wrote down. Whatever is scrolled where, the way to say no is in
// the same place.
func TestTheAnswerKeysAreAlwaysOnScreen(t *testing.T) {
	m, _ := fixture(t)

	press(t, m, "G")

	screen := m.View()

	if !strings.Contains(screen, "deny") {
		t.Error("scrolled to the bottom, there is no way to refuse on screen")
	}

	if !strings.Contains(screen, "approve once") {
		t.Error("scrolled to the bottom, there is no way to approve on screen")
	}
}

// TestTheDiffOpensAFileAtATime: the diffstat is what an approver reads first
// and the hunks are the drill-down, so every file starts closed and enter opens
// the one under the cursor.
func TestTheDiffOpensAFileAtATime(t *testing.T) {
	m, _ := fixture(t)

	press(t, m, "G")

	if strings.Contains(m.View(), "os.Chmod(path, 0o600)") {
		t.Error("the diff was open before anybody opened it")
	}

	if !strings.Contains(m.View(), "agent/server.go") {
		t.Error("the file the change touches is not listed")
	}

	press(t, m, "n", "enter")

	if !strings.Contains(m.View(), "os.Chmod(path, 0o600)") {
		t.Error("opening the file did not show its lines")
	}

	press(t, m, "enter")

	if strings.Contains(m.View(), "os.Chmod(path, 0o600)") {
		t.Error("closing the file did not hide its lines")
	}
}

// TestApprovingOnceSendsAnApprovalAndNoPromise: the ordinary answer, and the
// one it must not quietly become.
func TestApprovingOnceSendsAnApprovalAndNoPromise(t *testing.T) {
	m, host := fixture(t)

	press(t, m, "a")

	sent := host.sent()
	if len(sent) != 1 {
		t.Fatalf("the instance was told %d things", len(sent))
	}

	if sent[0].Decision != "approve" {
		t.Errorf("the decision was %q", sent[0].Decision)
	}

	if sent[0].GrantSeconds != 0 {
		t.Errorf("approving once made a promise of %ds", sent[0].GrantSeconds)
	}
}

// TestDenyingSendsADenial.
func TestDenyingSendsADenial(t *testing.T) {
	m, host := fixture(t)

	press(t, m, "d")

	sent := host.sent()
	if len(sent) != 1 || sent[0].Decision != "deny" {
		t.Fatalf("the instance was told %+v", sent)
	}
}

// TestAPromiseIsAReachAndALength: decision V asks two questions, and the answer
// carries both. The narrower reach is what an answer that says nothing means,
// so this checks the one that has to be said explicitly.
func TestAPromiseIsAReachAndALength(t *testing.T) {
	m, host := fixture(t)

	press(t, m, "w")

	if m.mode != modeGrant {
		t.Fatal("w did not open the promise")
	}

	// The session is the default reach, and the machine is a choice.
	press(t, m, "right", "tab")

	// Two quarter-hours past the hour it opens on.
	press(t, m, "right", "right", "enter")

	sent := host.sent()
	if len(sent) != 1 {
		t.Fatalf("the instance was told %d things", len(sent))
	}

	if sent[0].Decision != "approve" {
		t.Errorf("the decision was %q", sent[0].Decision)
	}

	if sent[0].GrantScope != "machine" {
		t.Errorf("the promise reaches %q", sent[0].GrantScope)
	}

	if sent[0].GrantSeconds != 3600+2*900 {
		t.Errorf("the promise runs for %ds", sent[0].GrantSeconds)
	}
}

// TestAPromiseIsBoundedByWhatTheInstanceOffers: the surface draws the bound and
// the instance owns it, so the form refuses to dial past what it was given
// rather than sending something that will be refused (decision V).
func TestAPromiseIsBoundedByWhatTheInstanceOffers(t *testing.T) {
	m, host := fixture(t)

	press(t, m, "w", "tab")

	for range 40 {
		press(t, m, "L")
	}

	press(t, m, "enter")

	sent := host.sent()
	if len(sent) != 1 {
		t.Fatalf("the instance was told %d things", len(sent))
	}

	if sent[0].GrantSeconds != 8*3600 {
		t.Errorf("the promise runs for %ds, past the 8 hours offered",
			sent[0].GrantSeconds)
	}
}

// TestAnAnswerThatLostItsRaceLeavesTheCardUp: the usual reason an answer fails
// is that somebody else answered first, and the second-usual is that the daemon
// went away. Neither is a reason to stop showing a question that this terminal
// cannot know has been settled.
func TestAnAnswerThatLostItsRaceLeavesTheCardUp(t *testing.T) {
	m, host := fixture(t)

	host.refuse = "this request is no longer waiting"

	press(t, m, "a")

	if len(m.queue) != 1 {
		t.Fatal("the card went away on an answer that did not go through")
	}

	if !strings.Contains(m.View(), "no longer waiting") {
		t.Errorf("the screen does not say what happened:\n%s", m.View())
	}

	// And it can be answered again, rather than being stuck mid-answer.
	press(t, m, "d")

	if len(host.sent()) != 2 {
		t.Error("the card could not be answered a second time")
	}
}

// TestACardTakenAwayWithoutAnAnswerSaysSo: a request settled by a phone, a
// grant or the budget running out disappears off this screen, and somebody
// looking at it deserves to be told which of those it was rather than watching
// a card vanish.
func TestACardTakenAwayWithoutAnAnswerSaysSo(t *testing.T) {
	m, _ := fixture(t)

	m.Update(dismissMsg{id: "req-1"})

	if len(m.queue) != 0 {
		t.Fatal("the card is still there")
	}

	if !strings.Contains(m.View(), "settled without this terminal") {
		t.Errorf("the screen does not say what happened:\n%s", m.View())
	}
}

// TestQuittingWithSomethingWaitingAsksFirst: leaving takes this approver away
// and the request goes on waiting for whoever else can answer — which is
// ordinary, and is not a denial, and is still worth one keystroke of
// confirmation, because the person quitting is often the one it was waiting for.
func TestQuittingWithSomethingWaitingAsksFirst(t *testing.T) {
	m, _ := fixture(t)

	_, cmd := m.Update(keystroke("q"))
	if cmd != nil {
		t.Fatal("q with a request waiting quit straight away")
	}

	if !strings.Contains(m.View(), "Press q again") {
		t.Error("the screen does not say what the second q does")
	}

	if _, cmd := m.Update(keystroke("q")); cmd == nil {
		t.Error("the second q did not quit")
	}
}

// TestNothingWaitingSaysWhatWillHappen: this program spends nearly all of its
// life with an empty screen, and an empty screen that says nothing is
// indistinguishable from one that has stopped working.
func TestNothingWaitingSaysWhatWillHappen(t *testing.T) {
	host := &stub{view: gitView()}
	m := newModel(&api{handler: host.handler()}, "/run/user/1000/ladulas/control.sock")

	m.width = 100
	m.height = 40
	m.attached = true

	if cmd := m.settingsCmd(); cmd != nil {
		m.Update(cmd())
	}

	screen := m.View()

	if !strings.Contains(screen, "Nothing is waiting") {
		t.Errorf("the idle screen reads:\n%s", screen)
	}

	// The budget is the daemon's and is worth saying, because it is the answer
	// to "how long have I got" (§9).
	if !strings.Contains(screen, "waits up to 1 hour") {
		t.Errorf("the idle screen does not say how long a request waits:\n%s",
			screen)
	}
}

// TestTheRestOfADiffCanBeFetched: the diff a request carries is capped because
// it travels with something somebody is waiting on, and that was never a
// statement about what an approver may see (§5).
func TestTheRestOfADiffCanBeFetched(t *testing.T) {
	m, host := fixture(t)

	host.full = bridge.DiffView{
		FilesChanged: 1,
		Insertions:   2,
		Deletions:    1,
		Files: []bridge.DiffFileView{{
			NewPath:    "agent/server.go",
			Insertions: 2,
			Deletions:  1,
			Hunks: []bridge.DiffHunkView{{
				Header: "@@ -150,4 +150,5 @@ func listen() {",
				Lines: []bridge.DiffLineView{
					{Kind: "added", Text: "\tthe rest of it"},
				},
			}},
		}},
	}

	press(t, m, "f", "n", "enter")

	if !strings.Contains(m.View(), "the rest of it") {
		t.Errorf("the fetched diff is not on screen:\n%s", m.View())
	}
}
