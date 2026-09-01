// Package tui is a second shell for the front end: the same approver the
// desktop window is, drawn in a terminal (decision AK, §12, §14).
//
// internal/frontend has said since decision Z that its host "supplies a
// bridge.Presenter and nothing else", and that a different toolkit or a
// terminal could be written against the same seam. This is that: the watching,
// the answering and the audit entry are the front end's, the card is the same
// RequestView the window draws from, and what is here is the drawing and the
// keys.
//
// It is not the console approver in pkg/approval. That one lives inside the
// daemon, prompts on the daemon's own stdin, and is what `ladulasd run` gives a
// box that was started interactively; it offers a yes, a no and the four fixed
// lengths, because a line-oriented prompt asked to express a reach and a clock
// would be asking somebody to spell out in the dark the thing the wording is
// there to make plain. This is a screen with a picker on it, so it offers what
// the window offers: the whole of decision V, and the diff.
package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/hugowetterberg/ladulas/internal/frontend"
	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/pkg/bridge"
)

// ID names this approver in the audit log, so that a decision reads "approved
// at the terminal" and a person reading the log later can tell which of the
// surfaces in front of them it came from.
const ID = "terminal"

// Run attaches to the daemon and answers on this terminal until the context is
// done or somebody quits.
func Run(ctx context.Context, client *localapi.Client, logger *slog.Logger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var program *tea.Program

	front, err := frontend.New(frontend.Options{
		Client: client,
		ID:     ID,
		Logger: logger,
		Attached: func(attached bool) {
			// Assigned before the stream that calls this is started, so there
			// is nothing to race with; the nil check is for a callback that
			// somehow arrives before Run has got that far.
			if program != nil {
				program.Send(attachedMsg(attached))
			}
		},
	})
	if err != nil {
		return fmt.Errorf("build the front end: %w", err)
	}

	session := front.Session()
	api := &api{handler: session.Handler()}

	program = tea.NewProgram(
		newModel(api, client.SocketPath()),
		tea.WithContext(ctx),
		// The alternate screen, because this is a program somebody leaves
		// running in a window: it should give the scrollback back untouched
		// when it exits, rather than leaving a page of somebody's commit
		// message in the terminal's history.
		tea.WithAltScreen())

	// No mouse reporting, deliberately. Turning it on would buy a scroll wheel
	// and cost the terminal's own selection, and this is a screen somebody
	// copies a fingerprint or a path off. Most terminals send arrow keys for
	// the wheel in the alternate screen anyway, which is what the scroll keys
	// already are.

	front.SetPresenter(&presenter{program: program, api: api, log: logger})

	// The front end keeps trying for as long as it is running, so a daemon that
	// is restarted underneath this does not end it. Its error is only ever the
	// context finishing.
	go func() {
		if err := front.Run(ctx); err != nil {
			logger.Debug("the front end stopped", "error", err.Error())
		}
	}()

	if _, err := program.Run(); err != nil {
		return fmt.Errorf("run the terminal approver: %w", err)
	}

	return nil
}

// presenter is the host's half of the bridge contract: it puts a request in
// front of somebody and takes it away again.
//
// Present must not block — the goroutine calling it is the one deciding the
// request — so the fetch of the card and the delivery of it both happen
// somewhere else.
type presenter struct {
	program *tea.Program
	api     *api
	log     *slog.Logger
}

var (
	_ bridge.Presenter = (*presenter)(nil)
	_ bridge.Announcer = (*presenter)(nil)
)

func (p *presenter) Present(req *bridge.PendingRequest) {
	id := req.ID
	since := req.Since

	go func() {
		view, err := p.api.request(id)
		if err != nil {
			// The request is still waiting and this terminal simply cannot
			// draw it, so it is reported rather than swallowed: a card that
			// silently never appears is indistinguishable from a daemon that
			// never asked.
			p.log.Error("a waiting request could not be drawn",
				"request_id", id, "error", err.Error())
			p.program.Send(troubleMsg{
				text: "a request arrived that could not be drawn: " + err.Error(),
			})

			return
		}

		p.program.Send(presentMsg{id: id, since: since, view: view})
	}()
}

func (p *presenter) Dismiss(id string) {
	p.program.Send(dismissMsg{id: id})
}

// Announce is the passive notification an auto-approved request still gets
// (§9). It never asked anybody anything, so it is a line at the bottom rather
// than a card.
func (p *presenter) Announce(activity bridge.ActivityView) {
	p.program.Send(announceMsg{activity: activity})
}

// api is the bridge as a client sees it: a method, a path and a body, which is
// the whole contract (bridge.Call).
//
// The terminal goes through the same handler the webview does rather than
// reaching into the session, so that both surfaces answer through one code
// path — the bound on a promise, the audit entry naming what was on screen, and
// the refusal of a request that has since been settled are all on the far side
// of it.
type api struct {
	handler http.Handler
}

func (a *api) request(id string) (bridge.RequestView, error) {
	var view bridge.RequestView

	err := a.call(http.MethodGet, "/api/v1/requests/"+id, nil, &view)
	if err != nil {
		return bridge.RequestView{}, err
	}

	return view, nil
}

// answerBody is what the bridge reads back: the decision, and the promise that
// goes with it when one was made.
type answerBody struct {
	Decision     string `json:"decision"`
	GrantSeconds int64  `json:"grantSeconds"`
	GrantScope   string `json:"grantScope"`
}

func (a *api) answer(id string, body answerBody) error {
	return a.call(http.MethodPost, "/api/v1/requests/"+id+"/answer", body, nil)
}

// diff asks the requester for the rest of a diff the caps cut short (§5). An
// empty path means the whole of it, which is what the one key that asks for it
// wants.
func (a *api) diff(id string) (bridge.DiffView, error) {
	var view bridge.DiffView

	body := struct {
		Path string `json:"path"`
	}{}

	if err := a.call(
		http.MethodPost, "/api/v1/requests/"+id+"/diff", body, &view); err != nil {
		return bridge.DiffView{}, err
	}

	return view, nil
}

// unlock hands the passphrase to the daemon, which is the only process that
// can do anything with it.
//
// The bytes are the caller's to wipe and the encoded body is wiped here: this
// is a screen somebody types a passphrase into, and the difference between a
// buffer that is cleared and one that is merely dropped is the difference
// between a core file that is embarrassing and one that is a key.
func (a *api) unlock(passphrase []byte) (bridge.LockView, error) {
	encoded, err := json.Marshal(struct {
		Passphrase []byte `json:"passphrase"`
	}{Passphrase: passphrase})
	if err != nil {
		return bridge.LockView{}, fmt.Errorf("encode the passphrase: %w", err)
	}

	defer wipe(encoded)

	var view bridge.LockView

	if err := a.callRaw(
		http.MethodPost, "/api/v1/lock/unlock", encoded, &view); err != nil {
		return bridge.LockView{}, err
	}

	return view, nil
}

// wipe clears a buffer that held key material. It is not a guarantee — Go moves
// memory and the daemon has its own copy — but it takes the obvious copy out of
// this process's heap, which is the same thing keystore.Wipe does on the other
// side of the socket.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (a *api) lock() (bridge.LockView, error) {
	var view bridge.LockView

	if err := a.call(http.MethodGet, "/api/v1/lock", nil, &view); err != nil {
		return bridge.LockView{}, err
	}

	return view, nil
}

func (a *api) settings() (bridge.SettingsView, error) {
	var view bridge.SettingsView

	if err := a.call(http.MethodGet, "/api/v1/settings", nil, &view); err != nil {
		return bridge.SettingsView{}, err
	}

	return view, nil
}

// call runs one request through the handler and reads the answer, turning the
// bridge's `{"error": …}` into an ordinary Go error.
func (a *api) call(method, path string, body, into any) error {
	var encoded []byte

	if body != nil {
		marshalled, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode the request: %w", err)
		}

		encoded = marshalled
	}

	return a.callRaw(method, path, encoded, into)
}

// callRaw is the same with the body already encoded, for the one caller that
// has to be able to clear the buffer afterwards.
func (a *api) callRaw(method, path string, body []byte, into any) error {
	req := &bridge.CallRequest{Method: method, Path: path}

	if body != nil {
		req.Body = body
		req.ContentType = "application/json"
	}

	resp := bridge.Call(a.handler, req)

	if resp.Status < 200 || resp.Status > 299 {
		var failure struct {
			Error string `json:"error"`
		}

		if err := json.Unmarshal(resp.Body, &failure); err == nil &&
			failure.Error != "" {
			return errors.New(failure.Error)
		}

		return fmt.Errorf("the instance answered %d", resp.Status)
	}

	if into == nil {
		return nil
	}

	if err := json.Unmarshal(resp.Body, into); err != nil {
		return fmt.Errorf("read the answer: %w", err)
	}

	return nil
}

// IsTerminal says whether there is a terminal to draw on, so the command can
// refuse with a sentence rather than painting escape codes into a pipe.
func IsTerminal() bool {
	return isTerminal(os.Stdout)
}

// IsTerminalErr says whether the log would land on the screen, which decides
// whether there is anywhere to write one.
func IsTerminalErr() bool {
	return isTerminal(os.Stderr)
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}

// tick is the clock the header runs on. A second is as fine as "waiting 3m12s"
// needs, and coarse enough that a terminal left open all day is not repainting
// for nothing.
const tick = time.Second
