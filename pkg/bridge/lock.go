package bridge

import (
	"encoding/json"
	"net/http"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The lock states in the viewer (§10).
//
// The unlock dialog is a page rather than a native dialog for the same reason
// every other prompt is: one bundle, several hosts. A desktop opens a window at
// /?unlock=1, and the phone shells will show the same panel in their own
// webview when M6 needs it. What is host-specific is opening the window.

// Lock is the host's store, as much of it as the viewer is allowed to touch.
// Optional: a session without one shows no unlock panel and no lock buttons.
type Lock interface {
	// State is what the store is doing right now.
	State() LockView
	// Unlock unseals, or lifts a soft lock. An empty passphrase means "use the
	// keychain", for an instance that unlocks at login.
	Unlock(passphrase []byte) error
	// Lock suspends approval here, or — with seal — wipes the store key.
	Lock(seal bool) error
}

// StateNotRunning is the state a front end reports when there is no instance to
// report the state of (decision Z).
//
// It is not a lock state and never comes from a daemon: it is what a desktop
// application says while nothing is listening on the control socket, which
// since the front end stopped being an instance is an ordinary thing to find —
// at login, before the user unit has come up, and for as long as somebody has
// stopped it. The panel says what to start rather than offering a passphrase
// field that has nothing to unlock, exactly as it does for a store that has
// never been created.
const StateNotRunning = "not running"

// StateWord names a lock state in the words every surface uses for it: the
// status pane, the unlock panel and the terminal.
//
// One function because they are one vocabulary. A viewer that said "closed"
// where `ladulas status` said "sealed" would be two programs describing one
// machine, and the words are load-bearing — "sealed" and "locked" are the whole
// of what §10 is about.
func StateWord(state ladulasv1.LockState) string {
	switch state {
	case ladulasv1.LockState_LOCK_STATE_SEALED:
		return "sealed"
	case ladulasv1.LockState_LOCK_STATE_UNLOCKED:
		return "unlocked"
	case ladulasv1.LockState_LOCK_STATE_LOCKED:
		return "locked"
	case ladulasv1.LockState_LOCK_STATE_UNINITIALIZED:
		return "not created yet"
	case ladulasv1.LockState_LOCK_STATE_UNSPECIFIED:
		return "unknown"
	default:
		return "unknown"
	}
}

// LockView is the store's state as the viewer sees it.
type LockView struct {
	// State is "sealed", "unlocked" or "locked".
	State string `json:"state"`
	// Reason says what put it in that state, when something other than a person
	// did: "the machine was suspended".
	Reason string `json:"reason,omitempty"`
	// Passphrase and KeyringEnrolled decide what the panel offers: an enrolled
	// instance is offered an unlock with nothing typed.
	Passphrase bool `json:"passphrase"`
	// KeyringEnrolled is only meaningful when State is not "unlocked", and a host
	// may leave it false otherwise rather than go and find out.
	//
	// Answering it is not free everywhere — on a phone the keychain holds the
	// item behind biometrics — and this view is read on a timer, so a host that
	// answered it unconditionally would pay for it many times a minute to
	// describe a gate that is not on screen. Nothing consumes it while the store
	// is open: there is nothing to unlock, and the panel says so and stops
	// before it reads this.
	KeyringEnrolled bool `json:"keyringEnrolled"`
}

func (s *Session) handleLockState(w http.ResponseWriter, _ *http.Request) {
	if s.opts.Lock == nil {
		writeError(w, http.StatusNotImplemented,
			"this host does not manage the store's lock state")

		return
	}

	writeJSON(w, http.StatusOK, s.opts.Lock.State())
}

// handleUnlock takes the passphrase the panel collected.
//
// The bridge is served to the host's own webview over an in-process handler, so
// the passphrase does not cross a socket here at all — but it does end up in a
// JSON body, and the body is wiped once the store has had it, for the same
// reason the control socket's is (§14).
func (s *Session) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if s.opts.Lock == nil {
		writeError(w, http.StatusNotImplemented,
			"this host does not manage the store's lock state")

		return
	}

	var body struct {
		Passphrase []byte `json:"passphrase"`
	}

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "the passphrase could not be read")

		return
	}

	err := s.opts.Lock.Unlock(body.Passphrase)

	wipe(body.Passphrase)

	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())

		return
	}

	writeJSON(w, http.StatusOK, s.opts.Lock.State())
}

func (s *Session) handleLock(w http.ResponseWriter, r *http.Request) {
	if s.opts.Lock == nil {
		writeError(w, http.StatusNotImplemented,
			"this host does not manage the store's lock state")

		return
	}

	var body struct {
		Seal bool `json:"seal"`
	}

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "the request could not be read")

		return
	}

	if err := s.opts.Lock.Lock(body.Seal); err != nil {
		writeError(w, http.StatusConflict, err.Error())

		return
	}

	writeJSON(w, http.StatusOK, s.opts.Lock.State())
}

// wipe clears a passphrase buffer. See keystore.Wipe for what that is and is
// not worth; this package does not import the store, so it has its own.
func wipe(secret []byte) {
	for i := range secret {
		secret[i] = 0
	}
}
