package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/bridge"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The three states of §10, and the transitions between them.
//
// Sealing and unsealing build and destroy the half of the instance that needs
// the data encryption key. Sealing drops that half and, once nothing is still
// signing, zeros the private material it can reach (Vault.Wipe, M5) — so "the
// DEK is not in memory" is close to a fact about the process rather than a bare
// promise, with the honest gap Vault.Wipe names: age's own copy of the scalar
// and the parsed signers are past its reach, and only the collector, in its own
// time, takes those. Soft locking touches none of this: it takes the prompts at
// this instance out of the engine's eligible set and leaves everything else
// exactly where it was, which is what keeps a desktop reachable over SSH while
// its screen is locked.

// ErrSealed is returned by everything that needs the store while it is sealed.
var ErrSealed = errors.New(
	"ladulas: the store is sealed; run `ladulas unlock`")

// ErrPeeringOff is returned when something needs the peer channel on an
// instance that has switched it off.
var ErrPeeringOff = errors.New("ladulas: peering is switched off here")

func errSealedOrNoPeering(state ladulasv1.LockState) error {
	if state == ladulasv1.LockState_LOCK_STATE_SEALED {
		return ErrSealed
	}

	return ErrPeeringOff
}

// State is the instance's lock state.
func (a *App) State() ladulasv1.LockState {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.state
}

// StateDetail is the lock state, when it was entered, and what put it there.
func (a *App) StateDetail() (ladulasv1.LockState, time.Time, string) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.state, a.since, a.reason
}

// StateWord names a lock state for a person reading a terminal.
// It is bridge.StateWord: the terminal and the viewer say the same words about
// the same machine, and a front end that has never opened a store needs them
// without importing this package (decision Z).
func StateWord(state ladulasv1.LockState) string {
	return bridge.StateWord(state)
}

// Initialised reports whether this instance has a store at all. An instance
// that has not is the one state where Unlock is not the way in — there is
// nothing to unlock, and `ladulas init` is the whole of what can be done.
func (a *App) Initialised() bool {
	return a.State() != ladulasv1.LockState_LOCK_STATE_UNINITIALIZED
}

// approverSlot is an approver registered with the instance rather than with an
// engine.
//
// Engines come and go with the data encryption key; the tray and the terminal
// do not, and neither should have to notice that the store was sealed and
// unsealed underneath them.
type approverSlot struct {
	handler approval.Handler
	detach  func()
}

// RegisterApprover adds an approver and returns a function that removes it
// again.
//
// It is the M5 replacement for registering with the engine directly: a handler
// registered while the store is sealed is attached to the engine the moment one
// exists, and detached again when the store is sealed.
func (a *App) RegisterApprover(h approval.Handler) func() {
	slot := &approverSlot{handler: h}

	a.mu.Lock()
	a.approvers = append(a.approvers, slot)

	if a.core != nil {
		slot.detach = a.core.engine.Register(h)
	}

	a.mu.Unlock()

	return func() {
		a.mu.Lock()

		detach := slot.detach
		slot.detach = nil

		for i, existing := range a.approvers {
			if existing == slot {
				a.approvers = append(a.approvers[:i], a.approvers[i+1:]...)

				break
			}
		}

		a.mu.Unlock()

		if detach != nil {
			detach()
		}
	}
}

// SetActivityHook installs the idle timer's poke. Every decision the instance
// is asked to make calls it.
func (a *App) SetActivityHook(activity func()) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.activity = activity
}

// Unlock brings the store back: it unseals a sealed instance, and lifts the
// soft lock on a locked one.
//
// An empty passphrase means "use the keychain", which is how an instance that
// has enrolled "unlock at login" comes back without anybody typing anything. It
// returns anything worth saying that was not a failure — a peer listener that
// could not bind, most likely.
func (a *App) Unlock(passphrase []byte) (string, error) {
	defer keystore.Wipe(passphrase)

	switch a.State() {
	case ladulasv1.LockState_LOCK_STATE_UNLOCKED:
		return "the store was already unlocked", nil
	case ladulasv1.LockState_LOCK_STATE_LOCKED:
		return "", a.lift(passphrase)
	case ladulasv1.LockState_LOCK_STATE_UNINITIALIZED:
		return "", ErrNotInitialised
	case ladulasv1.LockState_LOCK_STATE_SEALED,
		ladulasv1.LockState_LOCK_STATE_UNSPECIFIED:
	}

	// GivenPassphrase and not a prompt: these are bytes somebody typed, and the
	// store checks them rather than reaching past them to the keychain. Empty
	// still means "the keychain or nothing", which is what `ladulas unlock` on an
	// enrolled machine relies on.
	vault, err := keystore.Open(keystore.Options{
		Dir:             a.Config.DataDir,
		Keyring:         a.Config.keyring(),
		GivenPassphrase: passphrase,
	})
	if err != nil {
		return "", err
	}

	return a.adopt(vault)
}

// noStoreError says why there is no store to work with: sealed is one reason
// and never having been created is the other, and they want different things
// done about them.
func (a *App) noStoreError() error {
	if !a.Initialised() {
		return ErrNotInitialised
	}

	return ErrSealed
}

// lift takes the soft lock off, having checked that whoever asked knows the
// passphrase.
func (a *App) lift(passphrase []byte) error {
	current := a.currentCore()
	if current == nil {
		return a.noStoreError()
	}

	if err := current.vault.VerifyPassphrase(passphrase); err != nil {
		return err
	}

	current.engine.SuspendLocalPrompts(false)

	a.setState(ladulasv1.LockState_LOCK_STATE_UNLOCKED, "")
	a.lifecycle("the store was unlocked")

	return nil
}

// adopt takes an opened store and builds the rest of the instance around it.
func (a *App) adopt(vault *keystore.Vault) (string, error) {
	built, err := a.buildCore(vault)
	if err != nil {
		return "", err
	}

	a.mu.Lock()

	if a.core != nil {
		// Something else unsealed while this call was opening the store. Its
		// core is as good as this one, and two peer listeners on one port are
		// not.
		a.mu.Unlock()

		return "the store was already unlocked", nil
	}

	a.core = built

	for _, slot := range a.approvers {
		slot.detach = built.engine.Register(slot.handler)
	}

	serveCtx := a.serveCtx

	a.mu.Unlock()

	a.setState(ladulasv1.LockState_LOCK_STATE_UNLOCKED, "")

	var message string

	if serveCtx != nil {
		if err := a.startPeer(serveCtx, built); err != nil {
			// A store that is open with no peer listener is a worse instance
			// than one with both, and a much better one than a store that
			// stayed sealed because a port was busy.
			message = fmt.Sprintf("the peer channel could not start: %v", err)

			a.log.Error("the peer channel could not start", "error", err.Error())
		}
	}

	a.lifecycle("the store was unlocked as " +
		vault.Identity().Fingerprint())

	return message, nil
}

// Lock suspends local approval authority. With seal, it wipes the data
// encryption key instead.
func (a *App) Lock(seal bool, reason string) error {
	if seal {
		return a.Seal(reason)
	}

	return a.SoftLock(reason)
}

// SoftLock is §10's lock: the prompts at this instance leave the eligible
// approver set, and everything else stays where it is.
//
// Sealing on a session lock instead would recreate exactly the 1Password
// failure this project exists to fix, so the difference is worth being blunt
// about: after this call the keys are still usable, by a paired approver, which
// is the entire point.
func (a *App) SoftLock(reason string) error {
	current := a.currentCore()
	if current == nil {
		return a.noStoreError()
	}

	current.engine.SuspendLocalPrompts(true)

	a.setState(ladulasv1.LockState_LOCK_STATE_LOCKED, reason)
	a.lifecycle(withReason("local approval was suspended", reason))

	return nil
}

// Seal wipes the data encryption key and takes down everything that needed it,
// including the peer listener — the identity key that authenticates the channel
// lives in the store, so a sealed instance cannot hold up its end of a
// handshake at all.
func (a *App) Seal(reason string) error {
	current := a.takeCore()
	if current == nil {
		return nil
	}

	a.setState(ladulasv1.LockState_LOCK_STATE_SEALED, reason)

	// The audit entry goes in before the teardown, so that a seal-on-sleep that
	// races the machine going down is recorded rather than lost.
	a.lifecycle(withReason("the store was sealed", reason))

	a.tearDown(current)

	return nil
}

func withReason(what, reason string) string {
	if reason == "" {
		return what
	}

	return what + ": " + reason
}

// takeCore detaches the core from the instance under the lock, so that
// everything reaching for the store sees a sealed instance before any of it is
// taken apart.
func (a *App) takeCore() *core {
	a.mu.Lock()
	defer a.mu.Unlock()

	current := a.core
	a.core = nil

	for _, slot := range a.approvers {
		if slot.detach != nil {
			slot.detach()
			slot.detach = nil
		}
	}

	return current
}

// tearDown stops what a core was running. It is called with the core already
// detached, so nothing here is racing a request.
func (a *App) tearDown(current *core) {
	if current == nil {
		return
	}

	a.stopPeer(current)

	// Everything that could still be signing has stopped, so the store key and
	// the private keys can be zeroed rather than merely dropped (M5). Best effort
	// — Vault.Wipe says exactly what it can and cannot reach — but it takes the
	// recognisable material out of the heap before the seal is called done, which
	// is what §10's seal-on-sleep story needs to be true against a cold-boot or a
	// same-uid read.
	if current.vault != nil {
		current.vault.Wipe()
	}
}

func (a *App) setState(state ladulasv1.LockState, reason string) {
	a.mu.Lock()

	a.state = state
	a.since = time.Now()
	a.reason = reason

	var woken []chan struct{}

	if state == ladulasv1.LockState_LOCK_STATE_UNLOCKED ||
		state == ladulasv1.LockState_LOCK_STATE_LOCKED {
		woken, a.unsealWaiters = a.unsealWaiters, nil
	}

	changed := a.stateWaiters
	a.stateWaiters = nil

	a.mu.Unlock()

	for _, waiter := range woken {
		close(waiter)
	}

	for _, waiter := range changed {
		close(waiter)
	}
}

// AwaitState returns once this instance is in one of the states asked for, and
// returns the state it is in when the context ends otherwise.
//
// It exists so that waiting for somebody to unlock the store is a thing to wait
// on rather than a thing to poll. The wait is re-armed on every transition
// rather than only on unsealing, because the states somebody is waiting for are
// not always the one the store passes through first: a sealed store that is
// unlocked and then soft-locked a second later has been unlocked, and something
// waiting for "unlocked" that only ever heard about unsealing would have
// nothing to say about it afterwards.
func (a *App) AwaitState(
	ctx context.Context, want map[ladulasv1.LockState]bool,
) (ladulasv1.LockState, bool) {
	for {
		a.mu.Lock()

		state := a.state
		if want[state] {
			a.mu.Unlock()

			return state, true
		}

		changed := make(chan struct{})
		a.stateWaiters = append(a.stateWaiters, changed)

		a.mu.Unlock()

		select {
		case <-changed:
		case <-ctx.Done():
			a.forgetStateWaiter(changed)

			return a.State(), false
		}
	}
}

// forgetStateWaiter takes an abandoned waiter out, so that a caller that gave
// up does not leave a channel on the list until the next transition.
func (a *App) forgetStateWaiter(waiter chan struct{}) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for i, existing := range a.stateWaiters {
		if existing == waiter {
			a.stateWaiters = append(
				a.stateWaiters[:i], a.stateWaiters[i+1:]...)

			return
		}
	}
}

// UnsealNotify returns a channel that is closed when the data encryption key is
// in memory, and a function that gives the interest up again. A store that is
// already unsealed closes it immediately.
//
// It is what lets the two ways into a sealed daemon race safely (§10, §14): the
// prompt the unit put up at start, and `ladulas unlock` over the control
// socket. Whichever arrives first unseals the store; the loser is cancelled,
// which for systemd-ask-password means killing the child still holding a prompt
// up rather than leaving it there until it times out.
func (a *App) UnsealNotify() (<-chan struct{}, func()) {
	waiter := make(chan struct{})

	a.mu.Lock()

	if a.state != ladulasv1.LockState_LOCK_STATE_SEALED {
		a.mu.Unlock()
		close(waiter)

		return waiter, func() {}
	}

	a.unsealWaiters = append(a.unsealWaiters, waiter)

	a.mu.Unlock()

	return waiter, func() {
		a.mu.Lock()
		defer a.mu.Unlock()

		for i, existing := range a.unsealWaiters {
			if existing == waiter {
				a.unsealWaiters = append(
					a.unsealWaiters[:i], a.unsealWaiters[i+1:]...)

				break
			}
		}
	}
}

// SetUnsealPrompt records how the instance is asking for the passphrase right
// now — an empty string when it is not asking.
//
// Status reports it, because "sealed" on its own does not tell somebody who has
// just SSHed in whether a prompt is standing somewhere waiting for them, or
// whether nothing at all will happen until they type the unlock themselves.
func (a *App) SetUnsealPrompt(how string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.prompt = how
}

// UnsealPrompt is how the instance is asking for the passphrase, or empty.
func (a *App) UnsealPrompt() string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.prompt
}

// lifecycle records a transition. It writes to the audit log directly rather
// than through the engine, because the transitions worth recording are exactly
// the ones where there may be no engine (§10).
func (a *App) lifecycle(detail string) {
	a.log.Info("lock state", "state", StateWord(a.State()), "detail", detail)

	a.LogLifecycle(detail)
}

// LogLifecycle records something worth knowing that is not a request: a key
// imported, a peer renamed, the store sealed. It belongs to the instance rather
// than to the engine because the log outlives the store (§10).
func (a *App) LogLifecycle(detail string) {
	a.appendAudit(&ladulasv1.AuditEntry{
		Event:  ladulasv1.AuditEvent_AUDIT_EVENT_LIFECYCLE,
		Detail: detail,
	})
}

// LogKeyTransfer records a portable key arriving, being accepted or being
// refused here (decision S). It is separate from LogLifecycle for the reason the
// audit event is: it is the one entry somebody goes looking for after losing a
// device.
func (a *App) LogKeyTransfer(detail, fingerprint string) {
	a.appendAudit(&ladulasv1.AuditEntry{
		Event:          ladulasv1.AuditEvent_AUDIT_EVENT_KEY_TRANSFER,
		Detail:         detail,
		KeyFingerprint: fingerprint,
	})
}

// UnlockAtLogin enrols the platform keychain, or forgets it again (decision I).
func (a *App) UnlockAtLogin(enrol bool) error {
	vault := a.Vault()
	if vault == nil {
		return a.noStoreError()
	}

	if !enrol {
		if err := vault.ForgetKeyring(); err != nil {
			return err
		}

		a.lifecycle("unlock at login was switched off")

		return nil
	}

	if err := vault.StoreInKeyring(); err != nil {
		return err
	}

	a.lifecycle("unlock at login was switched on")

	return nil
}

// TryKeyring unseals from the platform keychain alone, and says whether it
// worked. It is what the daemon does before it asks anybody anything.
func (a *App) TryKeyring() bool {
	switch a.State() {
	case ladulasv1.LockState_LOCK_STATE_UNINITIALIZED:
		return false
	case ladulasv1.LockState_LOCK_STATE_UNLOCKED,
		ladulasv1.LockState_LOCK_STATE_LOCKED:
		return true
	case ladulasv1.LockState_LOCK_STATE_SEALED,
		ladulasv1.LockState_LOCK_STATE_UNSPECIFIED:
	}

	if _, err := a.Unlock(nil); err != nil {
		a.log.Debug("nothing in the keychain to unseal with",
			"error", err.Error())

		return false
	}

	return true
}

// Unsealed reports whether the data encryption key is in memory, which is a
// weaker statement than "unlocked" — a soft-locked instance is unsealed.
func (a *App) Unsealed() bool {
	state := a.State()

	return state == ladulasv1.LockState_LOCK_STATE_UNLOCKED ||
		state == ladulasv1.LockState_LOCK_STATE_LOCKED
}

// LockControl is the viewer's half of the lock states (§10). It is what makes
// the desktop's unlock dialog a page in the shared bundle rather than a native
// dialog only one platform has.
func (a *App) LockControl() bridge.Lock {
	return &lockControl{app: a}
}

type lockControl struct {
	app *App
}

var _ bridge.Lock = (*lockControl)(nil)

func (l *lockControl) State() bridge.LockView {
	state, _, reason := l.app.StateDetail()

	view := bridge.LockView{
		State:      StateWord(state),
		Reason:     reason,
		Passphrase: keystore.Exists(l.app.Config.DataDir),
	}

	if vault := l.app.Vault(); vault != nil {
		view.Passphrase = vault.HasPassphraseWrapping()
		view.KeyringEnrolled = vault.KeyringEnrolled()
	}

	return view
}

func (l *lockControl) Unlock(passphrase []byte) error {
	_, err := l.app.Unlock(passphrase)

	return err
}

func (l *lockControl) Lock(seal bool) error {
	return l.app.Lock(seal, "asked for at the desktop")
}
