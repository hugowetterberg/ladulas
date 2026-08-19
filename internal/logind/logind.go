// Package logind watches the login manager for the two things that should take
// local approval authority away: the machine going to sleep, and the session
// being locked (docs/architecture.md §10, decision J).
//
// The bus is a seam. Nothing here can be exercised on a build machine — there
// is no session to lock and suspending the host would be an unusual thing for a
// test to do — so the watcher is written against an interface, tested against a
// fake that delivers the same signals, and backed by a D-Bus implementation in
// systembus.go that talks to the real logind. That implementation is compiled
// and vetted; it has never been run against a real login manager, and the
// comment on it says so.
package logind

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Action is what a trigger does to the store.
type Action string

const (
	// ActionOff ignores the trigger.
	ActionOff Action = "off"
	// ActionLock soft-locks: the key stays, the prompts here stop being asked.
	ActionLock Action = "lock"
	// ActionSeal wipes the key.
	ActionSeal Action = "seal"
)

// ParseAction reads a configured action, defaulting an empty string to fallback.
func ParseAction(value string, fallback Action) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return fallback, nil
	case string(ActionOff), "none":
		return ActionOff, nil
	case string(ActionLock):
		return ActionLock, nil
	case string(ActionSeal):
		return ActionSeal, nil
	default:
		return "", errors.New(
			"logind: an action is one of lock, seal or off, not " + value)
	}
}

// Target is the instance the triggers act on.
type Target interface {
	// SoftLock suspends local approval authority, saying why.
	SoftLock(reason string) error
	// Seal wipes the data encryption key, saying why.
	Seal(reason string) error
}

// Bus is the login manager, or something standing in for it.
//
// The two signals are the two §10 names: PrepareForSleep on the manager, and
// the session's LockedHint property. Inhibit is what makes seal-on-sleep mean
// anything — without a delay lock the machine is already asleep by the time the
// signal is acted on.
type Bus interface {
	// Sleeping delivers logind's PrepareForSleep: true just before the machine
	// suspends, false once it is back.
	Sleeping() <-chan bool
	// Locked delivers the session's LockedHint as it changes.
	Locked() <-chan bool
	// Inhibit takes a delay inhibitor lock. Closing the returned handle
	// releases it, which is what lets the suspend proceed.
	Inhibit(what, who, why string) (io.Closer, error)
	// Close stops watching.
	Close() error
}

// Options configures a watcher.
type Options struct {
	// Bus is the login manager. Required.
	Bus Bus
	// Target is what gets locked. Required.
	Target Target
	// Suspend and SessionLock are what those triggers do. Empty means
	// ActionLock, which is decision J's default.
	Suspend     Action
	SessionLock Action
	// Idle, when positive, locks after that long with nothing decided.
	// Off by default: an idle timeout on a machine whose whole job is to answer
	// occasional questions mostly locks the store between questions.
	Idle time.Duration
	// IdleAction defaults to ActionLock.
	IdleAction Action
	// IdleCheck is how often the idle timer looks at the clock. Defaults to
	// DefaultIdleCheck; a timeout measured in minutes needs nothing finer.
	IdleCheck time.Duration
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Now defaults to time.Now, and exists so the idle timer can be tested
	// without waiting.
	Now func() time.Time
}

// Watcher applies the triggers.
type Watcher struct {
	bus     Bus
	target  Target
	suspend Action
	session Action
	idle    time.Duration
	idleDo  Action
	tick    time.Duration
	log     *slog.Logger
	now     func() time.Time

	mu        sync.Mutex
	inhibitor io.Closer
	lastSeen  time.Time

	stop      context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
}

// Start begins watching. The returned watcher runs until Stop.
func Start(ctx context.Context, opts Options) (*Watcher, error) {
	if opts.Bus == nil {
		return nil, errors.New("logind: no bus to watch")
	}

	if opts.Target == nil {
		return nil, errors.New("logind: nothing to lock")
	}

	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	w := &Watcher{
		bus:     opts.Bus,
		target:  opts.Target,
		suspend: orAction(opts.Suspend, ActionLock),
		session: orAction(opts.SessionLock, ActionLock),
		idle:    opts.Idle,
		idleDo:  orAction(opts.IdleAction, ActionLock),
		tick:    orDuration(opts.IdleCheck, DefaultIdleCheck),
		log:     log,
		now:     now,
		done:    make(chan struct{}),
	}

	w.lastSeen = now()

	// The inhibitor is taken now rather than when the signal arrives, because
	// by then it is too late: a delay lock has to be held before logind asks
	// whether anybody minds (§10).
	if w.suspend == ActionSeal {
		w.takeInhibitor()
	}

	ctx, cancel := context.WithCancel(ctx)
	w.stop = cancel

	go w.run(ctx)

	return w, nil
}

func orAction(action, fallback Action) Action {
	if action == "" {
		return fallback
	}

	return action
}

// Poke records activity, for the idle timer.
func (w *Watcher) Poke() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.lastSeen = w.now()
}

// Stop releases the inhibitor and stops watching.
func (w *Watcher) Stop() {
	w.closeOnce.Do(func() {
		if w.stop != nil {
			w.stop()
		}

		<-w.done

		w.releaseInhibitor()

		if err := w.bus.Close(); err != nil {
			w.log.Debug("could not close the login manager connection",
				"error", err.Error())
		}
	})
}

// DefaultIdleCheck is how often the idle timer looks at the clock. A ticker
// that runs when no timeout is configured would be a busy loop for nothing, so
// one is only created when there is a timeout to check.
const DefaultIdleCheck = 15 * time.Second

func orDuration(d, fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}

	return d
}

func (w *Watcher) run(ctx context.Context) {
	defer close(w.done)

	var idle <-chan time.Time

	if w.idle > 0 && w.idleDo != ActionOff {
		ticker := time.NewTicker(w.tick)
		defer ticker.Stop()

		idle = ticker.C
	}

	for {
		select {
		case <-ctx.Done():
			return
		case sleeping := <-w.bus.Sleeping():
			w.onSleep(sleeping)
		case locked := <-w.bus.Locked():
			w.onSessionLock(locked)
		case <-idle:
			w.onIdle()
		}
	}
}

// onSleep acts before the machine goes down, and lets it go down afterwards.
//
// The order is the whole point of holding an inhibitor: seal, then release. A
// seal that happened after the resume would defend nothing, which is the state
// a stolen suspended laptop is in.
func (w *Watcher) onSleep(sleeping bool) {
	if !sleeping {
		if w.suspend == ActionSeal {
			w.takeInhibitor()
		}

		return
	}

	w.apply(w.suspend, "the machine was suspended")

	if w.suspend == ActionSeal {
		w.releaseInhibitor()
	}
}

func (w *Watcher) onSessionLock(locked bool) {
	if !locked {
		// Unlocking the session does not unlock the store. The store's own
		// passphrase is a separate thing to know, and §10 says coming back from
		// a lock asks for it.
		return
	}

	w.apply(w.session, "the session was locked")
}

func (w *Watcher) onIdle() {
	w.mu.Lock()
	quiet := w.now().Sub(w.lastSeen)
	w.mu.Unlock()

	if quiet < w.idle {
		return
	}

	w.Poke()
	w.apply(w.idleDo, "nothing was decided for "+w.idle.String())
}

func (w *Watcher) apply(action Action, reason string) {
	var err error

	switch action {
	case ActionOff:
		return
	case ActionLock:
		err = w.target.SoftLock(reason)
	case ActionSeal:
		err = w.target.Seal(reason)
	}

	if err != nil {
		w.log.Debug("the store did not change state",
			"reason", reason, "error", err.Error())
	}
}

func (w *Watcher) takeInhibitor() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.inhibitor != nil {
		return
	}

	handle, err := w.bus.Inhibit("sleep", "Ladulås",
		"wiping the store key before the machine sleeps")
	if err != nil {
		// Without the lock the seal still happens, just possibly after the
		// machine has already gone down — which is worth saying out loud rather
		// than leaving as a silently weaker guarantee.
		w.log.Warn("could not hold a sleep inhibitor; "+
			"seal-on-sleep may not finish before the machine suspends",
			"error", err.Error())

		return
	}

	w.inhibitor = handle
}

func (w *Watcher) releaseInhibitor() {
	w.mu.Lock()
	handle := w.inhibitor
	w.inhibitor = nil
	w.mu.Unlock()

	if handle == nil {
		return
	}

	if err := handle.Close(); err != nil {
		w.log.Debug("could not release the sleep inhibitor",
			"error", err.Error())
	}
}
