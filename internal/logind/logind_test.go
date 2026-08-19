package logind_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/internal/logind"
)

// There is no login manager to test against — no session to lock, and
// suspending the build machine would be an odd thing for a test to do — so what
// is exercised here is the watcher against a fake bus that delivers the same
// two signals. The D-Bus implementation that produces them for real is in
// systembus.go and has never been run against a live logind.

// fakeBus stands in for logind.
type fakeBus struct {
	sleeping chan bool
	locked   chan bool

	mu         sync.Mutex
	inhibitors int
	held       int
	inhibitErr error
}

func newFakeBus() *fakeBus {
	return &fakeBus{
		sleeping: make(chan bool, 4),
		locked:   make(chan bool, 4),
	}
}

func (b *fakeBus) Sleeping() <-chan bool {
	return b.sleeping
}

func (b *fakeBus) Locked() <-chan bool {
	return b.locked
}

func (b *fakeBus) Inhibit(_, _, _ string) (io.Closer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.inhibitErr != nil {
		return nil, b.inhibitErr
	}

	b.inhibitors++
	b.held++

	return closerFunc(func() error {
		b.mu.Lock()
		defer b.mu.Unlock()

		b.held--

		return nil
	}), nil
}

func (b *fakeBus) Close() error {
	return nil
}

// heldInhibitors is how many delay locks are outstanding right now.
func (b *fakeBus) heldInhibitors() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.held
}

type closerFunc func() error

func (f closerFunc) Close() error {
	return f()
}

// recordingTarget is the instance the triggers act on.
type recordingTarget struct {
	mu      sync.Mutex
	actions []string
	reasons []string
	// order records what happened relative to the inhibitor being released.
	bus *fakeBus
	// heldAtSeal is how many inhibitors were still held when Seal ran, which is
	// the whole question seal-on-sleep turns on.
	heldAtSeal int
}

func (r *recordingTarget) SoftLock(reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.actions = append(r.actions, "lock")
	r.reasons = append(r.reasons, reason)

	return nil
}

func (r *recordingTarget) Seal(reason string) error {
	held := 0
	if r.bus != nil {
		held = r.bus.heldInhibitors()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.actions = append(r.actions, "seal")
	r.reasons = append(r.reasons, reason)
	r.heldAtSeal = held

	return nil
}

func (r *recordingTarget) wait(t *testing.T, want int) []string {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		r.mu.Lock()
		got := len(r.actions)
		r.mu.Unlock()

		if got >= want {
			break
		}

		time.Sleep(time.Millisecond)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]string, len(r.actions))
	copy(out, r.actions)

	return out
}

// The default of decision J: suspending and locking the screen both soft-lock,
// and neither of them seals.
func TestDefaultTriggersSoftLock(t *testing.T) {
	bus := newFakeBus()
	target := &recordingTarget{bus: bus}

	watcher, err := logind.Start(context.Background(), logind.Options{
		Bus:    bus,
		Target: target,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	defer watcher.Stop()

	bus.sleeping <- true
	bus.locked <- true

	got := target.wait(t, 2)

	if len(got) != 2 || got[0] != "lock" || got[1] != "lock" {
		t.Fatalf("actions %v, want two soft locks", got)
	}

	if bus.heldInhibitors() != 0 {
		t.Error("a soft lock on suspend took a sleep inhibitor it does not need")
	}
}

// Seal-on-sleep is only worth anything if the key is gone before the machine
// is: the inhibitor has to be held while the seal runs and released after it.
func TestSealOnSleepHoldsTheInhibitorUntilTheKeyIsGone(t *testing.T) {
	bus := newFakeBus()
	target := &recordingTarget{bus: bus}

	watcher, err := logind.Start(context.Background(), logind.Options{
		Bus:     bus,
		Target:  target,
		Suspend: logind.ActionSeal,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	defer watcher.Stop()

	if !waitFor(func() bool { return bus.heldInhibitors() == 1 }) {
		t.Fatal("no inhibitor was taken before the machine slept")
	}

	bus.sleeping <- true

	if got := target.wait(t, 1); len(got) != 1 || got[0] != "seal" {
		t.Fatalf("actions %v, want a seal", got)
	}

	target.mu.Lock()
	held := target.heldAtSeal
	target.mu.Unlock()

	if held != 1 {
		t.Error("the machine was allowed to sleep before the key was wiped")
	}

	if !waitFor(func() bool { return bus.heldInhibitors() == 0 }) {
		t.Error("the inhibitor was never released, so the machine cannot sleep")
	}

	// Coming back takes a fresh lock for the next time.
	bus.sleeping <- false

	if !waitFor(func() bool { return bus.heldInhibitors() == 1 }) {
		t.Error("no inhibitor was taken again after the machine woke")
	}
}

// A bus that will not give out inhibitors is a weaker guarantee, not a broken
// watcher: the seal still happens.
func TestSealOnSleepWithoutAnInhibitor(t *testing.T) {
	bus := newFakeBus()
	bus.inhibitErr = errors.New("no inhibitors here")
	target := &recordingTarget{bus: bus}

	watcher, err := logind.Start(context.Background(), logind.Options{
		Bus:     bus,
		Target:  target,
		Suspend: logind.ActionSeal,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	defer watcher.Stop()

	bus.sleeping <- true

	if got := target.wait(t, 1); len(got) != 1 || got[0] != "seal" {
		t.Fatalf("actions %v, want a seal", got)
	}
}

func TestTriggersCanBeSwitchedOff(t *testing.T) {
	bus := newFakeBus()
	target := &recordingTarget{bus: bus}

	watcher, err := logind.Start(context.Background(), logind.Options{
		Bus:         bus,
		Target:      target,
		Suspend:     logind.ActionOff,
		SessionLock: logind.ActionSeal,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	defer watcher.Stop()

	bus.sleeping <- true
	bus.locked <- true

	if got := target.wait(t, 1); len(got) != 1 || got[0] != "seal" {
		t.Fatalf("actions %v, want only the session lock to have done anything", got)
	}
}

// Unlocking the session does not unlock the store. The store passphrase is a
// separate thing to know (§10).
func TestUnlockingTheSessionDoesNothing(t *testing.T) {
	bus := newFakeBus()
	target := &recordingTarget{bus: bus}

	watcher, err := logind.Start(context.Background(), logind.Options{
		Bus:    bus,
		Target: target,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	defer watcher.Stop()

	bus.locked <- false
	bus.locked <- true

	if got := target.wait(t, 1); len(got) != 1 {
		t.Fatalf("actions %v, want only the lock", got)
	}
}

// The idle timeout counts from the last decision, so activity puts it off.
func TestIdleTimeoutCountsFromTheLastDecision(t *testing.T) {
	bus := newFakeBus()
	target := &recordingTarget{bus: bus}

	watcher, err := logind.Start(context.Background(), logind.Options{
		Bus:       bus,
		Target:    target,
		Idle:      120 * time.Millisecond,
		IdleCheck: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	defer watcher.Stop()

	// Keeping the instance busy for longer than the timeout must not lock it.
	for range 20 {
		watcher.Poke()
		time.Sleep(10 * time.Millisecond)
	}

	target.mu.Lock()
	early := len(target.actions)
	target.mu.Unlock()

	if early != 0 {
		t.Fatalf("a busy instance was locked %d times", early)
	}

	if got := target.wait(t, 1); len(got) != 1 || got[0] != "lock" {
		t.Fatalf("actions %v, want an idle lock once the instance went quiet", got)
	}
}

// Off by default: an instance that was never told a timeout is never locked by
// one.
func TestIdleTimeoutIsOffByDefault(t *testing.T) {
	bus := newFakeBus()
	target := &recordingTarget{bus: bus}

	watcher, err := logind.Start(context.Background(), logind.Options{
		Bus:       bus,
		Target:    target,
		IdleCheck: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	defer watcher.Stop()

	time.Sleep(50 * time.Millisecond)

	target.mu.Lock()
	defer target.mu.Unlock()

	if len(target.actions) != 0 {
		t.Errorf("an instance with no idle timeout was locked: %v", target.actions)
	}
}

func TestParseAction(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want logind.Action
		bad  bool
	}{
		{in: "", want: logind.ActionLock},
		{in: "lock", want: logind.ActionLock},
		{in: "SEAL", want: logind.ActionSeal},
		{in: " off ", want: logind.ActionOff},
		{in: "none", want: logind.ActionOff},
		{in: "sael", bad: true},
	} {
		got, err := logind.ParseAction(tc.in, logind.ActionLock)

		if tc.bad {
			if err == nil {
				t.Errorf("%q was accepted as %q", tc.in, got)
			}

			continue
		}

		if err != nil {
			t.Errorf("%q: %v", tc.in, err)

			continue
		}

		if got != tc.want {
			t.Errorf("%q became %q, want %q", tc.in, got, tc.want)
		}
	}
}

func waitFor(condition func() bool) bool {
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		if condition() {
			return true
		}

		time.Sleep(time.Millisecond)
	}

	return false
}
