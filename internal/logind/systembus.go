package logind

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"

	"github.com/godbus/dbus/v5"
)

// SystemBus is the real login manager, over D-Bus.
//
// Unverified against a live logind. There is no session to lock on the machine
// this was written on and suspending it to test would be a strange thing for a
// test suite to do, so what is exercised is the watcher above against a fake
// bus. The names, paths and signatures below are logind's documented ones
// (org.freedesktop.login1); the risk that remains is that this file connects
// and subscribes wrongly, and it fails loudly rather than quietly if it does —
// New returns an error and the daemon reports that the triggers are off.

const (
	loginService    = "org.freedesktop.login1"
	managerPath     = dbus.ObjectPath("/org/freedesktop/login1")
	managerIface    = "org.freedesktop.login1.Manager"
	sessionIface    = "org.freedesktop.login1.Session"
	propertiesIface = "org.freedesktop.DBus.Properties"
)

type systemBus struct {
	conn    *dbus.Conn
	signals chan *dbus.Signal
	session dbus.ObjectPath
	log     *slog.Logger

	sleeping chan bool
	locked   chan bool

	closeOnce sync.Once
	done      chan struct{}
}

var _ Bus = (*systemBus)(nil)

// NewSystemBus connects to logind and subscribes to the two signals.
//
// The session is the one this process belongs to, taken from XDG_SESSION_ID
// when it is set and from logind's own idea of "the session of this pid"
// otherwise. A process with no session — a system service, or a container —
// gets no session lock trigger, and says so rather than pretending.
func NewSystemBus(log *slog.Logger) (Bus, error) {
	if log == nil {
		log = slog.Default()
	}

	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("connect to the system bus: %w", err)
	}

	bus := &systemBus{
		conn:     conn,
		signals:  make(chan *dbus.Signal, 8),
		log:      log,
		sleeping: make(chan bool, 8),
		locked:   make(chan bool, 8),
		done:     make(chan struct{}),
	}

	err = conn.AddMatchSignal(
		dbus.WithMatchInterface(managerIface),
		dbus.WithMatchMember("PrepareForSleep"),
		dbus.WithMatchObjectPath(managerPath))
	if err != nil {
		return nil, fmt.Errorf("subscribe to PrepareForSleep: %w", err)
	}

	bus.session, err = sessionPath(conn)
	if err != nil {
		// A machine with no session of its own still suspends, and that is the
		// trigger that matters most on a laptop. Losing the other one is worth
		// a line in the log rather than a refusal to watch anything.
		log.Info("no login session to watch for a screen lock",
			"error", err.Error())
	} else {
		err = conn.AddMatchSignal(
			dbus.WithMatchInterface(propertiesIface),
			dbus.WithMatchMember("PropertiesChanged"),
			dbus.WithMatchObjectPath(bus.session))
		if err != nil {
			return nil, fmt.Errorf("subscribe to the session's properties: %w", err)
		}
	}

	conn.Signal(bus.signals)

	go bus.pump()

	return bus, nil
}

// sessionPath asks logind which session this process is in.
func sessionPath(conn *dbus.Conn) (dbus.ObjectPath, error) {
	manager := conn.Object(loginService, managerPath)

	if id := os.Getenv("XDG_SESSION_ID"); id != "" {
		var path dbus.ObjectPath

		err := manager.Call(managerIface+".GetSession", 0, id).Store(&path)
		if err == nil {
			return path, nil
		}
	}

	var path dbus.ObjectPath

	err := manager.Call(managerIface+".GetSessionByPID", 0,
		uint32(os.Getpid())).Store(&path) //nolint:gosec // a pid fits a uint32
	if err != nil {
		return "", fmt.Errorf("find this process's login session: %w", err)
	}

	return path, nil
}

// pump turns D-Bus signals into the two channels the watcher reads.
func (b *systemBus) pump() {
	defer close(b.done)

	for signal := range b.signals {
		switch {
		case signal.Name == managerIface+".PrepareForSleep":
			if len(signal.Body) != 1 {
				continue
			}

			if going, ok := signal.Body[0].(bool); ok {
				send(b.sleeping, going)
			}
		case signal.Path == b.session &&
			signal.Name == propertiesIface+".PropertiesChanged":
			b.onProperties(signal)
		}
	}
}

// onProperties picks LockedHint out of a PropertiesChanged, and re-reads it
// when the signal only said that it was invalidated.
func (b *systemBus) onProperties(signal *dbus.Signal) {
	if len(signal.Body) < 2 {
		return
	}

	iface, _ := signal.Body[0].(string)
	if iface != sessionIface {
		return
	}

	changed, _ := signal.Body[1].(map[string]dbus.Variant)

	if hint, ok := changed["LockedHint"]; ok {
		if locked, ok := hint.Value().(bool); ok {
			send(b.locked, locked)

			return
		}
	}

	if len(signal.Body) < 3 {
		return
	}

	invalidated, _ := signal.Body[2].([]string)

	for _, name := range invalidated {
		if name != "LockedHint" {
			continue
		}

		locked, err := b.readLockedHint()
		if err != nil {
			b.log.Debug("could not read the session's lock state",
				"error", err.Error())

			return
		}

		send(b.locked, locked)
	}
}

func (b *systemBus) readLockedHint() (bool, error) {
	object := b.conn.Object(loginService, b.session)

	value, err := object.GetProperty(sessionIface + ".LockedHint")
	if err != nil {
		return false, fmt.Errorf("read LockedHint: %w", err)
	}

	locked, ok := value.Value().(bool)
	if !ok {
		return false, errors.New("logind: LockedHint is not a boolean")
	}

	return locked, nil
}

// send never blocks: a watcher that is busy sealing should not wedge the bus
// pump, and a repeated signal says nothing new.
func send(ch chan bool, value bool) {
	select {
	case ch <- value:
	default:
	}
}

// Sleeping implements Bus.
func (b *systemBus) Sleeping() <-chan bool {
	return b.sleeping
}

// Locked implements Bus.
func (b *systemBus) Locked() <-chan bool {
	return b.locked
}

// Inhibit implements Bus by taking a delay lock, which logind hands back as a
// file descriptor: holding it open is the lock, closing it releases it.
func (b *systemBus) Inhibit(what, who, why string) (io.Closer, error) {
	manager := b.conn.Object(loginService, managerPath)

	var fd dbus.UnixFD

	err := manager.Call(managerIface+".Inhibit", 0,
		what, who, why, "delay").Store(&fd)
	if err != nil {
		return nil, fmt.Errorf("take an inhibitor lock: %w", err)
	}

	return os.NewFile(uintptr(fd), "logind-inhibitor"), nil
}

// Close implements Bus.
//
// The connection is the process-wide system bus; closing that would take
// anything else using it with it. Detaching the signal channel is the whole of
// what this owns.
func (b *systemBus) Close() error {
	b.closeOnce.Do(func() {
		b.conn.RemoveSignal(b.signals)
		close(b.signals)

		<-b.done
	})

	return nil
}
