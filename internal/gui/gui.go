//go:build gui

// Package gui is the desktop application (docs/architecture.md §12,
// decision C1).
//
// It is a thin shell, and thinner every milestone. The approval state and every
// pixel of the prompt live in pkg/bridge and viewer/, which the phone
// shells host too; the store, the keys and the agent live in the daemon, which
// internal/frontend attaches to over the control socket (decision Z). What is
// left here is what only a desktop can do — a tray icon, a window, a system
// notification — and the wiring that hands Wails the bridge handler as its
// asset server.
//
// Two kinds of window, and the difference is decision AA. The application window
// is one window with a sidebar in it, reused: asking for it twice brings back
// the one that is open. A prompt is a small popup with one request in it, and
// there is only ever one on screen — the rest wait their turn.
//
// Build with `-tags gui`. On a system with GTK 3 and webkit2gtk-4.1 rather
// than GTK 4 and webkitgtk-6.0, add Wails' own tag: `-tags gui,gtk3`.
package gui

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	"github.com/hugowetterberg/ladulas/internal/branding"
	"github.com/hugowetterberg/ladulas/internal/frontend"
	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/pkg/bridge"
)

// Window geometry.
//
// The prompt is a popup and is sized like one: one request, wide enough for a
// commit card with a diff in it, and it scrolls rather than growing, because a
// window taller than the screen is worse than one that scrolls. The application
// window has a sidebar and a pane beside it, so it is the shape of a small
// application window rather than of a dialog, and it has a floor under it —
// narrower than that and the sidebar is eating the pane it exists to navigate.
const (
	promptWidth  = 620
	promptHeight = 680

	mainWidth     = 1040
	mainHeight    = 720
	mainMinWidth  = 720
	mainMinHeight = 460
)

// trayBlink is how long the tray label marks that something happened.
const trayBlink = 4 * time.Second

// The tray label, which is also where "there is nothing to be attached to"
// shows. A desktop application that draws nothing while the daemon is down
// would be indistinguishable from one that is working and has nothing to say.
const (
	trayLabel   = "Ladulås"
	trayWaiting = "Ladulås — not attached"
	trayBlinked = "Ladulås ●"
)

// The screens of the shell this host asks for by name. They are fragments
// rather than paths or query parameters because the shell is one page: changing
// the fragment moves between its screens without reloading it, and the query
// string stays what it has always been — a host asking for one pane rather than
// for the application (§12).
const (
	routeHome      = "/#/home"
	routeDocuments = "/#/documents"
	routeSettings  = "/#/settings"
)

// GUI is the tray application, and the bridge's Presenter: it knows what
// showing a human something means on a desktop, and nothing else.
type GUI struct {
	front    *frontend.Frontend
	log      *slog.Logger
	session  *bridge.Session
	wailsApp *application.App
	tray     *application.SystemTray
	notifier *notifications.NotificationService

	mu sync.Mutex
	// main is the application window while there is one. A closed window is
	// destroyed rather than hidden, and a destroyed one cannot be shown again,
	// so this is nil between closing and reopening and the closing hook is what
	// makes it nil.
	main application.Window
	// showing is the request whose popup is on screen, and waiting are the ones
	// that arrived while it was (decision AA).
	showing *prompt
	waiting []*bridge.PendingRequest
	// started says the Wails application is running, which is the earliest moment
	// a window can exist: on GTK 4 the widget is built when the application's
	// activate signal fires, so anything asked for before that gets a handle to
	// a window that was never created. wanted is the screen somebody asked for
	// while that was still true, and is opened the moment it stops being.
	started bool
	wanted  string
	// quitting says the application is on its way out, and is what stops the
	// queue from opening a window during shutdown. Wails closes the windows it
	// knows about while holding its own window lock, and the closing hooks run on
	// the goroutine draining a five-deep event channel — so a hook that asks for
	// a new window there waits for a lock shutdown is holding, the channel fills
	// behind it, and the shutdown that was closing windows blocks on putting the
	// next event in. Nothing about that is visible: the application simply does
	// not exit.
	quitting bool
}

// prompt is one request's popup.
type prompt struct {
	id     string
	window application.Window
}

var (
	_ bridge.Presenter = (*GUI)(nil)
	_ bridge.Announcer = (*GUI)(nil)
)

// Present implements bridge.Presenter by putting the request in the queue,
// which shows it if there is nothing in front of it.
//
// The bridge calls this from the goroutine that is deciding, and does the
// waiting itself, so this only has to put the window up — or not, and let the
// popup that is already there be answered first (decision AA).
func (g *GUI) Present(req *bridge.PendingRequest) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.showing != nil {
		g.waiting = append(g.waiting, req)

		// The popup on screen is what somebody is reading, so the news that
		// another one arrived goes on the tray: a queued request has no window
		// of its own to say so with.
		g.blink()

		return
	}

	g.open(req)
}

// Dismiss implements bridge.Presenter.
//
// A request that never got its turn just leaves the queue: there is no window to
// take down and nothing to advance. The one on screen is closed, and its closing
// hook is what starts the next — so a request that was answered and one that was
// abandoned leave by the same door.
func (g *GUI) Dismiss(id string) {
	g.mu.Lock()

	index := slices.IndexFunc(g.waiting, func(req *bridge.PendingRequest) bool {
		return req.ID == id
	})
	if index >= 0 {
		g.waiting = slices.Delete(g.waiting, index, index+1)
		g.mu.Unlock()

		return
	}

	if g.showing == nil || g.showing.id != id {
		g.mu.Unlock()

		return
	}

	window := g.showing.window
	g.mu.Unlock()

	// Outside the lock, because closing runs the hook and the hook takes it.
	window.Close()
}

// open puts one request on screen. The caller holds the lock.
func (g *GUI) open(req *bridge.PendingRequest) {
	window := g.wailsApp.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "Ladulås — " + req.Request.Prompt.Title,
		Width:            promptWidth,
		Height:           promptHeight,
		URL:              req.URL,
		AlwaysOnTop:      true,
		BackgroundColour: application.NewRGB(24, 24, 27),
	})

	// Closing the window without answering is a refusal. Anything else would
	// mean a stray click could approve. By the time a window that has been
	// answered closes, the request has left the pending set and the refusal
	// lands on nothing, which is what makes closing that one harmless.
	//
	// The hook runs on Wails' event goroutine rather than on the main thread,
	// which is what lets it open the next popup from inside itself.
	window.RegisterHook(events.Common.WindowClosing, func(*application.WindowEvent) {
		g.session.Deny(req.ID, "the prompt was closed without answering")

		// The next popup is opened from a goroutine of its own rather than from
		// here. A hook runs on the goroutine draining Wails' window events, and
		// asking for a window from it is how shutdown deadlocks — see the
		// `quitting` field. It costs nothing: the queue is the GUI's own state
		// and the popup is not owed to this event.
		go g.closed(req.ID)
	})

	g.showing = &prompt{id: req.ID, window: window}

	window.Show()
	window.Focus()
}

// closed is one popup leaving the screen, and the queue moving up.
func (g *GUI) closed(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.showing == nil || g.showing.id != id {
		return
	}

	g.showing = nil

	if len(g.waiting) == 0 || g.quitting {
		return
	}

	next := g.waiting[0]
	g.waiting = g.waiting[1:]

	g.open(next)
}

// Announce implements bridge.Announcer: an auto-approved request still says so,
// because a silent auto-approval is how approval fatigue turns into an
// unnoticed compromise (§9).
func (g *GUI) Announce(activity bridge.ActivityView) {
	g.mu.Lock()
	g.blink()
	g.mu.Unlock()

	g.notify(activity)
}

// blink marks the tray for a few seconds. The caller holds the lock.
func (g *GUI) blink() {
	if g.tray == nil {
		return
	}

	g.tray.SetLabel(trayBlinked)

	go func() {
		time.Sleep(trayBlink)
		g.tray.SetLabel(trayLabel)
	}()
}

func (g *GUI) notify(activity bridge.ActivityView) {
	if g.notifier == nil {
		return
	}

	err := g.notifier.SendNotification(notifications.NotificationOptions{
		ID:                "ladulas-" + activity.When,
		Title:             "Ladulås " + activity.Outcome,
		Body:              activity.Title,
		ThreadID:          "ladulas-approvals",
		InterruptionLevel: notifications.InterruptionLevelPassive,
	})
	if err != nil {
		// A desktop with no notification daemon is a normal desktop; the tray
		// and the activity list still carry the same fact.
		g.log.Debug("could not send a notification", "error", err.Error())
	}
}

// Run starts the desktop application and blocks until the user quits.
//
// What it starts is a window, and nothing else. The agent, the store and the
// approval engine are the daemon's, and this attaches to them over the control
// socket (decision Z): it draws what a running instance says, and every answer
// it takes is a call. A desktop with no daemon running is an ordinary state
// rather than a failure — the front end says so on the tray and keeps trying,
// which is what makes the two startable in either order at login.
func Run(ctx context.Context, client *localapi.Client, logger *slog.Logger) error {
	g := &GUI{
		log: logger,
	}

	front, err := frontend.New(frontend.Options{
		Client:    client,
		Presenter: g,
		ID:        "desktop",
		Attached:  g.attached,
		Logger:    logger,
	})
	if err != nil {
		return fmt.Errorf("build the front end: %w", err)
	}

	g.front = front
	g.session = front.Session()

	g.notifier = notifications.New()

	g.wailsApp = application.New(application.Options{
		Name:        "Ladulås",
		Description: "SSH agent and signing approvals",
		Assets: application.AssetOptions{
			// The bridge is the whole front end: the shared viewer bundle and
			// the JSON API it talks to, the same handler a phone shell serves
			// from its own webview (§12).
			Handler: g.session.Handler(),
		},
		Services: []application.Service{
			application.NewService(g.notifier),
		},
		Mac: application.MacOptions{
			ActivationPolicy: application.ActivationPolicyAccessory,
		},
		// A tray application outlives its windows, and on GTK 4 saying so is not
		// a preference: see whyTheLastWindowMayNotQuit below.
		Linux: application.LinuxOptions{
			DisableQuitOnLastWindowClosed: true,
			// The program name is what GTK puts in WM_CLASS, and it is how a
			// window manager pairs a window with a desktop entry — so it has to
			// be the name of the entry, `ladulas.desktop`, and not the display
			// name with its å in it. Left unset it is the binary's name, which
			// is the same string today and one rename away from not being.
			ProgramName: "ladulas",
		},
		Windows: application.WindowsOptions{
			DisableQuitOnLastWindowClosed: true,
		},
		// One of these per session, and a second launch opens the first one's
		// window instead of becoming a process of its own.
		//
		// Without it a second launch is worse than a duplicate: two GApplications
		// with the same id means the second is a *remote* instance, so its
		// `activate` never fires and it can never create a window at all — a tray
		// icon whose every item does nothing, silently, which is what somebody who
		// starts it from the menu entry while one is already running gets. It also
		// registers a second approver on the control socket, so prompts start
		// arriving twice.
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "nu.wetterberg.ladulas.gui",
			OnSecondInstanceLaunch: func(application.SecondInstanceData) {
				g.showMain(routeHome)
			},
		},
	})

	// Nothing may open a window before this fires. It is not a nicety: a window
	// asked for earlier is a handle whose GTK widget does not exist, every call
	// on it is a GTK-CRITICAL on stderr and nothing on screen, and the handle is
	// indistinguishable from a working one afterwards. What made that a live
	// fault rather than a startup race is the ordinary state of this machine — a
	// sealed store asks for the window the moment the front end attaches, which
	// is usually before Wails has started (§10, decision I).
	g.wailsApp.Event.OnApplicationEvent(events.Common.ApplicationStarted,
		func(*application.ApplicationEvent) {
			g.mu.Lock()
			g.started = true
			route := g.wanted
			g.wanted = ""
			g.mu.Unlock()

			if route != "" {
				g.showMain(route)
			}
		})

	g.tray = g.wailsApp.SystemTray.New()
	g.tray.SetLabel(trayWaiting)
	g.tray.SetIcon(branding.TrayIcon())
	g.tray.SetMenu(g.menu())

	// The icon on the window and in the menus is not set from here, and cannot
	// be: GTK 4 removed every API that takes one as bytes, and Wails' own
	// backend says so where its `setIcon` used to do something. What draws it is
	// the desktop entry — `Icon=ladulas` in contrib/ladulas.desktop, resolved
	// against the icon theme — which is why ProgramName above has to match the
	// entry's name. `make install-desktop` puts both in place for a tree that
	// was installed with `make install` rather than from a package.

	// Clicking the icon opens the application window, which is what every other
	// tray application does and the first thing anybody tries.
	g.tray.OnClick(func() {
		g.showMain(routeHome)
	})

	// Wails' own complaint about a session with nowhere to put the icon is a
	// D-Bus error message; this is what it means.
	warnIfNoTrayHost(logger)

	watchCtx, stopWatching := context.WithCancel(ctx)
	defer stopWatching()

	go func() {
		if err := front.Run(watchCtx); err != nil {
			logger.Error("the approval stream stopped", "error", err.Error())
		}
	}()

	// A signal is the other way this ends. The context is watched from a
	// goroutine rather than in a select beside the loop, because the loop has to
	// have this one — see runsOnTheGoroutineThatStartedTheProcess below.
	go func() {
		<-ctx.Done()

		g.mu.Lock()
		g.quitting = true
		g.mu.Unlock()

		g.wailsApp.Quit()
	}()

	if err := g.wailsApp.Run(); err != nil {
		return fmt.Errorf("run the desktop application: %w", err)
	}

	return nil
}

// runsOnTheGoroutineThatStartedTheProcess is why `Run` is called above rather
// than in a goroutine, and it is the whole of two hangs.
//
// Wails locks the goroutine that imported it to the main OS thread — package
// `application`'s own init does `runtime.LockOSThread` — and remembers that
// thread. Every main-thread dispatch checks against it: `InvokeSync` made *from*
// the main thread runs its function inline instead of queueing it, which is what
// makes it safe for a main-thread callback to call another one.
//
// Run the GTK loop on any other goroutine and that check is false forever. The
// loop is on a thread Wails does not recognise as the main one, so a nested
// dispatch queues a task and waits for a loop that is already inside the
// dispatch — and nothing ever runs again. Two paths reach it:
//
//   - **Closing the last window.** Wails destroys the window on the main thread
//     and, if it was the last one, quits from inside the same call:
//     `unregisterWindow` → `linuxApp.destroy` → `App.cleanup`, which dispatches.
//   - **Quit.** `App.Quit` is `InvokeSync(impl.destroy)`, which reaches the same
//     `cleanup` the same way. Choosing Quit from the tray froze the application
//     instead of ending it: no exit, no window, no approval ever shown again.
//
// What either one looks like is nothing: the process stays alive, the front end
// stays attached to the daemon, the tray icon stays on the bar, and every item on
// its menu does nothing at all. Every request from then on waits out its timeout
// unanswered — failing closed, and silently. docs/ops.md has it as a failure
// mode.
//
// So the loop stays here, on the goroutine `main` handed to `runGUI`, and the two
// things that used to be a `select` beside it are a goroutine each. And
// `DisableQuitOnLastWindowClosed` stays set as well: a tray application has no
// business quitting when its last window closes, which is a separate statement
// from this one and true on its own.

// attached is what the front end calls when the stream comes up or goes down.
//
// The tray label is where it shows, because that is the one part of a desktop
// application that is always visible: "Ladulås" means attached, and anything
// else means the prompts are not going to arrive here. A sealed store gets the
// passphrase panel the moment there is a daemon to type it at, which is the
// ordinary way a desktop starts since decision I.
func (g *GUI) attached(attached bool) {
	if g.tray == nil {
		return
	}

	if !attached {
		g.tray.SetLabel(trayWaiting)

		return
	}

	g.tray.SetLabel(trayLabel)

	if g.front.State().State == "sealed" {
		g.showMain(routeSettings)
	}
}

func (g *GUI) menu() *application.Menu {
	menu := g.wailsApp.NewMenu()

	menu.Add("Ladulås").SetEnabled(false)
	menu.AddSeparator()

	menu.Add("Open Ladulås").OnClick(func(*application.Context) {
		g.showMain(routeHome)
	})

	menu.Add("Published documentation…").OnClick(func(*application.Context) {
		g.showMain(routeDocuments)
	})

	menu.AddSeparator()

	// Unlocking is a screen in the window rather than a window of its own: a
	// sealed store has nothing else worth drawing, so the shell puts the panel
	// wherever the reader happens to be standing (§10).
	menu.Add("Unlock…").OnClick(func(*application.Context) {
		g.showMain(routeSettings)
	})

	menu.Add("Lock").OnClick(func(*application.Context) {
		g.setLock(false)
	})

	menu.Add("Seal").OnClick(func(*application.Context) {
		g.setLock(true)
	})

	menu.AddSeparator()

	menu.Add("Reload store and policy").OnClick(func(*application.Context) {
		if err := g.front.Reload(); err != nil {
			g.wailsApp.Dialog.Error().
				SetTitle("Reload failed").
				SetMessage(err.Error()).
				Show()

			return
		}

		g.wailsApp.Dialog.Info().
			SetTitle("Reloaded").
			SetMessage("The store and the policy were re-read from disk.").
			Show()
	})

	menu.AddSeparator()

	menu.Add("Quit").OnClick(func(*application.Context) {
		// Said before asking, because what it stops is a window being opened
		// while the windows are being closed.
		g.mu.Lock()
		g.quitting = true
		g.mu.Unlock()

		g.wailsApp.Quit()
	})

	return menu
}

// setLock is the desktop's half of §10's lock verbs, and the same call the
// command line makes.
func (g *GUI) setLock(seal bool) {
	if err := g.front.Lock(seal); err != nil {
		g.wailsApp.Dialog.Error().
			SetTitle("The store did not change state").
			SetMessage(err.Error()).
			Show()
	}
}

// showMain opens the application window on one of the shell's screens, or brings
// the one that is already open to that screen (decision AA).
//
// There is one of it, and that is the change. Every menu item used to make a
// window of its own, so a few clicks left a pile of them behind one tray icon,
// each with a webview polling the daemon in it — and none of them was "the
// Ladulås window", which is what somebody clicking the icon is asking for.
func (g *GUI) showMain(route string) {
	g.mu.Lock()

	if g.quitting {
		g.mu.Unlock()

		return
	}

	// Asked for before there is an application to put it in: remember which
	// screen and let ApplicationStarted open it.
	if !g.started {
		g.wanted = route
		g.mu.Unlock()

		return
	}

	window := g.main
	g.mu.Unlock()

	if window != nil {
		// The shell moves between its screens on the fragment, so this is a
		// navigation rather than a reload.
		window.SetURL(route)
		window.Show()
		window.Focus()

		return
	}

	window = g.wailsApp.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "Ladulås",
		Width:            mainWidth,
		Height:           mainHeight,
		MinWidth:         mainMinWidth,
		MinHeight:        mainMinHeight,
		URL:              route,
		BackgroundColour: application.NewRGB(24, 24, 27),
	})

	// A closed window is destroyed rather than hidden, and a destroyed window
	// cannot be shown again — so the reference goes when the window does and the
	// next request for it builds a new one.
	window.RegisterHook(events.Common.WindowClosing, func(*application.WindowEvent) {
		g.mu.Lock()
		g.main = nil
		g.mu.Unlock()
	})

	g.mu.Lock()
	g.main = window
	g.mu.Unlock()

	window.Show()
	window.Focus()
}
