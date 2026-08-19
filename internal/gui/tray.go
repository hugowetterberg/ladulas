//go:build gui

package gui

import (
	"log/slog"

	"github.com/godbus/dbus/v5"
)

// Whether this session has anywhere to put a tray icon, and saying so in a
// sentence when it does not.
//
// Wails draws the tray as a StatusNotifierItem: it exports an object on the
// session bus and asks a StatusNotifierWatcher to show it. A session with no
// watcher — i3 and the other bars whose tray is XEmbed rather than SNI, which
// is most of them outside GNOME and KDE — answers that with
//
//	systray error: failed to register: The name is not activatable
//
// which is a true statement about D-Bus and tells nobody what happened to
// their icon. The desktop application goes on working: prompts are windows and
// windows do not need a tray. What is lost is the one always-visible surface,
// and with it the menu and the label that says whether the front end is
// attached (decision Z) — so it is worth a line that names the cause and the
// fix rather than leaving the library's to be searched for.

// trayHosts are the two bus names a StatusNotifierItem can be shown by. The
// second is xapp's, which Cinnamon and a few standalone proxies own.
var trayHosts = []string{
	"org.kde.StatusNotifierWatcher",
	"org.x.StatusNotifierWatcher",
}

// warnIfNoTrayHost logs what a failed tray registration means, and nothing at
// all when there is a host to register with.
//
// It is best effort in both directions: a session bus that cannot be reached is
// not worth a second complaint, since Wails is about to make the first one.
func warnIfNoTrayHost(log *slog.Logger) {
	conn, err := dbus.SessionBus()
	if err != nil {
		log.Debug("could not ask the session bus about the tray",
			"error", err.Error())

		return
	}

	// Not closed: dbus.SessionBus is a shared connection, and closing it here
	// would take it out from under whatever else in this process is using one.

	var names []string

	err = conn.BusObject().Call("org.freedesktop.DBus.ListNames", 0).Store(&names)
	if err != nil {
		log.Debug("could not list the session bus names",
			"error", err.Error())

		return
	}

	for _, name := range names {
		for _, host := range trayHosts {
			if name == host {
				return
			}
		}
	}

	log.Warn("this session has no tray for the icon to appear in, "+
		"so there is no menu and no attached/not-attached label; "+
		"approval windows are unaffected. The icon is a StatusNotifierItem "+
		"and nothing here shows one — a bar with SNI support, or snixembed "+
		"bridging it into an XEmbed tray, is what makes it appear",
		"looked_for", trayHosts)
}
