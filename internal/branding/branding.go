// Package branding is the application's own picture, for the one place a desktop
// needs it as bytes.
//
// icon-1024.png beside this file is the master — the one drawing anybody makes
// by hand, and what every other size in the tree is derived from. What is
// embedded here is a downscale of it, because a tray icon is sent to the bar as
// pixels and 1024×1024 of them is a megabyte of binary to draw something 22
// pixels wide. `make icons` regenerates it and a test in this package fails if
// the two drift apart, which is the whole reason a copy is allowed to exist.
//
// The master lives here because the Linux packages need the drawing whatever
// else is ever built from it, and a Go module cannot depend on a file in a
// Swift one anyway. Any copy of it kept outside this repository is compared by
// nothing here (§21).
//
// It is its own package rather than part of internal/gui because that one is
// behind `-tags gui`: the check that the embedded tray icon still matches the
// master should run in `go test ./...` on any machine, including the ones with
// no GTK on them.
package branding

import (
	_ "embed"
)

// trayPNG is the icon at the size a bar draws it, give or take. A
// StatusNotifierItem is one pixmap and the host scales it, so this is chosen to
// have something left after being scaled down to 22 or 24 pixels rather than to
// match any particular bar.
//
// What it loses at that size is the frosted glass: the barn is pale against pale
// teal, and contrast is the first thing to go. It is still the app's icon, which
// is the point — a crisper tray glyph would be a second drawing to keep in step
// with this one, and that is a design decision rather than a build step.
//
//go:embed tray-128.png
var trayPNG []byte

// TrayIcon is the icon as PNG bytes, for a host that wants pixels.
//
// The slice is copied because the caller is handing it to a library: Wails keeps
// the bytes it is given, and a package-level slice that anything could write
// through is a picture that could change under whoever is drawing it.
func TrayIcon() []byte {
	out := make([]byte, len(trayPNG))
	copy(out, trayPNG)

	return out
}
