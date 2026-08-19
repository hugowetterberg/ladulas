//go:build !gui

// Package gui is the desktop application. This is the build without one.
//
// The GUI lives behind a build tag because Wails needs the platform webview
// development headers at compile time, and a machine that has no desktop —
// a headless box, or a CI runner — should still be able to build and test
// everything else.
package gui

import (
	"context"
	"errors"
	"log/slog"

	"github.com/hugowetterberg/ladulas/internal/localapi"
)

// ErrNoGUI is returned when a build without the GUI is asked for one.
var ErrNoGUI = errors.New(
	"this build has no desktop GUI; rebuild with -tags gui, or run `ladulas agent` " +
		"to approve at the terminal")

// Run reports that there is no GUI to run.
func Run(context.Context, *localapi.Client, *slog.Logger) error {
	return ErrNoGUI
}
