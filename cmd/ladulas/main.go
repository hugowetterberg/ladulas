// Command ladulas is the Ladulås desktop application and its command line.
//
// `ladulas gui` runs the desktop application: the SSH agent, the approval
// engine, a tray icon and a graphical prompt for every signature. `ladulas
// agent` is the same instance with the terminal for a prompt. The subcommands
// manage keys, policy, grants and the audit log, and work the same in a
// terminal on a machine that has no desktop. With no arguments at all it prints
// the usage and nothing runs.
//
// The desktop application needs a build with the GUI in it:
//
//	go build -tags gui ./cmd/ladulas               # GTK 4 / webkitgtk-6.0
//	go build -tags gui,gtk3 ./cmd/ladulas          # GTK 3 / webkit2gtk-4.1
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/internal/command"
	"github.com/hugowetterberg/ladulas/internal/gui"
	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/internal/version"
)

func main() {
	cmd := &cli.Command{
		Name:    "ladulas",
		Usage:   "SSH agent and signing approvals",
		Version: version.String(),
		Flags:   command.GlobalFlags(),
		Commands: append(command.Commands(), &cli.Command{
			Name:   "gui",
			Usage:  "run the desktop application: the tray, the windows and the prompts",
			Before: command.NoArguments,
			Action: runGUI,
		}),
		Action: command.Usage,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "ladulas: %v\n", err)
		os.Exit(1)
	}
}

// There is no DefaultCommand, and that is the point: `ladulas` on its own
// prints the usage (decision Y, §14).
//
// It used to start something — the desktop application in a build with a GUI in
// it, the terminal agent in one without — on the argument that a launcher or a
// session manager has nothing to pass. Two costs, and both are paid by a person
// rather than by a launcher. The verb that started something was whichever one
// the build had, so the same command line meant the window here and `agent` on
// a headless box, and a build tag is not something a command line should be
// asked about. And the binary is the management CLI as much as it is the
// desktop application (§12, §14), so the reflex of typing its name to see what
// it does started an SSH agent instead of answering.
//
// What starts it is `ladulas gui`, which is what the packaged unit runs. Do not
// put a default back to spare a `.desktop` file an argument.

// runGUI starts the desktop application, which is a client of a running daemon
// and nothing more (decision Z).
//
// It takes no flags of its own. The ones it used to take — the debug listener,
// the automatic locks — were an instance's, and this is not one: the daemon
// serving the agent socket is where a lock trigger belongs, and where the heap
// a profile would dump actually holds a key. What is left is the global
// --control-socket, which is how it finds the instance to draw.
//
// The verb is `gui` rather than `tray` because the tray icon is one of the
// things it draws, and it does not prompt on the terminal the way `ladulas
// agent` does: a desktop application is started by a session manager, from a
// .desktop file or from a menu, and none of those has a terminal to type into.
// The passphrase dialog is the desktop's answer to the same question (§10).
func runGUI(ctx context.Context, cmd *cli.Command) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return gui.Run(ctx,
		localapi.NewClient(cmd.String("control-socket")),
		command.Logger(cmd))
}
