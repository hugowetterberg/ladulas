package command

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/internal/tui"
)

// tuiCommand is the terminal approver: the desktop window's screens, drawn in a
// terminal and answering over the same socket (decision AK).
//
// It is a client of a running daemon and nothing else — it opens no store,
// serves no agent socket and holds no key, exactly as `ladulas gui` does not
// (decision Z). Two of these attached at once are two approvers, and so are one
// of these and a window; the engine asks all of them and the first answer
// wins.
//
// The verb is `tui` rather than `approve` because this is the terminal shell
// and answering requests is the first thing it does rather than the only thing
// it will ever do — the window it is modelled on grew a status pane, a key list
// and an activity log around the same seam.
func tuiCommand() *cli.Command {
	return &cli.Command{
		Name:  "tui",
		Usage: "watch for approval requests and answer them in this terminal",
		Description: "Attaches to the running daemon as an approver and draws " +
			"the same card the desktop application draws: the commit, who is " +
			"asking, which key, and the diff a file at a time. Answering here " +
			"offers what the window offers, including approving for a while.\n\n" +
			"This is a second approver rather than a replacement for one. A " +
			"desktop window, a paired phone and this terminal can all be " +
			"attached at once, and quitting takes only this one away — " +
			"anything still waiting goes on waiting for the others.",
		Before: NoArguments,
		Action: runTUI,
	}
}

func runTUI(ctx context.Context, cmd *cli.Command) error {
	if !tui.IsTerminal() {
		// Drawing a full-screen program into a pipe produces a file of escape
		// codes and no way to answer anything, so it is refused with the
		// sentence that says which surface the caller wanted instead.
		return errors.New(
			"there is no terminal here to draw on — a daemon started with a " +
				"terminal already prompts on it, and `ladulas gui` is the window")
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return tui.Run(ctx,
		localapi.NewClient(cmd.String("control-socket")),
		tuiLogger(cmd))
}

// tuiLogger keeps the log off the screen it would be written over.
//
// The front end logs the ordinary things it does — attaching, losing the
// stream, an answer that did not arrive — and every one of those lines lands in
// the middle of a full-screen program's drawing, because stderr and the screen
// are the same file. One INFO line about attaching was enough to put a
// timestamp through the middle of the card.
//
// So: stderr when stderr has been sent somewhere, which is what
// `ladulas tui 2>/tmp/tui.log` asks for and how this is debugged, and nothing
// when it is the terminal. Nothing is not a loss of information here — whether
// this is attached is on the screen, and anything that goes wrong with a
// request that is waiting is put in the status line rather than logged past
// somebody.
func tuiLogger(cmd *cli.Command) *slog.Logger {
	if tui.IsTerminalErr() {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	return Logger(cmd)
}
