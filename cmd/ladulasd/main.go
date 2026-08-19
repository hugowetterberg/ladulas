// Command ladulasd is the headless Ladulås daemon.
//
// It is the same core as the desktop application with no GUI attached: the SSH
// agent, the approval engine, policies and the audit log. On a headless box
// approvals come from a paired peer, or from the terminal when it was started
// with one (docs/architecture.md §13).
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/internal/command"
	"github.com/hugowetterberg/ladulas/internal/version"
)

func main() {
	cmd := &cli.Command{
		Name:    "ladulasd",
		Usage:   "the Ladulås daemon: SSH agent, approval engine, audit log",
		Version: version.String(),
		Flags:   command.GlobalFlags(),
		Commands: append(command.Commands(), &cli.Command{
			Name:  "run",
			Usage: "run the agent, approving at the terminal or from a paired peer",
			Flags: append([]cli.Flag{command.ConsoleFlag(), command.UnlockFlag(),
				command.DebugFlag()}, command.TriggerFlags()...),
			Before: command.NoArguments,
			Action: func(ctx context.Context, cmd *cli.Command) error {
				return command.RunHeadless(ctx, cmd)
			},
		}),
		DefaultCommand: "run",
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "ladulasd: %v\n", err)
		os.Exit(1)
	}
}
