package command

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/internal/version"
)

// versionCommand prints the version of the binary it is in, and nothing else.
//
// It is deliberately a local answer rather than a question put to the daemon:
// `ladulas version` says what this command line is, not what the daemon it
// talks to is. Those differ, routinely — a packaged CLI against a daemon still
// running from an earlier `go install` is the normal state of a machine
// mid-upgrade. What the running daemon is, `ladulas status` says, because that
// one does ask it.
func versionCommand() *cli.Command {
	return &cli.Command{
		Name:   "version",
		Usage:  "print the version of this binary",
		Before: NoArguments,
		Action: func(_ context.Context, cmd *cli.Command) error {
			_, err := fmt.Fprintln(cmd.Root().Writer, version.String())
			if err != nil {
				return fmt.Errorf("write the version: %w", err)
			}

			return nil
		},
	}
}
