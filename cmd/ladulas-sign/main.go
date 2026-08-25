// Command ladulas-sign is git's signing program when Ladulås is signing
// commits (docs/architecture.md §5).
//
// It implements the ssh-keygen -Y sign command line, so git drives it exactly
// as it drives ssh-keygen, and it differs in what happens in between: instead
// of hashing the commit away and handing a digest to an agent, it submits the
// whole commit object plus the repository, branch and diff to the local Ladulås
// instance. The approval prompt is then worth reading, on the desktop or on a
// phone.
//
//	git config --global gpg.format ssh
//	git config --global gpg.ssh.program ladulas-sign
//
// Everything else git runs the same program for — -Y find-principals and
// -Y verify — is passed to the real ssh-keygen, and so is a signing request for
// a key this instance does not hold. Nothing that worked before this program
// was configured stops working because it was. A command line git did not
// build is a different matter: it gets the usage rather than a hand-over,
// because ssh-keygen with no operation flag generates a key (decision AI).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hugowetterberg/ladulas/internal/signcli"
)

func main() {
	args := os.Args[1:]

	// git kills the signer when the user interrupts a commit; leaving the
	// pending approval behind would strand a prompt on somebody's screen.
	ctx, stop := signal.NotifyContext(
		context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(signcli.Run(ctx, args, signcli.Options{}))
}
