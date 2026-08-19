package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// systemd-ask-password is how a daemon with no terminal asks for the store
// passphrase at service start (§14).
//
// It is worth being exact about what it does, because the mechanism is easy to
// mistake for something that needs root. `systemd-ask-password` writes a
// request into $XDG_RUNTIME_DIR/systemd/ask-password when it runs unprivileged,
// and any agent the user runs — `systemd-tty-ask-password-agent --query` in an
// SSH session, the desktop's own agent under a graphical session — can answer
// it. So a user unit that starts sealed puts a question up, and whoever gets to
// a shell first answers it. Nothing here is privileged, and the alternative is
// always there: `ladulas unlock` over the control socket.

// AskPasswordRunner runs the ask-password command. It is the seam the tests
// use: there is no way to answer a real prompt from a test, and a fake process
// is a truthful stand-in for one that writes a passphrase to stdout.
type AskPasswordRunner func(ctx context.Context, args []string) ([]byte, error)

// AskPassword is a keystore.PassphraseFunc backed by systemd-ask-password.
type AskPassword struct {
	// Run defaults to running the real binary.
	Run AskPasswordRunner
	// Timeout bounds the wait. Zero means DefaultAskTimeout.
	Timeout time.Duration
}

// DefaultAskTimeout is how long the daemon holds a password prompt up before
// giving up and staying sealed. Long enough for somebody to notice the machine
// rebooted and SSH in, short enough that a stale prompt does not outlive the
// reason for it.
const DefaultAskTimeout = 5 * time.Minute

// ErrNoAskPassword is returned when the binary is not installed.
var ErrNoAskPassword = errors.New(
	"command: systemd-ask-password is not on the PATH")

// Passphrase implements keystore.PassphraseFunc, waiting for an answer until
// the timeout runs out.
func (a AskPassword) Passphrase(prompt string, confirm bool) ([]byte, error) {
	return a.Ask(context.Background(), prompt, confirm)
}

// Ask is the prompt with a lifetime attached.
//
// Cancelling the context kills the systemd-ask-password child that is holding
// the prompt up, which is how a store unlocked over the control socket
// withdraws a question nobody needs to answer any more (§14). The two routes
// into a sealed daemon race, and the loser has to leave nothing behind.
//
// It never confirms. Establishing a passphrase is `ladulas init`, which is run
// by a person at a terminal; this only ever unlocks an existing store.
func (a AskPassword) Ask(
	ctx context.Context, prompt string, confirm bool,
) ([]byte, error) {
	if confirm {
		return nil, errors.New(
			"command: a store cannot be created through systemd-ask-password")
	}

	timeout := a.Timeout
	if timeout <= 0 {
		timeout = DefaultAskTimeout
	}

	run := a.Run
	if run == nil {
		run = runAskPassword
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{
		"--icon=dialog-password",
		// The id groups the request so that an agent can tell what is asking,
		// and so a second prompt for the same store replaces the first.
		"--id=ladulas:store",
		"--keyname=ladulas-store",
		fmt.Sprintf("--timeout=%d", int(timeout.Seconds())),
		"--no-tty",
		prompt,
	}

	out, err := run(ctx, args)
	if err != nil {
		return nil, err
	}

	// The binary prints the answer followed by a newline, and can print several
	// when more than one agent answered. The first is the one to use.
	answer, _, _ := bytes.Cut(out, []byte("\n"))

	if len(answer) == 0 {
		return nil, errors.New("command: nobody answered the password prompt")
	}

	return answer, nil
}

func runAskPassword(ctx context.Context, args []string) ([]byte, error) {
	binary, err := exec.LookPath("systemd-ask-password")
	if err != nil {
		return nil, ErrNoAskPassword
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = nil

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("systemd-ask-password: %w: %s",
			err, strings.TrimSpace(stderr.String()))
	}

	return out, nil
}

// AskPasswordAvailable reports whether systemd-ask-password can be used here.
func AskPasswordAvailable() bool {
	if _, err := exec.LookPath("systemd-ask-password"); err != nil {
		return false
	}

	// Unprivileged ask-password needs the runtime directory it writes requests
	// into. Without one there is nothing to answer.
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return os.Geteuid() == 0
	}

	_, err := os.Stat(dir)

	return err == nil
}
