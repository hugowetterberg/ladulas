package command_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/internal/command"
)

// The headless unlock of §14, at two levels: the argument handling against a
// fake process, and — where the machine running the tests has the binary and a
// runtime directory — a real systemd-ask-password answered the way an agent
// answers one.

func TestAskPasswordTakesTheFirstAnswer(t *testing.T) {
	var seen []string

	ask := command.AskPassword{
		Run: func(_ context.Context, args []string) ([]byte, error) {
			seen = args

			// More than one agent may answer; the binary prints each on its own
			// line.
			return []byte("the passphrase\nsomebody else's\n"), nil
		},
	}

	got, err := ask.Passphrase("Passphrase for the Ladulås store", false)
	if err != nil {
		t.Fatalf("ask: %v", err)
	}

	if string(got) != "the passphrase" {
		t.Errorf("got %q", got)
	}

	joined := strings.Join(seen, " ")

	for _, want := range []string{"--id=ladulas:store", "--no-tty", "--timeout="} {
		if !strings.Contains(joined, want) {
			t.Errorf("the command line has no %s: %v", want, seen)
		}
	}

	if seen[len(seen)-1] != "Passphrase for the Ladulås store" {
		t.Errorf("the prompt was not passed through: %v", seen)
	}
}

// A store is created by a person at a terminal, never through a password
// agent: there is nothing on the other end that can be asked to repeat itself.
func TestAskPasswordRefusesToCreateAStore(t *testing.T) {
	ask := command.AskPassword{
		Run: func(context.Context, []string) ([]byte, error) {
			return []byte("nope\n"), nil
		},
	}

	if _, err := ask.Passphrase("prompt", true); err == nil {
		t.Error("a store could be created through a password agent")
	}
}

func TestAskPasswordWithNoAnswer(t *testing.T) {
	ask := command.AskPassword{
		Run: func(context.Context, []string) ([]byte, error) {
			return nil, nil
		},
	}

	if _, err := ask.Passphrase("prompt", false); err == nil {
		t.Error("an empty answer was accepted as a passphrase")
	}
}

func TestAskPasswordPropagatesFailure(t *testing.T) {
	want := errors.New("no agent answered")

	ask := command.AskPassword{
		Run: func(context.Context, []string) ([]byte, error) {
			return nil, want
		},
	}

	if _, err := ask.Passphrase("prompt", false); !errors.Is(err, want) {
		t.Errorf("ask: %v", err)
	}
}

// TestAskPasswordAgainstTheRealBinary drives the whole headless unlock: the
// daemon's prompt goes up, and something with a shell answers it.
//
// Unprivileged systemd-ask-password writes its request into
// $XDG_RUNTIME_DIR/systemd/ask-password and waits on a datagram socket named in
// it; `systemd-tty-ask-password-agent --query` in an SSH session is one thing
// that answers, and this test is another. Skipped where there is no runtime
// directory or no binary, which is most build machines.
func TestAskPasswordAgainstTheRealBinary(t *testing.T) {
	if !command.AskPasswordAvailable() {
		t.Skip("systemd-ask-password cannot be used here")
	}

	dir := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "systemd", "ask-password")

	if _, err := os.Stat(dir); err != nil {
		t.Skipf("no per-user ask-password directory: %v", err)
	}

	const secret = "the real passphrase"

	answered := make(chan error, 1)

	go func() {
		answered <- answerPrompt(dir, secret)
	}()

	ask := command.AskPassword{Timeout: 20 * time.Second}

	got, err := ask.Passphrase("Ladulås test prompt", false)
	if err != nil {
		t.Fatalf("ask: %v (answering said %v)", err, <-answered)
	}

	if string(got) != secret {
		t.Errorf("got %q, want %q", got, secret)
	}

	if err := <-answered; err != nil {
		t.Errorf("answering the prompt: %v", err)
	}
}

// answerPrompt is what a password agent does: find the request, read the socket
// it names, and send the answer prefixed with a plus.
func answerPrompt(dir, secret string) error {
	deadline := time.Now().Add(15 * time.Second)

	for time.Now().Before(deadline) {
		socket, err := pendingSocket(dir)
		if err != nil {
			return err
		}

		if socket == "" {
			time.Sleep(20 * time.Millisecond)

			continue
		}

		conn, err := net.Dial("unixgram", socket)
		if err != nil {
			return err //nolint:wrapcheck // a test helper's error is read whole
		}

		defer func() {
			_ = conn.Close()
		}()

		if _, err := conn.Write([]byte("+" + secret)); err != nil {
			return err //nolint:wrapcheck // likewise
		}

		return nil
	}

	return errors.New("no password request appeared")
}

// pendingSocket finds the request this test put up, by the prompt it carries.
func pendingSocket(dir string) (string, error) {
	entries, err := filepath.Glob(filepath.Join(dir, "ask.*"))
	if err != nil {
		return "", err //nolint:wrapcheck // likewise
	}

	for _, entry := range entries {
		body, err := os.ReadFile(entry) //nolint:gosec // a path this test built
		if err != nil {
			continue
		}

		text := string(body)
		if !strings.Contains(text, "Ladulås test prompt") {
			continue
		}

		for line := range strings.SplitSeq(text, "\n") {
			if socket, ok := strings.CutPrefix(line, "Socket="); ok {
				return socket, nil
			}
		}
	}

	return "", nil
}
