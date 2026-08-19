package integration_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/internal/app"
	"github.com/hugowetterberg/ladulas/internal/testutil"
)

// The daemon as a unit starts it: `ladulasd run` in its own process, with no
// terminal anywhere, reached only through the sockets it makes.
//
// What the other integration tests drive is an instance assembled in the test
// process, which is the right level for everything except the order the daemon
// does things in. That order is the whole of §14's promise about a headless
// box: the control socket exists while the passphrase prompt is standing, so
// `ladulas unlock` and answering the prompt really are two ways to do the same
// thing rather than one way and one that cannot be reached until the other has
// happened.

// daemonBox is a real ladulasd process with its own store.
type daemonBox struct {
	dataDir   string
	configDir string
	control   string
	agent     string
	// askedPID is where the stand-in systemd-ask-password writes its process
	// id, so a test can see the prompt go up and see it withdrawn again.
	askedPID string
	logPath  string
	env      []string
}

// startDaemonBox creates a store, then hands it to a `ladulasd run` started the
// way a systemd user unit starts one: stdin is not a terminal, the runtime
// directory is its own, and nothing about the environment offers a way to type
// a passphrase except the ask-password stand-in on the PATH.
func startDaemonBox(t *testing.T, unlock string) *daemonBox {
	t.Helper()

	daemon := buildDaemon(t)

	runtime := shortDir(t)
	binDir := t.TempDir()

	box := &daemonBox{
		dataDir:   t.TempDir(),
		configDir: t.TempDir(),
		control:   filepath.Join(runtime, "control.sock"),
		agent:     filepath.Join(runtime, "agent.sock"),
		askedPID:  filepath.Join(runtime, "ask-password.pid"),
		logPath:   filepath.Join(runtime, "daemon.log"),
	}

	createStore(t, box)
	fakeAskPassword(t, binDir, box.askedPID)

	box.env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"XDG_RUNTIME_DIR="+runtime,
		"LADULAS_DATA_DIR="+box.dataDir,
		"LADULAS_CONFIG_DIR="+box.configDir,
		"LADULAS_SOCK="+box.control,
		"LADULAS_AGENT_SOCK="+box.agent,
		"LADULAS_PEER_LISTEN=127.0.0.1:0",
		"LADULAS_NO_KEYRING=1",
		"LADULAS_UNLOCK="+unlock,
		// The lock triggers would take an inhibitor on the developer's own
		// login manager, which is not this test's business.
		"LADULAS_ON_SUSPEND=off",
		"LADULAS_ON_SESSION_LOCK=off")

	log, err := os.Create(box.logPath)
	if err != nil {
		t.Fatalf("open the daemon's log: %v", err)
	}

	run := exec.Command(daemon, "run")
	run.Env = box.env
	run.Stdout = log
	run.Stderr = log

	if err := run.Start(); err != nil {
		t.Fatalf("start ladulasd: %v", err)
	}

	t.Cleanup(func() {
		if err := run.Process.Signal(syscall.SIGTERM); err != nil {
			t.Logf("stop ladulasd: %v", err)
		}

		stopped := make(chan error, 1)

		go func() {
			stopped <- run.Wait()
		}()

		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			_ = run.Process.Kill()
			<-stopped

			t.Error("ladulasd did not stop")
		}

		if err := log.Close(); err != nil {
			t.Logf("close the daemon's log: %v", err)
		}

		t.Logf("ladulasd said:\n%s", box.log(t))
	})

	return box
}

// createStore makes the store the daemon will find, since `ladulas init` needs
// a terminal to take a new passphrase from and this test has none.
func createStore(t *testing.T, box *daemonBox) {
	t.Helper()

	instance, err := app.Create(app.Config{
		DataDir:       box.dataDir,
		ConfigDir:     box.configDir,
		SocketPath:    box.agent,
		ControlSocket: box.control,
		InstanceName:  "headless",
		PeerListen:    app.PeeringOff,
		NoKeyring:     true,
		Passphrase: func(string, bool) ([]byte, error) {
			return []byte(testPassphrase), nil
		},
	})
	if err != nil {
		t.Fatalf("create the store: %v", err)
	}

	if _, err := instance.Vault().GenerateKey("work", "headless@example.test"); err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	if err := instance.Close(); err != nil {
		t.Fatalf("close the store: %v", err)
	}
}

// fakeAskPassword installs a systemd-ask-password that never answers.
//
// A real one cannot be used here: answering it needs a password agent, and what
// this test is about is what the daemon does while nobody has answered. The
// stand-in is a real process all the same — it records its own id and then
// waits, so the test can tell that the prompt went up and that the daemon
// killed it when the unlock arrived somewhere else.
func fakeAskPassword(t *testing.T, dir, pidPath string) {
	t.Helper()

	script := fmt.Sprintf("#!/bin/sh\necho $$ > %q\nexec sleep 300\n", pidPath)

	path := filepath.Join(dir, "systemd-ask-password")

	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write the ask-password stand-in: %v", err)
	}
}

// log is everything the daemon has printed so far.
func (b *daemonBox) log(t *testing.T) string {
	t.Helper()

	body, err := os.ReadFile(b.logPath)
	if err != nil {
		t.Fatalf("read the daemon's log: %v", err)
	}

	return string(body)
}

// cli runs the real command line against the box, the way somebody who has just
// SSHed in would.
func (b *daemonBox) cli(
	t *testing.T, binary, stdin string, args ...string,
) (string, error) {
	t.Helper()

	cmd := exec.Command(binary, args...)
	cmd.Env = b.env

	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	out, err := cmd.CombinedOutput()

	t.Logf("ladulas %s:\n%s", strings.Join(args, " "), out)

	return string(out), err
}

func (b *daemonBox) mustCLI(
	t *testing.T, binary, stdin string, args ...string,
) string {
	t.Helper()

	out, err := b.cli(t, binary, stdin, args...)
	if err != nil {
		t.Fatalf("ladulas %s: %v\n%s", strings.Join(args, " "), err, out)
	}

	return out
}

// waitForPrompt waits for the ask-password stand-in to say it is up.
func (b *daemonBox) waitForPrompt(t *testing.T) int {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)

	for time.Now().Before(deadline) {
		body, err := os.ReadFile(b.askedPID)
		if err == nil {
			pid, err := strconv.Atoi(strings.TrimSpace(string(body)))
			if err == nil {
				return pid
			}
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("the daemon never asked for a passphrase:\n%s", b.log(t))

	return 0
}

// alive reports whether a process is still there. A prompt that was withdrawn
// is a killed process, which is the only evidence there is that the daemon does
// not leave one standing behind an unlock that has already happened.
func alive(pid int) bool {
	err := syscall.Kill(pid, 0)

	return err == nil || errors.Is(err, syscall.EPERM)
}

// buildDaemon compiles ladulasd, because the order it starts things in is
// exactly what is being tested and a function call would not have one.
func buildDaemon(t *testing.T) string {
	t.Helper()

	testutil.RequireTool(t, "go")

	path := filepath.Join(shortDir(t), "ladulasd")

	cmd := exec.Command("go", "build", "-o", path,
		"github.com/hugowetterberg/ladulas/cmd/ladulasd")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build ladulasd: %v\n%s", err, out)
	}

	return path
}

// TestSealedDaemonServesWhileItIsAsking is the boot state of a headless box,
// which is where §10's sealed instance either exists or does not.
//
// The daemon comes up with no terminal, puts a systemd-ask-password prompt up,
// and nobody answers it. While that is standing, the control socket has to be
// there and answering: `ladulas status` says what is wrong with the box and
// `ladulas unlock` fixes it. A daemon that asked before it listened would leave
// the ask-password agent as the only way in, and a box nobody reached in time
// would sit sealed with no socket at all until it was restarted.
func TestSealedDaemonServesWhileItIsAsking(t *testing.T) {
	cli := buildCLI(t)

	box := startDaemonBox(t, "auto")

	// The prompt goes up, and stays up: nothing in this test answers it.
	prompt := box.waitForPrompt(t)

	// The sockets are there anyway, which is the whole claim.
	waitForSocket(t, box.control)
	waitForSocket(t, box.agent)

	if !alive(prompt) {
		t.Fatal("the passphrase prompt was gone before anything answered it")
	}

	status := box.mustCLI(t, cli, "", "status")

	if !strings.Contains(status, "sealed") {
		t.Errorf("status does not say the store is sealed:\n%s", status)
	}

	if !strings.Contains(status, "Running       yes") {
		t.Errorf("status does not say the daemon is running:\n%s", status)
	}

	// And it says which of the two situations this is: a question standing in
	// somebody else's session, rather than nothing happening at all.
	if !strings.Contains(status, "systemd-ask-password") {
		t.Errorf("status does not mention the prompt that is up:\n%s", status)
	}

	unlocked := box.mustCLI(t, cli, testPassphrase+"\n", "unlock", "--stdin")
	if !strings.Contains(unlocked, "unlocked") {
		t.Fatalf("unlock did not report an unlocked store:\n%s", unlocked)
	}

	// The prompt loses the race and is taken down rather than left waiting for
	// an answer that is no longer needed.
	deadline := time.Now().Add(10 * time.Second)

	for alive(prompt) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if alive(prompt) {
		t.Errorf("the passphrase prompt %d is still up after the unlock", prompt)
	}

	status = box.mustCLI(t, cli, "", "status")

	if !strings.Contains(status, "Store         unlocked") {
		t.Errorf("status does not say the store is unlocked:\n%s", status)
	}

	if !strings.Contains(status, "Keys          1") {
		t.Errorf("the unlocked daemon does not report its key:\n%s", status)
	}
}

// A daemon told to ask nothing serves just the same, and says so.
func TestSealedDaemonAsksNothingWhenToldNotTo(t *testing.T) {
	cli := buildCLI(t)

	box := startDaemonBox(t, "none")

	waitForSocket(t, box.control)

	status := box.mustCLI(t, cli, "", "status")

	if !strings.Contains(status, "sealed") {
		t.Errorf("status does not say the store is sealed:\n%s", status)
	}

	if strings.Contains(status, "systemd-ask-password") {
		t.Errorf("a daemon told to ask nothing put a prompt up:\n%s", status)
	}

	if _, err := os.Stat(box.askedPID); err == nil {
		t.Error("a daemon told to ask nothing ran systemd-ask-password")
	}

	box.mustCLI(t, cli, testPassphrase+"\n", "unlock", "--stdin")

	if got := box.mustCLI(t, cli, "", "status"); !strings.Contains(got, "unlocked") {
		t.Errorf("the store did not open:\n%s", got)
	}
}
