package integration_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A daemon with no store, which is the state §10 calls uninitialised.
//
// This is the one test that runs the real `ladulasd`, because the claim being
// checked is about the process: it used to exit with "No Ladulås store yet",
// which under a unit with Restart=on-failure is a restart loop that somebody
// has to notice. Now it comes up serving, answers Status and Initialize, and
// refuses everything else — and `ladulas init` is a client of it like every
// other verb, so nothing but the daemon ever writes store.age (§14).

func TestUninitialisedDaemonServesAndIsInitialisedOverTheSocket(t *testing.T) {
	cli := buildCLI(t)

	box := startEmptyDaemon(t)

	// It is up. That is the first claim, and the one that used to be false.
	status := box.must(t, cli, "", "status")
	if !strings.Contains(status, "not created yet") {
		t.Fatalf("status does not say the store has not been created:\n%s", status)
	}

	if !strings.Contains(status, "ladulas init") {
		t.Errorf("status does not say what to do about it:\n%s", status)
	}

	// And the surface really is Status and Initialize: everything that needs a
	// store says there is none, and none of it asks for a passphrase.
	for _, args := range [][]string{
		{"keys", "list"},
		{"keys", "generate", "deploy"},
		{"peers", "list"},
		{"grants", "list"},
		{"keyring", "status"},
		{"lock"},
		{"projects", "list"},
	} {
		out, err := box.run(t, cli, "", args...)
		if err == nil {
			t.Errorf("`%s` worked without a store:\n%s",
				strings.Join(args, " "), out)

			continue
		}

		if !strings.Contains(out, "no store") {
			t.Errorf("`%s` does not say there is no store:\n%s",
				strings.Join(args, " "), out)
		}

		if strings.Contains(out, noTerminal) {
			t.Errorf("`%s` asked for a passphrase:\n%s",
				strings.Join(args, " "), out)
		}
	}

	// Unlocking is the wrong advice here and says so: there is nothing to
	// unlock until there is something to unlock.
	unlocked, err := box.run(t, cli, "", "unlock", "--stdin")
	if err == nil {
		t.Errorf("unlock succeeded with no store:\n%s", unlocked)
	}

	if !strings.Contains(unlocked, "ladulas init") {
		t.Errorf("unlock does not point at init:\n%s", unlocked)
	}

	created := box.must(t, cli, testPassphrase+"\n",
		"init", "--stdin", "--name", "boxy")
	if !strings.Contains(created, "boxy") {
		t.Fatalf("init did not report the instance it made:\n%s", created)
	}

	if !strings.Contains(created, filepath.Join(box.dataDir, "store.age")) {
		t.Errorf("init did not say where the store went:\n%s", created)
	}

	// The daemon that made the store is the daemon serving it, so it is usable
	// immediately — no restart, which is the whole reason initialising over the
	// socket is better than initialising beside it.
	after := box.must(t, cli, "", "status")
	if !strings.Contains(after, "unlocked") {
		t.Fatalf("the instance did not come up unlocked after init:\n%s", after)
	}

	if !strings.Contains(after, "boxy") {
		t.Errorf("status does not know the instance's name:\n%s", after)
	}

	generated := box.must(t, cli, "", "keys", "generate", "work")
	if !strings.Contains(generated, "Generated SHA256:") {
		t.Fatalf("the fresh instance could not generate a key:\n%s", generated)
	}

	listed := box.must(t, cli, "", "keys", "list")
	if !strings.Contains(listed, "work") {
		t.Errorf("the generated key is not listed:\n%s", listed)
	}

	peers := box.must(t, cli, "", "peers", "list")
	if !strings.Contains(peers, "No paired instances yet") {
		t.Errorf("peers list did not answer on the fresh instance:\n%s", peers)
	}

	// Initialising twice is refused, and refused with the reason rather than
	// with whatever keystore.Create would have said to a second writer.
	again, err := box.run(t, cli, testPassphrase+"\n", "init", "--stdin")
	if err == nil {
		t.Fatalf("initialising twice succeeded:\n%s", again)
	}

	if !strings.Contains(again, "already has a store") {
		t.Errorf("the refusal does not say why:\n%s", again)
	}

	box.stillRunning(t)
}

// emptyDaemon is a real ladulasd started against directories with nothing in
// them.
type emptyDaemon struct {
	cmd       *exec.Cmd
	dataDir   string
	configDir string
	control   string
	agent     string
	log       string
}

func startEmptyDaemon(t *testing.T) *emptyDaemon {
	t.Helper()

	daemon := buildDaemon(t)
	runtime := shortDir(t)

	box := &emptyDaemon{
		dataDir:   t.TempDir(),
		configDir: t.TempDir(),
		control:   filepath.Join(runtime, "control.sock"),
		agent:     filepath.Join(runtime, "agent.sock"),
		log:       filepath.Join(runtime, "daemon.log"),
	}

	out, err := os.Create(box.log)
	if err != nil {
		t.Fatalf("open the daemon's log: %v", err)
	}

	// --unlock=none because there is nothing to unlock, and --console=off
	// because there is nobody to ask. Peering is off so the test claims no port.
	box.cmd = exec.Command(daemon, "run", "--unlock=none", "--console=off")
	box.cmd.Env = append(os.Environ(), box.env()...)
	box.cmd.Stdout = out
	box.cmd.Stderr = out

	if err := box.cmd.Start(); err != nil {
		t.Fatalf("start ladulasd: %v", err)
	}

	t.Cleanup(func() {
		_ = box.cmd.Process.Signal(syscall.SIGTERM)
		_ = box.cmd.Wait()
		_ = out.Close()

		if logged, err := os.ReadFile(box.log); err == nil {
			t.Logf("ladulasd said:\n%s", logged)
		}
	})

	waitForSocket(t, box.control)

	return box
}

func (b *emptyDaemon) env() []string {
	return []string{
		"LADULAS_SOCK=" + b.control,
		"LADULAS_AGENT_SOCK=" + b.agent,
		"LADULAS_DATA_DIR=" + b.dataDir,
		"LADULAS_CONFIG_DIR=" + b.configDir,
		"LADULAS_PEER_LISTEN=off",
	}
}

func (b *emptyDaemon) run(
	t *testing.T, cli, stdin string, args ...string,
) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cli, args...)
	cmd.Env = append(os.Environ(), b.env()...)

	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	out, err := cmd.CombinedOutput()

	t.Logf("ladulas %s:\n%s", strings.Join(args, " "), out)

	return string(out), err
}

func (b *emptyDaemon) must(
	t *testing.T, cli, stdin string, args ...string,
) string {
	t.Helper()

	out, err := b.run(t, cli, stdin, args...)
	if err != nil {
		t.Fatalf("ladulas %s: %v\n%s", strings.Join(args, " "), err, out)
	}

	return out
}

// stillRunning is the claim the unit file depends on: the daemon that came up
// with nothing to serve is the same process serving now.
func (b *emptyDaemon) stillRunning(t *testing.T) {
	t.Helper()

	if err := b.cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("the daemon is gone: %v", err)
	}
}
