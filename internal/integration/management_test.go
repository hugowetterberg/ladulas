package integration_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The rest of the management surface against a running daemon (§14).
//
// Grants and the keyring verbs were the last two that opened the store
// themselves, and they had exactly the defect the key verbs were fixed for: on
// a box whose daemon was running and unlocked they asked for a passphrase there
// was no terminal to type. Everything here is driven through the real command
// line, and the assertion that matters as much as the output is the one about
// what never appears in it — a passphrase prompt.

// noTerminal is what the CLI says when it tries to ask for a passphrase with no
// tty. Seeing it in the output of a management command means the command took a
// path it is not allowed to take any more.
const noTerminal = "no terminal to ask on"

func TestGrantVerbsGoThroughTheRunningDaemon(t *testing.T) {
	cli := buildCLI(t)

	box := startPeerInstance(t, "headless")

	empty := mustLadulas(t, cli, box, "", "grants", "list")
	if !strings.Contains(empty, "No live grants") {
		t.Fatalf("grants list did not report an empty set:\n%s", empty)
	}

	if strings.Contains(empty, noTerminal) {
		t.Fatalf("grants list asked for a passphrase:\n%s", empty)
	}

	// A grant put into the store the way the engine puts one there, so that the
	// listing has something to find.
	grant := &ladulasv1.Grant{
		GrantId:     "grant-under-test",
		Description: "github.com for an hour",
		ExpiresAt:   timestamppb.New(time.Now().Add(time.Hour)),
	}

	if err := box.app.Vault().AddGrant(grant); err != nil {
		t.Fatalf("add a grant: %v", err)
	}

	listed := mustLadulas(t, cli, box, "", "grants", "list")
	if !strings.Contains(listed, "grant-under-test") {
		t.Fatalf("grants list did not show the grant:\n%s", listed)
	}

	if !strings.Contains(listed, "github.com for an hour") {
		t.Errorf("grants list did not show the scope:\n%s", listed)
	}

	// A typo is refused rather than reported as a revocation, because the store
	// forgets a grant it never had without complaining.
	if out, err := ladulas(t, cli, box, "", "grants", "revoke", "no-such-grant"); err == nil {
		t.Errorf("revoking a grant that does not exist succeeded:\n%s", out)
	}

	revoked := mustLadulas(t, cli, box, "", "grants", "revoke", "grant-under-test")
	if !strings.Contains(revoked, "grant-under-test") {
		t.Errorf("grants revoke said nothing about the grant:\n%s", revoked)
	}

	// The daemon that revoked it is the daemon the engine consults, so it is
	// gone for the next request rather than for the next restart.
	live, err := box.app.Vault().Grants()
	if err != nil {
		t.Fatalf("read the grants back: %v", err)
	}

	if len(live) != 0 {
		t.Errorf("the running instance still holds %d grants", len(live))
	}
}

func TestKeyringVerbsGoThroughTheRunningDaemon(t *testing.T) {
	cli := buildCLI(t)

	// A keychain the test owns, since enrolling is now something the daemon
	// does rather than something a second process does to a file.
	box := startInstanceWithKeyring(t, "desktop", &keystore.MemoryKeyring{})

	before := mustLadulas(t, cli, box, "", "keyring", "status")
	if !strings.Contains(before, "Unlock at login  no") {
		t.Fatalf("keyring status did not report an unenrolled instance:\n%s", before)
	}

	if strings.Contains(before, noTerminal) {
		t.Fatalf("keyring status asked for a passphrase:\n%s", before)
	}

	enrolled := mustLadulas(t, cli, box, "", "keyring", "enrol")
	if !strings.Contains(enrolled, "unlock at login") {
		t.Errorf("keyring enrol said nothing:\n%s", enrolled)
	}

	// The daemon holds the key that was copied, so its own store is the one
	// that changed — no second opener, and no restart.
	if !box.app.Vault().KeyringEnrolled() {
		t.Error("the running instance does not think it is enrolled")
	}

	after := mustLadulas(t, cli, box, "", "keyring", "status")
	if !strings.Contains(after, "Unlock at login  yes") {
		t.Errorf("keyring status did not report the enrolment:\n%s", after)
	}

	mustLadulas(t, cli, box, "", "keyring", "forget")

	if box.app.Vault().KeyringEnrolled() {
		t.Error("the instance is still enrolled after forgetting")
	}
}

// A sealed daemon refuses the grant and keyring verbs and says why, rather than
// sending the CLI off to open the store behind its back.
func TestGrantAndKeyringVerbsRefuseASealedDaemon(t *testing.T) {
	cli := buildCLI(t)

	box := startPeerInstance(t, "headless")

	mustLadulas(t, cli, box, "", "lock", "--seal")

	for _, args := range [][]string{
		{"grants", "list"},
		{"grants", "revoke", "whatever"},
		{"keyring", "status"},
		{"keyring", "enrol"},
		{"keyring", "forget"},
	} {
		out, err := ladulas(t, cli, box, "", args...)
		if err == nil {
			t.Errorf("a sealed instance answered `%s`:\n%s",
				strings.Join(args, " "), out)

			continue
		}

		if !strings.Contains(out, "sealed") {
			t.Errorf("`%s` does not say the store is sealed:\n%s",
				strings.Join(args, " "), out)
		}

		if strings.Contains(out, noTerminal) {
			t.Errorf("`%s` asked for a passphrase behind a sealed daemon:\n%s",
				strings.Join(args, " "), out)
		}
	}
}

// With nothing listening, every verb that touches the store says so and says
// what to do about it. None of them asks for a passphrase: there is no store
// open to check one against, and asking would be how a second writer got to the
// file in the first place (§14).
func TestNoDaemonMeansAdviceRatherThanAPrompt(t *testing.T) {
	cli := buildCLI(t)

	dead := newDeadSockets(t)

	for _, args := range [][]string{
		{"keys", "list"},
		{"keys", "generate", "deploy"},
		{"keys", "public"},
		{"keys", "remove", "deploy"},
		{"keys", "disable", "deploy"},
		{"peers", "list"},
		{"peers", "allow", "somebody", "--approve"},
		{"peers", "rename", "somebody", "else"},
		{"peers", "revoke", "somebody"},
		{"grants", "list"},
		{"grants", "revoke", "whatever"},
		{"keyring", "status"},
		{"keyring", "enrol"},
		{"keyring", "forget"},
		{"lock"},
		{"unlock"},
		{"init"},
		{"projects", "list"},
	} {
		out, err := dead.run(t, cli, args...)
		if err == nil {
			t.Errorf("`%s` succeeded with nothing running:\n%s",
				strings.Join(args, " "), out)

			continue
		}

		if !strings.Contains(out, "No Ladulås instance is listening") {
			t.Errorf("`%s` does not say that nothing is listening:\n%s",
				strings.Join(args, " "), out)
		}

		if !strings.Contains(out, "ladulasd run") {
			t.Errorf("`%s` does not say how to start one:\n%s",
				strings.Join(args, " "), out)
		}

		if strings.Contains(out, noTerminal) {
			t.Errorf("`%s` tried to ask for a passphrase:\n%s",
				strings.Join(args, " "), out)
		}
	}
}

// `ladulas status` is the exception, and deliberately: it is the command
// somebody runs to find out why nothing works, so with nothing listening it
// still says where the files are and that nothing is running.
func TestStatusWithNoDaemonReportsRatherThanFails(t *testing.T) {
	cli := buildCLI(t)

	dead := newDeadSockets(t)

	out, err := dead.run(t, cli, "status")
	if err != nil {
		t.Fatalf("status failed with nothing running: %v\n%s", err, out)
	}

	for _, want := range []string{"Running       no", "store.age", "ladulasd run"} {
		if !strings.Contains(out, want) {
			t.Errorf("status does not mention %q:\n%s", want, out)
		}
	}

	if strings.Contains(out, noTerminal) {
		t.Errorf("status asked for a passphrase:\n%s", out)
	}
}

// `ladulas` with no arguments prints the usage and starts nothing (decision Y,
// §14).
//
// It used to start the desktop application, or the terminal agent in a build
// with no GUI in it — so typing the binary's name to see what it does started an
// SSH agent, and which one it started depended on a build tag.
func TestABareInvocationPrintsTheUsage(t *testing.T) {
	cli := buildCLI(t)

	dead := newDeadSockets(t)

	out, err := dead.run(t, cli)
	if err != nil {
		t.Fatalf("a bare invocation failed: %v\n%s", err, out)
	}

	if !strings.Contains(out, "COMMANDS:") {
		t.Errorf("a bare invocation printed no usage:\n%s", out)
	}

	// The agent socket is the evidence that nothing ran: starting either the
	// desktop application or the agent is precisely what would have created it.
	if _, err := os.Stat(dead.agent); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("something bound the agent socket: %v", err)
	}
}

// A verb nobody has heard of is refused, and is refused without starting
// anything (§14).
//
// `ladulasd` with no arguments runs the daemon, and urfave/cli sends everything
// it could not match there too — so `ladulasd pairings list`, before that verb
// existed, would start one and then die saying an agent was already listening
// on the socket. The agent had nothing to do with it. `ladulas` had the same
// default and put a webkit startup banner in front of the same error, on a
// machine that may have had no display for the window.
func TestAnUnknownVerbIsRefusedRatherThanRun(t *testing.T) {
	cli := buildCLI(t)

	dead := newDeadSockets(t)

	out, err := dead.run(t, cli, "pairungs", "list")
	if err == nil {
		t.Fatalf("a verb that does not exist was accepted:\n%s", out)
	}

	if !strings.Contains(out, `there is no ladulas command "pairungs"`) {
		t.Errorf("the refusal did not name what was not a command:\n%s", out)
	}

	if !strings.Contains(out, "COMMANDS:") {
		t.Errorf("the refusal printed no usage:\n%s", out)
	}

	// Nothing was started, and the agent socket is the evidence: running the
	// default command is precisely what would have created it.
	if _, err := os.Stat(dead.agent); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("something bound the agent socket: %v", err)
	}
}

// deadSockets is a set of directories with a store in none of them and nothing
// listening on the socket, which is the machine every command above is run on.
type deadSockets struct {
	dataDir   string
	configDir string
	control   string
	agent     string
}

func newDeadSockets(t *testing.T) deadSockets {
	t.Helper()

	runtime := shortDir(t)

	return deadSockets{
		dataDir:   t.TempDir(),
		configDir: t.TempDir(),
		control:   filepath.Join(runtime, "control.sock"),
		agent:     filepath.Join(runtime, "agent.sock"),
	}
}

func (d deadSockets) run(
	t *testing.T, cli string, args ...string,
) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cli, args...)
	cmd.Env = append(os.Environ(),
		"LADULAS_SOCK="+d.control,
		"LADULAS_DATA_DIR="+d.dataDir,
		"LADULAS_CONFIG_DIR="+d.configDir,
		"LADULAS_AGENT_SOCK="+d.agent)

	out, err := cmd.CombinedOutput()

	t.Logf("ladulas %s with nothing running:\n%s", strings.Join(args, " "), out)

	return string(out), err
}
