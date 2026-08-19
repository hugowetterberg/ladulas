package integration_test

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/hugowetterberg/ladulas/internal/testutil"
	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// M5's acceptance, driven the way the repository owner will drive it: over SSH,
// through the real command line, with no display anywhere.
//
// The two claims worth proving end to end are the two the design makes about
// the lock states. A sealed instance really does refuse what §10 says it
// refuses — the agent offers nothing, the peer listener is down, and the
// control surface is Status and Unlock. And a soft-locked instance really does
// keep signing, because a paired approver answers for it; that is the whole
// reason a session lock does not seal.

// ladulas runs the real command line against an instance, the way a person on
// the other end of an SSH connection would.
func ladulas(
	t *testing.T, cli string, inst *peerInstance, stdin string, args ...string,
) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cli, args...)
	cmd.Env = append(os.Environ(),
		"LADULAS_SOCK="+inst.control,
		"LADULAS_DATA_DIR="+inst.app.Config.DataDir,
		"LADULAS_CONFIG_DIR="+inst.app.Config.ConfigDir,
		"LADULAS_AGENT_SOCK="+inst.app.Config.SocketPath)

	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	out, err := cmd.CombinedOutput()

	t.Logf("ladulas %s on %s:\n%s", strings.Join(args, " "), inst.name, out)

	return string(out), err
}

func mustLadulas(
	t *testing.T, cli string, inst *peerInstance, stdin string, args ...string,
) string {
	t.Helper()

	out, err := ladulas(t, cli, inst, stdin, args...)
	if err != nil {
		t.Fatalf("ladulas %s: %v\n%s", strings.Join(args, " "), err, out)
	}

	return out
}

// agentKeys asks the agent socket what it is offering, which is the question
// ssh asks and the one a sealed instance has to answer with nothing.
func agentKeys(t *testing.T, inst *peerInstance) []*sshagent.Key {
	t.Helper()

	conn, err := net.Dial("unix", inst.app.Config.SocketPath)
	if err != nil {
		t.Fatalf("dial the agent socket: %v", err)
	}

	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close the agent connection: %v", err)
		}
	}()

	keys, err := sshagent.NewClient(conn).List()
	if err != nil {
		t.Fatalf("list agent keys: %v", err)
	}

	return keys
}

// TestSealedBoxOverSSH is the headless half of M5: everything below is a
// command somebody could type into a phone.
func TestSealedBoxOverSSH(t *testing.T) {
	cli := buildCLI(t)

	box := startPeerInstance(t, "headless")

	if got := mustLadulas(t, cli, box, "", "status"); !strings.Contains(got, "unlocked") {
		t.Fatalf("a fresh instance did not report itself unlocked:\n%s", got)
	}

	if keys := agentKeys(t, box); len(keys) != 1 {
		t.Fatalf("the unlocked agent offers %d keys", len(keys))
	}

	mustLadulas(t, cli, box, "", "lock", "--seal")

	status := mustLadulas(t, cli, box, "", "status")

	if !strings.Contains(status, "sealed") {
		t.Errorf("status does not say the store is sealed:\n%s", status)
	}

	if !strings.Contains(status, "ladulas unlock") {
		t.Errorf("status does not say how to get back in:\n%s", status)
	}

	// The agent offers nothing at all, which is what stops ssh from hanging on
	// a key that cannot be used.
	if keys := agentKeys(t, box); len(keys) != 0 {
		t.Errorf("a sealed agent offers %d keys", len(keys))
	}

	// The peer listener is down: the identity key that authenticates the
	// channel is inside the store.
	if addresses := box.app.PeerAddresses(); len(addresses) != 0 {
		t.Errorf("a sealed instance is still listening on %v", addresses)
	}

	// And the management surface has shrunk to what needs no store.
	out, err := ladulas(t, cli, box, "", "peers", "list")
	if err == nil {
		t.Errorf("a sealed instance listed its peers:\n%s", out)
	}

	if !strings.Contains(out, "sealed") {
		t.Errorf("the refusal does not say the store is sealed:\n%s", out)
	}

	// Getting back in is one command with the passphrase on standard input,
	// which is what makes this drivable from a phone.
	unlocked := mustLadulas(t, cli, box, testPassphrase+"\n", "unlock", "--stdin")
	if !strings.Contains(unlocked, "unlocked") {
		t.Fatalf("unlock did not report an unlocked store:\n%s", unlocked)
	}

	if keys := agentKeys(t, box); len(keys) != 1 {
		t.Errorf("the agent offers %d keys after unlocking", len(keys))
	}

	if addresses := box.app.PeerAddresses(); len(addresses) != 1 {
		t.Errorf("the peer listener did not come back: %v", addresses)
	}

	if got := mustLadulas(t, cli, box, "", "peers", "list"); got == "" {
		t.Error("peers list said nothing after unlocking")
	}
}

// A wrong passphrase leaves the box exactly where it was, and says so.
func TestSealedBoxRefusesTheWrongPassphrase(t *testing.T) {
	cli := buildCLI(t)

	box := startPeerInstance(t, "headless")

	mustLadulas(t, cli, box, "", "lock", "--seal")

	out, err := ladulas(t, cli, box, "hunter2\n", "unlock", "--stdin")
	if err == nil {
		t.Fatalf("the store opened with the wrong passphrase:\n%s", out)
	}

	if !strings.Contains(out, "sealed") {
		t.Errorf("the failure does not say what state the store is in:\n%s", out)
	}

	if state := box.app.State(); state != ladulasv1.LockState_LOCK_STATE_SEALED {
		t.Errorf("state %v after a failed unlock", state)
	}
}

// TestLockedDesktopStillSignsForItsOwnSSHSession is the point of the soft lock,
// end to end: the screen is locked, the phone answers, and the commit is
// signed with the key that never left the locked machine.
func TestLockedDesktopStillSignsForItsOwnSSHSession(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)
	signer := buildSigner(t)

	desktop := startPeerInstance(t, "desktop")
	phone := startPeerInstance(t, "phone")

	// The phone approves for the desktop. That is the pairing direction §10
	// says has to survive a locked screen.
	pairOverTheCommandLine(t, cli, phone, desktop)

	// Somebody is holding the phone, and takes a moment to answer.
	hand := &handHandler{
		name: "phone",
		answer: &approval.Answer{
			Decision: ladulasv1.Decision_DECISION_APPROVE,
			Reason:   "approved on the phone",
		},
	}
	defer phone.app.RegisterApprover(hand)()

	// And the desktop's own screen would say no instantly, if it were still
	// being asked. It is not: the soft lock takes it out of the set, so the
	// slower remote answer is the only answer there is.
	screen := &refusingScreen{}
	defer desktop.app.RegisterApprover(screen)()

	locked := mustLadulas(t, cli, desktop, "", "lock")
	if !strings.Contains(locked, "locked") {
		t.Fatalf("lock did not report a locked store:\n%s", locked)
	}

	if keys := agentKeys(t, desktop); len(keys) != 1 {
		t.Errorf("a soft lock took the agent's keys away: %d left", len(keys))
	}

	verified, err := signOn(t, desktop, signer, git,
		"raise the timeout on the slow mirror")
	if err != nil {
		t.Fatalf("the locked desktop could not sign: %v\n%s", err, verified)
	}

	if !strings.Contains(verified, "Good \"git\" signature") {
		t.Errorf("git did not verify the signature:\n%s", verified)
	}

	if screen.asked() {
		t.Error("the locked screen was asked to approve")
	}

	if hand.last() == nil {
		t.Error("the phone was never asked")
	}

	// Coming back needs the passphrase, and then the screen is an approver
	// again.
	mustLadulas(t, cli, desktop, testPassphrase+"\n", "unlock", "--stdin")

	if !desktop.app.Engine().HasLocalApprover() {
		t.Error("the desktop's own screen did not come back as an approver")
	}
}

// A locked desktop with nobody reachable does not sign. The lock is a real
// gate, not a hint.
func TestLockedDesktopWithNobodyToAskDoesNotSign(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)
	signer := buildSigner(t)

	desktop := startPeerInstance(t, "desktop")

	screen := &refusingScreen{}
	defer desktop.app.RegisterApprover(screen)()

	mustLadulas(t, cli, desktop, "", "lock")

	out, err := signOn(t, desktop, signer, git, "sneak one past the lock screen")
	if err == nil {
		t.Fatalf("a locked desktop with no approver signed anyway:\n%s", out)
	}

	if screen.asked() {
		t.Error("the locked screen was asked to approve")
	}
}

// refusingScreen is the local prompt of a machine whose screen is locked. It
// answers no, immediately, so that a soft lock that failed to remove it would
// lose the race deliberately rather than by chance.
type refusingScreen struct {
	mu   sync.Mutex
	seen bool
}

var (
	_ approval.Handler     = (*refusingScreen)(nil)
	_ approval.LocalPrompt = (*refusingScreen)(nil)
)

func (s *refusingScreen) ID() string {
	return "locked screen"
}

func (s *refusingScreen) LocalPrompt() {
}

func (s *refusingScreen) Decide(
	_ context.Context, _ *approval.Request,
) (*approval.Answer, error) {
	s.mark()

	return &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_DENY,
		Reason:   "the screen is locked",
	}, nil
}

func (s *refusingScreen) mark() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seen = true
}

func (s *refusingScreen) asked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.seen
}
