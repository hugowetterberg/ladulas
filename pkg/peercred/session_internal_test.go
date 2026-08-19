//go:build linux

package peercred

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The walk this package does on every local request, run against the process
// doing the walking (decision U).
//
// What it proves is the part that has to be right for a prompt to name the right
// thing: the session comes from the kernel rather than from a guess, and the
// chain above the caller is what /proc says it is.
func TestTheSessionAndTheChainAboveIt(t *testing.T) {
	proc := &ladulasv1.ClientProcess{Pid: int32(os.Getpid())}

	describeSession(proc, proc.GetPid())

	session, err := unix.Getsid(os.Getpid())
	if err != nil {
		t.Fatalf("getsid: %v", err)
	}

	if proc.GetSessionId() != int32(session) {
		t.Errorf("session %d, want %d", proc.GetSessionId(), session)
	}

	// A test binary is a child of something, so there is always something above
	// it — but how much is up to whoever ran the suite, and an empty chain is a
	// legitimate answer for a process whose parents have gone.
	for _, above := range proc.GetAncestry() {
		if above.GetPid() <= 0 {
			t.Errorf("an ancestor with pid %d", above.GetPid())
		}

		if above.GetSessionLeader() && above.GetPid() != proc.GetSessionId() {
			t.Errorf("the session leader is pid %d, and the session is %d",
				above.GetPid(), proc.GetSessionId())
		}

		if above.GetSessionLeader() && above.GetStartedSession() {
			t.Error("a process both leads the session and is outside it")
		}
	}

	// The walk stops at the session, so at most one entry past the leader — the
	// process that created it, when there is one.
	var leader, creator int

	for _, above := range proc.GetAncestry() {
		if above.GetSessionLeader() {
			leader++
		}

		if above.GetStartedSession() {
			creator++
		}
	}

	if leader > 1 || creator > 1 {
		t.Errorf("the chain names %d leaders and %d creators", leader, creator)
	}

	if creator == 1 && leader != 1 {
		t.Error("the chain names the creator of a session it never found")
	}
}

// A process that is its own session and has no terminal is a daemon, and the
// walk has nothing above it to name: not the parent that started it, which for
// anything on a desktop is a window manager or an init (decision U).
func TestAProcessThatIsItsOwnSession(t *testing.T) {
	child := exec.Command("sleep", "30")
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := child.Start(); err != nil {
		t.Skipf("could not start a child in its own session: %v", err)
	}

	defer func() {
		if err := child.Process.Kill(); err != nil {
			t.Errorf("kill the child: %v", err)
		}

		_ = child.Wait()
	}()

	pid := int32(child.Process.Pid)

	proc := &ladulasv1.ClientProcess{Pid: pid}

	describeSession(proc, pid)

	if proc.GetSessionId() != pid {
		t.Errorf("session %d, want the child's own pid %d",
			proc.GetSessionId(), pid)
	}

	if len(proc.GetAncestry()) != 0 {
		t.Errorf("the chain names %d processes above a session with no terminal",
			len(proc.GetAncestry()))
	}
}

// readStat has to survive an executable name with spaces and parentheses in it,
// which is why it reads from the last closing parenthesis rather than splitting
// the line.
func TestStatOfAProcessThatIsGone(t *testing.T) {
	if _, ok := readStat(-1); ok {
		t.Error("a process that cannot exist was read")
	}
}
