package approval

import (
	"fmt"
	"path/filepath"
	"strings"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Who is asking, in the words somebody recognises (decision U).
//
// The program at the socket is the wrong answer to that question and is the only
// one an agent has by default: `ssh` for every login and `ladulas-sign` for every
// commit, whether the person is in an editor or a terminal. What differs is the
// session — an editor that runs its own subprocesses is one, a terminal window is
// another — so the session is what a prompt names and what a timed approval is
// scoped to.
//
// Everything here reads what the requesting machine sent. It is context and not
// authorization, exactly as the process itself is (see pkg/peercred): a
// session is harder to fake than a path, since a process cannot join one it is
// not descended from, but a machine that lies about its own /proc lies about this
// too. What it buys is that a promise made while working in one place is not
// spent somewhere else — which is a bound on accidents and on unrelated
// programs, not a defence against a compromised daemon. Neither is any grant
// (§9, decision P).

// AskerName is the name of whatever the request came from: the session's leader,
// or the process that created the session when there is one — a terminal
// emulator behind its shell, which is the name on the window.
//
// Empty when the requester named no process, which is every request that arrived
// from a peer that runs no local sockets.
func AskerName(proc *ladulasv1.ClientProcess) string {
	if creator := sessionCreator(proc); creator != nil {
		return programName(creator.GetExecutable())
	}

	if leader := sessionLeader(proc); leader != nil {
		return programName(leader.GetExecutable())
	}

	// The caller leads its own session, so it is what asked: a daemon, or a
	// program a terminal ran in place of a shell.
	if proc.GetSessionId() != 0 && proc.GetPid() == proc.GetSessionId() {
		return programName(proc.GetExecutable())
	}

	return ""
}

// GrantSubject is who a promise would be made to, as the button on a prompt
// should word it.
//
// A session that somebody else created is a window of that somebody: one kitty
// window out of the twelve open, and saying so is the difference between the
// promise offered and the promise a person imagines. A session that leads itself
// is the program, and there is nothing to qualify.
func GrantSubject(req *ladulasv1.ApprovalRequest) string {
	proc := req.GetRequester().GetProcess()

	if proc.GetSessionId() == 0 {
		return ""
	}

	if creator := sessionCreator(proc); creator != nil {
		return "this " + programName(creator.GetExecutable()) + " window"
	}

	if leader := sessionLeader(proc); leader != nil {
		return programName(leader.GetExecutable())
	}

	// The caller is its own session, which is what a daemon looks like.
	return programName(proc.GetExecutable())
}

// GrantMachine is the machine a machine-wide promise would be made to, as a
// button should word it: the requester's own name, and something honest when it
// did not send one.
func GrantMachine(req *ladulasv1.ApprovalRequest) string {
	if name := req.GetRequester().GetName(); name != "" {
		return name
	}

	if req.GetRequester().GetLocal() {
		return "this machine"
	}

	return "that machine"
}

// GrantPromise is who a timed approval of this reach is promised to, in the
// words the button offered it in and the words the log keeps afterwards: "this
// kitty window", or "any session on guppy" (decisions U and V).
//
// The wider reach used to read "anywhere on guppy", and that was the wrong
// sentence for what widening does. A machine-wide promise is the request's scope
// with the session taken out of it and nothing else: the key, the kind, the
// repository, the destination host and the user name all stay pinned. So a
// commit promise still covers only the one working directory it was made in,
// and "anywhere" named the part of the scope that does not move — which on a
// git signing prompt is the part an approver most wants to be sure of. What
// actually widens is which session may spend it, and that is what it says now.
func GrantPromise(req *ladulasv1.ApprovalRequest, reach GrantReach) string {
	if reach == GrantReachMachine {
		return "any session on " + GrantMachine(req)
	}

	return GrantSubject(req)
}

// AskerDetail is the line a prompt shows: who is asking, and the session that
// says so.
func AskerDetail(proc *ladulasv1.ClientProcess) string {
	name := AskerName(proc)
	if name == "" {
		return ""
	}

	return fmt.Sprintf("%s (session %d)", name, proc.GetSessionId())
}

// AskerChain is the walk from the calling program up to the session, for the
// prompt: "git ← zsh ← kitty" behind an ssh, or "git ← emacs" behind a commit.
//
// It is what makes the session name checkable rather than a claim: somebody who
// does not recognise "emacs" can read what ran what.
func AskerChain(proc *ladulasv1.ClientProcess) string {
	if len(proc.GetAncestry()) == 0 {
		return ""
	}

	names := make([]string, 0, len(proc.GetAncestry()))

	for _, above := range proc.GetAncestry() {
		name := programName(above.GetExecutable())
		if name == "" {
			name = fmt.Sprintf("pid %d", above.GetPid())
		}

		names = append(names, name)
	}

	return strings.Join(names, " ← ")
}

func sessionLeader(proc *ladulasv1.ClientProcess) *ladulasv1.ProcessAncestor {
	for _, above := range proc.GetAncestry() {
		if above.GetSessionLeader() {
			return above
		}
	}

	return nil
}

func sessionCreator(proc *ladulasv1.ClientProcess) *ladulasv1.ProcessAncestor {
	for _, above := range proc.GetAncestry() {
		if above.GetStartedSession() {
			return above
		}
	}

	return nil
}

// programName is a path as a person would say it. The path is what gets
// compared; this is only ever what gets shown.
func programName(executable string) string {
	if executable == "" {
		return ""
	}

	return filepath.Base(executable)
}
