//go:build linux

// Package peercred reads the credentials of the process on the other end of a
// unix socket.
//
// It is the local equivalent of the identity a remote peer proves with its key:
// it says which program is asking, for the prompt and for policy rules. It is
// never an authorization — anything running as the same user can arrange to
// look like anything else — but "which binary is asking for this signature" is
// most of what makes a local prompt readable.
package peercred

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// maxCommandLine caps how much of a process command line is kept. It ends up in
// prompts and in the audit log, and neither wants a megabyte of arguments.
const maxCommandLine = 512

// Process reads SO_PEERCRED off a unix socket connection and fills in what /proc
// knows about the process on the other end.
//
// This is the local equivalent of the identity a remote peer proves with its
// key: it says which program is asking. It is context for the prompt and for
// policy rules, not an authorization — anything running as the same user can
// arrange to look like anything else.
func Process(conn net.Conn) (*ladulasv1.ClientProcess, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("not a unix socket connection")
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("get raw connection: %w", err)
	}

	var (
		ucred    *unix.Ucred
		credsErr error
	)

	err = raw.Control(func(fd uintptr) {
		ucred, credsErr = unix.GetsockoptUcred(
			int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return nil, fmt.Errorf("control socket: %w", err)
	}

	if credsErr != nil {
		return nil, fmt.Errorf("read peer credentials: %w", credsErr)
	}

	proc := &ladulasv1.ClientProcess{
		Pid: ucred.Pid,
		Uid: ucred.Uid,
		Gid: ucred.Gid,
	}

	if u, err := user.LookupId(strconv.FormatUint(uint64(ucred.Uid), 10)); err == nil {
		proc.UserName = u.Username
	}

	proc.Executable = processExecutable(ucred.Pid)
	proc.CommandLine = processCommandLine(ucred.Pid)

	describeSession(proc, ucred.Pid)

	return proc, nil
}

// maxAncestry bounds the walk up the process tree. Nothing legible is more than
// a handful of steps from its session, and a tree this deep is a tree with
// something wrong with it.
const maxAncestry = 8

// describeSession fills in the session and the walk up to it (decision U).
//
// The session is the answer to "who is asking", and the ancestry is what makes
// the answer readable: the program at the socket is a helper — ssh, or
// ladulas-sign — and the interesting name is two or three steps above it.
//
// The walk stops at the session, deliberately, rather than at init. Walking to
// the top of the tree looks like it would name the application and does not: on
// a desktop it ends at the window manager or at whatever launched the terminal,
// which is the same answer for everything and tells nobody anything.
//
// Everything here is best effort. A process that exits while its ancestry is
// being read leaves a shorter chain, and a shorter chain costs a word in a
// prompt.
func describeSession(proc *ladulasv1.ClientProcess, pid int32) {
	stat, ok := readStat(pid)
	if !ok {
		return
	}

	proc.SessionId = stat.session

	// The caller may be the session itself: a daemon that set one up, or a
	// program a terminal ran in place of a shell. There is nothing between it and
	// its session, so the only thing left to look for is whatever created it.
	if pid == stat.session {
		describeCreator(proc, stat)

		return
	}

	// Otherwise the caller is already described, so the walk starts at its parent
	// and the chain holds what is above it.
	for at := stat.parent; at > 1 && len(proc.Ancestry) < maxAncestry; {
		above, ok := readStat(at)
		if !ok {
			return
		}

		leader := at == stat.session

		proc.Ancestry = append(proc.Ancestry, &ladulasv1.ProcessAncestor{
			Pid:           at,
			Executable:    processExecutable(at),
			CommandLine:   processCommandLine(at),
			SessionLeader: leader,
		})

		if !leader {
			at = above.parent

			continue
		}

		describeCreator(proc, above)

		return
	}
}

// describeCreator adds the process that opened a terminal session, and adds
// nothing for a session that has no terminal.
//
// That condition is the whole difference between naming the right thing and
// naming the window manager. A session with a controlling terminal is a window:
// its leader is the shell inside, and the name somebody recognises is the
// emulator that opened it — kitty, or tmux, or sshd. A session without one was
// made by a program that wanted its own, an editor or a daemon, and that program
// is the answer; its parent is i3 or an init, which is the same answer for
// everything on the desktop and names nothing.
func describeCreator(proc *ladulasv1.ClientProcess, leader procStat) {
	if leader.tty == 0 || leader.parent <= 1 {
		return
	}

	parent, ok := readStat(leader.parent)
	if !ok || parent.session == leader.session {
		return
	}

	proc.Ancestry = append(proc.Ancestry, &ladulasv1.ProcessAncestor{
		Pid:            leader.parent,
		Executable:     processExecutable(leader.parent),
		CommandLine:    processCommandLine(leader.parent),
		StartedSession: true,
	})
}

// procStat is the fields of /proc/<pid>/stat this package has any use for.
type procStat struct {
	parent  int32
	session int32
	// tty is the controlling terminal, zero when there is none. It says whether
	// a session is a terminal window or a program that made its own session.
	tty int32
}

// readStat parses /proc/<pid>/stat.
//
// The second field is the executable name in parentheses and may contain both
// spaces and parentheses, so the fields after it are found from the *last*
// closing parenthesis rather than by splitting the line. Everything after that
// is space separated: state, ppid, pgrp, session, tty_nr.
func readStat(pid int32) (procStat, bool) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procStat{}, false
	}

	end := strings.LastIndex(string(raw), ")")
	if end < 0 {
		return procStat{}, false
	}

	fields := strings.Fields(string(raw)[end+1:])
	if len(fields) < 5 {
		return procStat{}, false
	}

	parent, err := strconv.ParseInt(fields[1], 10, 32)
	if err != nil {
		return procStat{}, false
	}

	session, err := strconv.ParseInt(fields[3], 10, 32)
	if err != nil {
		return procStat{}, false
	}

	// A terminal this process cannot be described by is the same as none, which
	// is why an unreadable field is not a failure.
	tty, _ := strconv.ParseInt(fields[4], 10, 32)

	return procStat{
		parent:  int32(parent),
		session: int32(session),
		tty:     int32(tty),
	}, true
}

func processExecutable(pid int32) string {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}

	return path
}

func processCommandLine(pid int32) string {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}

	// /proc/*/cmdline separates arguments with NUL and ends with one.
	args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")

	line := strings.Join(args, " ")
	if len(line) > maxCommandLine {
		line = line[:maxCommandLine] + "…"
	}

	return line
}
