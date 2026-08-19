package command

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// preventMemoryInspection marks the process undumpable (M6). PR_SET_DUMPABLE 0
// does two things at once on Linux: the kernel writes no core dump for this
// process, so a crash while unlocked cannot spill the DEK and the portable keys
// to disk where they would outlive the seal; and it makes the process
// un-ptrace-able and its /proc/<pid>/mem unreadable even by another process of
// the same uid, which is the honest limit §16 describes made a little harder to
// reach. It does not stop a debugger attached before this ran, and it is not a
// substitute for sealing — it bounds the blast radius of a crash and of casual
// same-uid inspection.
func preventMemoryInspection() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_DUMPABLE: %w", err)
	}

	return nil
}
