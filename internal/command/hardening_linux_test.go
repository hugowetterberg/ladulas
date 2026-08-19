//go:build linux

package command

import (
	"testing"

	"golang.org/x/sys/unix"
)

// preventMemoryInspection marks the process undumpable, which is what keeps a
// crash from core-dumping the keys and a same-uid process from ptracing them out
// (M6). This sets the flag on the test process itself; it is the last assertion
// in the package for that reason, and undumpable is harmless for a test binary.
func TestPreventMemoryInspectionSetsUndumpable(t *testing.T) {
	before, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("read dumpable: %v", err)
	}

	if before != 1 {
		t.Skipf("the process is already undumpable (%d)", before)
	}

	if err := preventMemoryInspection(); err != nil {
		t.Fatalf("preventMemoryInspection: %v", err)
	}

	after, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("read dumpable: %v", err)
	}

	if after != 0 {
		t.Errorf("dumpable is %d after preventMemoryInspection, want 0", after)
	}
}
