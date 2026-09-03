package project_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/project"
)

// The project id has to be one path element, which a derived one always is.
const trackedID = "n5rgc3tfmzxxg5dbnrwq"

func versionStore(t *testing.T) (*project.VersionStore, string) {
	t.Helper()

	dir := t.TempDir()

	store, err := project.OpenVersions(dir, reverseCipher{})
	if err != nil {
		t.Fatalf("open the version store: %v", err)
	}

	return store, dir
}

func record(
	t *testing.T, store *project.VersionStore, docPath, head, body string,
) bool {
	t.Helper()

	_, fresh, err := store.Record(
		trackedID, "/srv/build/ladulas", docPath, head, []byte(body))
	if err != nil {
		t.Fatalf("record %s at %s: %v", docPath, head, err)
	}

	return fresh
}

func TestASnapshotIsReadBackAtTheHeadItWasTakenAgainst(t *testing.T) {
	store, _ := versionStore(t)

	record(t, store, "README.md", "abc123", "# One\n")
	record(t, store, "README.md", "abc123", "# Two\n")

	snapshots := store.Snapshots(trackedID, "README.md", "abc123")
	if len(snapshots) != 2 {
		t.Fatalf("got %d snapshots, want 2", len(snapshots))
	}

	// Oldest first, so the newest is last and a reader walks forward from where
	// it was.
	body, err := store.Content(trackedID, snapshots[1].GetDigest())
	if err != nil {
		t.Fatalf("read the newest snapshot: %v", err)
	}

	if string(body) != "# Two\n" {
		t.Errorf("newest snapshot = %q, want %q", body, "# Two\n")
	}
}

// Editors touch files they have not changed, and the debounce upstream will
// happily fire on one of those. A version somebody could be offered as a change
// must not be minted by a save that changed nothing.
func TestASaveThatChangedNothingRecordsNothing(t *testing.T) {
	store, _ := versionStore(t)

	if fresh := record(t, store, "README.md", "abc123", "# One\n"); !fresh {
		t.Error("the first save should be a new version")
	}

	if fresh := record(t, store, "README.md", "abc123", "# One\n"); fresh {
		t.Error("a save with identical contents should not be a new version")
	}

	if got := len(store.Snapshots(trackedID, "README.md", "abc123")); got != 1 {
		t.Errorf("got %d snapshots, want 1", got)
	}
}

// The ghost-version rule, at the store's own level: a snapshot describes a
// working tree relative to a commit, so once HEAD moves it describes a tree
// that no longer exists.
func TestSnapshotsTakenAgainstAnotherHeadAreNotReturned(t *testing.T) {
	store, _ := versionStore(t)

	record(t, store, "README.md", "abc123", "# One\n")

	if got := len(store.Snapshots(trackedID, "README.md", "def456")); got != 0 {
		t.Errorf("got %d snapshots at the new head, want 0", got)
	}

	// And reading does not depend on having swept: the answer is already right
	// before anybody has told the store that HEAD moved.
	if got := len(store.Snapshots(trackedID, "README.md", "abc123")); got != 1 {
		t.Errorf("got %d snapshots at the old head, want 1", got)
	}
}

func TestResetDropsWhatBelongedToTheOldHead(t *testing.T) {
	store, _ := versionStore(t)

	record(t, store, "README.md", "abc123", "# One\n")
	record(t, store, "README.md", "abc123", "# Two\n")
	record(t, store, "docs/ops.md", "abc123", "# Ops\n")

	dropped, err := store.Reset(trackedID, "def456")
	if err != nil {
		t.Fatalf("reset: %v", err)
	}

	if dropped != 3 {
		t.Errorf("dropped %d snapshots, want 3", dropped)
	}

	if got := len(store.Snapshots(trackedID, "README.md", "abc123")); got != 0 {
		t.Errorf("got %d snapshots after the reset, want 0", got)
	}
}

// A branch switch has to be able to clear the history without anybody having
// edited anything, which is why Reset is not folded into Record.
func TestResetOnAProjectThatWasNeverTrackedIsNotAnError(t *testing.T) {
	store, _ := versionStore(t)

	dropped, err := store.Reset(trackedID, "abc123")
	if err != nil {
		t.Fatalf("reset an untracked project: %v", err)
	}

	if dropped != 0 {
		t.Errorf("dropped %d, want 0", dropped)
	}
}

// Recording against a new head cleans up as it goes, so a record never holds
// two heads at once.
func TestRecordingAtANewHeadDropsTheOldSnapshots(t *testing.T) {
	store, _ := versionStore(t)

	record(t, store, "README.md", "abc123", "# One\n")
	record(t, store, "README.md", "def456", "# Two\n")

	if got := len(store.Snapshots(trackedID, "README.md", "abc123")); got != 0 {
		t.Errorf("got %d snapshots at the old head, want 0", got)
	}

	if got := len(store.Snapshots(trackedID, "README.md", "def456")); got != 1 {
		t.Errorf("got %d snapshots at the new head, want 1", got)
	}
}

func TestOneDocumentsHistoryIsCapped(t *testing.T) {
	store, _ := versionStore(t)

	for i := range project.MaxSnapshotsPerDocument + 5 {
		record(t, store, "README.md", "abc123", fmt.Sprintf("# %d\n", i))
	}

	snapshots := store.Snapshots(trackedID, "README.md", "abc123")
	if len(snapshots) != project.MaxSnapshotsPerDocument {
		t.Fatalf("got %d snapshots, want %d",
			len(snapshots), project.MaxSnapshotsPerDocument)
	}

	// The oldest went, not the newest: the useful end is the recent one.
	body, err := store.Content(trackedID, snapshots[len(snapshots)-1].GetDigest())
	if err != nil {
		t.Fatalf("read the newest: %v", err)
	}

	want := fmt.Sprintf("# %d\n", project.MaxSnapshotsPerDocument+4)
	if string(body) != want {
		t.Errorf("newest = %q, want %q", body, want)
	}
}

// A blob nothing points at is a copy of somebody's uncommitted work that
// nothing will ever remove, which is exactly the file you do not want left on a
// disk.
func TestASweptSnapshotLeavesNoBlobBehind(t *testing.T) {
	store, dir := versionStore(t)

	_, _, err := store.Record(
		trackedID, "/srv/build/ladulas", "README.md", "abc123", []byte("# One\n"))
	if err != nil {
		t.Fatalf("record: %v", err)
	}

	blobs := filepath.Join(dir, trackedID, "blobs")

	before, err := os.ReadDir(blobs)
	if err != nil {
		t.Fatalf("read the blob directory: %v", err)
	}

	if len(before) != 1 {
		t.Fatalf("got %d blobs, want 1", len(before))
	}

	if _, err := store.Reset(trackedID, "def456"); err != nil {
		t.Fatalf("reset: %v", err)
	}

	after, err := os.ReadDir(blobs)
	if err != nil {
		t.Fatalf("read the blob directory: %v", err)
	}

	if len(after) != 0 {
		t.Errorf("got %d blobs after the sweep, want 0", len(after))
	}
}

func TestContentOfAVersionThatIsNotHeldSaysSo(t *testing.T) {
	store, _ := versionStore(t)

	record(t, store, "README.md", "abc123", "# One\n")

	_, err := store.Content(trackedID, []byte{0xde, 0xad, 0xbe, 0xef})
	if !errors.Is(err, project.ErrNoSuchSnapshot) {
		t.Errorf("error = %v, want ErrNoSuchSnapshot", err)
	}
}

func TestForgetRemovesEverythingHeldForAProject(t *testing.T) {
	store, dir := versionStore(t)

	record(t, store, "README.md", "abc123", "# One\n")

	if err := store.Forget(trackedID); err != nil {
		t.Fatalf("forget: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, trackedID)); !os.IsNotExist(err) {
		t.Errorf("the project directory is still there: %v", err)
	}

	if got := len(store.Snapshots(trackedID, "README.md", "abc123")); got != 0 {
		t.Errorf("got %d snapshots after forgetting, want 0", got)
	}
}

// A snapshot with no commit to be relative to means nothing, so it is refused
// rather than stored against the empty string.
func TestASnapshotWithNoHeadIsRefused(t *testing.T) {
	store, _ := versionStore(t)

	_, _, err := store.Record(
		trackedID, "/srv/build/ladulas", "README.md", "", []byte("# One\n"))
	if err == nil {
		t.Error("a snapshot with no head should be refused")
	}
}

// The same rail the cache has: a project id is about to become a path element,
// and one that is not a single element is a bug in whatever derived it.
func TestAProjectIdThatIsNotOnePathElementIsRefused(t *testing.T) {
	store, _ := versionStore(t)

	_, _, err := store.Record(
		"../elsewhere", "/srv/build/ladulas", "README.md", "abc123",
		[]byte("# One\n"))
	if !errors.Is(err, project.ErrOutsideRoot) {
		t.Errorf("error = %v, want ErrOutsideRoot", err)
	}
}

// Nothing readable reaches the disk, which is the whole reason the store is
// sealed: what is in a working tree before it is committed is at least as
// private as what has been.
func TestNothingReadableIsWrittenToDisk(t *testing.T) {
	store, dir := versionStore(t)

	record(t, store, "README.md", "abc123", "# The passphrase is hunter2\n")

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		body, err := os.ReadFile(path) //nolint:gosec // a path from our own walk
		if err != nil {
			return err
		}

		if bytes.Contains(body, []byte("hunter2")) {
			t.Errorf("%s holds the plaintext", path)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk the store: %v", err)
	}
}
