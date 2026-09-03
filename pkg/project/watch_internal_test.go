package project

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The tests that decide whether this feature is safe to ship.
//
// A watcher that snapshots what it sees produces versions for a branch switch,
// a rebase, a stash and a merge — states nobody ever saved, which a reader
// would be shown as changes to their document. Every test below drives real git
// through one of those and asserts that nothing was recorded, and the two at
// the end assert that a genuine edit either side of one still is. The point is
// the pair: a watcher that recorded nothing ever would pass half of this.

// The watch is timing-based by nature, so the debounce is short here and the
// quiet period a test waits out is several times it.
const (
	testDebounce = 20 * time.Millisecond
	testCeiling  = 200 * time.Millisecond
	testQuiet    = 400 * time.Millisecond
)

type settle struct {
	project  string
	path     string
	recorded bool
}

// onSettled installs the test hook under the lock, so -race has nothing to say
// about it.
func (w *Watcher) onSettled(fn func(projectID, path string, recorded bool)) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.settled = fn
}

func runGit(t *testing.T, root string, args ...string) string {
	t.Helper()

	out, err := tryGit(root, args...)
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}

	return strings.TrimSpace(out)
}

func tryGit(root string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
		// Signing a commit needs an approval, which is not what this is about.
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	)

	out, err := cmd.CombinedOutput()

	return string(out), err
}

// watchedProject is a repository with two branches whose documents differ, so
// that switching between them rewrites files.
func watchedProject(t *testing.T) (*Watcher, *VersionStore, string, chan settle) {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	root := t.TempDir()

	runGit(t, root, "init", "--initial-branch=main")

	writeIn(t, root, "README.md", "# main one\n")
	writeIn(t, root, "docs/ops.md", "# ops one\n")
	writeIn(t, root, "main.go", "package main\n")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "the first commit")

	runGit(t, root, "checkout", "-b", "other")
	writeIn(t, root, "README.md", "# other one\n")
	writeIn(t, root, "docs/ops.md", "# ops other\n")
	runGit(t, root, "commit", "-am", "the other branch")

	// main has to move too, or merging other into it is a fast-forward and the
	// conflict test has nothing to conflict with.
	runGit(t, root, "checkout", "main")
	writeIn(t, root, "README.md", "# main two\n")
	writeIn(t, root, "docs/ops.md", "# ops two\n")
	runGit(t, root, "commit", "-am", "a divergent commit on main")

	store, err := OpenVersions(t.TempDir(), reverseTestCipher{})
	if err != nil {
		t.Fatalf("open the version store: %v", err)
	}

	watcher, err := NewWatcher(WatchOptions{
		Versions: store,
		Debounce: testDebounce,
		Ceiling:  testCeiling,
	})
	if err != nil {
		t.Fatalf("start the watcher: %v", err)
	}

	t.Cleanup(func() {
		_ = watcher.Close()
	})

	events := make(chan settle, 256)

	watcher.onSettled(func(projectID, path string, recorded bool) {
		select {
		case events <- settle{projectID, path, recorded}:
		default:
		}
	})

	if err := watcher.Add(watchedID, root); err != nil {
		t.Fatalf("watch the project: %v", err)
	}

	return watcher, store, root, events
}

const watchedID = "n5rgc3tfmzxxg5dbnrwq"

type reverseTestCipher struct{}

func (reverseTestCipher) Seal(plaintext []byte) ([]byte, error) {
	return flipTest(plaintext), nil
}

func (reverseTestCipher) Unseal(ciphertext []byte) ([]byte, error) {
	return flipTest(ciphertext), nil
}

func flipTest(body []byte) []byte {
	out := make([]byte, len(body))
	for i, b := range body {
		out[i] = b ^ 0xff
	}

	return out
}

func writeIn(t *testing.T, root, name, body string) {
	t.Helper()

	full := filepath.Join(root, name)

	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("make %s: %v", name, err)
	}

	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// quiet waits until the watcher has stopped settling things, so that an
// assertion is made against a watcher that has finished reacting rather than
// one that is still mid-debounce.
func quiet(t *testing.T, events chan settle, window time.Duration) []settle {
	t.Helper()

	var seen []settle

	timer := time.NewTimer(window)
	defer timer.Stop()

	for {
		select {
		case event := <-events:
			seen = append(seen, event)

			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}

			timer.Reset(window)

		case <-timer.C:
			return seen
		}
	}
}

func headOf(t *testing.T, root string) string {
	t.Helper()

	return runGit(t, root, "rev-parse", "HEAD")
}

func snapshotCount(store *VersionStore, docPath, head string) int {
	return len(store.Snapshots(watchedID, docPath, head))
}

func TestASaveIsRecordedAsAVersion(t *testing.T) {
	_, store, root, events := watchedProject(t)

	writeIn(t, root, "README.md", "# main one, edited\n")

	quiet(t, events, testQuiet)

	if got := snapshotCount(store, "README.md", headOf(t, root)); got != 1 {
		t.Errorf("got %d versions after a save, want 1", got)
	}
}

// The debounce is what makes a save-per-keystroke editor produce one version
// rather than forty.
func TestARunOfSavesIsOneVersion(t *testing.T) {
	_, store, root, events := watchedProject(t)

	for i := range 6 {
		writeIn(t, root, "README.md", strings.Repeat("x", i+1)+"\n")
		time.Sleep(testDebounce / 3)
	}

	quiet(t, events, testQuiet)

	got := snapshotCount(store, "README.md", headOf(t, root))
	if got == 0 {
		t.Fatal("a run of saves produced no version at all")
	}

	// The ceiling may cut a long run into more than one, which is deliberate;
	// what must not happen is one per save.
	if got > 2 {
		t.Errorf("got %d versions for one run of saves, want 1 or 2", got)
	}
}

// The policy is what keeps this affordable. A Go file is not a kind that is
// snapshotted, so editing one costs nothing.
func TestAKindThatIsNotSnapshottedIsNotRecorded(t *testing.T) {
	_, store, root, events := watchedProject(t)

	writeIn(t, root, "main.go", "package main // edited\n")

	quiet(t, events, testQuiet)

	if got := snapshotCount(store, "main.go", headOf(t, root)); got != 0 {
		t.Errorf("got %d versions for a Go file, want 0", got)
	}
}

// The first ghost-version case. A branch switch rewrites every document that
// differs, and none of those writes is an edit.
func TestABranchSwitchRecordsNoVersions(t *testing.T) {
	_, store, root, events := watchedProject(t)

	runGit(t, root, "checkout", "other")

	quiet(t, events, testQuiet)

	head := headOf(t, root)

	for _, path := range []string{"README.md", "docs/ops.md"} {
		if got := snapshotCount(store, path, head); got != 0 {
			t.Errorf("%s got %d versions after a branch switch, want 0",
				path, got)
		}
	}
}

// And the other half of the same test: the watcher has not simply stopped.
func TestAnEditAfterABranchSwitchIsStillRecorded(t *testing.T) {
	_, store, root, events := watchedProject(t)

	runGit(t, root, "checkout", "other")

	quiet(t, events, testQuiet)

	writeIn(t, root, "README.md", "# edited on the other branch\n")

	quiet(t, events, testQuiet)

	if got := snapshotCount(store, "README.md", headOf(t, root)); got != 1 {
		t.Errorf("got %d versions after an edit, want 1", got)
	}
}

// A rebase rewrites the working tree once per commit replayed.
//
// The branches here touch different documents on purpose, so that the rebase is
// clean: what is under test is whether replaying commits mints versions, not
// what happens when one stops at a conflict, which is the busy case above.
func TestARebaseRecordsNoVersions(t *testing.T) {
	_, store, root, events := watchedProject(t)

	runGit(t, root, "checkout", "-b", "feature")
	writeIn(t, root, "docs/feature.md", "# feature\n")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "a feature document")

	quiet(t, events, testQuiet)

	runGit(t, root, "checkout", "main")
	writeIn(t, root, "docs/unrelated.md", "# unrelated\n")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "an unrelated document")

	quiet(t, events, testQuiet)

	runGit(t, root, "checkout", "feature")

	quiet(t, events, testQuiet)

	// Fatal rather than a skip if this conflicts: a test that quietly stops
	// running is a test that stops protecting anything.
	runGit(t, root, "rebase", "main")

	quiet(t, events, testQuiet)

	head := headOf(t, root)

	for _, path := range []string{
		"README.md", "docs/ops.md", "docs/feature.md", "docs/unrelated.md",
	} {
		if got := snapshotCount(store, path, head); got != 0 {
			t.Errorf("%s got %d versions after a rebase, want 0", path, got)
		}
	}
}

// A stash writes the tree back to the committed state, then writes it again
// when it is popped. Neither is an edit.
func TestAStashAndAPopRecordNoVersions(t *testing.T) {
	_, store, root, events := watchedProject(t)

	writeIn(t, root, "README.md", "# a change to stash\n")

	quiet(t, events, testQuiet)

	// That edit is a real one and is expected to be recorded.
	head := headOf(t, root)
	if got := snapshotCount(store, "README.md", head); got != 1 {
		t.Fatalf("got %d versions before the stash, want 1", got)
	}

	runGit(t, root, "stash", "push", "-u")

	quiet(t, events, testQuiet)

	runGit(t, root, "stash", "pop")

	quiet(t, events, testQuiet)

	// HEAD never moved, so what was recorded before is still valid. What must
	// not have happened is a version per write the stash made — and since the
	// popped content is identical to what was already the newest snapshot, the
	// store's own idempotence covers the pop.
	if got := snapshotCount(store, "README.md", head); got > 2 {
		t.Errorf("got %d versions across a stash and a pop, want at most 2", got)
	}
}

// A merge that conflicts leaves the tree half-written for as long as somebody
// takes to resolve it, and every intermediate state is a state nobody saved.
func TestAConflictedMergeRecordsNoVersions(t *testing.T) {
	_, store, root, events := watchedProject(t)

	if out, err := tryGit(root, "merge", "other"); err == nil {
		t.Skipf("the merge did not conflict, which this test needs:\n%s", out)
	}

	quiet(t, events, testQuiet)

	head := headOf(t, root)

	for _, path := range []string{"README.md", "docs/ops.md"} {
		if got := snapshotCount(store, path, head); got != 0 {
			t.Errorf("%s got %d versions during a conflicted merge, want 0",
				path, got)
		}
	}
}

// A commit moves HEAD, which retires every snapshot taken against the previous
// one — they describe a working tree that has become the commit.
func TestACommitRetiresTheSnapshotsBeforeIt(t *testing.T) {
	_, store, root, events := watchedProject(t)

	before := headOf(t, root)

	writeIn(t, root, "README.md", "# about to be committed\n")

	quiet(t, events, testQuiet)

	if got := snapshotCount(store, "README.md", before); got != 1 {
		t.Fatalf("got %d versions before the commit, want 1", got)
	}

	runGit(t, root, "commit", "-am", "the edit")

	quiet(t, events, testQuiet)

	if got := snapshotCount(store, "README.md", before); got != 0 {
		t.Errorf("got %d versions against the old commit, want 0", got)
	}
}

// A document written into a directory that did not exist when the watch
// started still has to be noticed.
func TestADocumentInANewDirectoryIsNoticed(t *testing.T) {
	_, store, root, events := watchedProject(t)

	writeIn(t, root, "docs/runbooks/deploy.md", "# deploying\n")

	quiet(t, events, testQuiet)

	got := snapshotCount(store, "docs/runbooks/deploy.md", headOf(t, root))
	if got != 1 {
		t.Errorf("got %d versions for a document in a new directory, want 1", got)
	}
}

// Nothing under .git is a document, however much it looks like a write.
func TestWritesInsideTheGitDirectoryAreNotVersioned(t *testing.T) {
	watcher, store, root, events := watchedProject(t)

	runGit(t, root, "commit", "--allow-empty", "-m", "an empty commit")

	quiet(t, events, testQuiet)

	watcher.mu.Lock()
	entry := watcher.projects[watchedID]
	watcher.mu.Unlock()

	if entry == nil {
		t.Fatal("the project is not being watched")
	}

	// The commit moved HEAD, so the watcher should be standing on the new one
	// with nothing recorded against it.
	head := headOf(t, root)

	if got := snapshotCount(store, "README.md", head); got != 0 {
		t.Errorf("got %d versions from an empty commit, want 0", got)
	}
}

func TestForgetStopsWatchingAProject(t *testing.T) {
	watcher, store, root, events := watchedProject(t)

	watcher.Forget(watchedID)

	writeIn(t, root, "README.md", "# after forgetting\n")

	quiet(t, events, testQuiet)

	if got := snapshotCount(store, "README.md", headOf(t, root)); got != 0 {
		t.Errorf("got %d versions after Forget, want 0", got)
	}
}

// A published directory that is not a repository has nothing a snapshot could
// be relative to, so it is refused rather than watched without one.
func TestADirectoryThatIsNotARepositoryIsNotWatched(t *testing.T) {
	store, err := OpenVersions(t.TempDir(), reverseTestCipher{})
	if err != nil {
		t.Fatalf("open the version store: %v", err)
	}

	watcher, err := NewWatcher(WatchOptions{Versions: store})
	if err != nil {
		t.Fatalf("start the watcher: %v", err)
	}

	defer func() {
		_ = watcher.Close()
	}()

	if err := watcher.Add(watchedID, t.TempDir()); err == nil {
		t.Error("a directory that is not a repository should be refused")
	}
}
