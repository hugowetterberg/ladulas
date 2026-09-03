package project_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/project"
)

// These tests shell out to git on purpose. What is under test is whether
// reading a repository with go-git agrees with what real git does to a
// directory — during a rebase, across a branch switch, with a merge half
// resolved — and a test that built those states with go-git would only be
// checking that a library agrees with itself.

func git(t *testing.T, root string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
		// A repository that signs is a repository whose commits need an
		// approval, which is not what any of this is testing.
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}

	return strings.TrimSpace(string(out))
}

// repository is a project with a little history in it.
func repository(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	root := t.TempDir()

	git(t, root, "init", "--initial-branch=main")
	git(t, root, "config", "commit.gpgsign", "false")

	write := func(name, body string) {
		t.Helper()

		full := filepath.Join(root, name)

		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("make %s: %v", name, err)
		}

		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	write("README.md", "# One\n")
	git(t, root, "add", "README.md")
	git(t, root, "commit", "-m", "the first commit")

	write("README.md", "# Two\n")
	write("docs/ops.md", "# Ops\n")
	git(t, root, "add", ".")
	git(t, root, "commit", "-m", "the second commit")

	return root
}

func openRepo(t *testing.T, root string) *project.Repository {
	t.Helper()

	repo, err := project.OpenRepository(root)
	if err != nil {
		t.Fatalf("open the repository: %v", err)
	}

	return repo
}

func TestHeadIsWhatGitSaysItIs(t *testing.T) {
	root := repository(t)
	repo := openRepo(t, root)

	head, err := repo.Head()
	if err != nil {
		t.Fatalf("head: %v", err)
	}

	if want := git(t, root, "rev-parse", "HEAD"); head != want {
		t.Errorf("head = %s, want %s", head, want)
	}
}

// The case the whole lifecycle rule turns on: a branch switch moves HEAD, and
// the watcher has to see that it moved.
func TestHeadFollowsABranchSwitch(t *testing.T) {
	root := repository(t)
	repo := openRepo(t, root)

	before, err := repo.Head()
	if err != nil {
		t.Fatalf("head: %v", err)
	}

	git(t, root, "checkout", "-b", "other", "HEAD~1")

	after, err := repo.Head()
	if err != nil {
		t.Fatalf("head after the switch: %v", err)
	}

	if after == before {
		t.Error("head did not move across a branch switch")
	}

	if want := git(t, root, "rev-parse", "HEAD"); after != want {
		t.Errorf("head = %s, want %s", after, want)
	}
}

func TestBranchIsEmptyWhenHeadIsDetached(t *testing.T) {
	root := repository(t)
	repo := openRepo(t, root)

	branch, err := repo.Branch()
	if err != nil {
		t.Fatalf("branch: %v", err)
	}

	if branch != "main" {
		t.Errorf("branch = %q, want main", branch)
	}

	git(t, root, "checkout", "--detach", "HEAD")

	branch, err = repo.Branch()
	if err != nil {
		t.Fatalf("branch when detached: %v", err)
	}

	if branch != "" {
		t.Errorf("branch = %q, want empty when detached", branch)
	}
}

// A project somebody has just started has no HEAD, and that is not a failure —
// there is nothing for a version to be a version of yet.
func TestARepositoryWithNoCommitsHasNoHead(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	root := t.TempDir()
	git(t, root, "init", "--initial-branch=main")

	repo := openRepo(t, root)

	head, err := repo.Head()
	if err != nil {
		t.Fatalf("head of an empty repository: %v", err)
	}

	if head != "" {
		t.Errorf("head = %q, want empty", head)
	}
}

func TestADirectoryThatIsNotARepositorySaysSo(t *testing.T) {
	_, err := project.OpenRepository(t.TempDir())
	if !errors.Is(err, project.ErrNotARepository) {
		t.Errorf("error = %v, want ErrNotARepository", err)
	}
}

func TestNothingIsInProgressInAQuietRepository(t *testing.T) {
	repo := openRepo(t, repository(t))

	if name, busy := repo.Busy(); busy {
		t.Errorf("a quiet repository reported %q in progress", name)
	}
}

// The ghost-version case that matters most. A conflicted merge leaves the
// working tree half-written for as long as somebody takes to resolve it, and a
// snapshot taken in that window is a state nobody ever saved.
func TestAConflictedMergeIsReportedAsBusy(t *testing.T) {
	root := repository(t)
	repo := openRepo(t, root)

	git(t, root, "checkout", "-b", "other", "HEAD~1")

	if err := os.WriteFile(
		filepath.Join(root, "README.md"), []byte("# Other\n"), 0o600,
	); err != nil {
		t.Fatalf("write on the branch: %v", err)
	}

	git(t, root, "commit", "-am", "a conflicting change")

	// Expected to fail: that is the conflict.
	merge := exec.Command("git", "merge", "main")
	merge.Dir = root
	merge.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	)

	if out, err := merge.CombinedOutput(); err == nil {
		t.Fatalf("the merge was meant to conflict:\n%s", out)
	}

	name, busy := repo.Busy()
	if !busy {
		t.Fatal("a conflicted merge should be reported as busy")
	}

	if name != "a merge" {
		t.Errorf("busy with %q, want %q", name, "a merge")
	}
}

// An interactive rebase stopped at a conflict is the other long window.
func TestAStoppedRebaseIsReportedAsBusy(t *testing.T) {
	root := repository(t)
	repo := openRepo(t, root)

	git(t, root, "checkout", "-b", "other", "HEAD~1")

	if err := os.WriteFile(
		filepath.Join(root, "README.md"), []byte("# Other\n"), 0o600,
	); err != nil {
		t.Fatalf("write on the branch: %v", err)
	}

	git(t, root, "commit", "-am", "a conflicting change")

	rebase := exec.Command("git", "rebase", "main")
	rebase.Dir = root
	rebase.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	)

	if out, err := rebase.CombinedOutput(); err == nil {
		t.Fatalf("the rebase was meant to stop at a conflict:\n%s", out)
	}

	name, busy := repo.Busy()
	if !busy {
		t.Fatal("a stopped rebase should be reported as busy")
	}

	if name != "a rebase" {
		t.Errorf("busy with %q, want %q", name, "a rebase")
	}

	// And it stops being busy once the operation is over, or the watcher would
	// wait for ever.
	git(t, root, "rebase", "--abort")

	if name, busy := repo.Busy(); busy {
		t.Errorf("still busy with %q after the abort", name)
	}
}

func TestCommitsTouchingListsOnlyTheCommitsThatDid(t *testing.T) {
	root := repository(t)
	repo := openRepo(t, root)

	readme, err := repo.CommitsTouching("README.md", 0)
	if err != nil {
		t.Fatalf("history of README.md: %v", err)
	}

	if len(readme) != 2 {
		t.Errorf("README.md was touched by %d commits, want 2", len(readme))
	}

	ops, err := repo.CommitsTouching("docs/ops.md", 0)
	if err != nil {
		t.Fatalf("history of docs/ops.md: %v", err)
	}

	if len(ops) != 1 {
		t.Fatalf("docs/ops.md was touched by %d commits, want 1", len(ops))
	}

	if ops[0].Subject != "the second commit" {
		t.Errorf("subject = %q, want %q", ops[0].Subject, "the second commit")
	}

	if ops[0].Author != "Test" {
		t.Errorf("author = %q, want Test", ops[0].Author)
	}
}

func TestCommitsTouchingHonoursTheLimit(t *testing.T) {
	repo := openRepo(t, repository(t))

	commits, err := repo.CommitsTouching("README.md", 1)
	if err != nil {
		t.Fatalf("history: %v", err)
	}

	if len(commits) != 1 {
		t.Errorf("got %d commits, want 1", len(commits))
	}
}

func TestContentAtIsTheDocumentAsItStood(t *testing.T) {
	root := repository(t)
	repo := openRepo(t, root)

	commits, err := repo.CommitsTouching("README.md", 0)
	if err != nil {
		t.Fatalf("history: %v", err)
	}

	// Newest first, so the older of the two is last.
	body, err := repo.ContentAt(commits[len(commits)-1].Hash, "README.md")
	if err != nil {
		t.Fatalf("content at the first commit: %v", err)
	}

	if string(body) != "# One\n" {
		t.Errorf("content = %q, want %q", body, "# One\n")
	}
}

// A document added last week has commits behind it that do not contain it, and
// a reader walking back through them should be told it was not there yet.
func TestContentAtACommitWithoutTheFileSaysSo(t *testing.T) {
	root := repository(t)
	repo := openRepo(t, root)

	first := git(t, root, "rev-parse", "HEAD~1")

	_, err := repo.ContentAt(first, "docs/ops.md")
	if !errors.Is(err, project.ErrNoSuchFile) {
		t.Errorf("error = %v, want ErrNoSuchFile", err)
	}
}

func TestAPathThatLeavesTheProjectIsRefused(t *testing.T) {
	repo := openRepo(t, repository(t))

	if _, err := repo.CommitsTouching("../elsewhere.md", 0); !errors.Is(
		err, project.ErrOutsideRoot,
	) {
		t.Errorf("history error = %v, want ErrOutsideRoot", err)
	}

	if _, err := repo.ContentAt("HEAD", "../elsewhere.md"); !errors.Is(
		err, project.ErrOutsideRoot,
	) {
		t.Errorf("content error = %v, want ErrOutsideRoot", err)
	}
}
