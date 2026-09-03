package project

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// Reading a published project's repository, for the two questions versions
// depend on (decision AP): what commit the working tree is on, and whether git
// is in the middle of something.
//
// It is go-git rather than `git`, and the reason is the watcher. A filesystem
// event arrives at an arbitrary moment — very often *during* a checkout, since
// a checkout is thousands of writes — and the answer to "what is HEAD" has to
// be read at that moment, cheaply, dozens of times a minute. Forking a process
// per question is the wrong shape for that, and `pkg/gitctx` forks for a
// different job: it collects a signing request's diff once, when somebody has
// asked for a signature, where the cost is invisible and git's own output is
// exactly what is wanted.
//
// So the two coexist deliberately. Nothing here replaces gitctx and gitctx's
// invocations are not moved; what would be worth doing later is an inventory of
// where else in the tree shelling out is buying nothing.
//
// **The tests shell out on purpose.** What is being checked is that reading a
// repository this way agrees with what real git actually does to a directory
// during a rebase or a branch switch, and a test that used go-git to set up the
// state it then read with go-git would be checking that a library agrees with
// itself.

// Repository is a published project's git repository.
type Repository struct {
	root   string
	gitDir string
	repo   *git.Repository
}

// ErrNotARepository is returned for a published directory that is not a git
// checkout. That is allowed — a project can be a directory of documents — and
// it means no version history beyond the snapshots.
var ErrNotARepository = errors.New("project: not a git repository")

// OpenRepository opens the repository a published project lives in.
func OpenRepository(root string) (*Repository, error) {
	repo, err := git.PlainOpen(root)
	if errors.Is(err, git.ErrRepositoryNotExists) {
		return nil, fmt.Errorf("%w: %s", ErrNotARepository, root)
	}

	if err != nil {
		return nil, fmt.Errorf("project: open the repository at %s: %w", root, err)
	}

	dir, err := gitDir(root)
	if err != nil {
		return nil, err
	}

	return &Repository{root: root, gitDir: dir, repo: repo}, nil
}

// Head is the commit the working tree is on.
//
// A repository with no commits yet has no HEAD, and that is not an error: it is
// a project somebody has just started, and it reports the empty string. A
// snapshot cannot be taken against it — VersionStore refuses a snapshot with no
// commit to be relative to — which is the right outcome rather than a special
// case, because there is nothing for a version to be a version *of* yet.
func (r *Repository) Head() (string, error) {
	ref, err := r.repo.Head()

	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return "", nil
	}

	if err != nil {
		return "", fmt.Errorf("project: read HEAD in %s: %w", r.root, err)
	}

	return ref.Hash().String(), nil
}

// Branch is the branch name HEAD is on, or empty when it is detached.
func (r *Repository) Branch() (string, error) {
	ref, err := r.repo.Head()

	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return "", nil
	}

	if err != nil {
		return "", fmt.Errorf("project: read HEAD in %s: %w", r.root, err)
	}

	if !ref.Name().IsBranch() {
		return "", nil
	}

	return ref.Name().Short(), nil
}

// inProgress are the marks git leaves in its own directory while an operation
// is under way, and the words to say about each.
//
// This is the list the watcher waits out. A rebase rewrites the working tree
// dozens of times and a merge conflict leaves it half-written for as long as
// somebody takes to resolve it; a snapshot taken in either is not a state
// anybody edited, and offering one to a reader as a version of their document
// would be a lie about a file nobody ever saved.
//
// It is checked by looking for the files rather than by asking go-git, because
// go-git does not model an interrupted operation — it reads repositories, and
// these are marks left by the porcelain. Missing one means a snapshot too many
// rather than a snapshot lost, which is why the sequencer and the bisect log
// are in a list that could get away with the first four.
var inProgress = []struct {
	name string
	path string
}{
	{"a git command holding the index", "index.lock"},
	{"a rebase", "rebase-merge"},
	{"a rebase", "rebase-apply"},
	{"a merge", "MERGE_HEAD"},
	{"a cherry-pick", "CHERRY_PICK_HEAD"},
	{"a revert", "REVERT_HEAD"},
	{"a bisect", "BISECT_LOG"},
	{"a sequence of commits being replayed", "sequencer"},
}

// Busy reports whether git is in the middle of something, and what.
//
// The name is for the log rather than for a decision: every answer is the same
// answer, which is to wait. It is there because a watcher that silently records
// nothing for twenty seconds is indistinguishable from a watcher that has
// stopped working, and this is the line that tells them apart.
func (r *Repository) Busy() (string, bool) {
	for _, mark := range inProgress {
		if _, err := os.Lstat(filepath.Join(r.gitDir, mark.path)); err == nil {
			return mark.name, true
		}
	}

	return "", false
}

// How far back a version list walks. They are the browse caps' shape: a
// default for a caller that does not care, and a maximum whatever it asks for.
const (
	// DefaultCommitLimit is what a caller that names no limit gets. Far enough
	// back to cover "when did this paragraph appear", not far enough to walk a
	// long-lived repository while somebody waits.
	DefaultCommitLimit = 50
	// MaxCommitLimit is the most any caller gets.
	MaxCommitLimit = 200
)

// Commit is one commit that touched a document.
type Commit struct {
	Hash    string
	Subject string
	Author  string
	When    time.Time
}

// CommitsTouching is the commits that changed a path, newest first.
//
// This is the permanent half of a document's history and the half that costs
// nothing to keep, because git is already keeping it. The snapshots in the
// version store are the other half, and they exist only because git has no
// record of what a file looked like between two commits.
func (r *Repository) CommitsTouching(
	rel string, limit int,
) ([]Commit, error) {
	if err := CheckPath(rel); err != nil {
		return nil, err
	}

	head, err := r.Head()
	if err != nil {
		return nil, err
	}

	if head == "" {
		return nil, nil
	}

	iter, err := r.repo.Log(&git.LogOptions{FileName: &rel})
	if err != nil {
		return nil, fmt.Errorf("project: read the history of %s: %w", rel, err)
	}

	defer iter.Close()

	var out []Commit

	err = iter.ForEach(func(commit *object.Commit) error {
		out = append(out, Commit{
			Hash:    commit.Hash.String(),
			Subject: subjectOf(commit.Message),
			Author:  commit.Author.Name,
			When:    commit.Author.When,
		})

		if limit > 0 && len(out) >= limit {
			return errEnough
		}

		return nil
	})

	if err != nil && !errors.Is(err, errEnough) {
		return nil, fmt.Errorf("project: walk the history of %s: %w", rel, err)
	}

	return out, nil
}

// errEnough ends a log walk early. go-git's ForEach treats any error as a
// reason to stop, so the sentinel is how a limit is expressed. It never leaves
// this file.
var errEnough = errors.New("project: enough")

// ContentAt is a document as it stood at one commit.
//
// A path that did not exist at that commit is reported as ErrNoSuchFile rather
// than as a failure: a document added last week has commits behind it that do
// not contain it, and a reader walking back through them should be told the
// file was not there yet.
func (r *Repository) ContentAt(commit, rel string) ([]byte, error) {
	if err := CheckPath(rel); err != nil {
		return nil, err
	}

	found, err := r.repo.CommitObject(plumbing.NewHash(commit))
	if err != nil {
		return nil, fmt.Errorf("project: read commit %s: %w", commit, err)
	}

	file, err := found.File(rel)
	if errors.Is(err, object.ErrFileNotFound) {
		return nil, fmt.Errorf("%w: %s at %s", ErrNoSuchFile, rel, commit)
	}

	if err != nil {
		return nil, fmt.Errorf("project: read %s at %s: %w", rel, commit, err)
	}

	reader, err := file.Reader()
	if err != nil {
		return nil, fmt.Errorf("project: open %s at %s: %w", rel, commit, err)
	}

	defer func() {
		_ = reader.Close()
	}()

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("project: read %s at %s: %w", rel, commit, err)
	}

	return body, nil
}

// gitDir resolves where a repository keeps its own files.
//
// It is usually <root>/.git, and in a worktree or a submodule it is a file
// holding "gitdir: <path>" instead. The marks Busy looks for are in the real
// one, so a watcher on a linked worktree that guessed would wait out no rebase
// at all.
func gitDir(root string) (string, error) {
	candidate := filepath.Join(root, ".git")

	info, err := os.Lstat(candidate)
	if err != nil {
		return "", fmt.Errorf("project: find the git directory of %s: %w", root, err)
	}

	if info.IsDir() {
		return candidate, nil
	}

	body, err := os.ReadFile(candidate) //nolint:gosec // the .git of a published project
	if err != nil {
		return "", fmt.Errorf("project: read %s: %w", candidate, err)
	}

	pointer := strings.TrimSpace(string(body))

	target, ok := strings.CutPrefix(pointer, "gitdir:")
	if !ok {
		return "", fmt.Errorf("project: %s does not name a git directory", candidate)
	}

	target = strings.TrimSpace(target)

	if !filepath.IsAbs(target) {
		target = filepath.Join(root, target)
	}

	return filepath.Clean(target), nil
}

// subjectOf is a commit message's first line, which is what a version list
// shows beside a hash.
func subjectOf(message string) string {
	subject, _, _ := strings.Cut(strings.TrimSpace(message), "\n")

	return subject
}
