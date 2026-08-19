package gitctx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Options configure context collection on the requesting machine.
type Options struct {
	// Dir is where git runs. Empty means the process working directory, which
	// is where git puts a signing program: inside the repository.
	Dir string
	// Git is the git executable. Empty means "git" on the PATH.
	Git string
	// Operation is what the caller was doing, "commit" or "tag". Display only.
	Operation string
	// Limits caps the diff. The zero value means DefaultLimits.
	Limits Limits
	// SkipDiff leaves the diff out entirely, for a repository where running
	// git diff on every commit costs more than the context is worth.
	SkipDiff bool
	// Paths narrows the diff to particular files, which is what an approver
	// asking to see one file of a capped diff wants (§5, M4).
	Paths []string
	// Env replaces the environment git runs with. Empty means inheriting.
	Env []string
}

// projectIDEncoding keeps a derived project identifier short and safe to put in
// a file name and a URL.
var projectIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// ProjectID is the identifier a project answers to, derived rather than
// assigned (§6).
//
// It lives here because both the thing that publishes a project and the thing
// that signs a commit in one have to arrive at the same string, and what they
// have in common is a repository. The origin URL comes first because it is what
// survives the directory being moved; a project with no remote is identified by
// its path alone, and is therefore a different project on every machine, which
// is the honest answer.
func ProjectID(originURL, path string) string {
	sum := sha256.Sum256([]byte(
		"ladulas-project-v1\x00" + originURL + "\x00" + path))

	return strings.ToLower(projectIDEncoding.EncodeToString(sum[:10]))
}

// Repository is where a working directory says it lives: the same
// requester-asserted facts a signing request carries, wanted on their own by
// project publishing (§6).
type Repository struct {
	// Path is the repository's top level, which is the project rather than
	// whichever directory the command was run in.
	Path      string
	OriginURL string
	Branch    string
	// Head is the commit HEAD points at, and is what a publication records so
	// that a later signing request can be labelled stale against it.
	Head string
}

// InspectRepository asks git where it is. Everything it cannot answer comes
// back empty: a directory that is not a repository is still a project somebody
// may want to publish, it simply has no commit to be measured against.
func InspectRepository(ctx context.Context, opts Options) Repository {
	runner := &gitRunner{
		exe: gitExecutable(opts.Git),
		dir: opts.Dir,
		env: opts.Env,
	}

	return Repository{
		Path:      runner.line(ctx, "rev-parse", "--show-toplevel"),
		OriginURL: runner.line(ctx, "config", "--get", "remote.origin.url"),
		Branch:    runner.branch(ctx),
		Head:      runner.line(ctx, "rev-parse", "HEAD"),
	}
}

// Collect gathers the context that goes with a signing request.
//
// Everything it returns except the raw object is requester-asserted: it is what
// the machine running git says about itself, and a compromised machine can say
// whatever it likes. The approving side labels it accordingly and derives the
// commit message and author from the object instead (§5). Collection failures
// are therefore never fatal — a signature request should not fail because
// `git config` did — and turn into missing fields or a note on the diff.
func Collect(ctx context.Context, payload []byte, opts Options) *ladulasv1.GitContext {
	git := &ladulasv1.GitContext{
		Object:    append([]byte(nil), payload...),
		Operation: opts.Operation,
	}

	runner := &gitRunner{
		exe: gitExecutable(opts.Git),
		dir: opts.Dir,
		env: opts.Env,
	}

	git.RepositoryPath = runner.line(ctx, "rev-parse", "--show-toplevel")
	git.OriginUrl = runner.line(ctx, "config", "--get", "remote.origin.url")
	git.Branch = runner.branch(ctx)

	// The project identifier is derived from the same two facts on both sides,
	// so naming it here costs nothing and lets an approver find the
	// documentation this change belongs to (§6).
	if git.GetRepositoryPath() != "" {
		git.ProjectId = ProjectID(git.GetOriginUrl(), git.GetRepositoryPath())
	}

	object, err := ParseObject(payload)
	if err != nil {
		// Not being able to parse the object is not this side's problem to
		// report — the approver parses it again and refuses on its own terms —
		// but it does mean there is nothing to diff against.
		return git
	}

	if opts.SkipDiff {
		return git
	}

	git.Diff = runner.diff(ctx, object, opts.Limits, opts.Paths)

	return git
}

// FullLimits are what the deferred fetch-back uses.
//
// The caps on a request are a display decision — a diff travels to a phone with
// something somebody is waiting on — and not a limit on what an approver may
// see. Asking for the rest is a deliberate act on a screen somebody is already
// looking at, so it gets far more room, and still a bound: this is a peer
// telling us how much to read.
var FullLimits = Limits{
	Bytes:        8 << 20,
	Files:        2000,
	LinesPerFile: 100000,
	TotalLines:   400000,
	LineLength:   4000,
}

// CollectDiff re-derives a commit's diff, for an approver that asked to see
// what the caps left out (§5).
//
// It runs on the requesting machine, where the repository is, and it works from
// the signed object rather than from anything the asking side sent: the range
// is the commit's own first parent and its own tree, so a peer cannot use the
// request as a way to ask for a diff of something else.
func CollectDiff(ctx context.Context, payload []byte, opts Options) *ladulasv1.GitDiff {
	object, err := ParseObject(payload)
	if err != nil {
		return &ladulasv1.GitDiff{
			Error: "the object does not parse: " + err.Error(),
		}
	}

	runner := &gitRunner{
		exe: gitExecutable(opts.Git),
		dir: opts.Dir,
		env: opts.Env,
	}

	limits := opts.Limits
	if limits == (Limits{}) {
		limits = FullLimits
	}

	return runner.diff(ctx, object, limits, opts.Paths)
}

func gitExecutable(configured string) string {
	if configured != "" {
		return configured
	}

	return "git"
}

type gitRunner struct {
	exe string
	dir string
	env []string
}

func (r *gitRunner) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.exe, args...) //nolint:gosec // the arguments are ours
	cmd.Dir = r.dir
	cmd.Env = r.env

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}

	return out, nil
}

// line runs a git command that produces one line, and returns an empty string
// rather than an error when it does not work.
func (r *gitRunner) line(ctx context.Context, args ...string) string {
	out, err := r.run(ctx, args...)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}

// branch is the current branch, or a description of the detached head the
// commit is being made on.
func (r *gitRunner) branch(ctx context.Context) string {
	if branch := r.line(ctx, "symbolic-ref", "--short", "HEAD"); branch != "" {
		return branch
	}

	if head := r.line(ctx, "rev-parse", "--short", "HEAD"); head != "" {
		return "detached at " + head
	}

	return ""
}

// emptyTree is what a root commit is diffed against. It is asked of git rather
// than hardcoded because a SHA-256 repository has a different one.
func (r *gitRunner) emptyTree(ctx context.Context) string {
	return r.line(ctx, "hash-object", "-t", "tree", "/dev/null")
}

// diffRange works out what to diff for an object.
//
// For a commit it is the first parent against the tree the commit records —
// both of which exist by the time git asks for a signature, since the tree is
// written before the commit object is built. For a tag it is the tagged commit
// against its own first parent, which is the change the tag is being put on.
func (r *gitRunner) diffRange(
	ctx context.Context, object *ladulasv1.GitObject,
) (string, string, error) {
	switch object.GetType() {
	case TypeCommit:
		if parents := object.GetParents(); len(parents) > 0 {
			return parents[0], object.GetTree(), nil
		}

		empty := r.emptyTree(ctx)
		if empty == "" {
			return "", "", errors.New("could not resolve the empty tree")
		}

		return empty, object.GetTree(), nil
	case TypeTag:
		target := object.GetTaggedObject()

		if object.GetTaggedType() != TypeCommit {
			return "", "", fmt.Errorf(
				"a tag on a %s has no diff", object.GetTaggedType())
		}

		parent := r.line(ctx, "rev-parse", "--verify", "--quiet", target+"^")
		if parent == "" {
			empty := r.emptyTree(ctx)
			if empty == "" {
				return "", "", errors.New("could not resolve the empty tree")
			}

			return empty, target, nil
		}

		return parent, target, nil
	default:
		return "", "", fmt.Errorf("no diff for a %q object", object.GetType())
	}
}

func (r *gitRunner) diff(
	ctx context.Context, object *ladulasv1.GitObject, limits Limits, paths []string,
) *ladulasv1.GitDiff {
	from, to, err := r.diffRange(ctx, object)
	if err != nil {
		return &ladulasv1.GitDiff{Error: err.Error()}
	}

	limits = limits.withDefaults()

	// Two passes: the patch for what changed, and numstat for how much. The
	// counts have to survive the patch being capped (§5).
	patch, err := r.run(ctx, diffArgs(from, to, paths, "--patch")...)
	if err != nil {
		return &ladulasv1.GitDiff{
			Range: shortRange(from, to),
			Error: "the diff could not be collected",
		}
	}

	capped := false

	if len(patch) > limits.Bytes {
		patch = patch[:limits.Bytes]
		capped = true
	}

	diff := ParseDiff(patch, limits)
	diff.Range = shortRange(from, to)

	if capped {
		diff.Truncated = true
		diff.TruncationNote = strings.TrimPrefix(
			diff.GetTruncationNote()+"; the diff was cut off at "+
				byteSize(limits.Bytes), "; ")
	}

	if numstat, err := r.run(ctx, diffArgs(from, to, paths, "--numstat", "-z")...); err == nil {
		applyNumstat(diff, numstat)
	}

	return diff
}

func diffArgs(from, to string, paths []string, extra ...string) []string {
	// The diff is pinned rather than taken as configured: colour, prefixes and
	// pagers would all corrupt the parse, an external diff driver or a textconv
	// filter would run a program and show something other than what is being
	// committed, and quoted paths would reach the approver as escapes instead
	// of file names.
	args := []string{
		"--no-pager",
		"-c", "core.quotePath=false",
		"diff",
		"--no-color",
		"--no-ext-diff",
		"--no-textconv",
		"--find-renames",
		"--src-prefix=a/",
		"--dst-prefix=b/",
	}

	args = append(args, extra...)
	args = append(args, from, to, "--")

	// The paths are the ones a manifest named, and git is told they are paths
	// rather than revisions by the separator above.
	return append(args, paths...)
}

func shortRange(from, to string) string {
	return short(from) + ".." + short(to)
}

func short(rev string) string {
	const shown = 10

	if len(rev) > shown {
		return rev[:shown]
	}

	return rev
}

func byteSize(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n>>10)
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}
