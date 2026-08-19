package project_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hugowetterberg/ladulas/internal/testutil"
	"github.com/hugowetterberg/ladulas/pkg/project"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()

	path := filepath.Join(dir, filepath.FromSlash(name))

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(path), err)
	}

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// TestTheProjectIDIsDerived: both ends work the identifier out from the same
// two facts, which is what lets a signing request name a project without
// carrying one (§6).
func TestTheProjectIDIsDerived(t *testing.T) {
	first := project.ID("git@github.com:example/ladulas.git", "/srv/build/ladulas")
	again := project.ID("git@github.com:example/ladulas.git", "/srv/build/ladulas")

	if first != again {
		t.Error("the same project derived two identifiers")
	}

	if first == project.ID("git@github.com:example/other.git", "/srv/build/ladulas") {
		t.Error("two remotes derived the same identifier")
	}

	if first == project.ID("git@github.com:example/ladulas.git", "/home/hugo/ladulas") {
		t.Error("two paths derived the same identifier")
	}

	if strings.ContainsAny(first, "/=+") {
		t.Errorf("the identifier %q is not safe in a path or a URL", first)
	}
}

// TestCheckPathRefusesToLeaveTheProject is the cheap half of §6's rail, applied
// where a distrusted machine's path comes in.
func TestCheckPathRefusesToLeaveTheProject(t *testing.T) {
	if err := project.CheckPath("docs/design.md"); err != nil {
		t.Errorf("an ordinary path was refused: %v", err)
	}

	for _, name := range []string{
		"../secrets.md",
		"docs/../../secrets.md",
		"/etc/passwd",
		"./docs/design.md",
		"",
		".",
	} {
		if err := project.CheckPath(name); !errors.Is(err, project.ErrOutsideRoot) {
			t.Errorf("%q was accepted as a path inside the project", name)
		}
	}
}

// TestDescribeRecordsTheCommit: publishing reads a project's identity and none
// of its contents (decision Q), and the commit is what a later signing request
// is labelled against (§6).
func TestDescribeRecordsTheCommit(t *testing.T) {
	git := testutil.RequireTool(t, "git")

	dir := t.TempDir()
	write(t, dir, "README.md", "# a real repository\n")

	testutil.Run(t, dir, git, "init", "-q", "-b", "main", ".")
	testutil.Run(t, dir, git, "remote", "add", "origin",
		"git@github.com:example/ladulas.git")
	testutil.Run(t, dir, git, "add", ".")
	testutil.Run(t, dir, git, "commit", "-q", "-m", "first")

	publication, err := project.Describe(context.Background(), dir, "")
	if err != nil {
		t.Fatalf("describe: %v", err)
	}

	if publication.GetOriginUrl() != "git@github.com:example/ladulas.git" {
		t.Errorf("the origin came back as %q", publication.GetOriginUrl())
	}

	if publication.GetBranch() != "main" {
		t.Errorf("the branch came back as %q", publication.GetBranch())
	}

	if len(publication.GetCommit()) != 40 && len(publication.GetCommit()) != 64 {
		t.Errorf("the commit came back as %q", publication.GetCommit())
	}

	if publication.GetProjectId() != project.ID(
		publication.GetOriginUrl(), publication.GetPath()) {
		t.Error("the identifier is not the derived one")
	}
}

// TestDescribeNeedsNoRepository: a directory of notes is a perfectly good thing
// to publish. It simply has no commit to be stale against.
func TestDescribeNeedsNoRepository(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "README.md", "# notes\n")

	publication, err := project.Describe(context.Background(), dir, "notes")
	if err != nil {
		t.Fatalf("describe: %v", err)
	}

	if publication.GetName() != "notes" {
		t.Errorf("the project is called %q", publication.GetName())
	}

	if publication.GetCommit() != "" {
		t.Errorf("a directory with no repository is at %q",
			publication.GetCommit())
	}
}
