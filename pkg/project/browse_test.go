package project_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/project"
)

// browsable builds a project to look around in.
func browsable(t *testing.T) string {
	t.Helper()

	root := t.TempDir()

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

	write("README.md", "# The project\n")
	write("main.go", "package main\n")
	write(".env", "SECRET=hunter2\n")
	write("docs/deployment.md", "# Deploying\n")
	write("docs/architecture.md", "# How it fits together\n")
	write("docs/images/diagram.png", "not really a png")
	write(".git/config", "[core]\n")
	write("node_modules/left-pad/README.md", "# left-pad\n")

	return root
}

func TestReadDirListsDirectoriesFirst(t *testing.T) {
	root := browsable(t)

	entries, next, total, err := project.ReadDir(
		root, "", "", "", 0, project.DefaultLimits)
	if err != nil {
		t.Fatalf("read the root: %v", err)
	}

	if next != "" {
		t.Errorf("a short directory offered another page: %q", next)
	}

	var names []string
	for _, entry := range entries {
		names = append(names, entry.GetName())
	}

	// docs before the files, and neither the dotfiles nor the directories a
	// documentation browser has no business walking into.
	want := []string{"docs", "README.md", "main.go"}

	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("the root lists %v, want %v", names, want)
	}

	if total != len(want) {
		t.Errorf("total is %d, want %d", total, len(want))
	}
}

// Listing and serving are different questions: a project full of Go files
// should list Go files, and say that it will not hand one over.
func TestReadDirSaysWhatItWillNotServe(t *testing.T) {
	root := browsable(t)

	entries, _, _, err := project.ReadDir(root, "", "", "", 0, project.DefaultLimits)
	if err != nil {
		t.Fatalf("read the root: %v", err)
	}

	for _, entry := range entries {
		switch entry.GetName() {
		case "README.md":
			if !entry.GetReadable() {
				t.Errorf("markdown is not offered: %s", entry.GetReason())
			}
		case "main.go":
			if entry.GetReadable() {
				t.Error("a Go file is offered for reading")
			}

			if entry.GetReason() == "" {
				t.Error("a file that is not offered does not say why")
			}
		case "docs":
			if !entry.GetDirectory() {
				t.Error("docs is not a directory")
			}
		}
	}
}

// A folder is worth a row when there is something behind it. The publisher is
// the end that can say so — it has the directory on a local disk, and an
// approver asking would be a call per folder down a network (§6, decision R).
func TestReadDirSaysWhichFoldersLeadNowhere(t *testing.T) {
	root := browsable(t)

	entries, _, _, err := project.ReadDir(root, "", "", "", 0, project.DefaultLimits)
	if err != nil {
		t.Fatalf("read the root: %v", err)
	}

	for _, entry := range entries {
		switch entry.GetName() {
		case "docs":
			if entry.GetNothingReadable() {
				t.Error("docs, which holds two markdown files, is reported as " +
					"leading nowhere")
			}
		case "README.md", "main.go":
			if entry.GetNothingReadable() {
				t.Errorf("%s is a file and is answering a question about "+
					"directories", entry.GetName())
			}
		}
	}

	// One level down, where the answer is the other way: a folder of images has
	// nothing this instance would hand over, at any depth.
	entries, _, _, err = project.ReadDir(
		root, "docs", "", "", 0, project.DefaultLimits)
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}

	var seen bool

	for _, entry := range entries {
		if entry.GetName() != "images" {
			continue
		}

		seen = true

		if !entry.GetNothingReadable() {
			t.Error("a folder holding one png is not reported as leading nowhere")
		}
	}

	if !seen {
		t.Fatal("docs/images was not listed at all")
	}
}

func TestReadDirPagesAndFilters(t *testing.T) {
	root := browsable(t)

	first, next, total, err := project.ReadDir(
		root, "docs", "", "", 1, project.DefaultLimits)
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}

	if len(first) != 1 {
		t.Fatalf("a page of one returned %d entries", len(first))
	}

	if next == "" {
		t.Fatal("there is more to read and no way to carry on")
	}

	// images, architecture.md, deployment.md — directories first.
	if total != 3 {
		t.Errorf("docs holds %d entries, want 3", total)
	}

	second, _, _, err := project.ReadDir(
		root, "docs", "", next, 10, project.DefaultLimits)
	if err != nil {
		t.Fatalf("read the second page: %v", err)
	}

	if len(second) != 2 {
		t.Errorf("the rest of docs is %d entries, want 2", len(second))
	}

	if second[0].GetName() == first[0].GetName() {
		t.Error("the second page repeats the first")
	}

	// The filter runs on the publisher, so a directory of ten thousand files
	// costs one page either way. Total still counts what is there.
	filtered, _, total, err := project.ReadDir(
		root, "docs", "deploy", "", 0, project.DefaultLimits)
	if err != nil {
		t.Fatalf("filter docs: %v", err)
	}

	if len(filtered) != 1 || filtered[0].GetName() != "deployment.md" {
		t.Errorf("the filter returned %+v", filtered)
	}

	if total != 3 {
		t.Errorf("total is %d after filtering, want the unfiltered 3", total)
	}
}

// Browsing must not become a way to read arbitrary files off the requester,
// which is §6's rail and the reason every open goes through a root handle.
func TestBrowsingCannotLeaveTheProject(t *testing.T) {
	root := browsable(t)

	outside := filepath.Join(t.TempDir(), "secrets.md")

	if err := os.WriteFile(outside, []byte("# not yours\n"), 0o600); err != nil {
		t.Fatalf("write the outside file: %v", err)
	}

	if err := os.Symlink(outside, filepath.Join(root, "escape.md")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}

	for _, name := range []string{"..", "../..", "/etc", "docs/../.."} {
		if _, _, _, err := project.ReadDir(
			root, name, "", "", 0, project.DefaultLimits,
		); err == nil {
			t.Errorf("listing %q was allowed", name)
		}
	}

	for _, name := range []string{"../secrets.md", "/etc/passwd", "escape.md"} {
		if _, _, err := project.ReadFile(
			root, name, project.DefaultLimits,
		); err == nil {
			t.Errorf("reading %q was allowed", name)
		}
	}

	// The symlink is listed, because pretending it is not there would be
	// lying about the directory — and it says it will not be followed.
	entries, _, _, err := project.ReadDir(root, "", "", "", 0, project.DefaultLimits)
	if err != nil {
		t.Fatalf("read the root: %v", err)
	}

	var found bool

	for _, entry := range entries {
		if entry.GetName() != "escape.md" {
			continue
		}

		found = true

		if entry.GetReadable() {
			t.Error("a symbolic link is offered for reading")
		}
	}

	if !found {
		t.Error("the symbolic link was left out of the listing")
	}
}

func TestSearchMatchesTheWholePath(t *testing.T) {
	root := browsable(t)

	entries, _, truncated, err := project.Search(
		root, "docs/dep", "", 0, project.DefaultLimits)
	if err != nil {
		t.Fatalf("search: %v", err)
	}

	if truncated {
		t.Error("a search of eight files ran out of budget")
	}

	if len(entries) != 1 || entries[0].GetPath() != "docs/deployment.md" {
		t.Fatalf("the search found %+v", entries)
	}

	// Nothing from the directories a documentation browser skips, however well
	// the name matches.
	hits, _, _, err := project.Search(root, "readme", "", 0, project.DefaultLimits)
	if err != nil {
		t.Fatalf("search again: %v", err)
	}

	for _, entry := range hits {
		if strings.Contains(entry.GetPath(), "node_modules") {
			t.Errorf("the search walked into node_modules: %s", entry.GetPath())
		}
	}

	if len(hits) != 1 {
		t.Errorf("searching for readme found %d files, want 1", len(hits))
	}
}

func TestSearchPages(t *testing.T) {
	root := browsable(t)

	first, next, _, err := project.Search(root, ".md", "", 1, project.DefaultLimits)
	if err != nil {
		t.Fatalf("search: %v", err)
	}

	if len(first) != 1 {
		t.Fatalf("a page of one returned %d", len(first))
	}

	if next == "" {
		t.Fatal("there are more matches and no way to carry on")
	}

	second, _, _, err := project.Search(root, ".md", next, 10, project.DefaultLimits)
	if err != nil {
		t.Fatalf("search the second page: %v", err)
	}

	for _, entry := range second {
		if entry.GetPath() == first[0].GetPath() {
			t.Errorf("the second page repeats %s", entry.GetPath())
		}
	}
}

func TestReadFileServesOnlyWhatIsOffered(t *testing.T) {
	root := browsable(t)

	body, entry, err := project.ReadFile(root, "docs/deployment.md", project.DefaultLimits)
	if err != nil {
		t.Fatalf("read the deployment doc: %v", err)
	}

	if !strings.Contains(string(body), "Deploying") {
		t.Errorf("the file came back as %q", body)
	}

	if !entry.GetReadable() {
		t.Error("a file that was served says it is not readable")
	}

	if _, _, err := project.ReadFile(root, "main.go", project.DefaultLimits); err == nil {
		t.Error("a Go file was served")
	}

	if _, _, err := project.ReadFile(root, ".env", project.DefaultLimits); err == nil {
		t.Error("a dotfile was served")
	}
}

// A path that would leave the project fails inside the kernel rather than
// against a check this package makes.
//
// The distinction is not pedantry. Resolving a path, satisfying yourself it is
// inside the root, and then opening it leaves a window: the thing being opened
// can become a symlink between the two, and what opens is not what was checked.
// os.Root is openat2 with RESOLVE_BENEATH on Linux, so there is no window —
// which matters here more than anywhere else in the codebase, because the
// filesystem on the other side belongs to the machine §6 distrusts most.
func TestBrowsingIsConfinedByTheKernel(t *testing.T) {
	root := browsable(t)

	outside := t.TempDir()

	if err := os.WriteFile(
		filepath.Join(outside, "secret.md"), []byte("# no\n"), 0o600,
	); err != nil {
		t.Fatalf("write outside: %v", err)
	}

	// A directory symlink pointing out of the project. Listing through it, and
	// reading through it, both have to fail — and neither depends on this
	// package noticing what it is.
	if err := os.Symlink(outside, filepath.Join(root, "docs/elsewhere")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}

	if _, _, _, err := project.ReadDir(
		root, "docs/elsewhere", "", "", 0, project.DefaultLimits,
	); err == nil {
		t.Error("a directory outside the project was listed through a symlink")
	}

	if _, _, err := project.ReadFile(
		root, "docs/elsewhere/secret.md", project.DefaultLimits,
	); err == nil {
		t.Error("a file outside the project was read through a symlink")
	}

	// And a search does not wander out through it either.
	entries, _, _, err := project.Search(root, "secret", "", 0, project.DefaultLimits)
	if err != nil {
		t.Fatalf("search: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("the search followed a symlink out of the project: %+v", entries)
	}
}
