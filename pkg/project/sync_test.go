package project_test

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/project"
)

func collect(
	t *testing.T, root string, have map[string][]byte, serving project.Serving,
) ([]project.SyncChange, project.SyncResult) {
	t.Helper()

	var changes []project.SyncChange

	result, err := project.Reconcile(root, have, serving,
		func(change project.SyncChange) error {
			changes = append(changes, change)

			return nil
		})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	return changes, result
}

func digestOf(body string) []byte {
	sum := sha256.Sum256([]byte(body))

	return sum[:]
}

func paths(changes []project.SyncChange) []string {
	out := make([]string, 0, len(changes))

	for _, change := range changes {
		out = append(out, change.Path)
	}

	return out
}

// A first sync is answered with every document of a pushed kind, and with
// nothing else in the project.
func TestAFirstSyncSendsEveryPushedDocument(t *testing.T) {
	root := browsable(t)

	changes, result := collect(t, root, nil, project.DefaultServing)

	want := map[string]bool{
		"README.md":            true,
		"docs/deployment.md":   true,
		"docs/architecture.md": true,
	}

	if len(changes) != len(want) {
		t.Fatalf("got %d changes (%v), want %d", len(changes), paths(changes),
			len(want))
	}

	for _, change := range changes {
		if !want[change.Path] {
			t.Errorf("%s should not have been sent", change.Path)
		}

		if change.Removed {
			t.Errorf("%s was reported removed on a first sync", change.Path)
		}

		if len(change.Content) == 0 {
			t.Errorf("%s was sent with no contents", change.Path)
		}

		if !change.Entry.GetReadable() {
			t.Errorf("%s was sent marked unreadable", change.Path)
		}
	}

	if result.Truncated {
		t.Error("a small project should not truncate")
	}
}

// The reason pushing is affordable: a doc set nobody has touched costs one
// manifest and no content at all.
func TestASyncOfWhatIsAlreadyHeldSendsNothing(t *testing.T) {
	root := browsable(t)

	have := map[string][]byte{
		"README.md":            digestOf("# The project\n"),
		"docs/deployment.md":   digestOf("# Deploying\n"),
		"docs/architecture.md": digestOf("# How it fits together\n"),
	}

	changes, _ := collect(t, root, have, project.DefaultServing)

	if len(changes) != 0 {
		t.Errorf("got %d changes (%v), want none", len(changes), paths(changes))
	}
}

func TestADocumentWithDifferentBytesIsSentAgain(t *testing.T) {
	root := browsable(t)

	have := map[string][]byte{
		"README.md":            digestOf("# something else entirely\n"),
		"docs/deployment.md":   digestOf("# Deploying\n"),
		"docs/architecture.md": digestOf("# How it fits together\n"),
	}

	changes, _ := collect(t, root, have, project.DefaultServing)

	if len(changes) != 1 || changes[0].Path != "README.md" {
		t.Fatalf("got %v, want one change to README.md", paths(changes))
	}

	if string(changes[0].Content) != "# The project\n" {
		t.Errorf("content = %q, want the current README", changes[0].Content)
	}
}

func TestADocumentTheApproverHoldsAndThePublisherLostIsRemoved(t *testing.T) {
	root := browsable(t)

	have := map[string][]byte{
		"README.md":            digestOf("# The project\n"),
		"docs/deployment.md":   digestOf("# Deploying\n"),
		"docs/architecture.md": digestOf("# How it fits together\n"),
		"docs/gone.md":         digestOf("# was here once\n"),
	}

	changes, _ := collect(t, root, have, project.DefaultServing)

	if len(changes) != 1 {
		t.Fatalf("got %v, want one change", paths(changes))
	}

	if !changes[0].Removed || changes[0].Path != "docs/gone.md" {
		t.Errorf("got %+v, want docs/gone.md removed", changes[0])
	}

	if changes[0].Content != nil || changes[0].Entry != nil {
		t.Error("a removal should carry neither contents nor an entry")
	}
}

// The one that would do real damage if it were wrong. An approver's cache also
// holds pages it pulled because somebody opened them (decision Q), and a
// reconciliation that removed everything the publisher does not push would
// delete those.
func TestAPulledPageOfAnUnpushedKindIsNeverRemoved(t *testing.T) {
	root := browsable(t)

	// A Go file the approver could only have because somebody opened it under a
	// policy that served it, and a kind that is served but pulled.
	serving := project.Serving{
		Limits: project.DefaultLimits,
		Policy: project.Policy{Kinds: []project.Kind{
			{
				Name:       "markdown",
				Extensions: []string{".md", ".markdown"},
				Serve:      true,
				Distribute: project.DistributePush,
				Versions:   project.VersionsSnapshots,
			},
			{
				Name:       "go",
				Extensions: []string{".go"},
				Serve:      true,
				Distribute: project.DistributePull,
				Versions:   project.VersionsGit,
			},
		}},
	}

	have := map[string][]byte{
		"README.md":            digestOf("# The project\n"),
		"docs/deployment.md":   digestOf("# Deploying\n"),
		"docs/architecture.md": digestOf("# How it fits together\n"),
		// Held, pulled, and stale — and none of that is this call's business.
		"main.go": digestOf("package something-else\n"),
		// Held, pulled, and gone from the publisher entirely.
		"deleted.go": digestOf("package gone\n"),
	}

	changes, _ := collect(t, root, have, serving)

	for _, change := range changes {
		t.Errorf("nothing should have been sent, got %+v", change)
	}
}

func TestAKindThatIsNotPushedIsNotSent(t *testing.T) {
	root := browsable(t)

	changes, _ := collect(t, root, nil, project.DefaultServing)

	for _, change := range changes {
		if filepath.Ext(change.Path) == ".go" {
			t.Errorf("%s is not a pushed kind and should not be sent",
				change.Path)
		}
	}
}

// The walk uses the browser's rules, so a repository with a node_modules in it
// does not push other people's READMEs.
func TestTheSkippedDirectoriesAreNotSynced(t *testing.T) {
	root := browsable(t)

	changes, _ := collect(t, root, nil, project.DefaultServing)

	for _, change := range changes {
		if change.Path == "node_modules/left-pad/README.md" {
			t.Error("a README from node_modules was sent")
		}
	}
}

// A file over the per-file cap is pushed cut short rather than skipped.
//
// It used to be skipped, on the reasoning that what cannot be served should not
// be sent. That was right while the cap meant "not offered" and became a way of
// hiding long documents once it stopped meaning that: the file was not sent,
// not reported removed, and did not appear in a listing either, so the reader
// was given no way to find out it existed.
func TestADocumentOverTheFileCapIsSentCutShort(t *testing.T) {
	root := browsable(t)

	serving := project.Serving{
		Limits: project.Limits{FileBytes: 8, ProjectBytes: 1 << 20},
		Policy: project.DefaultPolicy,
	}

	have := map[string][]byte{
		"README.md": digestOf("# an older, shorter version\n"),
	}

	changes, _ := collect(t, root, have, serving)

	var sent *project.SyncChange

	for _, change := range changes {
		if change.Path == "README.md" {
			sent = &change

			break
		}
	}

	if sent == nil {
		t.Fatal("README.md over the cap was not sent at all")
	}

	if !sent.Entry.GetTruncated() {
		t.Error("the entry did not say it had been cut short")
	}

	if len(sent.Content) > 8 {
		t.Errorf("%d bytes were sent, over the cap of 8", len(sent.Content))
	}

	// The size stays the file's own, so the reader can say how much of it it is
	// looking at.
	if sent.Entry.GetSize() <= int64(len(sent.Content)) {
		t.Errorf("the entry reported size %d for %d bytes of content, want the "+
			"whole file's size", sent.Entry.GetSize(), len(sent.Content))
	}
}

// A truncated walk has not established that anything is missing, so it must
// remove nothing: a path it never reached looks exactly like a path that is
// gone.
func TestATruncatedSyncRemovesNothing(t *testing.T) {
	root := t.TempDir()

	// More entries than the walk will look at.
	for i := range project.MaxSyncWalk + 10 {
		name := filepath.Join(root, "doc"+strconv.Itoa(i)+".md")

		if err := os.WriteFile(name, []byte("# one\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	have := map[string][]byte{"gone.md": digestOf("# was here\n")}

	changes, result := collect(t, root, have, project.DefaultServing)

	if !result.Truncated {
		t.Fatal("the walk should have truncated")
	}

	for _, change := range changes {
		if change.Removed {
			t.Errorf("a truncated sync removed %s", change.Path)
		}
	}
}
