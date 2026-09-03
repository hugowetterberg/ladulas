package project_test

import (
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/project"
)

func TestTheDefaultPolicyServesMarkdownAndNothingElse(t *testing.T) {
	policy := project.DefaultPolicy

	for _, name := range []string{
		"README.md", "docs/architecture.markdown", "DOCS/UPPER.MD",
	} {
		if !policy.Serves(name) {
			t.Errorf("%s should be served", name)
		}
	}

	for _, name := range []string{
		"main.go", "go.mod", "docs/images/diagram.png", "Makefile",
	} {
		if policy.Serves(name) {
			t.Errorf("%s should not be served", name)
		}
	}
}

// A kind nothing claims is not served, which is what keeps adding one a
// deliberate act rather than something a forgotten entry does by accident.
func TestAPolicyThatClaimsNoKindServesNothing(t *testing.T) {
	policy := project.Policy{Kinds: []project.Kind{{
		Name:       "text",
		Extensions: []string{".txt"},
		Serve:      true,
		Distribute: project.DistributePull,
		Versions:   project.VersionsGit,
	}}}

	if policy.Serves("README.md") {
		t.Error("markdown is not in this policy and should not be served")
	}

	if !policy.Serves("notes.txt") {
		t.Error("text is in this policy and should be served")
	}
}

func TestMarkdownIsPushedAndSnapshotted(t *testing.T) {
	policy := project.DefaultPolicy

	if !policy.Pushes("README.md") {
		t.Error("markdown should be pushed")
	}

	if !policy.Snapshots("README.md") {
		t.Error("markdown should have its working-tree versions tracked")
	}

	if got := policy.History("README.md"); got != project.VersionsSnapshots {
		t.Errorf("markdown history = %q, want %q", got, project.VersionsSnapshots)
	}
}

// The whole point of the split: a kind that is turned on later arrives
// pull-only, so turning one on costs a call when somebody opens a file and
// nothing at all before that. A Go file must never become something the phone
// mirrors.
func TestAServedKindIsNotPushedUnlessItSaysSo(t *testing.T) {
	policy := project.Policy{Kinds: []project.Kind{{
		Name:       "go",
		Extensions: []string{".go"},
		Serve:      true,
		Distribute: project.DistributePull,
		Versions:   project.VersionsGit,
	}}}

	if !policy.Serves("main.go") {
		t.Fatal("go should be served by this policy")
	}

	if policy.Pushes("main.go") {
		t.Error("a pull kind must not be pushed")
	}

	if policy.Snapshots("main.go") {
		t.Error("a pull kind must not cost a filesystem watch")
	}

	if got := policy.History("main.go"); got != project.VersionsGit {
		t.Errorf("go history = %q, want %q", got, project.VersionsGit)
	}
}

// Serve is the outer door. A kind that is somehow marked push without being
// served is read as not pushed rather than as a way past it.
func TestAKindThatIsNotServedIsNotPushedEither(t *testing.T) {
	policy := project.Policy{Kinds: []project.Kind{{
		Name:       "secrets",
		Extensions: []string{".env"},
		Serve:      false,
		Distribute: project.DistributePush,
		Versions:   project.VersionsSnapshots,
	}}}

	if policy.Serves(".env") {
		t.Error("an unserved kind must not be served")
	}

	if policy.Pushes(".env") {
		t.Error("an unserved kind must not be pushed")
	}

	if policy.Snapshots(".env") {
		t.Error("an unserved kind must not be snapshotted")
	}

	if got := policy.History(".env"); got != project.VersionsNone {
		t.Errorf("history = %q, want %q", got, project.VersionsNone)
	}
}

// A zero Policy is what a caller that was never given one holds, and it has to
// mean the default rather than "no kinds at all" — an instance that quietly
// stopped publishing is the worst reading of an unset field.
func TestAZeroPolicyIsTheDefaultOne(t *testing.T) {
	var policy project.Policy

	if !policy.Serves("README.md") {
		t.Error("a zero policy should serve what the default policy serves")
	}

	if policy.Serves("main.go") {
		t.Error("a zero policy should serve no more than the default policy")
	}
}

// A zero Serving must behave like the default one through every accessor, not
// only through the calls that happen to resolve it on the way in.
//
// This is a regression test for a real failure: a version fetch in another
// package read Serving.Limits.FileBytes directly, got the zero value from a
// node nobody had configured, and refused every document as "larger than this
// instance sends" — because a zero cap does not mean no limit, it means nothing
// may be sent.
func TestAZeroServingResolvesItsCapsAndNotJustItsKinds(t *testing.T) {
	var serving project.Serving

	caps := serving.Caps()

	if caps.FileBytes != project.DefaultLimits.FileBytes {
		t.Errorf("FileBytes = %d, want the default %d — a zero cap refuses "+
			"every file rather than none",
			caps.FileBytes, project.DefaultLimits.FileBytes)
	}

	if caps.ProjectBytes != project.DefaultLimits.ProjectBytes {
		t.Errorf("ProjectBytes = %d, want the default %d",
			caps.ProjectBytes, project.DefaultLimits.ProjectBytes)
	}

	if caps.TotalBytes != project.DefaultLimits.TotalBytes {
		t.Errorf("TotalBytes = %d, want the default %d",
			caps.TotalBytes, project.DefaultLimits.TotalBytes)
	}

	if len(serving.Kinds()) == 0 {
		t.Error("a zero Serving should resolve to the default kinds")
	}
}
