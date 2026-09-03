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
