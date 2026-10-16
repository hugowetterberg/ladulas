// Package phonebuild checks the two things a phone's build needs from pkg/
// that nothing else here would notice (docs/architecture.md §21, decision AB).
//
// Neither is gomobile's type rules. gomobile binds the one package it is
// handed, the consumer's own bind surface, and that package reaches pkg/
// through ordinary Go; a slice of structs or an interface in pkg/ binds
// nothing and breaks nothing. What does break a phone is a package it reaches
// that will not compile for it, and a desktop-only dependency that comes along
// with a package it needs.
package phonebuild_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// targets are the phone platforms the apps build for.
var targets = []struct{ goos, goarch string }{
	{"android", "arm64"},
	{"android", "amd64"},
	{"ios", "arm64"},
}

// optIn are the packages under pkg/ a phone links only by asking for them,
// and which are therefore allowed what the rest are not. pkg/tunnel is tailcat
// (decision BA).
var optIn = map[string]bool{
	"github.com/hugowetterberg/ladulas/pkg/tunnel": true,
}

// forbidden are dependencies that have no business in a phone build unless it
// asked for them: tailcat and the Tailscale stack under it, and the metrics
// client, which lives in internal/observe and nowhere else.
var forbidden = []string{
	"tailscale.com/",
	"github.com/tailscale/",
	"gvisor.dev/",
	"github.com/prometheus/",
}

func moduleRoot(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("module root: %v", err)
	}

	return root
}

func goCommand(t *testing.T, goos, goarch string, args ...string) *exec.Cmd {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), "go", args...)
	cmd.Dir = moduleRoot(t)
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")

	return cmd
}

// Every package under pkg/ that a phone links without asking — everything but
// the opt-in ones — reaches no desktop-only dependency on any phone platform.
func TestNothingDesktopOnlyReachesThePhone(t *testing.T) {
	t.Parallel()

	for _, target := range targets {
		out, err := goCommand(t, target.goos, target.goarch, "list",
			"-f", `{{.ImportPath}}{{range .Deps}} {{.}}{{end}}`, "./pkg/...").Output()
		if err != nil {
			t.Fatalf("%s/%s: go list: %v", target.goos, target.goarch, err)
		}

		for line := range strings.Lines(string(out)) {
			fields := strings.Fields(line)
			if len(fields) == 0 || optIn[fields[0]] {
				continue
			}

			for _, dep := range fields[1:] {
				for _, prefix := range forbidden {
					if strings.HasPrefix(dep, prefix) {
						t.Errorf("%s/%s: %s links %s, which a phone should only "+
							"get by asking for it", target.goos, target.goarch, fields[0], dep)
					}
				}
			}
		}
	}
}

// All of pkg/, the opt-in packages included, compiles for every phone
// platform. Without cgo, which gomobile does use: what this catches is a
// package that cannot be built there at all, a desktop-only import or a file
// with the wrong build constraint, and not a linker problem.
func TestPkgCompilesForThePhones(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-compiles the whole of pkg/ for each phone platform")
	}

	t.Parallel()

	for _, target := range targets {
		out, err := goCommand(t, target.goos, target.goarch,
			"build", "-o", os.DevNull, "./pkg/...").CombinedOutput()
		if err != nil {
			t.Errorf("%s/%s: pkg/ does not compile: %v\n%s",
				target.goos, target.goarch, err, out)
		}
	}
}
