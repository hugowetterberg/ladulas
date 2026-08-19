// Package testutil holds the small helpers the tests share: finding the
// external tools some of them need, and running them.
//
// The tests that drive real git and ssh-keygen are the ones that catch the
// mistakes that matter — an SSHSIG file that only Ladulås can read, or a
// command line that only resembles the one git uses — so they are worth having
// even though they have to be skipped where the tools are missing.
package testutil

import (
	"os"
	"os/exec"
	"testing"
)

// RequireTool skips the test when an external tool is not on the PATH, and
// returns its absolute path.
func RequireTool(t *testing.T, name string) string {
	t.Helper()

	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed: %v", name, err)
	}

	return path
}

// Run runs a command in a directory and fails the test if it does not succeed.
func Run(t *testing.T, dir, name string, args ...string) string {
	t.Helper()

	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = Env()

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}

	return string(out)
}

// Env is an environment for a git subprocess that does not read the developer's
// own configuration, so a test behaves the same on every machine.
func Env(extra ...string) []string {
	env := []string{
		"PATH=" + pathEnv(),
		"HOME=/nonexistent",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=Test Author",
		"GIT_AUTHOR_EMAIL=author@example.test",
		"GIT_COMMITTER_NAME=Test Committer",
		"GIT_COMMITTER_EMAIL=committer@example.test",
		"TZ=UTC",
	}

	return append(env, extra...)
}

func pathEnv() string {
	if path := os.Getenv("PATH"); path != "" {
		return path
	}

	return "/usr/local/bin:/usr/bin:/bin"
}
