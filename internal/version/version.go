// Package version is what every binary answers `--version` with.
//
// There are two ways a Ladulås binary gets built and they know different
// things about themselves. A release build is a goreleaser build off a tag,
// and the tag arrives through -ldflags because nothing in the tree records
// which tag points at it. A development build is `go install ./cmd/ladulasd`,
// which passes no ldflags at all — and that is the build that matters most
// here, because the daemon running on the maintainer's own machine is one of
// those (CLAUDE.md).
//
// So the ldflags are not the only source: with none set, this falls back to
// the VCS stamps the Go toolchain puts in every build from a checkout, which
// give the commit and whether the tree was dirty. The failure that motivates
// the fallback is specific and has happened here — "the feature does nothing"
// and "the feature is not running" look identical from the outside, and a
// version that reads `dev` for every build ever made cannot tell them apart.
// One that reads `0.0.0-dev (g1a2b3c4.dirty, go1.26.5)` can.
package version

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// Version, Commit and Date are set at link time by goreleaser:
//
//	-X github.com/hugowetterberg/ladulas/internal/version.Version=1.2.3
//
// Left alone they stay empty and the build stamps answer instead.
var (
	Version string
	Commit  string
	Date    string
)

// String is the one-line version: `1.2.3 (g1a2b3c4, 2026-08-12T13:45:30Z, go1.26.5)`
// for a release build, `0.0.0-dev (g1a2b3c4.dirty, go1.26.5)` for a local one.
//
// It never returns the empty string. A binary that knows nothing about itself
// still says so out loud, because a blank line is indistinguishable from a
// version command that did not run.
func String() string {
	release, revision := describe()

	detail := []string{}

	if revision != "" {
		detail = append(detail, revision)
	}

	if Date != "" {
		detail = append(detail, Date)
	}

	detail = append(detail, runtime.Version())

	return release + " (" + strings.Join(detail, ", ") + ")"
}

// describe works out the release and the revision together, because on a
// development build the answer to one decides the other.
//
// The discriminator is whether the toolchain recorded a VCS revision, and it
// is worth spelling out why rather than the more obvious test. Go does not
// leave Main.Version as "(devel)" for a build from a checkout any more — since
// 1.24 it synthesises a pseudo-version like
// `0.0.0-20260812134530-f2ff2da8e61f+dirty`, which is a plausible-looking
// version string that no tag anywhere corresponds to. Believing it would put a
// fabricated version in front of a person reading it and, worse, hand a
// package manager a version to compare. So: a build with VCS stamps came from
// somebody's checkout and is a development build whatever Main.Version claims,
// and only a build without them — a `go install …@v1.2.3`, where the module
// came from the proxy — is trusted to name its own version.
func describe() (string, string) {
	const dev = "0.0.0-dev"

	if Version != "" {
		return strings.TrimPrefix(Version, "v"), commitOf(Commit)
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return dev, ""
	}

	var commit, modified string

	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			commit = setting.Value
		case "vcs.modified":
			modified = setting.Value
		}
	}

	if commit == "" {
		// No checkout behind this one: an installed module version is the
		// truth if there is one.
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return strings.TrimPrefix(v, "v"), ""
		}

		return dev, ""
	}

	revision := commitOf(commit)

	// The dirty marker is the point of this on a development machine: a binary
	// built from a modified tree is the only kind whose behaviour cannot be
	// looked up anywhere, so it is the kind worth labelling.
	if modified == "true" {
		revision += ".dirty"
	}

	return dev, revision
}

func commitOf(commit string) string {
	if commit == "" {
		return ""
	}

	return "g" + short(commit)
}

func short(commit string) string {
	const shortHash = 8

	if len(commit) > shortHash {
		return commit[:shortHash]
	}

	return commit
}
