// Package project is project publishing and doc browsing (docs/architecture.md
// §6, decision Q).
//
// Publishing is a state. A requester marks a project as published and nothing
// leaves; an approver that wants to read one asks for a directory at a time,
// searches the names, and fetches the files it opens — and keeps those, so what
// has been read once stays readable with no signal.
//
// The two halves live side by side here. `browse.go` is the publisher's, and
// serves out of a directory belonging to the machine §6 distrusts most.
// `cache.go` and `browser.go` are the approver's: what has been read, and the
// reading. Everything that looks like a precaution is one — the caps keep a
// compromised requester from filling an approver's disk, the path handling
// keeps browsing from becoming a way to read the rest of the requester's
// filesystem, and everything served is display context rather than evidence.
package project

import (
	"crypto/sha256"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/hugowetterberg/ladulas/pkg/gitctx"
)

// Markdown is the extensions the markdown kind matches. What is done with that
// kind — whether it is served, pushed, and versioned — is the policy's to say
// (decision AP), and the default policy is built out of this list.
var Markdown = []string{".md", ".markdown"}

// Limits bound browsing, on both sides of it.
//
// They are per-call and per-project rather than per-publication, which is what
// changed with decision Q: there is no moment at which a whole doc set is
// weighed, so what is bounded is what one call may return and what one project
// may come to occupy on an approver that keeps reading it.
type Limits struct {
	// FileBytes caps one file, on the side that serves it.
	FileBytes int64
	// ProjectBytes caps what one project's pages may occupy in an approver's
	// cache. Reading past it drops the pages that have gone longest unread,
	// which is the behaviour somebody browsing a large project would choose if
	// they were asked.
	ProjectBytes int64
}

// DefaultLimits are what an instance uses unless told otherwise.
var DefaultLimits = Limits{
	FileBytes:    256 << 10,
	ProjectBytes: 4 << 20,
}

func (l Limits) withDefaults() Limits {
	if l.FileBytes <= 0 {
		l.FileBytes = DefaultLimits.FileBytes
	}

	if l.ProjectBytes <= 0 {
		l.ProjectBytes = DefaultLimits.ProjectBytes
	}

	return l
}

// skipped are directories a doc browser has no business entering. They are
// skipped for noise rather than for safety — the confinement is what keeps a
// listing honest — but a repository with a node_modules in it would otherwise
// answer every search with other people's READMEs.
var skipped = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"target":       true,
	"dist":         true,
	"build":        true,
	".venv":        true,
}

// ID is the identifier a project answers to, derived rather than assigned.
//
// Both ends work it out from the same two facts, so a signing request can name
// the project it belongs to without carrying one, and a project marked
// published twice lands on the same record. It is derived in gitctx because
// ladulas-sign has to arrive at the same string from a repository it is
// standing in, and there must be exactly one derivation.
func ID(originURL, path string) string {
	return gitctx.ProjectID(originURL, path)
}

// Key names a project inside an approver: the publisher and the project
// together, since two peers may perfectly well both have a project called
// "docs".
func Key(peerFingerprint, projectID string) string {
	sum := sha256.Sum256([]byte(peerFingerprint))

	return fmt.Sprintf("%x-%s", sum[:6], projectID)
}

// ErrOutsideRoot is returned for a path that does not resolve inside the
// project.
var ErrOutsideRoot = fmt.Errorf("project: the path is not inside the project")

// CheckPath refuses a path that is not a plain relative one.
//
// It is the cheap half of the rail, applied where a path comes in rather than
// where it is used: a path is a distrusted machine's string and ends up as a
// key into a cache and as a link in a viewer, and the place to stop a bad one
// is at the door. The half that matters is os.Root, in browse.go.
func CheckPath(name string) error {
	if name == "" || path.IsAbs(name) || filepath.IsAbs(name) ||
		strings.ContainsRune(name, 0) {
		return fmt.Errorf("%w: %q", ErrOutsideRoot, name)
	}

	cleaned := path.Clean(name)
	if cleaned != name || cleaned == "." || cleaned == ".." ||
		strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("%w: %q", ErrOutsideRoot, name)
	}

	return nil
}

// IsMarkdown reports whether a file name is markdown.
//
// It is not the question "may this be read", which is the policy's and is asked
// through Policy.Serves. This one is asked by the parser, about a link: a link
// to another markdown file in the same project is one the viewer can navigate
// with, and anything else becomes text (see markdown.go). A policy that served
// more kinds would not make a link to one of them navigable, because the viewer
// renders markdown and nothing else.
func IsMarkdown(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))

	for _, candidate := range Markdown {
		if ext == candidate {
			return true
		}
	}

	return false
}

func byteSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n>>10)
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}
