package project

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Browsing a published project, from the publisher's side (decision Q, §6).
//
// Publishing sends nothing. What an approver gets is what it asks for: one
// directory at a time, a search over the names, and the files it opens. So the
// work here is reading a directory rather than walking a tree, and the caps are
// on what one call may return rather than on what one publication may contain.
//
// Two rules run through all of it.
//
// **Nothing is served from outside the project root**, and that is enforced by
// os.Root rather than checked. Every open goes through a root handle, which on
// Linux is openat2 with RESOLVE_BENEATH: a path that would leave the directory
// fails in the kernel, and a symlink pointing out of it fails as it is
// traversed. The alternative — resolve the path, check it is inside, then open
// it — has a window between the check and the open that a swapped symlink
// walks straight through, and this is the one place in the codebase where the
// thing on the other side of that window is a machine we distrust by
// construction (§6).
//
// **Listing and serving are different questions.** A directory listing says
// what the project contains, including the files this instance will not hand
// over; a browser that silently omitted them would be lying about the project.
// What may be *read* is the narrower set, and each entry says which it is and
// why. Today that set is markdown, which is what the viewer renders; it is
// expected to grow, and the shape here is what lets it grow without the
// protocol changing.

// Browsing caps. They bound one call rather than one project: a directory of
// ten thousand files is a fact about somebody's repository, not a problem, and
// the answer is to send a page of it.
const (
	// DefaultPageSize is what a caller that does not care gets.
	DefaultPageSize = 100
	// MaxPageSize is the most any caller gets, however much it asks for.
	MaxPageSize = 500
	// MaxSearchWalk bounds how many entries one search looks at. A repository
	// with a vendor directory in it can be very large, and a search that walked
	// all of it would hold a connection open while somebody waited.
	MaxSearchWalk = 20000
	// MaxEmptinessWalk bounds the look inside one directory that answers "is
	// there anything readable in here at all". It is much smaller than the
	// search walk and it is per directory in a page, because a listing of ten
	// folders should not turn into ten walks of a repository — and it stops at
	// the first file that would be served, which in a documentation directory is
	// the first file it looks at. A walk that runs out says nothing rather than
	// saying no.
	MaxEmptinessWalk = 2000
)

// Entry is one thing in a directory, as an approver sees it.
type Entry = ladulasv1.ProjectEntry

// ReadDir returns one page of a directory.
//
// The filter is applied here rather than by the caller, so a directory of ten
// thousand files costs one page either way. Total counts what is in the
// directory before the filter, which is what lets a browser say how much of it
// is being shown.
func ReadDir(
	root, rel, filter, token string, size int, limits Limits,
) ([]*Entry, string, int, error) {
	limits = limits.withDefaults()

	confined, err := os.OpenRoot(root)
	if err != nil {
		return nil, "", 0, fmt.Errorf("open the project: %w", err)
	}

	defer func() {
		_ = confined.Close()
	}()

	listing, err := fs.ReadDir(confined.FS(), where(rel))
	if err != nil {
		return nil, "", 0, fmt.Errorf("read the directory: %w", err)
	}

	names := make([]fs.DirEntry, 0, len(listing))

	for _, item := range listing {
		if hidden(item.Name()) || skipped[item.Name()] {
			continue
		}

		names = append(names, item)
	}

	sort.Slice(names, func(i, j int) bool {
		// Directories first, then by name: a browser opened on a project root
		// wants docs/ before README.md, and somebody scanning for a folder
		// should not have to read past the files to find it.
		if names[i].IsDir() != names[j].IsDir() {
			return names[i].IsDir()
		}

		return names[i].Name() < names[j].Name()
	})

	total := len(names)
	wanted := strings.ToLower(filter)

	var (
		out    []*Entry
		next   string
		limit  = pageSize(size)
		after  = token
		seen   int
		passed = after == ""
	)

	for _, item := range names {
		if !passed {
			if item.Name() == after {
				passed = true
			}

			continue
		}

		if wanted != "" && !strings.Contains(strings.ToLower(item.Name()), wanted) {
			continue
		}

		if seen == limit {
			next = out[len(out)-1].GetName()

			break
		}

		out = append(out, entryFor(confined, path.Join(rel, item.Name()), item, limits))
		seen++
	}

	return out, next, total, nil
}

// Search finds files by name across a project.
//
// The match is against the whole path rather than the base name, so "docs/dep"
// finds what somebody meant by it. The walk is bounded: a repository can be
// arbitrarily large, and a search that read all of it would hold a connection
// open while somebody waited — so it says it stopped early rather than
// reporting a partial answer as a complete one.
func Search(
	root, query, token string, size int, limits Limits,
) ([]*Entry, string, bool, error) {
	limits = limits.withDefaults()

	wanted := strings.ToLower(strings.TrimSpace(query))
	if wanted == "" {
		return nil, "", false, nil
	}

	confined, err := os.OpenRoot(root)
	if err != nil {
		return nil, "", false, fmt.Errorf("open the project: %w", err)
	}

	defer func() {
		_ = confined.Close()
	}()

	var (
		out       []*Entry
		next      string
		limit     = pageSize(size)
		walked    int
		truncated bool
		passed    = token == ""
	)

	err = fs.WalkDir(confined.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			// A directory that cannot be read is not a reason to fail the
			// search; it is one place the answer does not come from.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}

			return nil
		}

		if name == "." {
			return nil
		}

		if hidden(d.Name()) || skipped[d.Name()] {
			if d.IsDir() {
				return fs.SkipDir
			}

			return nil
		}

		walked++

		if walked > MaxSearchWalk {
			truncated = true

			return fs.SkipAll
		}

		if d.IsDir() {
			return nil
		}

		if !passed {
			if name == token {
				passed = true
			}

			return nil
		}

		if !strings.Contains(strings.ToLower(name), wanted) {
			return nil
		}

		if len(out) == limit {
			next = out[len(out)-1].GetPath()

			return fs.SkipAll
		}

		out = append(out, entryFor(confined, name, d, limits))

		return nil
	})
	if err != nil {
		return nil, "", false, fmt.Errorf("search the project: %w", err)
	}

	return out, next, truncated, nil
}

// ReadFile serves one file, having checked that it is one this instance offers.
func ReadFile(root, rel string, limits Limits) ([]byte, *Entry, error) {
	limits = limits.withDefaults()

	if err := CheckPath(rel); err != nil {
		return nil, nil, err
	}

	confined, err := os.OpenRoot(root)
	if err != nil {
		return nil, nil, fmt.Errorf("open the project: %w", err)
	}

	defer func() {
		_ = confined.Close()
	}()

	// Lstat rather than Stat: a symlink is listed and never served, and asking
	// about the link itself is how that stays true even for one that points
	// somewhere perfectly legitimate.
	info, err := confined.Lstat(rel)
	if err != nil {
		return nil, nil, fmt.Errorf("read the file: %w", err)
	}

	if info.IsDir() {
		return nil, nil, fmt.Errorf("%s is a directory", rel)
	}

	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%s is a symbolic link", rel)
	}

	entry := &Entry{
		Name:     path.Base(rel),
		Path:     rel,
		Size:     info.Size(),
		Modified: timestamppb.New(info.ModTime()),
	}

	entry.Readable, entry.Reason = servable(rel, info.Size(), limits)

	if !entry.GetReadable() {
		return nil, entry, fmt.Errorf("%s is not offered: %s", rel, entry.GetReason())
	}

	body, err := confined.ReadFile(rel)
	if err != nil {
		return nil, entry, fmt.Errorf("read %s: %w", rel, err)
	}

	return body, entry, nil
}

// where turns a caller's relative path into one fs.FS understands. The root
// itself is ".", which is the one path CheckPath has no name for.
func where(rel string) string {
	if rel == "" || rel == "." {
		return "."
	}

	return rel
}

func entryFor(confined *os.Root, rel string, d fs.DirEntry, limits Limits) *Entry {
	entry := &Entry{
		Name:      d.Name(),
		Path:      rel,
		Directory: d.IsDir(),
	}

	// Lstat through the root handle, so a symlink is reported as itself rather
	// than as whatever it points at.
	if info, err := confined.Lstat(rel); err == nil {
		entry.Size = info.Size()
		entry.Modified = timestamppb.New(info.ModTime())
		entry.Directory = info.IsDir()

		if info.Mode()&fs.ModeSymlink != 0 {
			entry.Reason = "a symbolic link"

			return entry
		}
	}

	if d.IsDir() {
		entry.NothingReadable = nothingReadable(confined, rel, limits)

		return entry
	}

	entry.Readable, entry.Reason = servable(rel, entry.GetSize(), limits)

	return entry
}

// nothingReadable reports whether a directory leads nowhere: no file anywhere
// beneath it is one this instance would hand over.
//
// It is answered here because this is the machine with the directory on it. The
// approver's alternative is a call per folder and then a call per folder inside
// that one, over a network, to find out whether a row is worth drawing — and it
// would still be wrong about a folder whose only document is four levels down.
//
// Every uncertainty resolves to false, which means "say nothing and let the
// folder be shown": a walk that fails, a walk that hits the cap, a symlink that
// might be a document. Hiding something that is there is the one outcome worth
// avoiding, and the cost of showing an empty folder is one tap.
func nothingReadable(confined *os.Root, rel string, limits Limits) bool {
	var (
		walked int
		found  bool
	)

	err := fs.WalkDir(confined.FS(), rel, func(
		name string, d fs.DirEntry, err error,
	) error {
		if err != nil {
			// A directory that cannot be read is one place the answer does not
			// come from, not a reason to claim there is nothing here.
			found = true

			return fs.SkipAll
		}

		if name == rel {
			return nil
		}

		if hidden(d.Name()) || skipped[d.Name()] {
			if d.IsDir() {
				return fs.SkipDir
			}

			return nil
		}

		walked++

		if walked > MaxEmptinessWalk {
			found = true

			return fs.SkipAll
		}

		if d.IsDir() {
			return nil
		}

		size := int64(0)
		if info, err := d.Info(); err == nil {
			size = info.Size()
		}

		if ok, _ := servable(name, size, limits); ok {
			found = true

			return fs.SkipAll
		}

		return nil
	})
	if err != nil {
		return false
	}

	return !found
}

// servable decides whether this instance will hand a file over, and says why
// not when it will not.
//
// The set is markdown today, because markdown is what the viewer renders. It is
// deliberately a separate question from what gets listed: a project full of Go
// files is a project whose listing should show Go files, and the answer to "may
// I read one" is expected to change without the protocol doing so.
func servable(rel string, size int64, limits Limits) (bool, string) {
	if !IsMarkdown(rel) {
		return false, "not a kind this instance offers to read"
	}

	if size > limits.FileBytes {
		return false, fmt.Sprintf("larger than the %s this instance sends",
			byteSize(limits.FileBytes))
	}

	return true, ""
}

// hidden skips dotfiles. A project's documentation is not in them, and a
// listing that offered .env alongside README.md would be inviting somebody to
// ask for it.
func hidden(name string) bool {
	return strings.HasPrefix(name, ".")
}

func pageSize(size int) int {
	switch {
	case size <= 0:
		return DefaultPageSize
	case size > MaxPageSize:
		return MaxPageSize
	default:
		return size
	}
}
