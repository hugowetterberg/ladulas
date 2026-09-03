package project

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// Working out what an approver is missing, from the publisher's side
// (decision AP).
//
// The approver says what it holds — a path and its own digest of the contents,
// per document — and this answers with the difference. That is the whole of
// why pushing documentation is affordable: a doc set that has not changed
// costs one manifest and no content at all, and one where a heading moved
// costs the file it moved in.
//
// **Only pushed kinds are considered, in both directions**, and the second
// direction is the one that would do damage if it were not. An approver's cache
// holds two sorts of thing: documents that were pushed to it, and pages it
// pulled because somebody opened them (decision Q). A reconciliation that
// removed everything the publisher does not push would delete the second sort
// — pages that are legitimately readable and that nobody said anything about.
// So a path that is not a pushed kind is left alone, whatever the publisher
// does or does not have at it.

// Sync caps. They bound one reconciliation, not one project.
const (
	// MaxSyncWalk bounds how many directory entries one reconciliation looks
	// at. A project that reaches it has a policy that is pushing far more than
	// a doc set, and the answer is to fix the policy rather than to raise this.
	MaxSyncWalk = 20000

	// MaxSyncBytes bounds the content one reconciliation streams. Reaching it
	// leaves the approver partly synced, which is a state it is already built
	// for — it holds what it holds, and the next sync carries on. It is
	// insurance against a policy that pushes something enormous rather than a
	// limit anybody should meet.
	MaxSyncBytes = 64 << 20
)

// SyncChange is one document that differs.
type SyncChange struct {
	// Removed says the approver holds this path and the publisher does not.
	// Entry and Content are nil.
	Removed bool
	Path    string
	Entry   *Entry
	Content []byte
}

// SyncResult is what a reconciliation did.
type SyncResult struct {
	Walked int
	Bytes  int64
	// Truncated says a cap was reached and the answer is incomplete. The
	// approver is not misled by this: what it did receive is correct, and what
	// it did not it still believes it is missing.
	Truncated bool
}

// Reconcile compares what an approver holds against what this instance pushes,
// calling emit for each difference in the order it is found.
//
// have maps a document's path to the digest the approver computed over its own
// copy. It is consumed rather than copied — the caller's map is left alone, but
// the entries that are accounted for are tracked, and whatever is left at the
// end is what the approver has and the publisher does not.
func Reconcile(
	root string, have map[string][]byte, serving Serving,
	emit func(SyncChange) error,
) (SyncResult, error) {
	serving = serving.withDefaults()

	var result SyncResult

	confined, err := os.OpenRoot(root)
	if err != nil {
		return result, fmt.Errorf("project: open the project: %w", err)
	}

	defer func() {
		_ = confined.Close()
	}()

	// seen is what the walk accounted for, so that what is left of have is the
	// set the approver holds and this machine does not.
	seen := make(map[string]bool, len(have))

	walkErr := fs.WalkDir(confined.FS(), ".", func(
		name string, d fs.DirEntry, err error,
	) error {
		if err != nil {
			// A directory that cannot be read contributes nothing rather than
			// failing the reconciliation: the documents that could be read are
			// still worth sending.
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

		if d.IsDir() {
			return nil
		}

		result.Walked++

		if result.Walked > MaxSyncWalk {
			result.Truncated = true

			return fs.SkipAll
		}

		if !serving.Policy.Pushes(name) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			// Marked seen, so a stat that failed does not become a removal.
			//
			// The walk has just listed this file, so it exists; what failed is
			// reading anything about it. The two failure modes are not
			// symmetric — a page wrongly removed is content the reader loses,
			// while a page wrongly kept is stale content the next sync
			// corrects — so the benefit of the doubt goes to keeping it. If it
			// really has gone, the walk will not find it next time and it will
			// be removed then.
			seen[name] = true

			return nil //nolint:nilerr // the walk continues past what it cannot read
		}

		// A symlink is listed and never served (§6), so it is never pushed
		// either.
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil
		}

		seen[name] = true

		body, err := confined.ReadFile(name)
		if err != nil {
			// Marked seen above, deliberately: the file is there, this side
			// just could not read it this time. An approver holding a copy
			// keeps it rather than having it deleted by a transient failure.
			return nil //nolint:nilerr // the walk continues past what it cannot read
		}

		// A file over the cap is pushed cut short rather than skipped. It used
		// to be skipped, on the reasoning that what cannot be served should not
		// be sent — which was right while the cap meant "not offered", and
		// became a way of hiding long documents once it stopped meaning that.
		body, cut := ServeBytes(body, serving.Caps().FileBytes)

		// Except when it is not text, where half a file is not a shorter one.
		// Marked seen, so an approver holding an older copy keeps it: taking a
		// page away because the file has since grown past what can be sent
		// would lose something for nothing.
		if cut && !IsText(body) {
			return nil
		}

		// The digest is of what is sent, not of what is on disk. It is what the
		// other side will hold and hash, and a digest of the whole file would
		// never match the bytes that went with it — so every sweep would send
		// the same document again for ever.
		digest := sha256.Sum256(body)

		if held, ok := have[name]; ok && string(held) == string(digest[:]) {
			return nil
		}

		if result.Bytes+int64(len(body)) > MaxSyncBytes {
			result.Truncated = true

			return fs.SkipAll
		}

		result.Bytes += int64(len(body))

		entry := &Entry{
			Name: filepath.Base(name),
			Path: name,
			// The size on disk, not the size of what is being sent, so that
			// the other side can say how much of the document it has.
			Size:      info.Size(),
			Modified:  timestamppb.New(info.ModTime()),
			Readable:  true,
			Truncated: cut,
		}

		return emit(SyncChange{Path: name, Entry: entry, Content: body})
	})
	if walkErr != nil {
		return result, fmt.Errorf("project: reconcile %s: %w", root, walkErr)
	}

	// A truncated walk has not established that anything is missing, so it
	// removes nothing: the paths it did not reach look exactly like paths that
	// are gone.
	if result.Truncated {
		return result, nil
	}

	// Sorted, so that two reconciliations of the same pair of machines produce
	// the same stream. A map's order would make a wrong answer harder to read
	// than it has to be.
	gone := make([]string, 0, len(have))

	for path := range have {
		if seen[path] {
			continue
		}

		// Not a pushed kind, so not this reconciliation's business — it may
		// well be a page the approver pulled because somebody opened it.
		if !serving.Policy.Pushes(path) {
			continue
		}

		gone = append(gone, path)
	}

	sort.Strings(gone)

	for _, path := range gone {
		if err := emit(SyncChange{Removed: true, Path: path}); err != nil {
			return result, err
		}
	}

	return result, nil
}
