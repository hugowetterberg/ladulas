package project

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The publisher's side of versions: what a document looked like before the
// edit somebody is reading it after (decision AP).
//
// A reader wants two different histories and they come from two different
// places. The commits that touched a document are git's, are permanent, and
// cost nothing to offer — they are read at the moment of asking. The states a
// document has been through *since* the last commit are not written down
// anywhere: git has the committed one and the working tree has the current one,
// and everything in between is gone the moment an editor saves over it. Those
// are what this keeps.
//
// It keeps them only for kinds the policy snapshots, which is markdown by
// default, and that is what bounds the whole thing: this store is the size of a
// doc set's edit history between two commits, not the size of a repository.
//
// **A snapshot is relative to a commit, and that is the entire lifecycle
// rule.** "The document as it stood at 14:03" means nothing on its own; it
// means something as "the document at 14:03, when HEAD was abc123". So every
// snapshot records the HEAD it was taken against, and once HEAD moves the
// snapshots taken against the old one describe a working tree that no longer
// exists. They are not served to a peer and they are not kept. That makes
// garbage collection and correctness the same act, which is the only way a
// cache of somebody's unsaved work should ever be managed: the alternative is
// deciding how long to keep something whose meaning has already expired.
//
// It is sealed with the store key, like the approver's cache and for a stronger
// version of the same reason. What is in a working tree before anybody has
// committed it is at least as private as what they have committed, and rather
// more embarrassing.

// Version-store caps. They bound one document's edit history rather than the
// store, because the number of documents is the doc set's business and the
// number of states one of them goes through in an afternoon is nobody's.
const (
	// MaxSnapshotsPerDocument is how many states of one document are kept
	// between commits, newest wins.
	//
	// The debounce upstream of this already coalesces a run of keystrokes into
	// one snapshot, so reaching twenty means twenty distinct pauses in the
	// editing of one file since the last commit — a real afternoon's work on a
	// document, and further back than any reader has asked to see. The oldest
	// is dropped rather than the middle thinned out: the useful end is the
	// recent one, and the committed state at the far end is git's and is not in
	// here at all.
	MaxSnapshotsPerDocument = 20
)

// ErrNoSuchSnapshot is returned for a version that is not held here — which
// includes one that was, until HEAD moved.
var ErrNoSuchSnapshot = errors.New("project: that version is not kept here")

// VersionStore holds the working-tree states of this instance's own published
// documents.
type VersionStore struct {
	dir    string
	cipher Cipher

	// mu serialises the read-modify-write of a project's record. The watcher is
	// one writer, but a sweep on a HEAD change and a snapshot from a save that
	// landed in the same instant are two, and the second must not write a
	// record the first has already decided to discard.
	mu sync.Mutex
}

// OpenVersions prepares the directory. Like the cache it is created on first
// use, so an instance that publishes nothing markdown has no directory at all.
func OpenVersions(dir string, cipher Cipher) (*VersionStore, error) {
	if cipher == nil {
		return nil, errors.New("project: no cipher to seal what is being edited")
	}

	return &VersionStore{dir: dir, cipher: cipher}, nil
}

// Dir is where the store keeps its files.
func (v *VersionStore) Dir() string {
	return v.dir
}

// Record takes a snapshot of one document, against the HEAD it was read at.
//
// It is idempotent on content: a save that changed nothing adds nothing, which
// matters because editors touch files they have not altered and a debounce that
// fires on one of those would otherwise mint a version somebody could be
// offered as a change. The returned snapshot is the newest one either way, so a
// caller can tell what the current version is without asking again; ok reports
// whether this call was what made it.
func (v *VersionStore) Record(
	projectID, projectPath, docPath, head string, content []byte,
) (*ladulasv1.DocumentSnapshot, bool, error) {
	if projectID == "" {
		return nil, false, errors.New("project: the snapshot belongs to no project")
	}

	if head == "" {
		return nil, false, errors.New(
			"project: a snapshot with no commit to be relative to means nothing")
	}

	if err := CheckPath(docPath); err != nil {
		return nil, false, err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// The project id is derived from the origin URL and the path (§6), so it is
	// base32 and safe — but it is about to become the path element MkdirAll
	// creates, and the cache guards the same composition for the same reason.
	// One that is not a single path element is a bug in whatever derived it,
	// not a project.
	if filepath.Base(projectID) != projectID {
		return nil, false, fmt.Errorf("%w: %q", ErrOutsideRoot, projectID)
	}

	dir := filepath.Join(v.dir, projectID)

	tracked, err := v.read(projectID)
	if errors.Is(err, os.ErrNotExist) {
		tracked = &ladulasv1.TrackedProject{ProjectId: projectID}
	} else if err != nil {
		return nil, false, err
	}

	tracked.Path = projectPath

	// Anything taken against another commit is gone before this one is added,
	// so a record never holds two HEADs at once and nothing downstream has to
	// reason about which of them a snapshot belongs to.
	dropped := pruneOtherHeads(tracked, head)

	document := documentIn(tracked, docPath)

	digest := sha256.Sum256(content)

	if newest := newestSnapshot(document); newest != nil &&
		string(newest.GetDigest()) == string(digest[:]) {
		if dropped > 0 {
			if err := v.write(dir, tracked); err != nil {
				return nil, false, err
			}
		}

		return newest, false, nil
	}

	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return nil, false, fmt.Errorf(
			"project: create the version directory: %w", err)
	}

	if err := sealBlob(v.cipher, dir, digest[:], content); err != nil {
		return nil, false, err
	}

	snapshot := &ladulasv1.DocumentSnapshot{
		Digest:  digest[:],
		Size:    int64(len(content)),
		TakenAt: timestamppb.Now(),
		Head:    head,
	}

	document.Snapshots = append(document.GetSnapshots(), snapshot)

	if over := len(document.GetSnapshots()) - MaxSnapshotsPerDocument; over > 0 {
		document.Snapshots = document.GetSnapshots()[over:]
	}

	tracked.UpdatedAt = timestamppb.Now()

	if err := v.write(dir, tracked); err != nil {
		return nil, false, err
	}

	v.sweep(dir, tracked)

	return snapshot, true, nil
}

// Snapshots is what is held for one document at the given HEAD, oldest first.
//
// A HEAD that does not match what is stored returns nothing rather than what is
// stored: the caller is asking "what has this document been through since the
// commit I am standing on", and states from before another commit are not an
// answer to it. The sweep that removes them is a separate act, so that reading
// never depends on having written.
func (v *VersionStore) Snapshots(
	projectID, docPath, head string,
) []*ladulasv1.DocumentSnapshot {
	v.mu.Lock()
	defer v.mu.Unlock()

	tracked, err := v.read(projectID)
	if err != nil {
		return nil
	}

	for _, document := range tracked.GetDocuments() {
		if document.GetPath() != docPath {
			continue
		}

		var out []*ladulasv1.DocumentSnapshot

		for _, snapshot := range document.GetSnapshots() {
			if snapshot.GetHead() == head {
				out = append(out, snapshot)
			}
		}

		return out
	}

	return nil
}

// Content is one snapshot's bytes.
func (v *VersionStore) Content(projectID string, digest []byte) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if projectID == "" || filepath.Base(projectID) != projectID {
		return nil, fmt.Errorf("%w: %q", ErrOutsideRoot, projectID)
	}

	body, err := unsealBlob(v.cipher, filepath.Join(v.dir, projectID), digest)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %x", ErrNoSuchSnapshot, digest)
	}

	if err != nil {
		return nil, fmt.Errorf("project: read a version: %w", err)
	}

	return body, nil
}

// Reset drops everything held for a project that was taken against a different
// commit, and reports how many went.
//
// This is what a HEAD change calls, and it is deliberately not merged into
// Record: a checkout, a rebase or a branch switch has to be able to clear the
// history without anybody having edited anything, and the watcher calls it at
// the moment it notices rather than the next time somebody saves a file.
func (v *VersionStore) Reset(projectID, head string) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	tracked, err := v.read(projectID)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}

	if err != nil {
		return 0, err
	}

	dropped := pruneOtherHeads(tracked, head)
	if dropped == 0 {
		return 0, nil
	}

	dir := filepath.Join(v.dir, projectID)

	if err := v.write(dir, tracked); err != nil {
		return 0, err
	}

	v.sweep(dir, tracked)

	return dropped, nil
}

// Forget removes a project's versions entirely, for one that has been
// unpublished. Nothing is told: there is no copy of any of this anywhere else.
func (v *VersionStore) Forget(projectID string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if projectID == "" || filepath.Base(projectID) != projectID {
		return fmt.Errorf("%w: %q", ErrOutsideRoot, projectID)
	}

	if err := os.RemoveAll(filepath.Join(v.dir, projectID)); err != nil {
		return fmt.Errorf("project: forget the versions of %s: %w", projectID, err)
	}

	return nil
}

// pruneOtherHeads removes every snapshot not taken against head, and every
// document left with none. Callers must hold the lock.
func pruneOtherHeads(tracked *ladulasv1.TrackedProject, head string) int {
	var (
		dropped   int
		documents []*ladulasv1.TrackedDocument
	)

	for _, document := range tracked.GetDocuments() {
		var kept []*ladulasv1.DocumentSnapshot

		for _, snapshot := range document.GetSnapshots() {
			if snapshot.GetHead() == head {
				kept = append(kept, snapshot)

				continue
			}

			dropped++
		}

		if len(kept) == 0 {
			continue
		}

		document.Snapshots = kept
		documents = append(documents, document)
	}

	tracked.Documents = documents

	return dropped
}

// documentIn finds or adds one document's entry. Callers must hold the lock.
func documentIn(
	tracked *ladulasv1.TrackedProject, docPath string,
) *ladulasv1.TrackedDocument {
	for _, document := range tracked.GetDocuments() {
		if document.GetPath() == docPath {
			return document
		}
	}

	document := &ladulasv1.TrackedDocument{Path: docPath}
	tracked.Documents = append(tracked.GetDocuments(), document)

	return document
}

func newestSnapshot(
	document *ladulasv1.TrackedDocument,
) *ladulasv1.DocumentSnapshot {
	snapshots := document.GetSnapshots()
	if len(snapshots) == 0 {
		return nil
	}

	return snapshots[len(snapshots)-1]
}

func (v *VersionStore) read(
	projectID string,
) (*ladulasv1.TrackedProject, error) {
	if projectID == "" || filepath.Base(projectID) != projectID {
		return nil, fmt.Errorf("%w: %q", ErrOutsideRoot, projectID)
	}

	var tracked ladulasv1.TrackedProject

	err := unsealMessage(
		v.cipher, filepath.Join(v.dir, projectID, "record"), &tracked)
	if err != nil {
		return nil, err //nolint:wrapcheck // callers match on os.ErrNotExist
	}

	return &tracked, nil
}

func (v *VersionStore) write(
	dir string, tracked *ladulasv1.TrackedProject,
) error {
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return fmt.Errorf("project: create the version directory: %w", err)
	}

	return sealMessage(v.cipher, filepath.Join(dir, "record"), tracked)
}

// sweep removes the blobs no snapshot points at any more. Callers must hold the
// lock.
//
// It is the same shape as the cache's sweep and exists for a sharper reason: a
// blob left behind here is a copy of somebody's uncommitted work that nothing
// refers to and nothing will ever remove, which is exactly the file you do not
// want found on a disk.
func (v *VersionStore) sweep(dir string, tracked *ladulasv1.TrackedProject) {
	wanted := make(map[string]bool)

	for _, document := range tracked.GetDocuments() {
		for _, snapshot := range document.GetSnapshots() {
			wanted[fmt.Sprintf("%x", snapshot.GetDigest())] = true
		}
	}

	entries, err := os.ReadDir(filepath.Join(dir, "blobs"))
	if err != nil {
		return
	}

	names := make([]string, 0, len(entries))

	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}

	sort.Strings(names)

	for _, name := range names {
		if wanted[name] {
			continue
		}

		_ = os.Remove(filepath.Join(dir, "blobs", name))
	}
}
