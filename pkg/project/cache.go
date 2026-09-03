package project

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The approver's side of browsing: what somebody has actually read, kept so
// that reading it again needs no signal (decision Q).
//
// It is a cache rather than a copy of anything. Nothing is here because a peer
// sent it — publishing sends nothing — and nothing is here because somebody
// might want it. A page is here because it was opened, which is the whole of
// what the offline story now promises: the pages that have a reader stay
// readable, and a project nobody has opened is not readable offline at all.
//
// It does not live in the encrypted store document. Pages are bulk content and
// the document is rewritten whole on every change, so putting them together
// would mean re-encrypting a key store to record that a README was read. It is
// sealed all the same, with the store's own key, for the same reason the trust
// records are (§10): which projects somebody has been reading, and where they
// live, is exactly the map an attacker with the disk would want.
//
// Files are content-addressed, so a page re-read unchanged costs nothing and
// two projects that share a file share the blob.

// ErrNoSuchProject is returned for a project nothing has been read of.
var ErrNoSuchProject = errors.New("project: nothing has been read of that project")

// ErrNoSuchFile is returned for a page that has never been read here.
var ErrNoSuchFile = errors.New("project: that page has not been read here")

// Cipher seals bytes at rest. keystore.Vault implements it with the same data
// encryption key the store document uses, so what has been read is protected
// exactly as well as the keys are and by the same unlock.
type Cipher interface {
	Seal(plaintext []byte) ([]byte, error)
	Unseal(ciphertext []byte) ([]byte, error)
}

// Cache holds the pages this instance has read.
type Cache struct {
	dir    string
	cipher Cipher
	limits Limits

	// mu serialises the read-modify-write of a project directory. Two pages of
	// the same project can perfectly well be opened at once — the viewer's
	// outline search is one way — and this is cheaper than reasoning about
	// whether they can.
	mu sync.Mutex
}

// OpenCache prepares the directory. It is created on first use rather than at
// startup, so an instance that has read nothing has no directory at all.
func OpenCache(dir string, cipher Cipher, limits Limits) (*Cache, error) {
	if cipher == nil {
		return nil, errors.New("project: no cipher to seal what has been read")
	}

	return &Cache{dir: dir, cipher: cipher, limits: limits.withDefaults()}, nil
}

// Dir is where the cache keeps its files.
func (c *Cache) Dir() string {
	return c.dir
}

// Keep records a page that has been read, and what the project was when it was.
//
// The digest is computed here rather than taken from the publisher: it is what
// the blob is stored under, and letting the machine we distrust choose the file
// name would be handing it the one thing this side gets to decide.
func (c *Cache) Keep(
	peerName, fingerprint string,
	publication *ladulasv1.Publication,
	entry *ladulasv1.ProjectEntry,
	content []byte,
) (*ladulasv1.CachedProject, error) {
	if publication.GetProjectId() == "" {
		return nil, errors.New("project: the page belongs to no project")
	}

	if err := CheckPath(entry.GetPath()); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	key := Key(fingerprint, publication.GetProjectId())

	// The project id is a distrusted peer's string, and here it becomes the path
	// element MkdirAll is about to create (§6). read and Drop guard the composed
	// key against a separator or a climb; this is the half that makes the
	// directory, so it guards too, and refuses before anything exists. A real id
	// is base32 with nothing but [a-z2-7] in it — a key that is not one path
	// element is a peer reaching outside the cache, not a project.
	if filepath.Base(key) != key {
		return nil, fmt.Errorf("%w: %q", ErrOutsideRoot, publication.GetProjectId())
	}

	dir := filepath.Join(c.dir, key)

	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return nil, fmt.Errorf("project: create the project directory: %w", err)
	}

	digest := sha256.Sum256(content)

	if err := c.writeBlob(dir, digest[:], content); err != nil {
		return nil, err
	}

	now := timestamppb.Now()

	cached, err := c.read(key)
	if errors.Is(err, ErrNoSuchProject) {
		cached = &ladulasv1.CachedProject{
			Key:             key,
			Peer:            peerName,
			PeerFingerprint: fingerprint,
			FirstReadAt:     now,
		}
	} else if err != nil {
		return nil, err
	}

	cached.Peer = peerName
	cached.Project = publication
	cached.LastReadAt = now

	page := &ladulasv1.CachedFile{
		Path:       entry.GetPath(),
		Digest:     digest[:],
		Size:       int64(len(content)),
		ModifiedAt: entry.GetModified(),
		ReadAt:     now,
		Commit:     publication.GetCommit(),
	}

	kept := []*ladulasv1.CachedFile{page}

	for _, existing := range cached.GetFiles() {
		if existing.GetPath() == page.GetPath() {
			continue
		}

		kept = append(kept, existing)
	}

	cached.Files = c.withinBudget(kept)

	if err := c.writeMessage(filepath.Join(dir, "record"), cached); err != nil {
		return nil, err
	}

	c.sweep(dir, cached)

	// And then the cap over every project together, which is the one that
	// matters now that documentation arrives without being asked for
	// (decision AP).
	c.withinTotal(key, page.GetPath())

	return cached, nil
}

// withinTotal drops the pages that have gone longest unread, across every
// project, until the whole cache fits. Callers must hold the lock.
//
// It is a second pass rather than part of withinBudget because the two answer
// different questions. A project's own cap keeps one project from filling a
// disk, and it can be applied while holding just that project's record. This
// one is about how many projects there are, which is a number the publishing
// side chose, so it has to look at all of them.
//
// The page just written is never dropped, however far over the cap it puts
// things. Fetching a document and then discarding it before anybody reads it
// would be the one outcome worse than being over budget.
func (c *Cache) withinTotal(keepKey, keepPath string) {
	type held struct {
		key  string
		file *ladulasv1.CachedFile
	}

	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return
	}

	var (
		total   int64
		pages   []held
		records = map[string]*ladulasv1.CachedProject{}
	)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		cached, err := c.read(entry.Name())
		if err != nil {
			continue
		}

		records[entry.Name()] = cached

		for _, file := range cached.GetFiles() {
			total += file.GetSize()

			if entry.Name() == keepKey && file.GetPath() == keepPath {
				continue
			}

			pages = append(pages, held{key: entry.Name(), file: file})
		}
	}

	if total <= c.limits.TotalBytes {
		return
	}

	// Longest unread first, which is the order to give them up in — and the
	// same order withinBudget uses within one project, so a reader cannot tell
	// which cap took a page away.
	sort.SliceStable(pages, func(i, j int) bool {
		return pages[i].file.GetReadAt().AsTime().Before(
			pages[j].file.GetReadAt().AsTime())
	})

	dropped := map[string]map[string]bool{}

	for _, page := range pages {
		if total <= c.limits.TotalBytes {
			break
		}

		if dropped[page.key] == nil {
			dropped[page.key] = map[string]bool{}
		}

		dropped[page.key][page.file.GetPath()] = true
		total -= page.file.GetSize()
	}

	for key, paths := range dropped {
		cached := records[key]

		kept := make([]*ladulasv1.CachedFile, 0, len(cached.GetFiles()))

		for _, file := range cached.GetFiles() {
			if paths[file.GetPath()] {
				continue
			}

			kept = append(kept, file)
		}

		cached.Files = kept

		dir := filepath.Join(c.dir, key)

		if err := c.writeMessage(filepath.Join(dir, "record"), cached); err != nil {
			continue
		}

		c.sweep(dir, cached)
	}
}

// withinBudget drops the pages that have gone longest unread until the project
// fits its cap (§6).
//
// The order is by when a page was last read rather than by when it was written,
// because what an approver is browsing now is what it will want again in a
// minute, and the runbook read once in March is what it can afford to fetch
// again.
func (c *Cache) withinBudget(files []*ladulasv1.CachedFile) []*ladulasv1.CachedFile {
	sort.SliceStable(files, func(i, j int) bool {
		return files[i].GetReadAt().AsTime().After(files[j].GetReadAt().AsTime())
	})

	var total int64

	for i, file := range files {
		total += file.GetSize()

		if total > c.limits.ProjectBytes {
			// The page just read is first in this order, so it is never the one
			// dropped — reading a file larger than the whole budget is a
			// question for the serving side's file cap, not for this one.
			return files[:max(i, 1)]
		}
	}

	return files
}

// sweep removes the blobs no page points at any more. Callers must hold the
// lock.
func (c *Cache) sweep(dir string, cached *ladulasv1.CachedProject) {
	wanted := make(map[string]bool, len(cached.GetFiles()))

	for _, file := range cached.GetFiles() {
		wanted[fmt.Sprintf("%x", file.GetDigest())] = true
	}

	entries, err := os.ReadDir(filepath.Join(dir, "blobs"))
	if err != nil {
		return
	}

	for _, entry := range entries {
		if wanted[entry.Name()] {
			continue
		}

		_ = os.Remove(filepath.Join(dir, "blobs", entry.Name()))
	}
}

// List returns every project something has been read of, most recently read
// first.
func (c *Cache) List() ([]*ladulasv1.CachedProject, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries, err := os.ReadDir(c.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("project: read the project directory: %w", err)
	}

	out := make([]*ladulasv1.CachedProject, 0, len(entries))

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		cached, err := c.read(entry.Name())
		if err != nil {
			// A directory that will not parse is a thing to skip rather than a
			// reason to refuse to list anything at all.
			continue
		}

		out = append(out, cached)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].GetLastReadAt().AsTime().After(
			out[j].GetLastReadAt().AsTime())
	})

	return out, nil
}

// Get returns one project's record by its key.
func (c *Cache) Get(key string) (*ladulasv1.CachedProject, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.read(key)
}

// Find is the lookup a signing request needs: the publisher is the peer that
// sent the request, and the project is the one the request names (§6).
func (c *Cache) Find(fingerprint, projectID string) (*ladulasv1.CachedProject, error) {
	if fingerprint == "" || projectID == "" {
		return nil, ErrNoSuchProject
	}

	return c.Get(Key(fingerprint, projectID))
}

// File returns one page as it was read, and when.
func (c *Cache) File(
	key, name string,
) ([]byte, *ladulasv1.CachedFile, error) {
	cached, err := c.Get(key)
	if err != nil {
		return nil, nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, file := range cached.GetFiles() {
		if file.GetPath() != name {
			continue
		}

		body, err := c.readBlob(filepath.Join(c.dir, key), file.GetDigest())
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("%w: %s", ErrNoSuchFile, name)
		}

		return body, file, err
	}

	return nil, nil, fmt.Errorf("%w: %s", ErrNoSuchFile, name)
}

// Drop forgets everything read of one project.
func (c *Cache) Drop(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if key == "" || filepath.Base(key) != key {
		return fmt.Errorf("%w: %s", ErrNoSuchProject, key)
	}

	dir := filepath.Join(c.dir, key)

	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrNoSuchProject, key)
	}

	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("project: remove %s: %w", key, err)
	}

	return nil
}

// DropPeer forgets everything read from a peer, which is the other half of
// revoking a pairing: a peer that is no longer trusted should not still be
// occupying an approver's screen.
func (c *Cache) DropPeer(fingerprint string) (int, error) {
	cached, err := c.List()
	if err != nil {
		return 0, err
	}

	var dropped int

	for _, project := range cached {
		if project.GetPeerFingerprint() != fingerprint {
			continue
		}

		if err := c.Drop(project.GetKey()); err != nil {
			return dropped, err
		}

		dropped++
	}

	return dropped, nil
}

// read loads a project record. Callers must hold the lock.
func (c *Cache) read(key string) (*ladulasv1.CachedProject, error) {
	if key == "" || filepath.Base(key) != key {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchProject, key)
	}

	var cached ladulasv1.CachedProject

	err := unsealMessage(c.cipher, filepath.Join(c.dir, key, "record"), &cached)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchProject, key)
	}

	if err != nil {
		return nil, fmt.Errorf("project: read %s: %w", key, err)
	}

	return &cached, nil
}

func (c *Cache) writeMessage(path string, msg proto.Message) error {
	return sealMessage(c.cipher, path, msg)
}

func (c *Cache) writeBlob(dir string, digest, content []byte) error {
	return sealBlob(c.cipher, dir, digest, content)
}

func (c *Cache) readBlob(dir string, digest []byte) ([]byte, error) {
	return unsealBlob(c.cipher, dir, digest)
}
