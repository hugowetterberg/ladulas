package project_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// reverseCipher is a stand-in for the vault's own sealing. What the cache cares
// about is that nothing readable is written, and that what is read back is what
// was put in; how the bytes are encrypted is the keystore's business.
type reverseCipher struct{}

func (reverseCipher) Seal(plaintext []byte) ([]byte, error) {
	return flip(plaintext), nil
}

func (reverseCipher) Unseal(ciphertext []byte) ([]byte, error) {
	return flip(ciphertext), nil
}

func flip(body []byte) []byte {
	out := make([]byte, len(body))
	for i, b := range body {
		out[i] = b ^ 0xff
	}

	return out
}

func publicationOf(id, commit string) *ladulasv1.Publication {
	return &ladulasv1.Publication{
		ProjectId:   id,
		Name:        "ladulas",
		Path:        "/srv/build/ladulas",
		OriginUrl:   "git@github.com:example/ladulas.git",
		Branch:      "main",
		Commit:      commit,
		PublishedAt: timestamppb.Now(),
	}
}

func entryOf(path string) *ladulasv1.ProjectEntry {
	return &ladulasv1.ProjectEntry{
		Name:     filepath.Base(path),
		Path:     path,
		Readable: true,
	}
}

// TestKeepRefusesAProjectIdThatClimbsOutOfTheCache: the project id is a
// distrusted peer's string, and Keep is the half that creates directories, so a
// peer that names a project "../../../../tmp/pwn" must be refused before
// MkdirAll runs — nothing is written outside the cache root.
func TestKeepRefusesAProjectIdThatClimbsOutOfTheCache(t *testing.T) {
	dir := t.TempDir()

	cache, err := project.OpenCache(dir, reverseCipher{}, project.DefaultLimits)
	if err != nil {
		t.Fatalf("open the cache: %v", err)
	}

	escape := filepath.Join(dir, "..", "ladulas-cache-escape")
	t.Cleanup(func() { _ = os.RemoveAll(escape) })

	hostile := publicationOf(
		"../../ladulas-cache-escape", "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678")

	_, err = cache.Keep("headless", "SHA256:headless", hostile,
		entryOf("README.md"), []byte("# pwn\n"))
	if err == nil {
		t.Fatal("Keep accepted a project id that climbs out of the cache")
	}

	if !errors.Is(err, project.ErrOutsideRoot) {
		t.Errorf("the error is %v, want ErrOutsideRoot", err)
	}

	if _, statErr := os.Stat(escape); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("something was written outside the cache root: %v", statErr)
	}
}

// TestTheCacheKeepsWhatWasRead: a page read once is readable back, and nothing
// readable is left on disk.
func TestTheCacheKeepsWhatWasRead(t *testing.T) {
	dir := t.TempDir()

	cache, err := project.OpenCache(dir, reverseCipher{}, project.DefaultLimits)
	if err != nil {
		t.Fatalf("open the cache: %v", err)
	}

	publication := publicationOf(
		"abcdefghij", "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678")

	if _, err := cache.Keep("headless", "SHA256:headless", publication,
		entryOf("README.md"), []byte("# Ladulås\n")); err != nil {
		t.Fatalf("keep the README: %v", err)
	}

	cached, err := cache.Keep("headless", "SHA256:headless", publication,
		entryOf("docs/design.md"),
		[]byte("# Design\n\nA barn with a lock on it.\n"))
	if err != nil {
		t.Fatalf("keep the design: %v", err)
	}

	if len(cached.GetFiles()) != 2 {
		t.Errorf("the cache holds %d pages", len(cached.GetFiles()))
	}

	if cached.GetKey() != project.Key("SHA256:headless", "abcdefghij") {
		t.Errorf("the record is keyed %q", cached.GetKey())
	}

	body, file, err := cache.File(cached.GetKey(), "docs/design.md")
	if err != nil {
		t.Fatalf("read a page: %v", err)
	}

	if !strings.Contains(string(body), "A barn with a lock on it") {
		t.Errorf("the page came back as %q", body)
	}

	// The commit the page was read at is what the staleness label needs, and
	// keeping it is the only reason the cache knows about commits at all.
	if file.GetCommit() != publication.GetCommit() {
		t.Errorf("the page was recorded at %q", file.GetCommit())
	}

	// Nothing on disk says what the project is called or what it holds.
	if leaked := grepTree(t, dir, []string{"Ladulås", "barn", "ladulas"}); leaked != "" {
		t.Errorf("%s is readable on disk", leaked)
	}

	// A page nobody has read is not there whatever is asked for.
	if _, _, err := cache.File(cached.GetKey(), "../../etc/passwd"); !errors.Is(
		err, project.ErrNoSuchFile) {
		t.Errorf("a path nobody read gave %v", err)
	}
}

// TestRereadingAPageReplacesIt: the same path read twice is one page, at the
// digest it has now, and the bytes it had before are gone.
func TestRereadingAPageReplacesIt(t *testing.T) {
	dir := t.TempDir()

	cache, err := project.OpenCache(dir, reverseCipher{}, project.DefaultLimits)
	if err != nil {
		t.Fatalf("open the cache: %v", err)
	}

	publication := publicationOf("abcdefghij", "1111111111")

	if _, err := cache.Keep("headless", "SHA256:headless", publication,
		entryOf("README.md"), []byte("# one\n")); err != nil {
		t.Fatalf("keep: %v", err)
	}

	moved := publicationOf("abcdefghij", "2222222222")

	cached, err := cache.Keep("headless", "SHA256:headless", moved,
		entryOf("README.md"), []byte("# two\n"))
	if err != nil {
		t.Fatalf("keep again: %v", err)
	}

	if len(cached.GetFiles()) != 1 {
		t.Fatalf("re-reading one page left %d", len(cached.GetFiles()))
	}

	body, file, err := cache.File(cached.GetKey(), "README.md")
	if err != nil {
		t.Fatalf("read it back: %v", err)
	}

	if string(body) != "# two\n" {
		t.Errorf("the page came back as %q", body)
	}

	if file.GetCommit() != "2222222222" {
		t.Errorf("the page is recorded at %q", file.GetCommit())
	}

	// The blob nothing points at any more is swept: a cache that grew a copy
	// per read would be a copy of the repository's history.
	blobs, err := os.ReadDir(filepath.Join(dir, cached.GetKey(), "blobs"))
	if err != nil {
		t.Fatalf("read the blobs: %v", err)
	}

	if len(blobs) != 1 {
		t.Errorf("%d blobs remain for one page", len(blobs))
	}
}

// TestTheCacheStaysInsideItsBudget: reading past the per-project cap drops the
// pages that have gone longest unread (§6).
func TestTheCacheStaysInsideItsBudget(t *testing.T) {
	cache, err := project.OpenCache(t.TempDir(), reverseCipher{},
		project.Limits{ProjectBytes: 24})
	if err != nil {
		t.Fatalf("open the cache: %v", err)
	}

	publication := publicationOf("abcdefghij", "1111111111")

	var cached *ladulasv1.CachedProject

	for _, name := range []string{"a.md", "b.md", "c.md"} {
		cached, err = cache.Keep("headless", "SHA256:headless", publication,
			entryOf(name), []byte("0123456789\n"))
		if err != nil {
			t.Fatalf("keep %s: %v", name, err)
		}
	}

	if len(cached.GetFiles()) != 2 {
		t.Fatalf("the cache holds %d pages inside a 24 byte budget",
			len(cached.GetFiles()))
	}

	if _, _, err := cache.File(cached.GetKey(), "a.md"); !errors.Is(
		err, project.ErrNoSuchFile) {
		t.Errorf("the page read longest ago is still there: %v", err)
	}

	if _, _, err := cache.File(cached.GetKey(), "c.md"); err != nil {
		t.Errorf("the page just read was dropped: %v", err)
	}
}

// TestDroppingAPeerTakesItsProjects: revoking a pairing should not leave the
// peer's documentation on an approver's screen.
func TestDroppingAPeerTakesItsProjects(t *testing.T) {
	cache, err := project.OpenCache(
		t.TempDir(), reverseCipher{}, project.DefaultLimits)
	if err != nil {
		t.Fatalf("open the cache: %v", err)
	}

	if _, err := cache.Keep("headless", "SHA256:headless",
		publicationOf("aaaaaaaaaa", "1111111111"),
		entryOf("a.md"), []byte("a\n")); err != nil {
		t.Fatalf("keep: %v", err)
	}

	if _, err := cache.Keep("laptop", "SHA256:laptop",
		publicationOf("bbbbbbbbbb", "2222222222"),
		entryOf("b.md"), []byte("b\n")); err != nil {
		t.Fatalf("keep: %v", err)
	}

	dropped, err := cache.DropPeer("SHA256:headless")
	if err != nil {
		t.Fatalf("drop a peer: %v", err)
	}

	if dropped != 1 {
		t.Errorf("dropping a peer removed %d projects", dropped)
	}

	cached, err := cache.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(cached) != 1 || cached[0].GetPeer() != "laptop" {
		t.Errorf("the cache holds %d projects after the revocation", len(cached))
	}

	if _, err := cache.Get("no-such-key"); !errors.Is(err, project.ErrNoSuchProject) {
		t.Errorf("an unknown key gave %v", err)
	}
}

// grepTree returns the first needle it finds anywhere under a directory.
func grepTree(t *testing.T, dir string, needles []string) string {
	t.Helper()

	var found string

	err := filepath.WalkDir(dir, func(name string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || found != "" {
			return err
		}

		body, err := os.ReadFile(name) //nolint:gosec // a path from the test's own tree
		if err != nil {
			return err
		}

		for _, needle := range needles {
			if bytes.Contains(body, []byte(needle)) {
				found = needle

				return filepath.SkipAll
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk the cache: %v", err)
	}

	return found
}

// The cap over every project together (decision AP).
//
// ProjectBytes alone bounded a browser: somebody reading one large project
// could not fill a disk with it. It does not bound a phone that is *sent* the
// documentation of every project its peers publish, because how much that is
// depends on how many projects somebody else marked published.

func keptPage(
	t *testing.T, cache *project.Cache, peer, id, path string, size int,
) {
	t.Helper()

	body := make([]byte, size)
	for i := range body {
		body[i] = byte('a' + i%26)
	}

	_, err := cache.Keep(peer, "SHA256:"+peer, publicationOf(id, "abc123"),
		&ladulasv1.ProjectEntry{Path: path, Name: path, Readable: true},
		body)
	if err != nil {
		t.Fatalf("keep %s in %s: %v", path, id, err)
	}
}

func totalHeld(t *testing.T, cache *project.Cache) int64 {
	t.Helper()

	projects, err := cache.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	var total int64

	for _, held := range projects {
		for _, file := range held.GetFiles() {
			total += file.GetSize()
		}
	}

	return total
}

func TestTheCacheIsBoundedAcrossProjectsAndNotOnlyWithinThem(t *testing.T) {
	limits := project.Limits{
		FileBytes:    4 << 10,
		ProjectBytes: 4 << 10,
		TotalBytes:   6 << 10,
	}

	cache, err := project.OpenCache(t.TempDir(), reverseCipher{}, limits)
	if err != nil {
		t.Fatalf("open the cache: %v", err)
	}

	// Four projects of a kilobyte each fits under ProjectBytes every time and
	// blows the total, which is exactly the case the second cap exists for.
	for _, id := range []string{"aaaa", "bbbb", "cccc", "dddd"} {
		keptPage(t, cache, "laptop", id, "README.md", 2<<10)
	}

	if got := totalHeld(t, cache); got > limits.TotalBytes {
		t.Errorf("the cache holds %d bytes, over the %d total",
			got, limits.TotalBytes)
	}
}

// The page just fetched is never the one dropped, however far over the cap it
// puts things: fetching a document and discarding it before anybody reads it
// is the one outcome worse than being over budget.
func TestThePageJustReadSurvivesTheTotalCap(t *testing.T) {
	limits := project.Limits{
		FileBytes:    4 << 10,
		ProjectBytes: 4 << 10,
		TotalBytes:   1 << 10,
	}

	cache, err := project.OpenCache(t.TempDir(), reverseCipher{}, limits)
	if err != nil {
		t.Fatalf("open the cache: %v", err)
	}

	keptPage(t, cache, "laptop", "aaaa", "README.md", 2<<10)
	keptPage(t, cache, "laptop", "bbbb", "OPS.md", 2<<10)

	held, err := cache.Find("SHA256:laptop", "bbbb")
	if err != nil {
		t.Fatalf("find the project just read: %v", err)
	}

	var found bool

	for _, file := range held.GetFiles() {
		if file.GetPath() == "OPS.md" {
			found = true
		}
	}

	if !found {
		t.Error("the page just read was dropped by the total cap")
	}
}

// Least-recently-read across projects, so the project somebody is reading
// keeps its pages and the one read in March gives them up.
func TestTheLongestUnreadPagesAreTheOnesDropped(t *testing.T) {
	limits := project.Limits{
		FileBytes:    4 << 10,
		ProjectBytes: 8 << 10,
		TotalBytes:   5 << 10,
	}

	cache, err := project.OpenCache(t.TempDir(), reverseCipher{}, limits)
	if err != nil {
		t.Fatalf("open the cache: %v", err)
	}

	// Oldest first, so the last one kept is the most recently read.
	keptPage(t, cache, "laptop", "aaaa", "old.md", 2<<10)
	keptPage(t, cache, "laptop", "bbbb", "middle.md", 2<<10)
	keptPage(t, cache, "laptop", "cccc", "recent.md", 2<<10)

	recent, err := cache.Find("SHA256:laptop", "cccc")
	if err != nil {
		t.Fatalf("find the most recent project: %v", err)
	}

	if len(recent.GetFiles()) != 1 {
		t.Errorf("the most recently read project holds %d pages, want 1",
			len(recent.GetFiles()))
	}

	// And the oldest is the one that went.
	old, err := cache.Find("SHA256:laptop", "aaaa")
	if err == nil && len(old.GetFiles()) != 0 {
		t.Errorf("the longest-unread project still holds %d pages",
			len(old.GetFiles()))
	}
}

// A cache well under the cap is left entirely alone: the pass costs a
// directory listing and then does nothing.
func TestACacheUnderTheCapLosesNothing(t *testing.T) {
	cache, err := project.OpenCache(
		t.TempDir(), reverseCipher{}, project.DefaultLimits)
	if err != nil {
		t.Fatalf("open the cache: %v", err)
	}

	keptPage(t, cache, "laptop", "aaaa", "README.md", 512)
	keptPage(t, cache, "laptop", "bbbb", "OPS.md", 512)

	if got := totalHeld(t, cache); got != 1024 {
		t.Errorf("the cache holds %d bytes, want both pages at 1024", got)
	}
}
