package project

import (
	"errors"
	"testing"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The rules that matter live in drain rather than in the transport, so this
// drives it directly: the header before anything is applied, a bad path
// skipped, an unknown kind ignored, and a removal that takes one page rather
// than the project.

type fakeStream struct {
	events []*ladulasv1.SyncProjectEvent
	at     int
	err    error
}

func (f *fakeStream) Receive() bool {
	if f.at >= len(f.events) {
		return false
	}

	f.at++

	return true
}

func (f *fakeStream) Msg() *ladulasv1.SyncProjectEvent {
	return f.events[f.at-1]
}

func (f *fakeStream) Err() error {
	return f.err
}

type xorCipher struct{}

func (xorCipher) Seal(plaintext []byte) ([]byte, error) {
	return xorAll(plaintext), nil
}

func (xorCipher) Unseal(ciphertext []byte) ([]byte, error) {
	return xorAll(ciphertext), nil
}

func xorAll(body []byte) []byte {
	out := make([]byte, len(body))
	for i, b := range body {
		out[i] = b ^ 0xff
	}

	return out
}

const (
	syncPeer = "SHA256:laptop"
	syncID   = "n5rgc3tfmzxxg5dbnrwq"
)

func syncBrowser(t *testing.T) *Browser {
	t.Helper()

	cache, err := OpenCache(t.TempDir(), xorCipher{}, DefaultLimits)
	if err != nil {
		t.Fatalf("open the cache: %v", err)
	}

	return NewBrowser(cache, nil)
}

func syncPublication() *ladulasv1.Publication {
	return &ladulasv1.Publication{
		ProjectId: syncID,
		Name:      "ladulas",
		Path:      "/srv/ladulas",
		Branch:    "main",
		Commit:    "abc123",
	}
}

func header() *ladulasv1.SyncProjectEvent {
	return &ladulasv1.SyncProjectEvent{Project: syncPublication()}
}

func put(path, body string) *ladulasv1.SyncProjectEvent {
	return &ladulasv1.SyncProjectEvent{
		Kind:    ladulasv1.SyncChangeKind_SYNC_CHANGE_KIND_PUT,
		Path:    path,
		File:    &ladulasv1.ProjectEntry{Path: path, Name: path},
		Content: []byte(body),
	}
}

func remove(path string) *ladulasv1.SyncProjectEvent {
	return &ladulasv1.SyncProjectEvent{
		Kind: ladulasv1.SyncChangeKind_SYNC_CHANGE_KIND_REMOVE,
		Path: path,
	}
}

func drainInto(
	t *testing.T, browser *Browser, events ...*ladulasv1.SyncProjectEvent,
) (SyncSummary, error) {
	t.Helper()

	var summary SyncSummary

	err := browser.drain(
		&fakeStream{events: events},
		&Publisher{Name: "laptop", Fingerprint: syncPeer},
		syncPeer, syncID, &summary)

	return summary, err
}

func TestASyncKeepsWhatThePublisherSent(t *testing.T) {
	browser := syncBrowser(t)

	summary, err := drainInto(t, browser,
		header(),
		put("README.md", "# One\n"),
		put("docs/ops.md", "# Ops\n"))
	if err != nil {
		t.Fatalf("drain: %v", err)
	}

	if summary.Fetched != 2 {
		t.Errorf("fetched %d, want 2", summary.Fetched)
	}

	if summary.Bytes == 0 {
		t.Error("no bytes counted")
	}

	page, _, err := browser.cache.File(Key(syncPeer, syncID), "docs/ops.md")
	if err != nil {
		t.Fatalf("read the kept page: %v", err)
	}

	if string(page) != "# Ops\n" {
		t.Errorf("kept %q, want the sent contents", page)
	}
}

// The whole reason a sync is cheap: what the approver already holds is what it
// tells the publisher, so an unchanged doc set costs a manifest and nothing
// else.
func TestTheManifestIsWhatTheCacheHolds(t *testing.T) {
	browser := syncBrowser(t)

	if _, err := drainInto(t, browser,
		header(), put("README.md", "# One\n")); err != nil {
		t.Fatalf("drain: %v", err)
	}

	manifest := browser.manifest(syncPeer, syncID)

	if len(manifest) != 1 {
		t.Fatalf("manifest has %d entries, want 1", len(manifest))
	}

	if manifest[0].GetPath() != "README.md" {
		t.Errorf("manifest names %q", manifest[0].GetPath())
	}

	if len(manifest[0].GetDigest()) == 0 {
		t.Error("the manifest carries no digest, so the publisher cannot compare")
	}
}

// A page is kept against the commit the publisher was standing on, so nothing
// is applied before it has said what that was — keeping one against a commit
// from a different answer would stitch two moments into one claim.
func TestAChangeBeforeTheHeaderIsRefused(t *testing.T) {
	browser := syncBrowser(t)

	_, err := drainInto(t, browser, put("README.md", "# One\n"))
	if err == nil {
		t.Error("a change before the project header should be refused")
	}
}

func TestARemovalTakesOnePageAndNotTheProject(t *testing.T) {
	browser := syncBrowser(t)

	if _, err := drainInto(t, browser,
		header(),
		put("README.md", "# One\n"),
		put("docs/ops.md", "# Ops\n")); err != nil {
		t.Fatalf("drain: %v", err)
	}

	summary, err := drainInto(t, browser, header(), remove("docs/ops.md"))
	if err != nil {
		t.Fatalf("drain the removal: %v", err)
	}

	if summary.Removed != 1 {
		t.Errorf("removed %d, want 1", summary.Removed)
	}

	if _, _, err := browser.cache.File(
		Key(syncPeer, syncID), "docs/ops.md"); err == nil {
		t.Error("the removed page is still readable")
	}

	// And the project is still there, with the page nobody removed.
	if _, _, err := browser.cache.File(
		Key(syncPeer, syncID), "README.md"); err != nil {
		t.Errorf("the other page went with it: %v", err)
	}
}

// Two syncs in a row report the same removal if the first was interrupted, so
// removing a page that is not held must not fail.
func TestRemovingAPageThatIsNotHeldIsNotAnError(t *testing.T) {
	browser := syncBrowser(t)

	if _, err := drainInto(t, browser,
		header(), remove("never-had-it.md")); err != nil {
		t.Errorf("removing an absent page failed: %v", err)
	}
}

// A path that would leave the cache is dropped rather than refused: one bad
// entry from a compromised publisher should not cost the approver the rest of
// its sync.
func TestABadPathIsSkippedRatherThanFatal(t *testing.T) {
	browser := syncBrowser(t)

	summary, err := drainInto(t, browser,
		header(),
		put("../escape.md", "# Nope\n"),
		put("README.md", "# One\n"))
	if err != nil {
		t.Fatalf("drain: %v", err)
	}

	// The good one still landed.
	if _, _, err := browser.cache.File(
		Key(syncPeer, syncID), "README.md"); err != nil {
		t.Errorf("the good page did not land: %v", err)
	}

	// The bad one is counted as fetched — put reports no error — but nothing
	// was written under it, which is what matters.
	if summary.Fetched == 0 {
		t.Error("the sync applied nothing at all")
	}
}

// A kind this side does not understand is skipped rather than guessed at:
// guessing wrong means either losing a page or keeping a stale one.
func TestAnUnknownChangeKindIsIgnored(t *testing.T) {
	browser := syncBrowser(t)

	summary, err := drainInto(t, browser, header(),
		&ladulasv1.SyncProjectEvent{
			Kind: ladulasv1.SyncChangeKind_SYNC_CHANGE_KIND_UNSPECIFIED,
			Path: "README.md",
		})
	if err != nil {
		t.Fatalf("drain: %v", err)
	}

	if summary.Fetched != 0 || summary.Removed != 0 {
		t.Errorf("an unknown kind was acted on: %+v", summary)
	}
}

func TestAStreamThatFailedIsReported(t *testing.T) {
	browser := syncBrowser(t)

	var summary SyncSummary

	stream := &fakeStream{
		events: []*ladulasv1.SyncProjectEvent{header()},
		err:    errRecvFailed,
	}

	err := browser.drain(stream,
		&Publisher{Name: "laptop", Fingerprint: syncPeer},
		syncPeer, syncID, &summary)
	if err == nil {
		t.Error("a stream that failed was reported as a clean sync")
	}
}

var errRecvFailed = errors.New("the connection went away")

// The picker's list, which is what opening a project draws before anything
// else. It has to come from here rather than from the publisher: asking meant
// walking somebody else's project over the network to be told what this
// machine already had.
func TestDocumentsAreAnsweredFromTheCache(t *testing.T) {
	browser := syncBrowser(t)

	if _, err := drainInto(t, browser,
		header(),
		put("docs/ops.md", "# Ops\n"),
		put("README.md", "# One\n"),
		put("docs/architecture.md", "# How\n")); err != nil {
		t.Fatalf("drain: %v", err)
	}

	got := browser.Documents(syncPeer, syncID)

	want := []string{"README.md", "docs/architecture.md", "docs/ops.md"}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	// Sorted, because the cache keeps its pages newest-read first and that is
	// not an order to show anybody a project in.
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("document %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// A project nothing has been synced of answers empty rather than failing, so
// that the caller can fall back to asking the publisher on a first run.
func TestDocumentsOfAnUnsyncedProjectIsEmpty(t *testing.T) {
	browser := syncBrowser(t)

	if got := browser.Documents(syncPeer, syncID); len(got) != 0 {
		t.Errorf("got %v, want nothing", got)
	}
}
