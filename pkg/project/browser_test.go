package project_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
)

// The publisher, as a browser reaches it: the real serving code over a
// directory on disk, with a switch for the state a phone spends most of its
// life in.
type publisher struct {
	root        string
	fingerprint string
	name        string
	publication *ladulasv1.Publication
	offline     bool
	// asked counts the exchanges that reached this machine, which is what a
	// reader is waiting for when a screen is slow.
	asked int
}

func (p *publisher) Publishers() []project.Publisher {
	return []project.Publisher{{Name: p.name, Fingerprint: p.fingerprint}}
}

func (p *publisher) Ask(
	ctx context.Context, fingerprint string,
	fn func(context.Context, ladulasv1connect.ProjectServiceClient) error,
) error {
	if p.offline {
		return errors.New("the machine could not be reached")
	}

	if fingerprint != p.fingerprint {
		return errors.New("no such peer")
	}

	p.asked++

	return fn(ctx, p)
}

func (p *publisher) ListProjects(
	_ context.Context, _ *connect.Request[ladulasv1.ListProjectsRequest],
) (*connect.Response[ladulasv1.ListProjectsResponse], error) {
	return connect.NewResponse(&ladulasv1.ListProjectsResponse{
		Projects: []*ladulasv1.Publication{p.publication},
	}), nil
}

func (p *publisher) ListDirectory(
	_ context.Context, req *connect.Request[ladulasv1.ListDirectoryRequest],
) (*connect.Response[ladulasv1.ListDirectoryResponse], error) {
	entries, next, total, err := project.ReadDir(
		p.root, req.Msg.GetPath(), req.Msg.GetFilter(), req.Msg.GetPageToken(),
		int(req.Msg.GetPageSize()), project.DefaultServing)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&ladulasv1.ListDirectoryResponse{
		Entries:       entries,
		NextPageToken: next,
		Total:         int32(total), //nolint:gosec // a test directory
	}), nil
}

func (p *publisher) SearchProjectFiles(
	_ context.Context, req *connect.Request[ladulasv1.SearchProjectFilesRequest],
) (*connect.Response[ladulasv1.SearchProjectFilesResponse], error) {
	entries, next, truncated, err := project.Search(
		p.root, req.Msg.GetQuery(), req.Msg.GetPageToken(),
		int(req.Msg.GetPageSize()), project.DefaultServing)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&ladulasv1.SearchProjectFilesResponse{
		Entries:       entries,
		NextPageToken: next,
		Truncated:     truncated,
	}), nil
}

func (p *publisher) FetchProjectFile(
	_ context.Context, req *connect.Request[ladulasv1.FetchProjectFileRequest],
) (*connect.Response[ladulasv1.FetchProjectFileResponse], error) {
	body, entry, err := project.ReadFile(
		p.root, req.Msg.GetPath(), project.DefaultServing)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&ladulasv1.FetchProjectFileResponse{
		File:    entry,
		Content: body,
	}), nil
}

func browser(t *testing.T) (*project.Browser, *publisher) {
	t.Helper()

	cache, err := project.OpenCache(
		t.TempDir(), reverseCipher{}, project.DefaultLimits)
	if err != nil {
		t.Fatalf("open the cache: %v", err)
	}

	source := &publisher{
		root:        browsable(t),
		fingerprint: "SHA256:headless",
		name:        "headless",
		publication: publicationOf("abcdefghij", "1111111111"),
	}

	return project.NewBrowser(cache, source), source
}

// TestReadingIsWhatKeeps is decision Q in one test: browsing a directory keeps
// nothing, opening a page keeps that page, and the page stays readable when the
// machine it came from does not answer.
func TestReadingIsWhatKeeps(t *testing.T) {
	ctx := context.Background()
	browsing, source := browser(t)

	listing, err := browsing.Directory(
		ctx, source.fingerprint, "abcdefghij", "docs", "", "", 0)
	if err != nil {
		t.Fatalf("list a directory: %v", err)
	}

	if !listing.Live || len(listing.Entries) == 0 {
		t.Fatalf("the directory came back %+v", listing)
	}

	// Nothing was kept: a listing is not a read.
	if _, ok := browsing.Cached(source.fingerprint, "abcdefghij"); ok {
		t.Error("listing a directory kept something")
	}

	page, err := browsing.File(
		ctx, source.fingerprint, "abcdefghij", "docs/deployment.md")
	if err != nil {
		t.Fatalf("read a page: %v", err)
	}

	if !page.Live || !strings.Contains(string(page.Content), "Deploying") {
		t.Fatalf("the page came back %+v", page)
	}

	source.offline = true

	kept, err := browsing.File(
		ctx, source.fingerprint, "abcdefghij", "docs/deployment.md")
	if err != nil {
		t.Fatalf("read the kept page: %v", err)
	}

	if kept.Live {
		t.Error("a page read with the publisher unreachable says it is live")
	}

	if !strings.Contains(string(kept.Content), "Deploying") {
		t.Errorf("the kept page came back as %q", kept.Content)
	}

	if kept.Commit != "1111111111" {
		t.Errorf("the kept page is recorded at %q", kept.Commit)
	}

	// And a page nobody read is not there, which is the price stated in §6.
	if _, err := browsing.File(
		ctx, source.fingerprint, "abcdefghij", "README.md",
	); err == nil {
		t.Error("a page nobody read was readable offline")
	}
}

// TestALiveListingCarriesThePublishersOwnAccount: a listing that came from the
// publisher brings the publisher's account of itself with it, taken in the same
// exchange (§6).
//
// The commit is why. A page read yesterday is kept along with the commit it was
// read at, and that is the right thing to say about the page — but a directory
// the publisher answered a moment ago is a directory of whatever the machine is
// standing on now, and heading it with yesterday's commit would describe the
// wrong tree.
func TestALiveListingCarriesThePublishersOwnAccount(t *testing.T) {
	ctx := context.Background()
	browsing, source := browser(t)

	if _, err := browsing.File(
		ctx, source.fingerprint, "abcdefghij", "docs/deployment.md",
	); err != nil {
		t.Fatalf("read a page: %v", err)
	}

	// Somebody commits on the publishing machine.
	source.publication = publicationOf("abcdefghij", "2222222222")

	for _, listing := range map[string]*project.Listing{
		"directory": mustList(t, func() (*project.Listing, error) {
			return browsing.Directory(
				ctx, source.fingerprint, "abcdefghij", "docs", "", "", 0)
		}),
		"search": mustList(t, func() (*project.Listing, error) {
			return browsing.Search(
				ctx, source.fingerprint, "abcdefghij", "deploy", "", 0)
		}),
	} {
		if listing.Publisher == nil {
			t.Fatal("a live listing carries no account of the publisher")
		}

		if !listing.Publisher.Live || listing.Publisher.Peer != "headless" {
			t.Errorf("the account is %+v", listing.Publisher)
		}

		if listing.Publisher.Project.GetCommit() != "2222222222" {
			t.Errorf("the listing is headed by commit %q",
				listing.Publisher.Project.GetCommit())
		}

		// What has been read here is still counted. It is the other half of the
		// sentence a browser puts under the name, and it is this instance's own
		// bookkeeping rather than anything the publisher said.
		if listing.Publisher.Kept != 1 {
			t.Errorf("the account counts %d kept pages", listing.Publisher.Kept)
		}
	}

	// A listing that did not come from the publisher has no such account to
	// give, and offering the kept one in its place is the thing this is for.
	source.offline = true

	offline, err := browsing.Directory(
		ctx, source.fingerprint, "abcdefghij", "docs", "", "", 0)
	if err != nil {
		t.Fatalf("list a directory offline: %v", err)
	}

	if offline.Publisher != nil {
		t.Errorf("an offline listing claims the publisher answered: %+v",
			offline.Publisher)
	}
}

func mustList(
	t *testing.T, read func() (*project.Listing, error),
) *project.Listing {
	t.Helper()

	listing, err := read()
	if err != nil {
		t.Fatalf("read a listing: %v", err)
	}

	return listing
}

// TestOfflineListingsAreWhatWasRead: an unreachable publisher does not make the
// browser an error message. It shows the pages that have a reader, and says
// that is what they are.
func TestOfflineListingsAreWhatWasRead(t *testing.T) {
	ctx := context.Background()
	browsing, source := browser(t)

	for _, name := range []string{"README.md", "docs/deployment.md"} {
		if _, err := browsing.File(
			ctx, source.fingerprint, "abcdefghij", name); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
	}

	source.offline = true

	root, err := browsing.Directory(
		ctx, source.fingerprint, "abcdefghij", "", "", "", 0)
	if err != nil {
		t.Fatalf("list the root: %v", err)
	}

	if root.Live || root.Err == "" {
		t.Errorf("an offline listing claims to be live: %+v", root)
	}

	var names []string
	for _, entry := range root.Entries {
		names = append(names, entry.GetName())
	}

	// The directory the read page is in, and the read page. Not main.go, not
	// .env, not anything else the real directory holds.
	if strings.Join(names, ",") != "docs,README.md" {
		t.Errorf("the offline root listed %v", names)
	}

	found, err := browsing.Search(
		ctx, source.fingerprint, "abcdefghij", "deploy", "", 0)
	if err != nil {
		t.Fatalf("search: %v", err)
	}

	if len(found.Entries) != 1 ||
		found.Entries[0].GetPath() != "docs/deployment.md" {
		t.Errorf("the offline search found %+v", found.Entries)
	}

	listed, err := browsing.List(ctx, "")
	if err != nil {
		t.Fatalf("list projects: %v", err)
	}

	if len(listed) != 1 || listed[0].Live || listed[0].Kept != 2 {
		t.Errorf("the offline listing is %+v", listed)
	}
}

// TestWithdrawnProjectsSaySo: a publisher that answers and does not name a
// project has stopped publishing it, which is a different thing from being
// asleep and is worth saying.
func TestWithdrawnProjectsSaySo(t *testing.T) {
	ctx := context.Background()
	browsing, source := browser(t)

	if _, err := browsing.File(
		ctx, source.fingerprint, "abcdefghij", "README.md"); err != nil {
		t.Fatalf("read the README: %v", err)
	}

	source.publication = publicationOf("zzzzzzzzzz", "1111111111")

	listed, err := browsing.List(ctx, "")
	if err != nil {
		t.Fatalf("list projects: %v", err)
	}

	if len(listed) != 2 {
		t.Fatalf("the listing has %d rows", len(listed))
	}

	var withdrawn int

	for _, item := range listed {
		if item.Withdrawn {
			withdrawn++
		}
	}

	if withdrawn != 1 {
		t.Errorf("%d projects are reported as withdrawn", withdrawn)
	}
}

// The three calls decision AP added. This fake exists to exercise the browser,
// which does not use them — the sync worker and the version list are their
// callers and have their own tests — so they are here to satisfy the client
// interface and say so rather than to pretend.

func (p *publisher) SyncProject(
	_ context.Context, _ *connect.Request[ladulasv1.SyncProjectRequest],
) (*connect.ServerStreamForClient[ladulasv1.SyncProjectEvent], error) {
	return nil, errors.New("this fake does not sync")
}

func (p *publisher) DocumentVersions(
	_ context.Context, _ *connect.Request[ladulasv1.DocumentVersionsRequest],
) (*connect.Response[ladulasv1.DocumentVersionsResponse], error) {
	return nil, errors.New("this fake keeps no versions")
}

func (p *publisher) FetchProjectVersion(
	_ context.Context, _ *connect.Request[ladulasv1.FetchProjectVersionRequest],
) (*connect.Response[ladulasv1.FetchProjectVersionResponse], error) {
	return nil, errors.New("this fake keeps no versions")
}

// What opening a project and reading a document costs in calls to the
// publishing machine.
//
// **This is the test that was missing, and both regressions it now covers were
// shipped.** Each was a call added in front of the thing being made faster
// rather than a slow call made quicker, which is exactly the shape no other
// test here could see: every one of them asserts what came back, and none
// asserts what it took to get it.
//
// The first: reading reached the cache only after a network call had failed, so
// the sync filled a cache that every open dialled past. The second: the file
// picker asked the publisher to walk its whole project before anything could be
// drawn, which was slower than the directory listing it replaced.
//
// Both look right in a diff and both are one number away in this test.
func TestOpeningASyncedProjectCostsNoCalls(t *testing.T) {
	reader, source := browser(t)

	ctx := context.Background()
	id := source.publication.GetProjectId()

	// Fill the cache the way anything does — the syncer over the wire, or a
	// read. What this is about is what happens afterwards, so it goes through
	// the read path rather than standing up a streaming fake.
	held := []string{"README.md", "docs/deployment.md", "docs/architecture.md"}

	for _, name := range held {
		if _, err := reader.File(ctx, source.fingerprint, id, name); err != nil {
			t.Fatalf("fill the cache with %s: %v", name, err)
		}
	}

	filled := source.asked

	if filled == 0 {
		t.Fatal("filling the cache reached the publisher no times")
	}

	// Now a person opening the project and reading it: the picker's list, a
	// document, that document again, and another one.
	documents := reader.Documents(source.fingerprint, id)

	if len(documents) != len(held) {
		t.Fatalf("the picker offers %v, want the %d documents held",
			documents, len(held))
	}

	for _, name := range []string{
		documents[0], documents[0], documents[len(documents)-1],
	} {
		if _, err := reader.File(ctx, source.fingerprint, id, name); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
	}

	if source.asked != filled {
		t.Errorf(
			"opening the project and reading three documents took %d calls to "+
				"the publisher, want none: the cache already had them",
			source.asked-filled)
	}
}

// A document nothing has synced is fetched, because there is nowhere else to
// get it — the cache-first read must not turn a miss into a blank page.
func TestADocumentThatWasNeverSyncedIsStillFetched(t *testing.T) {
	reader, source := browser(t)

	before := source.asked

	page, err := reader.File(context.Background(), source.fingerprint,
		source.publication.GetProjectId(), "README.md")
	if err != nil {
		t.Fatalf("read an unsynced document: %v", err)
	}

	if len(page.Content) == 0 {
		t.Error("the document came back empty")
	}

	if source.asked == before {
		t.Error("a cache miss did not reach the publisher, so it guessed")
	}
}

// And the second read of it is free, because the first one kept it.
func TestTheSecondReadOfADocumentIsFree(t *testing.T) {
	reader, source := browser(t)

	ctx := context.Background()
	id := source.publication.GetProjectId()

	if _, err := reader.File(ctx, source.fingerprint, id, "README.md"); err != nil {
		t.Fatalf("first read: %v", err)
	}

	after := source.asked

	if _, err := reader.File(ctx, source.fingerprint, id, "README.md"); err != nil {
		t.Fatalf("second read: %v", err)
	}

	if source.asked != after {
		t.Errorf("reading the same document twice took %d calls, want the "+
			"second to be free", source.asked-after+1)
	}
}
