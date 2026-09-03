package bridge_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/bridge"
	"github.com/hugowetterberg/ladulas/pkg/gitctx"
	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
)

// The doc browser and the deferred diff fetch, as the viewer meets them.

const publishedCommit = "937fa9137d03e1ca64111b86264e78dc907127e7"

const (
	publisher = "SHA256:headless"
	published = "abcdefghij"
)

// browsedProjects is a publisher and the pages that have been read of it, which
// is the whole of what the bridge sees (decision Q). Taking it offline is what
// a phone spends most of its life being.
type browsedProjects struct {
	files   map[string]string
	commit  string
	offline bool
	read    map[string]time.Time
}

func newBrowsedProjects() *browsedProjects {
	return &browsedProjects{
		files: map[string]string{
			"README.md": "# Ladulås\n\nSee [the design](docs/design.md) " +
				"and [the site](https://example.com).\n",
			"docs/design.md": "# Design\n\n- pinned TLS\n- one engine\n",
		},
		commit: publishedCommit,
		read:   map[string]time.Time{},
	}
}

func (b *browsedProjects) publication() *ladulasv1.Publication {
	return &ladulasv1.Publication{
		ProjectId:   published,
		Name:        "ladulas",
		Path:        "/srv/build/ladulas",
		OriginUrl:   "git@github.com:example/ladulas.git",
		Branch:      "main",
		Commit:      b.commit,
		PublishedAt: timestamppb.New(time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)),
	}
}

func (b *browsedProjects) overview() *project.Overview {
	view := &project.Overview{
		Fingerprint: publisher,
		Peer:        "headless",
		Project:     b.publication(),
		Live:        !b.offline,
		Kept:        len(b.read),
	}

	for _, when := range b.read {
		if when.After(view.Read) {
			view.Read = when
		}
	}

	return view
}

// answered is what the browser hangs on a listing that came from the publisher:
// the machine's account of itself, taken in the same exchange. A listing that
// did not come from it has none, which is what the offline case is.
func (b *browsedProjects) answered() *project.Overview {
	if b.offline {
		return nil
	}

	return b.overview()
}

func (b *browsedProjects) List(
	_ context.Context, _ string,
) ([]*project.Overview, error) {
	return []*project.Overview{b.overview()}, nil
}

func (b *browsedProjects) Open(
	_ context.Context, _, _ string,
) (*project.Overview, error) {
	return b.overview(), nil
}

func (b *browsedProjects) Directory(
	_ context.Context, _, _, dir, filter, _ string, _ int,
) (*project.Listing, error) {
	listing := &project.Listing{
		Path: dir, Live: !b.offline, Publisher: b.answered(),
	}

	if b.offline {
		listing.Err = "the headless box is not answering"
	}

	seen := map[string]bool{}

	for name := range b.files {
		if b.offline && b.read[name].IsZero() {
			continue
		}

		if !strings.HasPrefix(name, prefixOf(dir)) {
			continue
		}

		rest := strings.TrimPrefix(name, prefixOf(dir))

		if head, _, nested := strings.Cut(rest, "/"); nested {
			if seen[head] {
				continue
			}

			seen[head] = true

			listing.Entries = append(listing.Entries, &ladulasv1.ProjectEntry{
				Name: head, Path: path.Join(dir, head), Directory: true,
			})

			continue
		}

		if filter != "" && !strings.Contains(rest, filter) {
			continue
		}

		listing.Entries = append(listing.Entries, &ladulasv1.ProjectEntry{
			Name: rest, Path: name, Size: int64(len(b.files[name])),
			Readable: true,
		})
	}

	sort.Slice(listing.Entries, func(i, j int) bool {
		return listing.Entries[i].GetPath() < listing.Entries[j].GetPath()
	})

	listing.Total = len(listing.Entries)

	return listing, nil
}

func prefixOf(dir string) string {
	if dir == "" {
		return ""
	}

	return dir + "/"
}

func (b *browsedProjects) Search(
	_ context.Context, _, _, query, _ string, _ int,
) (*project.Listing, error) {
	listing := &project.Listing{Live: !b.offline, Publisher: b.answered()}

	for name := range b.files {
		if strings.Contains(name, query) {
			listing.Entries = append(listing.Entries, &ladulasv1.ProjectEntry{
				Name: path.Base(name), Path: name, Readable: true,
			})
		}
	}

	listing.Total = len(listing.Entries)

	return listing, nil
}

func (b *browsedProjects) File(
	_ context.Context, _, _, name string,
) (*project.Page, error) {
	body, ok := b.files[name]
	if !ok {
		return nil, project.ErrNoSuchFile
	}

	if b.offline {
		when, read := b.read[name]
		if !read {
			return nil, project.ErrNoSuchFile
		}

		return &project.Page{
			Path: name, Content: []byte(body), ReadAt: when,
			Commit: b.commit,
		}, nil
	}

	b.read[name] = time.Now()

	return &project.Page{
		Path: name, Content: []byte(body), Live: true, Commit: b.commit,
	}, nil
}

func (b *browsedProjects) Cached(
	_, projectID string,
) (*project.Overview, bool) {
	if projectID != published || len(b.read) == 0 {
		return nil, false
	}

	view := b.overview()
	view.Live = false

	return view, true
}

// projectFixture is a session with a doc browser and a diff fetch behind it.
type projectFixture struct {
	*fixture

	projects *browsedProjects
	fetched  []string
	diff     *ladulasv1.GitDiff
	fetchErr error
}

func newProjectFixture(t *testing.T) *projectFixture {
	t.Helper()

	host := &presenter{}
	projects := newBrowsedProjects()

	out := &projectFixture{projects: projects}

	session := bridge.NewSession(bridge.Options{
		Name:        "workstation",
		Fingerprint: "SHA256:instance",
		Presenter:   host,
		Projects:    projects,
		FetchDiff: func(
			_ context.Context, _ *approval.Request, path string,
		) (*ladulasv1.GitDiff, error) {
			out.fetched = append(out.fetched, path)

			if out.fetchErr != nil {
				return nil, out.fetchErr
			}

			return out.diff, nil
		},
	})

	server := httptest.NewServer(session.Handler())
	t.Cleanup(server.Close)

	out.fixture = &fixture{session: session, presenter: host, server: server}

	return out
}

func (f *projectFixture) post(t *testing.T, path, body string) (int, []byte) {
	t.Helper()

	resp, err := f.server.Client().Post(
		f.server.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return resp.StatusCode, out
}

// browse builds one of the browsing URLs: a project is named by the peer that
// publishes it and the identifier both ends derive, never by a handle this side
// invented (§6).
func browse(verb string, params map[string]string) string {
	query := url.Values{"peer": {publisher}, "project": {published}}

	for name, value := range params {
		query.Set(name, value)
	}

	return "/api/v1/projects/" + verb + "?" + query.Encode()
}

// TestTheDocBrowserServesParsedMarkdown: the bundle gets blocks, never a
// markdown source it would have to parse (§12).
func TestTheDocBrowserServesParsedMarkdown(t *testing.T) {
	f := newProjectFixture(t)

	status, body := f.get(t, "/api/v1/projects")
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	var listing []bridge.ProjectView

	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	if len(listing) != 1 || listing[0].Name != "ladulas" {
		t.Fatalf("the listing is %v", listing)
	}

	if listing[0].Fingerprint != publisher || listing[0].ProjectID != published {
		t.Errorf("the listing names the project as %+v", listing[0])
	}

	status, body = f.get(t, browse("file", map[string]string{"path": "README.md"}))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	var page bridge.ProjectPageView

	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	if page.Title != "Ladulås" {
		t.Errorf("the page title is %q", page.Title)
	}

	if !page.Live {
		t.Error("a page read from a reachable publisher is not marked live")
	}

	if len(page.Blocks) == 0 {
		t.Fatal("the page carries no blocks")
	}

	// The link inside the project survived as a link; the one to the open
	// internet did not, because a published document may not navigate an
	// approver's window anywhere (§6).
	var links, plain int

	for _, block := range page.Blocks {
		for _, span := range block.Spans {
			switch {
			case span.Kind == project.SpanLink:
				links++

				if span.Target != "docs/design.md" {
					t.Errorf("a link points at %q", span.Target)
				}
			case strings.Contains(span.Text, "https://example.com"):
				plain++
			}
		}
	}

	if links != 1 {
		t.Errorf("%d links survived", links)
	}

	if plain != 1 {
		t.Error("the external link was not shown as text")
	}

	// And the raw markdown never crosses: the response is blocks.
	if bytes.Contains(body, []byte("# Ladulås")) {
		t.Error("the unparsed markdown was sent to the viewer")
	}
}

// TestADirectoryIsListedAPageAtATime: browsing is a pull, and what comes back
// carries the project it belongs to so a browser needs one call rather than
// two.
func TestADirectoryIsListedAPageAtATime(t *testing.T) {
	f := newProjectFixture(t)

	status, body := f.get(t, browse("directory", nil))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	var listing bridge.ProjectListingView

	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	if listing.Name != "ladulas" || !listing.Live {
		t.Errorf("the listing header is %+v", listing.ProjectView)
	}

	var names []string
	for _, entry := range listing.Entries {
		names = append(names, entry.Name)
	}

	if strings.Join(names, ",") != "README.md,docs" {
		t.Errorf("the root listed %v", names)
	}

	status, body = f.get(t, browse("search", map[string]string{"q": "design"}))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	if len(listing.Entries) != 1 || listing.Entries[0].Path != "docs/design.md" {
		t.Errorf("the search found %+v", listing.Entries)
	}
}

// TestAnUnreachablePublisherShowsWhatWasRead is the offline half of decision Q,
// and the whole of what it promises: the pages that have a reader, labelled as
// that rather than as the directory.
// A listing the publisher answered is headed by what the publisher said, even
// once pages of it have been read here (§6).
//
// The two provenances are the whole of decision Q and they are easy to cross:
// what has been read here is the only account of a project that is always
// available, so it is the tempting one to head every screen with — and its
// sentence says the machine could not be reached, which over a directory the
// machine just answered is simply false.
func TestALiveListingIsHeadedByThePublisher(t *testing.T) {
	f := newProjectFixture(t)

	// Read a page, so that there is a kept account of the project to prefer by
	// mistake.
	status, body := f.get(t, browse("file", map[string]string{"path": "README.md"}))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	for _, verb := range []string{"directory", "search"} {
		status, body = f.get(t, browse(verb, map[string]string{"q": "design"}))
		if status != http.StatusOK {
			t.Fatalf("%s: status %d: %s", verb, status, body)
		}

		var listing bridge.ProjectListingView

		if err := json.Unmarshal(body, &listing); err != nil {
			t.Fatalf("%s: decode: %v\n%s", verb, err, body)
		}

		if !listing.Live {
			t.Fatalf("%s: the listing is not live", verb)
		}

		if strings.Contains(listing.State, "could not be reached") {
			t.Errorf("%s: a live listing says %q", verb, listing.State)
		}

		if !strings.Contains(listing.State, "Read from headless") {
			t.Errorf("%s: the listing does not say where it came from: %q",
				verb, listing.State)
		}

		// The pages read here are still worth counting — they are what stays
		// readable when the machine goes away — but they are the second half of
		// the sentence rather than the first.
		if listing.Kept != 1 {
			t.Errorf("%s: the listing counts %d kept pages", verb, listing.Kept)
		}

		if listing.Name != "ladulas" || listing.Commit != publishedCommit[:10] {
			t.Errorf("%s: the header is %s at %q", verb, listing.Name, listing.Commit)
		}
	}
}

func TestAnUnreachablePublisherShowsWhatWasRead(t *testing.T) {
	f := newProjectFixture(t)

	status, body := f.get(t, browse("file", map[string]string{"path": "docs/design.md"}))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	f.projects.offline = true

	status, body = f.get(t, browse("directory", nil))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	var listing bridge.ProjectListingView

	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	if listing.Live {
		t.Error("an offline listing claims to be live")
	}

	if !strings.Contains(listing.Note, "read here") {
		t.Errorf("the listing does not say what it is: %q", listing.Note)
	}

	if !strings.Contains(listing.Error, "not answering") {
		t.Errorf("the reader is not told why: %q", listing.Error)
	}

	// The page that was read is still readable, and says when it was read.
	status, body = f.get(t, browse("file", map[string]string{"path": "docs/design.md"}))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	var page bridge.ProjectPageView

	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	if page.Live || !strings.Contains(page.Note, "Read here") {
		t.Errorf("the kept page says %q", page.Note)
	}

	// The one nobody opened is not, which is the price §6 states rather than
	// glosses.
	status, _ = f.get(t, browse("file", map[string]string{"path": "README.md"}))
	if status != http.StatusNotFound {
		t.Errorf("a page nobody read answered with %d", status)
	}
}

// pagedProjects is a publisher that answers a directory in pages, most of them
// full of files it will not hand over. It is the shape the filter has to survive
// (§6): the paging is the publisher's, so dropping entries here can empty a page
// that still has a token in it.
type pagedProjects struct {
	pages map[string]*project.Listing
	asked []string
}

func newPagedProjects() *pagedProjects {
	return &pagedProjects{pages: map[string]*project.Listing{
		"": {
			Live: true, Total: 6, Next: "page-2",
			Entries: []*ladulasv1.ProjectEntry{
				{Name: "main.go", Path: "main.go", Size: 400,
					Reason: "not a kind this instance offers to read"},
				{Name: "notes.txt", Path: "notes.txt", Size: 20,
					Reason: "not a kind this instance offers to read"},
			},
		},
		"page-2": {
			Live: true, Total: 6, Next: "page-3",
			Entries: []*ladulasv1.ProjectEntry{
				{Name: "vendor.lock", Path: "vendor.lock",
					Reason: "not a kind this instance offers to read"},
			},
		},
		"page-3": {
			Live: true, Total: 6, Next: "page-4",
			Entries: []*ladulasv1.ProjectEntry{
				{Name: "docs", Path: "docs", Directory: true},
				// A folder the publisher has already looked inside of: there is
				// nothing beneath it that it would hand over, so it is a row that
				// opens onto an empty screen.
				{Name: "images", Path: "images", Directory: true,
					NothingReadable: true},
				{Name: "README.md", Path: "README.md", Size: 30, Readable: true},
			},
		},
		"page-4": {Live: true, Total: 6},
	}}
}

func (p *pagedProjects) List(
	_ context.Context, _ string,
) ([]*project.Overview, error) {
	return nil, nil
}

func (p *pagedProjects) Open(
	_ context.Context, _, _ string,
) (*project.Overview, error) {
	return &project.Overview{
		Fingerprint: publisher, Peer: "headless", Live: true,
		Project: &ladulasv1.Publication{ProjectId: published, Name: "ladulas"},
	}, nil
}

func (p *pagedProjects) Directory(
	_ context.Context, _, _, _, _, token string, _ int,
) (*project.Listing, error) {
	p.asked = append(p.asked, token)

	page, ok := p.pages[token]
	if !ok {
		return nil, project.ErrNoSuchFile
	}

	return page, nil
}

func (p *pagedProjects) Search(
	_ context.Context, _, _, _, _ string, _ int,
) (*project.Listing, error) {
	return &project.Listing{Live: true}, nil
}

func (p *pagedProjects) File(
	_ context.Context, _, _, _ string,
) (*project.Page, error) {
	return nil, project.ErrNoSuchFile
}

func (p *pagedProjects) Cached(_, _ string) (*project.Overview, bool) {
	return nil, false
}

// TestABrowserCanAskForOnlyWhatItCanShow is the phone's half of §6's split
// between listing and showing. The desktop draws the greyed-out row and the
// reason beside it; a phone asks not to be handed forty of them, and the reading
// on is here rather than in every host that asks.
func TestABrowserCanAskForOnlyWhatItCanShow(t *testing.T) {
	projects := newPagedProjects()

	session := bridge.NewSession(bridge.Options{
		Name:        "phone",
		Fingerprint: "SHA256:instance",
		Presenter:   &presenter{},
		Projects:    projects,
	})

	server := httptest.NewServer(session.Handler())
	t.Cleanup(server.Close)

	f := &fixture{session: session, server: server}

	// Without the flag nothing is hidden, which is what keeps the desktop
	// honest about what a project contains.
	status, body := f.get(t, browse("directory", nil))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	var listing bridge.ProjectListingView

	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	if len(listing.Entries) != 2 || listing.Entries[0].Readable {
		t.Fatalf("the unfiltered page is %+v", listing.Entries)
	}

	if listing.Entries[0].Reason == "" {
		t.Error("an entry that is not offered does not say why")
	}

	// With it, the first two pages hold nothing this phone could draw, so the
	// answer is the page that does — and it is one call from the browser.
	status, body = f.get(t, browse("directory", map[string]string{
		"only": "readable",
	}))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	var names []string
	for _, entry := range listing.Entries {
		names = append(names, entry.Name)
	}

	// The folder with something in it, and the file. Not the folder that leads
	// nowhere, and not the four files the publisher would refuse.
	if strings.Join(names, ",") != "docs,README.md" {
		t.Errorf("the filtered listing holds %v", names)
	}

	if listing.Next != "page-4" {
		t.Errorf("the token carries on from %q", listing.Next)
	}

	if want := []string{"", "", "page-2", "page-3"}; strings.Join(projects.asked, ",") !=
		strings.Join(want, ",") {
		t.Errorf("the publisher was asked for %v", projects.asked)
	}
}

// remoteGitRequest is a request as it arrives from a paired peer, naming the
// project it belongs to.
func remoteGitRequest(t *testing.T, id, projectID, parent string) *approval.Request {
	t.Helper()

	object := "tree e95bc8444bcd06692c882451e807e45dfe27b5ba\n" +
		"parent " + parent + "\n" +
		"author A U Thor <author@example.test> 1786209283 +0200\n" +
		"committer A U Thor <author@example.test> 1786209283 +0200\n" +
		"\n" +
		"tighten the socket permissions\n"

	digest, err := sshsig.Hash(sshsig.HashSHA512, []byte(object))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	msg := &ladulasv1.ApprovalRequest{
		RequestId: id,
		Kind:      ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
		Key:       &ladulasv1.KeyRef{Label: "work", Fingerprint: "SHA256:workkey"},
		Requester: &ladulasv1.RequesterInfo{
			InstanceId: "SHA256:headless",
			Name:       "headless",
			Headless:   true,
		},
		Operation: &ladulasv1.ApprovalRequest_Sshsig{
			Sshsig: &ladulasv1.SshsigRequest{
				Namespace:     "git",
				HashAlgorithm: sshsig.HashSHA512,
				MessageDigest: digest,
				GitContext: &ladulasv1.GitContext{
					RepositoryPath: "/srv/build/ladulas",
					Branch:         "main",
					ProjectId:      projectID,
					Object:         []byte(object),
					Diff: &ladulasv1.GitDiff{
						FilesChanged:   3,
						Truncated:      true,
						TruncationNote: "2 more files are not shown",
						Files: []*ladulasv1.GitDiffFile{{
							NewPath: "agent/server.go", Status: "modified",
						}},
					},
				},
			},
		},
	}

	if problem := gitctx.VerifyRequest(msg); problem != "" {
		t.Fatalf("the fixture does not verify: %s", problem)
	}

	return &approval.Request{
		Msg:    msg,
		Prompt: approval.RenderPrompt(msg),
	}
}

// TestAPromptLinksToTheDocumentationAndSaysHowStaleItIs is §6's labelling: the
// prompt says which state the documentation describes rather than leaving an
// approver to assume it is this one — and it links to the project either way,
// because browsing is a pull and the machine that is asking is by definition
// awake (decision Q).
func TestAPromptLinksToTheDocumentationAndSaysHowStaleItIs(t *testing.T) {
	f := newProjectFixture(t)

	// Nothing has been read yet, which is the ordinary state and still a way in.
	req := remoteGitRequest(t, "req-unread", published, publishedCommit)
	answers := f.decide(t, req)

	view := f.requestView(t, "req-unread")

	if view.Project == nil || view.Project.Known {
		t.Fatalf("an unread project is reported as held: %+v", view.Project)
	}

	if view.Project.Fingerprint != publisher || view.Project.ProjectID != published {
		t.Errorf("the prompt cannot link to the project: %+v", view.Project)
	}

	f.session.Deny("req-unread", "done")
	<-answers

	// Read a page, and the label is what §6 asks for.
	if status, body := f.get(t, browse("file", map[string]string{
		"path": "README.md",
	})); status != http.StatusOK {
		t.Fatalf("read the README: %d %s", status, body)
	}

	req = remoteGitRequest(t, "req-fresh", published, publishedCommit)
	answers = f.decide(t, req)

	view = f.requestView(t, "req-fresh")

	if view.Project == nil || !view.Project.Known {
		t.Fatalf("the prompt does not name the project: %+v", view.Project)
	}

	if view.Project.Stale {
		t.Errorf("a change built on the commit the page was read at is marked "+
			"stale: %q", view.Project.Note)
	}

	if !strings.Contains(view.Project.Note, "built on") {
		t.Errorf("the note reads %q", view.Project.Note)
	}

	f.session.Deny("req-fresh", "done")
	<-answers

	// And one built on something else says so.
	req = remoteGitRequest(t, "req-stale", published,
		"0000000000000000000000000000000000000000")
	answers = f.decide(t, req)

	view = f.requestView(t, "req-stale")

	if view.Project == nil || !view.Project.Stale {
		t.Fatalf("a change built elsewhere is not marked stale: %+v", view.Project)
	}

	f.session.Deny("req-stale", "done")
	<-answers
}

func (f *projectFixture) requestView(t *testing.T, id string) bridge.RequestView {
	t.Helper()

	status, body := f.get(t, "/api/v1/requests/"+id)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	var view bridge.RequestView

	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	return view
}

// TestTheRestOfADiffCanBeFetched is M2's deferred fetch-back (§5): the caps are
// a display decision, not a limit on what an approver may see.
func TestTheRestOfADiffCanBeFetched(t *testing.T) {
	f := newProjectFixture(t)
	f.diff = &ladulasv1.GitDiff{FilesChanged: 3, Insertions: 40, Deletions: 12}

	req := remoteGitRequest(t, "req-diff", "abcdefghij", publishedCommit)
	answers := f.decide(t, req)

	status, body := f.post(t, "/api/v1/requests/req-diff/diff", `{"path":""}`)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}

	var view bridge.DiffView

	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	if view.FilesChanged != 3 || view.Insertions != 40 {
		t.Errorf("the fetched diff is %+v", view)
	}

	if len(f.fetched) != 1 || f.fetched[0] != "" {
		t.Errorf("the host was asked for %v", f.fetched)
	}

	f.session.Deny("req-diff", "done")
	<-answers

	// A request that is no longer waiting cannot be asked about, which is the
	// same bound the peer side enforces.
	status, _ = f.post(t, "/api/v1/requests/req-diff/diff", `{"path":""}`)
	if status != http.StatusNotFound {
		t.Errorf("a settled request answered a diff fetch with %d", status)
	}
}

// The two calls decision AP added. Both fakes get them so that the existing
// tests keep compiling; the version list and the comparison have their own
// tests over the real browser, where there is a publisher to ask.

func (b *browsedProjects) Versions(
	_ context.Context, _, _, _ string, _ int,
) (*project.VersionList, error) {
	return &project.VersionList{}, nil
}

func (b *browsedProjects) Read(
	ctx context.Context, fingerprint, projectID, name string,
	_ []byte, _ string,
) (*project.DocumentAt, error) {
	page, err := b.File(ctx, fingerprint, projectID, name)
	if err != nil {
		return nil, err
	}

	return project.Composed(name, page, nil), nil
}

func (p *pagedProjects) Versions(
	_ context.Context, _, _, _ string, _ int,
) (*project.VersionList, error) {
	return &project.VersionList{}, nil
}

func (p *pagedProjects) Read(
	_ context.Context, _, _, _ string, _ []byte, _ string,
) (*project.DocumentAt, error) {
	return nil, project.ErrNoSuchFile
}
