package project

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
)

// Browsing a published project, from the approver's side (decision Q).
//
// Every question goes to the machine that owns the answer, and the answer is
// kept only when it is a page somebody opened. So there are two states for
// every surface here rather than one: what the publisher says right now, and
// what was true when somebody last read it. Both are real states and the second
// is not a failure — a phone is offline by construction — so nothing here
// treats an unreachable publisher as an error to report and stop at. It says
// what it has, and says where it came from.

// Source is how a browser reaches the machines it reads from. peer.Node
// implements it; an instance with peering switched off has none, and browses
// only what it has already read.
type Source interface {
	// Publishers is the peers whose documentation this instance may read: the
	// ones that ask it for approvals.
	Publishers() []Publisher
	// Ask runs one exchange against one peer. The client it hands over is
	// already capped and already talking over the pinned-TLS channel.
	Ask(
		ctx context.Context, fingerprint string,
		fn func(context.Context, ladulasv1connect.ProjectServiceClient) error,
	) error
}

// Publisher is a peer that may have something to read.
type Publisher struct {
	Name        string
	Fingerprint string
}

// Overview is one project as a browser lists it.
type Overview struct {
	Fingerprint string
	Peer        string
	Project     *ladulasv1.Publication
	// Live says the publisher answered just now, so the commit and the branch
	// are what that machine is standing on rather than what it was standing on
	// when somebody last read a page.
	Live bool
	// Withdrawn is set when the publisher answered and did not name this
	// project: it has stopped publishing, and what is left here is what was
	// read before it did.
	Withdrawn bool
	// Kept is how many pages have been read here, and Read is when the last one
	// was.
	Kept int
	Read time.Time
	// Err is why the publisher could not be asked, in the words to show.
	Err string
}

// Listing is one directory, or one search, as a browser shows it.
type Listing struct {
	Path      string
	Entries   []*ladulasv1.ProjectEntry
	Next      string
	Total     int
	Truncated bool
	// Live says this came from the publisher. When it is false the entries are
	// the pages that have been read here, which is a different and much shorter
	// list than the directory — and saying so is the whole of being honest
	// about it.
	Live bool
	Err  string
	// Publisher is the publishing machine's account of itself, taken in the same
	// exchange as the entries, and nil when they did not come from it.
	//
	// It is here because the two halves of what a browser puts above a listing
	// have two provenances, and a header assembled out of the pages somebody
	// read once would put the commit those were read at over a directory the
	// publisher answered just now. Both are true statements and stitching them
	// together makes a false one (§6).
	Publisher *Overview
}

// Page is one document, and where it came from.
type Page struct {
	Path     string
	Content  []byte
	Modified time.Time
	ReadAt   time.Time
	// Commit is the commit the project was at when this was read.
	Commit string
	Live   bool
	Err    string
	// FullSize is the whole document's size when Content is only the start of
	// it, and zero when the page is all of it (decision AP). The publisher is
	// the only side that can say, because it is the side that did the cutting.
	FullSize int64
}

// Browser reads published projects and keeps what it has read.
type Browser struct {
	cache  *Cache
	source Source
}

// NewBrowser ties the two halves together. The source may be nil, which is an
// instance that can still read what it has read before.
func NewBrowser(cache *Cache, source Source) *Browser {
	return &Browser{cache: cache, source: source}
}

// List is every project this instance's requesters publish.
//
// The publishers are asked in parallel because one that is asleep should not
// hold up one that is awake, and each of them contributes what it can: a live
// answer, or the projects something has been read of, or a line saying why it
// could not be asked.
func (b *Browser) List(
	ctx context.Context, fingerprint string,
) ([]*Overview, error) {
	cached, err := b.cache.List()
	if err != nil {
		return nil, err
	}

	held := map[string]*ladulasv1.CachedProject{}

	for _, item := range cached {
		if fingerprint != "" && item.GetPeerFingerprint() != fingerprint {
			continue
		}

		held[item.GetKey()] = item
	}

	var (
		mu   sync.Mutex
		out  []*Overview
		seen = map[string]bool{}
		wg   sync.WaitGroup
	)

	for _, publisher := range b.publishers(fingerprint) {
		wg.Add(1)

		go func() {
			defer wg.Done()

			live, err := b.ask(ctx, publisher)

			mu.Lock()
			defer mu.Unlock()

			for _, item := range live {
				seen[Key(publisher.Fingerprint, item.GetProjectId())] = true
			}

			out = append(out, b.merge(publisher, live, held, err)...)
		}()
	}

	wg.Wait()

	// A project read from a peer this instance is no longer paired with is
	// still readable: forgetting it is what revoking the pairing does, and
	// until somebody does that it is a thing on the disk with a reader.
	for key, item := range held {
		if seen[key] || b.publisher(item.GetPeerFingerprint()) != nil {
			continue
		}

		out = append(out, fromCache(item, false))
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Peer != out[j].Peer {
			return out[i].Peer < out[j].Peer
		}

		return out[i].Project.GetName() < out[j].Project.GetName()
	})

	return out, nil
}

// merge turns one publisher's answer, or its silence, into rows.
func (b *Browser) merge(
	publisher Publisher,
	live []*ladulasv1.Publication,
	held map[string]*ladulasv1.CachedProject,
	askErr error,
) []*Overview {
	var out []*Overview

	for _, item := range live {
		view := &Overview{
			Fingerprint: publisher.Fingerprint,
			Peer:        publisher.Name,
			Project:     item,
			Live:        true,
		}

		if cached := held[Key(publisher.Fingerprint, item.GetProjectId())]; cached != nil {
			view.Kept = len(cached.GetFiles())
			view.Read = cached.GetLastReadAt().AsTime()
		}

		out = append(out, view)
	}

	for _, cached := range held {
		if cached.GetPeerFingerprint() != publisher.Fingerprint {
			continue
		}

		if hasProject(live, cached.GetProject().GetProjectId()) {
			continue
		}

		// Answered and did not name it, or did not answer at all. The two are
		// genuinely different things to say about a project somebody has read.
		view := fromCache(cached, askErr == nil)

		if askErr != nil {
			view.Err = askErr.Error()
		}

		out = append(out, view)
	}

	if askErr != nil && len(out) == 0 {
		out = append(out, &Overview{
			Fingerprint: publisher.Fingerprint,
			Peer:        publisher.Name,
			Project:     &ladulasv1.Publication{Name: publisher.Name},
			Err:         askErr.Error(),
		})
	}

	return out
}

// Open is one project's identity, live if the publisher answers.
func (b *Browser) Open(
	ctx context.Context, fingerprint, projectID string,
) (*Overview, error) {
	publisher := b.publisher(fingerprint)
	cached, cacheErr := b.cache.Find(fingerprint, projectID)

	if publisher == nil {
		if cacheErr != nil {
			return nil, cacheErr
		}

		return fromCache(cached, false), nil
	}

	var found *ladulasv1.Publication

	err := b.source.Ask(ctx, fingerprint, func(
		ctx context.Context, client ladulasv1connect.ProjectServiceClient,
	) error {
		publication, err := publication(ctx, client, projectID)
		if err != nil {
			return err
		}

		found = publication

		return nil
	})
	if err != nil {
		if cacheErr != nil {
			return nil, fmt.Errorf(
				"%s could not be asked about that project: %w",
				publisher.Name, err)
		}

		view := fromCache(cached, false)
		view.Err = err.Error()

		return view, nil
	}

	if cacheErr != nil {
		cached = nil
	}

	return liveOverview(*publisher, found, cached), nil
}

// overviewOf is liveOverview for a caller that has not already read the cache.
func (b *Browser) overviewOf(
	publisher Publisher, projectID string, found *ladulasv1.Publication,
) *Overview {
	cached, err := b.cache.Find(publisher.Fingerprint, projectID)
	if err != nil {
		cached = nil
	}

	return liveOverview(publisher, found, cached)
}

// liveOverview is a publisher's answer about one project, with what has been
// read of it here counted in. The publication is the machine's account of
// itself as of this exchange; the count and the date are this instance's own
// books, and neither is worth a call to anybody.
func liveOverview(
	publisher Publisher,
	found *ladulasv1.Publication,
	cached *ladulasv1.CachedProject,
) *Overview {
	view := &Overview{
		Fingerprint: publisher.Fingerprint,
		Peer:        publisher.Name,
		Project:     found,
		Live:        true,
	}

	if cached != nil {
		view.Kept = len(cached.GetFiles())
		view.Read = cached.GetLastReadAt().AsTime()
	}

	return view
}

// Cached is what has been read of a project, without asking anybody.
//
// It is what an approval card uses: a prompt is drawn while somebody is waiting
// and must not be made to wait on a machine that may be asleep (§6).
func (b *Browser) Cached(fingerprint, projectID string) (*Overview, bool) {
	cached, err := b.cache.Find(fingerprint, projectID)
	if err != nil {
		return nil, false
	}

	return fromCache(cached, false), true
}

// Directory is one page of one directory, from the publisher if it answers and
// from what has been read here if it does not.
//
// The entries and the identity are one exchange rather than two, for the reason
// File takes them together: a listing that came from the publisher is shown
// under the publisher's branch and commit, and asking for those separately would
// be a second call to a machine that has just proved it is awake — or, worse, a
// header quietly filled in from the last time somebody read a page.
func (b *Browser) Directory(
	ctx context.Context, fingerprint, projectID, dir, filter, token string,
	size int,
) (*Listing, error) {
	if dir != "" {
		if err := CheckPath(dir); err != nil {
			return nil, err
		}
	}

	publisher := b.publisher(fingerprint)
	if publisher == nil {
		return b.keptListing(fingerprint, projectID, dir, filter, ""), nil
	}

	var listing *Listing

	err := b.source.Ask(ctx, fingerprint, func(
		ctx context.Context, client ladulasv1connect.ProjectServiceClient,
	) error {
		found, err := publication(ctx, client, projectID)
		if err != nil {
			return err
		}

		resp, err := client.ListDirectory(ctx, connect.NewRequest(
			&ladulasv1.ListDirectoryRequest{
				Project:   projectID,
				Path:      dir,
				Filter:    filter,
				PageToken: token,
				PageSize:  int32(size), //nolint:gosec // a page size from a viewer
			}))
		if err != nil {
			return err //nolint:wrapcheck // the source wraps it with the address
		}

		listing = &Listing{
			Path:      dir,
			Entries:   resp.Msg.GetEntries(),
			Next:      resp.Msg.GetNextPageToken(),
			Total:     int(resp.Msg.GetTotal()),
			Live:      true,
			Publisher: b.overviewOf(*publisher, projectID, found),
		}

		return nil
	})
	if err != nil {
		return b.keptListing(fingerprint, projectID, dir, filter, err.Error()), nil
	}

	return listing, nil
}

// Search finds files by name across a project, and carries the same header its
// directories do.
func (b *Browser) Search(
	ctx context.Context, fingerprint, projectID, query, token string, size int,
) (*Listing, error) {
	publisher := b.publisher(fingerprint)
	if publisher == nil {
		return b.keptSearch(fingerprint, projectID, query, ""), nil
	}

	var listing *Listing

	err := b.source.Ask(ctx, fingerprint, func(
		ctx context.Context, client ladulasv1connect.ProjectServiceClient,
	) error {
		found, err := publication(ctx, client, projectID)
		if err != nil {
			return err
		}

		resp, err := client.SearchProjectFiles(ctx, connect.NewRequest(
			&ladulasv1.SearchProjectFilesRequest{
				Project:   projectID,
				Query:     query,
				PageToken: token,
				PageSize:  int32(size), //nolint:gosec // a page size from a viewer
			}))
		if err != nil {
			return err //nolint:wrapcheck // the source wraps it with the address
		}

		listing = &Listing{
			Entries:   resp.Msg.GetEntries(),
			Next:      resp.Msg.GetNextPageToken(),
			Total:     len(resp.Msg.GetEntries()),
			Truncated: resp.Msg.GetTruncated(),
			Live:      true,
			Publisher: b.overviewOf(*publisher, projectID, found),
		}

		return nil
	})
	if err != nil {
		return b.keptSearch(fingerprint, projectID, query, err.Error()), nil
	}

	return listing, nil
}

// File fetches one page and keeps it, falling back to the copy it kept.
//
// The fetch and the identity are one exchange rather than two, so the commit
// recorded beside the page is the commit the publisher was at when the page was
// read — which is what "the documentation you have is from before this change"
// is computed against later.
func (b *Browser) File(
	ctx context.Context, fingerprint, projectID, name string,
) (*Page, error) {
	if err := CheckPath(name); err != nil {
		return nil, err
	}

	// **The cache is read first, and that is what decision AP bought.**
	//
	// Under decision Q the cache was a fallback: a page was here because
	// somebody had opened it, nothing kept it current, and the only honest
	// thing to do was ask the publisher every time. The sync changed that — the
	// documentation here is reconciled on the way up, on a timer and on an
	// event — so the copy in the cache is the copy the publisher has, and
	// dialling to confirm what is already known is what turned opening a
	// document into the time it takes to reach a laptop.
	//
	// So a hit is served and nothing is dialled. What keeps it true is the
	// syncer rather than this call, which is the right place for it: one
	// reconciliation covers every document, and a read that revalidated would
	// pay a round trip per document to learn what one manifest already said.
	//
	// **A pulled kind would need the publisher asked**, because nothing keeps
	// it current — there is no such kind today, since everything served is
	// pushed (decision AP), and the check to add when there is one is the
	// publisher's advertised policy rather than this instance's.
	if page, ok := b.cachedPage(fingerprint, projectID, name); ok {
		return page, nil
	}

	publisher := b.publisher(fingerprint)
	if publisher == nil {
		return b.keptPage(fingerprint, projectID, name, "")
	}

	var page *Page

	err := b.source.Ask(ctx, fingerprint, func(
		ctx context.Context, client ladulasv1connect.ProjectServiceClient,
	) error {
		found, err := publication(ctx, client, projectID)
		if err != nil {
			return err
		}

		resp, err := client.FetchProjectFile(ctx, connect.NewRequest(
			&ladulasv1.FetchProjectFileRequest{
				ProjectId: projectID,
				Path:      name,
			}))
		if err != nil {
			return err //nolint:wrapcheck // the source wraps it with the address
		}

		body := resp.Msg.GetContent()

		// The record is built from what was asked for rather than from what came
		// back, apart from the one fact only the publisher has. A path is the
		// field a compromised requester would want to choose, and it does not
		// get to choose the name a page is kept under here.
		entry := &ladulasv1.ProjectEntry{
			Name: path.Base(name),
			Path: name,
			// Two of the facts are the publisher's, because this side cannot
			// work them out: whether what came back is the whole document, and
			// how big the whole of it is. Everything else is still built from
			// what was asked for.
			Size:      servedSize(resp.Msg.GetFile(), body),
			Modified:  resp.Msg.GetFile().GetModified(),
			Readable:  true,
			Truncated: resp.Msg.GetFile().GetTruncated(),
		}

		if _, err := b.cache.Keep(
			publisher.Name, fingerprint, found, entry, body); err != nil {
			return err
		}

		page = &Page{
			Path:     name,
			Content:  body,
			Modified: entry.GetModified().AsTime(),
			ReadAt:   time.Now(),
			Commit:   found.GetCommit(),
			Live:     true,
			FullSize: truncatedSize(entry),
		}

		return nil
	})
	if err != nil {
		return b.keptPage(fingerprint, projectID, name, err.Error())
	}

	return page, nil
}

// Forget drops everything read of one project.
func (b *Browser) Forget(fingerprint, projectID string) error {
	return b.cache.Drop(Key(fingerprint, projectID))
}

// ask asks one publisher what it publishes.
func (b *Browser) ask(
	ctx context.Context, publisher Publisher,
) ([]*ladulasv1.Publication, error) {
	var out []*ladulasv1.Publication

	err := b.source.Ask(ctx, publisher.Fingerprint, func(
		ctx context.Context, client ladulasv1connect.ProjectServiceClient,
	) error {
		resp, err := client.ListProjects(ctx,
			connect.NewRequest(&ladulasv1.ListProjectsRequest{}))
		if err != nil {
			return err //nolint:wrapcheck // the source wraps it with the address
		}

		out = resp.Msg.GetProjects()

		return nil
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (b *Browser) publishers(fingerprint string) []Publisher {
	if b.source == nil {
		return nil
	}

	var out []Publisher

	for _, publisher := range b.source.Publishers() {
		if fingerprint != "" && publisher.Fingerprint != fingerprint {
			continue
		}

		out = append(out, publisher)
	}

	return out
}

func (b *Browser) publisher(fingerprint string) *Publisher {
	for _, publisher := range b.publishers(fingerprint) {
		if publisher.Fingerprint == fingerprint {
			return &publisher
		}
	}

	return nil
}

// keptListing is the directory as the pages that have been read here describe
// it: the subdirectories those pages are in, and the pages themselves.
//
// It is deliberately not dressed up as the real directory. Everything in it has
// been read, nothing that has not been read is in it, and the caller says so on
// screen.
func (b *Browser) keptListing(
	fingerprint, projectID, dir, filter, problem string,
) *Listing {
	listing := &Listing{Path: dir, Err: problem}

	cached, err := b.cache.Find(fingerprint, projectID)
	if err != nil {
		return listing
	}

	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}

	dirs := map[string]bool{}
	wanted := strings.ToLower(filter)

	for _, file := range cached.GetFiles() {
		if !strings.HasPrefix(file.GetPath(), prefix) {
			continue
		}

		rest := strings.TrimPrefix(file.GetPath(), prefix)

		if name, _, nested := strings.Cut(rest, "/"); nested {
			if dirs[name] || !matches(name, wanted) {
				continue
			}

			dirs[name] = true

			listing.Entries = append(listing.Entries, &ladulasv1.ProjectEntry{
				Name:      name,
				Path:      path.Join(dir, name),
				Directory: true,
			})

			continue
		}

		if !matches(rest, wanted) {
			continue
		}

		listing.Entries = append(listing.Entries, entryOf(file))
	}

	sortEntries(listing.Entries)

	listing.Total = len(listing.Entries)

	return listing
}

// keptSearch is the same answer to the other question.
func (b *Browser) keptSearch(
	fingerprint, projectID, query, problem string,
) *Listing {
	listing := &Listing{Err: problem}

	cached, err := b.cache.Find(fingerprint, projectID)
	if err != nil {
		return listing
	}

	wanted := strings.ToLower(strings.TrimSpace(query))
	if wanted == "" {
		return listing
	}

	for _, file := range cached.GetFiles() {
		if !matches(file.GetPath(), wanted) {
			continue
		}

		listing.Entries = append(listing.Entries, entryOf(file))
	}

	sortEntries(listing.Entries)

	listing.Total = len(listing.Entries)

	return listing
}

// Documents is every document this instance holds of a project, from the cache
// and without dialling.
//
// It is what a file picker wants, and the reason it exists rather than reusing
// Search: a search asks the publisher, which is right for a question about the
// project — a directory listing is wider than what is served (§6), so only that
// machine can answer it — and wrong for a list of things to open. After a sync
// the cache holds every document the publisher pushes, which is exactly the set
// a reader can be offered, and asking for it costs a walk of somebody else's
// disk over a network to be told what is already here.
//
// Empty is a real answer and means nothing has been synced yet, which the
// caller can tell from the length rather than from an error.
func (b *Browser) Documents(fingerprint, projectID string) []string {
	cached, err := b.cache.Find(fingerprint, projectID)
	if err != nil {
		return nil
	}

	out := make([]string, 0, len(cached.GetFiles()))

	for _, file := range cached.GetFiles() {
		out = append(out, file.GetPath())
	}

	// The cache keeps its pages newest-read first, which is not an order to
	// show anybody a project in.
	sort.Strings(out)

	return out
}

// cachedPage is what is held here, and whether anything is.
//
// It is the boolean-returning shape rather than keptPage's error one because
// its caller is asking a question — is this here — rather than handling a
// failure, and a miss is the ordinary answer for a document nobody has synced.
func (b *Browser) cachedPage(
	fingerprint, projectID, name string,
) (*Page, bool) {
	page, err := b.keptPage(fingerprint, projectID, name, "")
	if err != nil {
		return nil, false
	}

	// Kept means kept by the syncer now, not read once and abandoned, so it is
	// not the offline answer it used to be. Saying so is the note's business
	// (pkg/bridge), and what travels is when it was last written here.
	return page, true
}

func (b *Browser) keptPage(
	fingerprint, projectID, name, problem string,
) (*Page, error) {
	body, file, err := b.cache.File(Key(fingerprint, projectID), name)
	if err != nil {
		if problem != "" {
			return nil, fmt.Errorf("%s has not been read here: %s", name, problem)
		}

		return nil, err
	}

	return &Page{
		Path:     name,
		Content:  body,
		Modified: file.GetModifiedAt().AsTime(),
		ReadAt:   file.GetReadAt().AsTime(),
		Commit:   file.GetCommit(),
		Err:      problem,
		FullSize: file.GetFullSize(),
	}, nil
}

// publication picks one project out of what a publisher offers.
//
// Asking for the list rather than for the project is not a detour: there is no
// call that returns one project, because a browser that can be told "that one
// is gone" by the same answer that describes the others needs no such call.
func publication(
	ctx context.Context,
	client ladulasv1connect.ProjectServiceClient,
	projectID string,
) (*ladulasv1.Publication, error) {
	resp, err := client.ListProjects(ctx,
		connect.NewRequest(&ladulasv1.ListProjectsRequest{}))
	if err != nil {
		return nil, err //nolint:wrapcheck // the source wraps it with the address
	}

	for _, item := range resp.Msg.GetProjects() {
		if item.GetProjectId() == projectID {
			return item, nil
		}
	}

	return nil, errors.New("that machine no longer publishes this project")
}

func hasProject(live []*ladulasv1.Publication, projectID string) bool {
	for _, item := range live {
		if item.GetProjectId() == projectID {
			return true
		}
	}

	return false
}

func fromCache(cached *ladulasv1.CachedProject, withdrawn bool) *Overview {
	return &Overview{
		Fingerprint: cached.GetPeerFingerprint(),
		Peer:        cached.GetPeer(),
		Project:     cached.GetProject(),
		Withdrawn:   withdrawn,
		Kept:        len(cached.GetFiles()),
		Read:        cached.GetLastReadAt().AsTime(),
	}
}

func entryOf(file *ladulasv1.CachedFile) *ladulasv1.ProjectEntry {
	return &ladulasv1.ProjectEntry{
		Name:     path.Base(file.GetPath()),
		Path:     file.GetPath(),
		Size:     file.GetSize(),
		Modified: file.GetModifiedAt(),
		Readable: true,
	}
}

func matches(name, wanted string) bool {
	return wanted == "" || strings.Contains(strings.ToLower(name), wanted)
}

func sortEntries(entries []*ladulasv1.ProjectEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].GetDirectory() != entries[j].GetDirectory() {
			return entries[i].GetDirectory()
		}

		return entries[i].GetPath() < entries[j].GetPath()
	})
}

// servedSize is the size to record for a page: the whole document's when the
// publisher cut it short, and the size of what arrived when it did not.
//
// The publisher's number is taken only for the truncated case. Believing it for
// every page would let a peer state a size that disagrees with the bytes it
// sent, and every cap on this side is counted against what is actually held.
func servedSize(file *ladulasv1.ProjectEntry, body []byte) int64 {
	if file.GetTruncated() {
		return file.GetSize()
	}

	return int64(len(body))
}
