package bridge

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The doc browser and the deferred diff fetch, as the viewer sees them (§6).
//
// Everything under here is a peer's account of itself. The views say so, the
// markdown arrives already parsed into blocks so that the bundle has no parser
// in it, and two pieces of judgement are added on this side. One is the
// staleness label: documentation read at one commit and a request signing
// another is the ordinary case, and an approver should be told which is which.
// The other is where an answer came from — the machine, or the pages somebody
// read of it once — because under decision Q those are different answers to the
// same question and a browser that blurred them would be claiming to know
// things it does not.

// Projects is what a host needs in order to browse what its peers publish.
// *project.Browser is it; a host with no store open has none.
//
// A project is named by the peer that publishes it and the identifier both ends
// derive (§6), never by a handle this side invented — which is what lets an
// approval card link to a project nothing has been read of yet.
type Projects interface {
	// List is what the peers publish. An empty fingerprint is all of them.
	List(ctx context.Context, fingerprint string) ([]*project.Overview, error)
	// Kept is what is held here of what they publish, without asking anybody.
	// It is what a screen draws first, and List is what replaces it (§6).
	Kept(ctx context.Context, fingerprint string) ([]*project.Overview, error)
	// Open is one project's identity.
	Open(ctx context.Context, fingerprint, projectID string) (*project.Overview, error)
	// Directory and Search are the two ways through a project, both paged.
	Directory(
		ctx context.Context, fingerprint, projectID, path, filter, token string,
		size int,
	) (*project.Listing, error)
	Search(
		ctx context.Context, fingerprint, projectID, query, token string, size int,
	) (*project.Listing, error)
	// KeptDirectory is Directory's answer from what is held here, without
	// asking the publisher, and in one page.
	KeptDirectory(
		ctx context.Context, fingerprint, projectID, path, filter string,
	) (*project.Listing, error)
	// File reads one page and keeps it.
	File(ctx context.Context, fingerprint, projectID, path string) (*project.Page, error)
	// Cached is what has been read of a project, without asking anybody. It is
	// what a prompt uses: a card is drawn while somebody waits.
	Cached(fingerprint, projectID string) (*project.Overview, bool)
	// Versions is what a document has been: the publisher's working-tree states
	// since its last commit, then the commits that touched it (decision AP).
	Versions(
		ctx context.Context, fingerprint, projectID, path string, limit int,
	) (*project.VersionList, error)
	// Read is one document ready to draw, with what changed since a named
	// version marked in it when one is named.
	Read(
		ctx context.Context, fingerprint, projectID, path string,
		digest []byte, commit string,
	) (*project.DocumentAt, error)
	// Documents is every document held here of a project, without dialling.
	// Empty means nothing has been synced yet.
	Documents(fingerprint, projectID string) []string
}

// ProjectView is one project in a listing.
type ProjectView struct {
	Peer        string `json:"peer"`
	Fingerprint string `json:"fingerprint"`
	ProjectID   string `json:"projectId"`
	Name        string `json:"name"`
	Path        string `json:"path,omitempty"`
	OriginURL   string `json:"originUrl,omitempty"`
	Branch      string `json:"branch,omitempty"`
	Commit      string `json:"commit,omitempty"`
	// Live says the publisher answered just now.
	Live bool `json:"live"`
	// Kept is how many pages have been read here and are readable with no
	// signal.
	Kept int `json:"kept"`
	// Unasked says this row was drawn from what is held here before anybody
	// was asked, so a shell knows to keep waiting for the answer that replaces
	// it rather than reading the row as the publisher's silence.
	Unasked bool `json:"unasked,omitempty"`
	// State is the sentence to put under the name: where this came from, and
	// what is readable right now.
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

// ProjectEntryView is one thing in a directory.
type ProjectEntryView struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Directory bool   `json:"directory,omitempty"`
	Size      int64  `json:"size,omitempty"`
	// Modified is the rendered date; ModifiedAt is the instant it was rendered
	// from. A host that knows the reader's time zone and clock preference — a
	// phone does, a Go runtime in an app sandbox does not — draws the second.
	Modified   string `json:"modified,omitempty"`
	ModifiedAt string `json:"modifiedAt,omitempty"`
	Readable   bool   `json:"readable"`
	// Reason is why a file will not be handed over, when it will not.
	Reason string `json:"reason,omitempty"`
	// Empty says a directory leads nowhere: the publisher has nothing beneath it
	// that it would hand over. It is the publisher's answer because the publisher
	// is the one with the directory (§6).
	Empty bool `json:"empty,omitempty"`
}

// ProjectListingView is one page of a directory, or of a search.
type ProjectListingView struct {
	ProjectView

	// Dir rather than Path: the embedded project carries the repository path,
	// and two fields called the same thing at two depths is how one of them
	// silently disappears from the JSON.
	Dir     string             `json:"dir"`
	Entries []ProjectEntryView `json:"entries"`
	// Next carries on from here, and is empty on the last page.
	Next  string `json:"next,omitempty"`
	Total int    `json:"total"`
	// Truncated says a search gave up before it had looked everywhere.
	Truncated bool `json:"truncated,omitempty"`
	// Note is what to say about where this listing came from, which matters
	// most when it did not come from the publisher.
	Note string `json:"note,omitempty"`
	// Unasked says the entries are what is held here, drawn before the
	// publisher was asked; the shell that asked for it this way is about to
	// ask the ordinary way and draw that answer over this one.
	Unasked bool `json:"unasked,omitempty"`
}

// ProjectPageView is a rendered document.
type ProjectPageView struct {
	Path   string          `json:"path"`
	Title  string          `json:"title,omitempty"`
	Blocks []project.Block `json:"blocks"`
	// Note says when this was read and from what commit, which is the whole of
	// what an offline reader needs to know about what is in front of it.
	Note  string `json:"note,omitempty"`
	Live  bool   `json:"live"`
	Error string `json:"error,omitempty"`
	// Compared says the blocks carry change marks, because a version was named
	// to compare against (decision AP). ComparedTo is which one.
	Compared   bool                `json:"compared,omitempty"`
	ComparedTo *ProjectVersionView `json:"comparedTo,omitempty"`
	// CompareError is why the comparison did not happen, when a version was
	// asked for and has since gone. The document is still here and still
	// readable; only the comparison is missing.
	CompareError string `json:"compareError,omitempty"`
	// Truncated says this is the start of a longer document: it is over the
	// publisher's per-file cap, so what was sent was cut back to a line ending
	// (decision AP). Shown and FullSize are the two numbers a reader wants,
	// which is how much is here against how much there is.
	//
	// It is said rather than left to be noticed. A document that simply stops
	// two thirds of the way through looks like a document somebody has not
	// finished writing, and the reader would go looking for the rest of a
	// sentence that is on the other machine.
	// TruncatedNote is that sentence, composed here for the same reason
	// pageNote is: the viewer renders prose and does not compose it.
	Truncated     bool   `json:"truncated,omitempty"`
	TruncatedNote string `json:"truncatedNote,omitempty"`
}

// RequestProjectView ties a signing request to the documentation behind it, and
// says how far the two have drifted apart (§6).
type RequestProjectView struct {
	// The project, named the way every browsing call names one. Both are
	// present whether or not anything has been read, because the way in from a
	// card is a pull like any other (decision Q).
	Fingerprint string `json:"fingerprint,omitempty"`
	ProjectID   string `json:"projectId,omitempty"`
	Name        string `json:"name,omitempty"`
	// Note is the staleness label, in the words the prompt should use.
	Note string `json:"note"`
	// Stale marks the case worth reading twice: the documentation that was read
	// here is from a commit this change is not built on.
	Stale bool `json:"stale,omitempty"`
	// Known is false when nothing of the project has been read here, which is
	// the ordinary state and worth saying rather than hiding.
	Known bool `json:"known"`
}

// presentedProject is the documentation panel on its way into the audit log:
// the same sentence, kept rather than recomputed (§6).
func presentedProject(view *RequestProjectView) *ladulasv1.PresentedProject {
	if view == nil {
		return nil
	}

	return &ladulasv1.PresentedProject{
		PeerFingerprint: view.Fingerprint,
		ProjectId:       view.ProjectID,
		Name:            view.Name,
		Note:            view.Note,
		Stale:           view.Stale,
		Known:           view.Known,
	}
}

// projectShown is presentedProject read back: what a card said about the
// documentation, in the words it said it.
func projectShown(shown *ladulasv1.PresentedProject) *RequestProjectView {
	if shown == nil {
		return nil
	}

	return &RequestProjectView{
		Fingerprint: shown.GetPeerFingerprint(),
		ProjectID:   shown.GetProjectId(),
		Name:        shown.GetName(),
		Note:        shown.GetNote(),
		Stale:       shown.GetStale(),
		Known:       shown.GetKnown(),
	}
}

// where is the project a browsing call is about: the peer that publishes it and
// the identifier both ends derive.
func where(r *http.Request) (string, string) {
	return r.URL.Query().Get("peer"), r.URL.Query().Get("project")
}

// wantsKept is the `kept` query parameter: answer from what is held here and
// ask nobody. A screen asks this way first and the ordinary way second, and
// draws the second over the first (§6).
func wantsKept(query url.Values) bool {
	switch query.Get("kept") {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func (s *Session) handleProjects(w http.ResponseWriter, r *http.Request) {
	if s.opts.Projects == nil {
		writeJSON(w, http.StatusOK, []ProjectView{})

		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), BrowseTimeout)
	defer cancel()

	list := s.opts.Projects.List
	if wantsKept(r.URL.Query()) {
		list = s.opts.Projects.Kept
	}

	listed, err := list(ctx, r.URL.Query().Get("peer"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())

		return
	}

	views := make([]ProjectView, 0, len(listed))
	for _, item := range listed {
		views = append(views, projectView(item))
	}

	writeJSON(w, http.StatusOK, views)
}

func (s *Session) handleProject(w http.ResponseWriter, r *http.Request) {
	ctx, cancel, ok := s.browsing(w, r)
	if !ok {
		return
	}

	defer cancel()

	fingerprint, id := where(r)

	overview, err := s.opts.Projects.Open(ctx, fingerprint, id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())

		return
	}

	writeJSON(w, http.StatusOK, projectView(overview))
}

// handleProjectDirectory is one page of one directory (decision Q).
func (s *Session) handleProjectDirectory(w http.ResponseWriter, r *http.Request) {
	ctx, cancel, ok := s.browsing(w, r)
	if !ok {
		return
	}

	defer cancel()

	fingerprint, id := where(r)
	query := r.URL.Query()

	// What is held here is one page and all of it readable, so neither the
	// paging nor the readable-only walk applies to it.
	if wantsKept(query) {
		listing, err := s.opts.Projects.KeptDirectory(ctx,
			fingerprint, id, query.Get("path"), query.Get("filter"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())

			return
		}

		s.writeListing(w, fingerprint, id, listing)

		return
	}

	read := func(ctx context.Context, token string) (*project.Listing, error) {
		return s.opts.Projects.Directory(ctx,
			fingerprint, id, query.Get("path"), query.Get("filter"),
			token, pageSize(query.Get("size")))
	}

	listing, err := read(ctx, query.Get("token"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())

		return
	}

	if wantsReadable(query) {
		listing = keepReadable(ctx, listing, read)
	}

	s.writeListing(w, fingerprint, id, listing)
}

func (s *Session) handleProjectSearch(w http.ResponseWriter, r *http.Request) {
	ctx, cancel, ok := s.browsing(w, r)
	if !ok {
		return
	}

	defer cancel()

	fingerprint, id := where(r)
	query := r.URL.Query()

	read := func(ctx context.Context, token string) (*project.Listing, error) {
		return s.opts.Projects.Search(ctx,
			fingerprint, id, query.Get("q"), token,
			pageSize(query.Get("size")))
	}

	listing, err := read(ctx, query.Get("token"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())

		return
	}

	if wantsReadable(query) {
		listing = keepReadable(ctx, listing, read)
	}

	s.writeListing(w, fingerprint, id, listing)
}

// wantsReadable is a browser saying it will only draw what it can show.
//
// §6 keeps listing and showing apart on purpose: a project full of Go files is
// a project whose listing shows Go files, and a viewer that renders markdown
// says so per entry rather than pretending the rest is not there. That is the
// right answer for a window with room for a greyed-out row and a reason beside
// it, and the wrong one for a phone, where the same honesty is forty taps that
// do nothing. So the caller says which it is, and the desktop bundle — which
// draws the reason — does not ask.
func wantsReadable(query url.Values) bool {
	return query.Get("only") == "readable"
}

// maxReadablePages bounds the reading-on below. A directory of ten thousand
// source files and one README should not be answered with an empty page, and it
// should not cost an unbounded walk of somebody else's repository either.
const maxReadablePages = 8

// keepReadable drops the files the publisher will not hand over, and reads on
// while that is what empties a page.
//
// Paging is the publisher's, so filtering here can turn a full page into an
// empty one with a token still in it — which to a browser looks exactly like
// the end of a directory that has more in it. Rather than teach every host that
// "no entries and a next token" means "ask again", the ask happens here.
func keepReadable(
	ctx context.Context, listing *project.Listing,
	read func(ctx context.Context, token string) (*project.Listing, error),
) *project.Listing {
	out := *listing
	out.Entries = readableEntries(listing.Entries)

	for pages := 0; len(out.Entries) == 0 && out.Next != ""; pages++ {
		if pages == maxReadablePages {
			break
		}

		next, err := read(ctx, out.Next)
		if err != nil {
			break
		}

		// A publisher that stopped answering mid-walk leaves a kept listing,
		// which is a different and much shorter list than the directory being
		// paged through (§6). Stitching one onto the other would be reporting
		// the pages somebody read as the rest of a directory, so the token is
		// left where it is and whoever wants the rest asks again.
		if !next.Live {
			break
		}

		out.Entries = readableEntries(next.Entries)
		out.Next = next.Next
		out.Truncated = out.Truncated || next.Truncated
	}

	return &out
}

func readableEntries(entries []*ladulasv1.ProjectEntry) []*ladulasv1.ProjectEntry {
	kept := make([]*ladulasv1.ProjectEntry, 0, len(entries))

	for _, entry := range entries {
		if !entry.GetDirectory() {
			if entry.GetReadable() {
				kept = append(kept, entry)
			}

			continue
		}

		// A folder is not a file that cannot be read, so what is behind one is a
		// question for the listing of it — unless the publisher has already
		// answered it. A folder with nothing readable anywhere beneath it is a
		// row that opens onto an empty screen, and the publisher is the only end
		// that can say so without a call per folder.
		if !entry.GetNothingReadable() {
			kept = append(kept, entry)
		}
	}

	return kept
}

// handleProjectFile reads one page, and keeps it (decision Q).
func (s *Session) handleProjectFile(w http.ResponseWriter, r *http.Request) {
	ctx, cancel, ok := s.browsing(w, r)
	if !ok {
		return
	}

	defer cancel()

	fingerprint, id := where(r)
	name := r.URL.Query().Get("path")

	// A version to compare against, named the way the version list named it.
	// Neither is a reader asking for the document plain, which is the ordinary
	// case and the one that must stay cheap.
	digest, digestErr := versionDigest(r.URL.Query().Get("digest"))
	if digestErr != nil {
		writeError(w, http.StatusBadRequest, digestErr.Error())

		return
	}

	commit := r.URL.Query().Get("commit")

	read, err := s.opts.Projects.Read(
		ctx, fingerprint, id, name, digest, commit)
	if err != nil && read == nil {
		writeError(w, http.StatusNotFound, err.Error())

		return
	}

	view := ProjectPageView{
		Path:      read.Page.Path,
		Title:     s.documentTitle(read.Document, fingerprint, id, name),
		Blocks:    read.Document.Blocks,
		Note:      pageNote(read.Page),
		Live:      read.Page.Live,
		Error:     read.Page.Err,
		Compared:  read.Compared,
		Truncated: read.Page.FullSize > 0,
		TruncatedNote: truncatedNote(
			int64(len(read.Page.Content)), read.Page.FullSize),
	}

	// A version that has gone since the list was read is not a reason to refuse
	// the document: the reader gets what they asked to read, and a line saying
	// the version they picked to compare against is no longer there.
	if err != nil {
		view.CompareError = err.Error()
	}

	if read.Against != nil {
		against := versionView(read.Against)
		view.ComparedTo = &against
	}

	writeJSON(w, http.StatusOK, view)
}

// versionDigest decodes a snapshot handle. It is hex on the wire because that
// is what a digest is everywhere else in this system, and an unparseable one is
// a request to refuse rather than a comparison to skip silently.
func versionDigest(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}

	out, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("the version digest is not hexadecimal: %w", err)
	}

	return out, nil
}

// handleProjectDocuments is what a file picker offers: the documents held here,
// answered without dialling anybody (decision AP).
//
// A live search is the fallback rather than the source. After a sync the cache
// holds every document the publisher pushes, so the list is already here; going
// to the publisher for it means walking somebody else's disk over a network to
// be told what this machine could have said at once — which is what opening a
// project was doing, and it was slower than the directory listing it replaced.
func (s *Session) handleProjectDocuments(w http.ResponseWriter, r *http.Request) {
	ctx, cancel, ok := s.browsing(w, r)
	if !ok {
		return
	}

	defer cancel()

	fingerprint, id := where(r)

	held := s.opts.Projects.Documents(fingerprint, id)
	if len(held) > 0 {
		writeJSON(w, http.StatusOK, ProjectDocumentsView{
			ProjectView: s.projectFacts(fingerprint, id),
			Documents:   held,
			Kept:        true,
		})

		return
	}

	// Nothing synced yet — a project opened before the first sweep, or one
	// whose publisher has never been reached. Ask, so that a first run is not
	// an empty picker.
	listing, err := s.opts.Projects.Search(ctx, fingerprint, id, "", "", 0)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())

		return
	}

	view := ProjectDocumentsView{Live: listing.Live, Error: listing.Err}

	switch {
	case listing.Publisher != nil:
		view.ProjectView = projectView(listing.Publisher)
	default:
		view.ProjectView = s.projectFacts(fingerprint, id)
	}

	for _, entry := range listing.Entries {
		if entry.GetDirectory() || !entry.GetReadable() {
			continue
		}

		view.Documents = append(view.Documents, entry.GetPath())
	}

	writeJSON(w, http.StatusOK, view)
}

// ProjectDocumentsView is the picker's list, and the reader's account of what
// it is showing.
//
// The facts ride along because the reader asks for this once when it opens a
// project and would otherwise need a second call to answer "which commit is
// this README from" — the question core §6 requires be answerable, and the one
// that makes documentation worth reading beside a signing request.
type ProjectDocumentsView struct {
	ProjectView

	Documents []string `json:"documents"`
	// Kept says the list came from what is held here rather than from the
	// publisher, which is the ordinary case and the fast one.
	Kept  bool   `json:"kept,omitempty"`
	Live  bool   `json:"live,omitempty"`
	Error string `json:"error,omitempty"`
}

// handleProjectVersions is what a document has been (decision AP).
func (s *Session) handleProjectVersions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel, ok := s.browsing(w, r)
	if !ok {
		return
	}

	defer cancel()

	fingerprint, id := where(r)
	name := r.URL.Query().Get("path")

	list, err := s.opts.Projects.Versions(ctx, fingerprint, id, name, 0)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())

		return
	}

	view := ProjectVersionsView{
		Head:      list.Head,
		Truncated: list.Truncated,
		Live:      list.Live,
		Error:     list.Err,
	}

	for _, version := range list.Versions {
		view.Versions = append(view.Versions, versionView(version))
	}

	writeJSON(w, http.StatusOK, view)
}

// ProjectVersionsView is the version list as a browser draws it.
type ProjectVersionsView struct {
	Versions  []ProjectVersionView `json:"versions"`
	Head      string               `json:"head,omitempty"`
	Truncated bool                 `json:"truncated,omitempty"`
	Live      bool                 `json:"live"`
	Error     string               `json:"error,omitempty"`
}

// ProjectVersionView is one version, with the handle to ask for it by.
type ProjectVersionView struct {
	// Kind is "snapshot" or "commit", which is the difference a reader has to
	// see: one of them will still be there tomorrow and the other will not.
	Kind string `json:"kind"`
	// Digest names a snapshot, hex; Commit names a commit.
	Digest string `json:"digest,omitempty"`
	Commit string `json:"commit,omitempty"`
	Size   int64  `json:"size,omitempty"`
	At     string `json:"at,omitempty"`
	// Subject and Author are a commit's, and empty on a snapshot: nobody writes
	// a message about saving a file.
	Subject string `json:"subject,omitempty"`
	Author  string `json:"author,omitempty"`
}

func versionView(version *ladulasv1.DocumentVersion) ProjectVersionView {
	out := ProjectVersionView{
		Digest:  fmt.Sprintf("%x", version.GetDigest()),
		Commit:  version.GetCommit(),
		Size:    version.GetSize(),
		Subject: version.GetSubject(),
		Author:  version.GetAuthor(),
	}

	if version.GetDigest() == nil {
		out.Digest = ""
	}

	switch version.GetKind() {
	case ladulasv1.DocumentVersionKind_DOCUMENT_VERSION_KIND_SNAPSHOT:
		out.Kind = "snapshot"
	case ladulasv1.DocumentVersionKind_DOCUMENT_VERSION_KIND_COMMIT:
		out.Kind = "commit"
	case ladulasv1.DocumentVersionKind_DOCUMENT_VERSION_KIND_UNSPECIFIED:
		// A version this side does not recognise is still one the publisher
		// offered, and naming it by its handle is better than dropping it.
		out.Kind = ""
	}

	if at := version.GetAt(); at != nil {
		out.At = at.AsTime().Format(time.RFC3339)
	}

	return out
}

// writeListing puts the project's own facts on a listing, so that a browser
// showing a directory can also show whose it is without a second call.
//
// The header has to describe the entries under it. A listing the publisher
// answered is headed by what that machine said in the same breath; a listing
// assembled out of the pages read here is headed by what was true when they
// were read, and says so. Taking the second and putting it over the first is
// what a reader would read as "the machine is unreachable" while looking at its
// answer.
func (s *Session) writeListing(
	w http.ResponseWriter, fingerprint, id string, listing *project.Listing,
) {
	view := ProjectListingView{
		Dir:       listing.Path,
		Entries:   make([]ProjectEntryView, 0, len(listing.Entries)),
		Next:      listing.Next,
		Total:     listing.Total,
		Truncated: listing.Truncated,
	}

	for _, entry := range listing.Entries {
		view.Entries = append(view.Entries, entryView(entry))
	}

	switch cached, ok := s.opts.Projects.Cached(fingerprint, id); {
	case listing.Publisher != nil:
		view.ProjectView = projectView(listing.Publisher)
	case ok:
		// The heading over a listing nobody asked for must not accuse the
		// publisher either: the cached account is written as if a dial had
		// failed, and here none was made.
		if listing.Unasked {
			unasked := *cached
			unasked.Unasked = true
			cached = &unasked
		}

		view.ProjectView = projectView(cached)
	default:
		view.ProjectView = ProjectView{Fingerprint: fingerprint, ProjectID: id}
	}

	view.Live = listing.Live
	view.Error = listing.Err
	view.Unasked = listing.Unasked
	view.Note = listingNote(listing, view.Peer)

	writeJSON(w, http.StatusOK, view)
}

// projectFacts is the publishing machine's account of a project, from the copy
// held here. It is what the (i) shows, and it is the same account the project
// list shows, so the two never disagree.
func (s *Session) projectFacts(fingerprint, id string) ProjectView {
	cached, ok := s.opts.Projects.Cached(fingerprint, id)
	if !ok {
		return ProjectView{Fingerprint: fingerprint, ProjectID: id}
	}

	return projectView(cached)
}

// BrowseTimeout bounds a call made while somebody is looking at a screen.
//
// Everything else on the peer channel is bounded by what it is waiting for, and
// for an approval that is a human deciding — §9 gives it an hour, and a client
// timeout there would be a promise taken away from somebody halfway through
// making it. Reading a document is the opposite: the wait *is* the delay, and a
// reader who cannot be told "that machine is not answering" until four dial
// timeouts have run is a reader looking at nothing for the better part of a
// minute.
//
// Twenty seconds is past what a reachable peer takes and short of the wait that
// reads as broken. It bounds the whole call including the addresses tried after
// the first, which is the number that was unbounded before.
const BrowseTimeout = 20 * time.Second

// browsing bounds a browsing call and reports whether there is anything to
// browse.
//
// The deadline is applied here rather than by each host because both of them
// had the same gap in different shapes: the phone passes no context at all, so
// its calls ran under context.Background() and could not be given up on, and
// the desktop's own timeout covers the control socket rather than what the
// daemon does behind it.
func (s *Session) browsing(
	w http.ResponseWriter, r *http.Request,
) (context.Context, context.CancelFunc, bool) {
	if !s.browsable(w) {
		return nil, nil, false
	}

	ctx, cancel := context.WithTimeout(r.Context(), BrowseTimeout)

	return ctx, cancel, true
}

func (s *Session) browsable(w http.ResponseWriter) bool {
	if s.opts.Projects == nil {
		writeError(w, http.StatusNotImplemented,
			"this host cannot read published documentation")

		return false
	}

	return true
}

// handleRequestDiff is the deferred fetch-back: the approver asks the requester
// for what the caps cut short (§5).
func (s *Session) handleRequestDiff(w http.ResponseWriter, r *http.Request) {
	if s.opts.FetchDiff == nil {
		writeError(w, http.StatusNotImplemented,
			"this host cannot fetch the rest of a diff")

		return
	}

	pending := s.lookup(r.PathValue("id"))
	if pending == nil {
		writeError(w, http.StatusNotFound, "this request is no longer waiting")

		return
	}

	var body struct {
		Path string `json:"path"`
	}

	if r.Body != nil {
		// An empty body means the whole diff, which is what the button at the
		// bottom of a truncated one asks for.
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	}

	diff, err := s.opts.FetchDiff(r.Context(), pending.Request, body.Path)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())

		return
	}

	writeJSON(w, http.StatusOK, diffView(diff))
}

func projectView(overview *project.Overview) ProjectView {
	publication := overview.Project

	view := ProjectView{
		Peer:        overview.Peer,
		Fingerprint: overview.Fingerprint,
		ProjectID:   publication.GetProjectId(),
		Name:        publication.GetName(),
		Path:        publication.GetPath(),
		OriginURL:   publication.GetOriginUrl(),
		Branch:      publication.GetBranch(),
		Commit:      shortCommit(publication.GetCommit()),
		Live:        overview.Live,
		Kept:        overview.Kept,
		Unasked:     overview.Unasked,
		Error:       overview.Err,
	}

	view.State = projectState(overview)

	return view
}

// projectState is the sentence under the name, and it is the one place the
// difference decision Q made has to be said out loud.
func projectState(overview *project.Overview) string {
	switch {
	case overview.Unasked && overview.Kept > 0:
		return fmt.Sprintf("Read from %s before. %s readable with no signal.",
			overview.Peer, pages(overview.Kept))
	case overview.Unasked:
		return fmt.Sprintf("Read from %s before. Nothing of it is held here.",
			overview.Peer)
	case overview.Live && overview.Kept > 0:
		return fmt.Sprintf("Read from %s. %s also readable with no signal.",
			overview.Peer, pages(overview.Kept))
	case overview.Live:
		return "Read from " + overview.Peer + "."
	case overview.Withdrawn:
		return fmt.Sprintf("%s no longer publishes this. %s read here remain.",
			overview.Peer, pages(overview.Kept))
	case overview.Kept > 0:
		return fmt.Sprintf("%s could not be reached. %s read here.",
			overview.Peer, pages(overview.Kept))
	default:
		return overview.Peer + " could not be reached, and nothing of this has " +
			"been read here."
	}
}

func pages(n int) string {
	if n == 1 {
		return "1 page"
	}

	return fmt.Sprintf("%d pages", n)
}

func entryView(entry *ladulasv1.ProjectEntry) ProjectEntryView {
	view := ProjectEntryView{
		Name:      entry.GetName(),
		Path:      entry.GetPath(),
		Directory: entry.GetDirectory(),
		Size:      entry.GetSize(),
		Readable:  entry.GetReadable(),
		Reason:    entry.GetReason(),
		Empty:     entry.GetNothingReadable(),
	}

	if modified := entry.GetModified(); modified != nil {
		view.Modified = modified.AsTime().Local().Format("2 Jan 15:04")
		view.ModifiedAt = modified.AsTime().Format(time.RFC3339)
	}

	return view
}

func listingNote(listing *project.Listing, peer string) string {
	if listing.Live {
		if listing.Truncated {
			return "The project was too large to search all of it; " +
				"these are the matches found before the publisher gave up."
		}

		return ""
	}

	// Nobody was asked, so there is nothing to apologise for and nothing to
	// claim about the publisher: what is here is what is held here.
	if listing.Unasked {
		if peer == "" {
			return "These are the documents held here; the publisher has not " +
				"been asked."
		}

		return fmt.Sprintf(
			"These are the documents held here; %s has not been asked.", peer)
	}

	note := "These are the pages that have been read here, not the directory."

	if listing.Err != "" {
		note = listing.Err + ". " + note
	}

	return note
}

// pageNote says where a document came from, when that is worth saying.
//
// It used to have two cases, because a page that was not live meant one thing:
// the publisher could not be reached and this is what was read of it once. The
// sync made a third — a page served from here because it is kept current, which
// is the ordinary case now and is not an apology (decision AP).
//
// The two are told apart by whether anything went wrong. A read that failed
// carries the reason; one that never needed to dial carries none, and saying
// "could not be reached" about a machine nobody tried to reach would be the
// note lying about the thing it exists to be honest about.
// truncatedNote is what to say about a document that arrived cut short.
//
// Both numbers, because either one alone leaves the reader guessing at the
// other: how much is here says nothing about how much is missing, and how big
// the document is says nothing about where it stops.
func truncatedNote(shown, full int64) string {
	if full <= 0 {
		return ""
	}

	return fmt.Sprintf("You are reading the first %s of this %s document. "+
		"The machine that publishes it sends no more of it than that.",
		project.ByteSize(shown), project.ByteSize(full))
}

func pageNote(page *project.Page) string {
	if page.Live {
		return ""
	}

	when := page.ReadAt.Local().Format("2 Jan 15:04")

	if page.Err == "" {
		if page.Commit != "" {
			return fmt.Sprintf("Kept here, last updated %s, at %s.",
				when, shortCommit(page.Commit))
		}

		return fmt.Sprintf("Kept here, last updated %s.", when)
	}

	if page.Commit != "" {
		return fmt.Sprintf("Read here on %s, at %s. The machine it belongs to "+
			"could not be reached just now.", when, shortCommit(page.Commit))
	}

	return fmt.Sprintf("Read here on %s. The machine it belongs to could not "+
		"be reached just now.", when)
}

func (s *Session) documentTitle(
	document project.Document, fingerprint, id, name string,
) string {
	if document.Title != "" {
		return document.Title
	}

	if name == "README.md" {
		if cached, ok := s.opts.Projects.Cached(fingerprint, id); ok {
			return cached.Project.GetName()
		}
	}

	return name
}

// pageSize is what the viewer asked for, or nothing, which the publisher reads
// as its own default.
func pageSize(raw string) int {
	size, err := strconv.Atoi(raw)
	if err != nil || size < 0 {
		return 0
	}

	return size
}

// requestProject looks up the documentation a signing request belongs to and
// works out what to say about how current it is.
//
// It always names the project, whether or not anything has been read of it.
// Browsing is a pull (decision Q), so the way in from a card works exactly when
// the machine that asked is reachable — which, since it is currently waiting
// for an answer, it very nearly always is.
func (s *Session) requestProject(req *approval.Request) *RequestProjectView {
	if s.opts.Projects == nil {
		return nil
	}

	git := req.Msg.GetSshsig().GetGitContext()

	projectID := git.GetProjectId()
	if projectID == "" {
		return nil
	}

	requester := req.Msg.GetRequester()

	// Only the peer that sent the request may name a project: an id is a string
	// on a request, and looking it up against anybody else would let a requester
	// point a prompt at somebody else's documentation.
	if requester.GetLocal() {
		return nil
	}

	view := &RequestProjectView{
		Fingerprint: requester.GetInstanceId(),
		ProjectID:   projectID,
	}

	cached, ok := s.opts.Projects.Cached(requester.GetInstanceId(), projectID)
	if !ok {
		view.Note = "Part of a project the machine that asked publishes. " +
			"Nothing of it has been read here yet; opening it reads from that " +
			"machine."

		return view
	}

	view.Name = cached.Project.GetName()
	view.Known = true
	view.Note, view.Stale = staleness(cached, git)

	return view
}

// staleness is §6's label: "the documentation you have was read at commit X,
// this request signs commit Y".
//
// The commit being signed has no identifier yet — git computes it over the
// object including the signature that does not exist — so what is compared is
// the commit this change is built on. Equal means the pages that have been read
// describe exactly the state the change starts from; different means they do
// not, which is not a problem so much as something to know.
func staleness(
	cached *project.Overview, git *ladulasv1.GitContext,
) (string, bool) {
	read := cached.Project.GetCommit()
	parents := git.GetParsed().GetParents()

	when := ""
	if !cached.Read.IsZero() {
		when = " on " + cached.Read.Local().Format("2 Jan 15:04")
	}

	held := fmt.Sprintf("%s read here%s", pages(cached.Kept), when)

	switch {
	case read == "":
		return held + ", from a directory with no commit.", false
	case len(parents) == 0:
		return fmt.Sprintf("%s, at %s; this is a first commit.",
			held, shortCommit(read)), true
	case parents[0] == read:
		return fmt.Sprintf("%s, at %s, which is the commit this change is "+
			"built on.", held, shortCommit(read)), false
	default:
		return fmt.Sprintf("%s, at %s; this change is built on %s.",
			held, shortCommit(read), shortCommit(parents[0])), true
	}
}

func shortCommit(commit string) string {
	const shown = 10

	if len(commit) > shown {
		return commit[:shown]
	}

	return commit
}
