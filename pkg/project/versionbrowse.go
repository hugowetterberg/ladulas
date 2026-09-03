package project

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
)

// Asking a publisher what a document used to be, from the approver's side
// (decision AP).
//
// This is the half that makes the version list reachable. The publisher keeps
// the working-tree states and git keeps the commits; both are read at the
// moment of asking, because both belong to the machine with the repository on
// it and neither is worth mirroring.
//
// **Nothing here is kept.** A version somebody looked at once is not a page
// they are reading — the cache holds the current document, which is what has to
// survive going offline, and an old version is a thing you fetch to answer one
// question and then stop caring about. Keeping them would grow the cache by the
// number of times somebody was curious.

// VersionList is what a reader may ask to see of one document.
type VersionList struct {
	// Versions, newest first: the working-tree states since the last commit,
	// then the commits that touched the document.
	Versions []*ladulasv1.DocumentVersion
	// Head is the commit the publisher is standing on, which is what the
	// snapshots are relative to.
	Head string
	// CurrentDigest is the publisher's document as it stands. A reader that
	// hashed what it holds can compare against this and know whether it is
	// current without another call.
	CurrentDigest []byte
	// Truncated says the walk back through the commits stopped early.
	Truncated bool
	// Live says the publisher answered. When it is false the rest is empty:
	// there is no offline version history, because the versions are the
	// publisher's and always were.
	Live bool
	// Err is why the publisher could not be asked, in the words to show.
	Err string
}

// Versions asks a publisher what a document has been.
//
// An unreachable publisher is not an error. It is the state a phone spends most
// of its life in, and the honest answer is an empty list that says why — the
// document itself is still readable from the cache, and only its history is
// gone.
func (b *Browser) Versions(
	ctx context.Context, fingerprint, projectID, name string, limit int,
) (*VersionList, error) {
	if err := CheckPath(name); err != nil {
		return nil, err
	}

	if b.publisher(fingerprint) == nil {
		return &VersionList{
			Err: "this peer publishes nothing here",
		}, nil
	}

	out := &VersionList{}

	err := b.source.Ask(ctx, fingerprint, func(
		ctx context.Context, client ladulasv1connect.ProjectServiceClient,
	) error {
		resp, err := client.DocumentVersions(ctx, connect.NewRequest(
			&ladulasv1.DocumentVersionsRequest{
				ProjectId:   projectID,
				Path:        name,
				CommitLimit: int32(limit), //nolint:gosec // a caller's page size
			}))
		if err != nil {
			return err //nolint:wrapcheck // the source wraps it with the address
		}

		out.Versions = resp.Msg.GetVersions()
		out.Head = resp.Msg.GetHead()
		out.CurrentDigest = resp.Msg.GetCurrentDigest()
		out.Truncated = resp.Msg.GetTruncated()
		out.Live = true

		return nil
	})
	if err != nil {
		// An unreachable publisher is a state, not a failure — it is where a
		// phone spends most of its life. The document is still readable from
		// the cache; only its history is the publisher's alone.
		return &VersionList{Err: err.Error()}, nil //nolint:nilerr // offline is an answer
	}

	return out, nil
}

// ErrNoSuchVersion is returned for a version the publisher no longer has, which
// for a snapshot is the ordinary way one ends: the project moved to another
// commit and every snapshot taken against the old one went with it.
var ErrNoSuchVersion = errors.New("project: that version is no longer available")

// FileAt reads one document as it stood at one version.
//
// It goes to the publisher every time and keeps nothing. Unlike File, there is
// no cached answer to fall back on — an old version is not something this
// instance ever held — so an unreachable publisher is a real error here.
func (b *Browser) FileAt(
	ctx context.Context, fingerprint, projectID, name string,
	digest []byte, commit string,
) (*Page, error) {
	if err := CheckPath(name); err != nil {
		return nil, err
	}

	if (len(digest) == 0) == (commit == "") {
		return nil, errors.New(
			"project: name either a snapshot digest or a commit, and not both")
	}

	if b.publisher(fingerprint) == nil {
		return nil, fmt.Errorf(
			"project: %s publishes nothing here", fingerprint)
	}

	var page *Page

	err := b.source.Ask(ctx, fingerprint, func(
		ctx context.Context, client ladulasv1connect.ProjectServiceClient,
	) error {
		resp, err := client.FetchProjectVersion(ctx, connect.NewRequest(
			&ladulasv1.FetchProjectVersionRequest{
				ProjectId: projectID,
				Path:      name,
				Digest:    digest,
				Commit:    commit,
			}))
		if err != nil {
			if connect.CodeOf(err) == connect.CodeNotFound {
				return fmt.Errorf("%w: %s", ErrNoSuchVersion, err.Error())
			}

			return err //nolint:wrapcheck // the source wraps it with the address
		}

		body := resp.Msg.GetContent()

		page = &Page{
			Path:     name,
			Content:  body,
			Modified: resp.Msg.GetVersion().GetAt().AsTime(),
			ReadAt:   time.Now(),
			Commit:   resp.Msg.GetVersion().GetCommit(),
			Live:     true,
		}

		return nil
	})
	if err != nil {
		return nil, err //nolint:wrapcheck // the source wraps it with the address
	}

	return page, nil
}

// DocumentAt is one document ready to draw, compared against a version when one
// was named.
//
// It is here rather than in the bridge because both halves are this package's:
// the fetch, the parse and the comparison. What the caller gets back is the
// document to draw and enough about the comparison to say what is being shown.
type DocumentAt struct {
	Document Document
	// Compared says a version was named and the document carries change marks.
	Compared bool
	// Against describes what it was compared with, for the line above the
	// document that says so.
	Against *ladulasv1.DocumentVersion
	// Page is the current document as it was read, so a caller that also wants
	// its provenance does not fetch it twice.
	Page *Page
}

// Composed builds what a reader draws out of the current page and, when one was
// asked for, the version to compare it against.
//
// It is exported because two processes do this. The daemon does it when the
// bridge is in-process, and the desktop's window does it over the control
// socket (decision Z) after the daemon has fetched both pages — and a second
// implementation of "parse both and compare" is a second thing to get wrong.
//
// The comparison runs wherever the document is being read rather than on the
// publisher. Asking the publisher to diff would mean sending it what the reader
// holds and trusting the answer, and the whole point of Compare is that the
// change is computed from bytes the reader has.
func Composed(name string, current, before *Page) *DocumentAt {
	parsed := ParseMarkdown(string(current.Content), name)

	out := &DocumentAt{Document: parsed, Page: current}

	if before == nil {
		return out
	}

	out.Document = Compare(ParseMarkdown(string(before.Content), name), parsed)
	out.Compared = true

	return out
}

// Read gets a document and, when a version is named, marks what changed since
// it.
func (b *Browser) Read(
	ctx context.Context, fingerprint, projectID, name string,
	digest []byte, commit string,
) (*DocumentAt, error) {
	page, err := b.File(ctx, fingerprint, projectID, name)
	if err != nil {
		return nil, err
	}

	if len(digest) == 0 && commit == "" {
		return Composed(name, page, nil), nil
	}

	before, err := b.FileAt(ctx, fingerprint, projectID, name, digest, commit)
	if err != nil {
		// A version that has gone is not a reason to refuse the document. The
		// reader asked to see what changed; what they get is the document, and
		// a line saying the version they picked is no longer there.
		out := Composed(name, page, nil)
		out.Against = &ladulasv1.DocumentVersion{Digest: digest, Commit: commit}

		return out, err
	}

	out := Composed(name, page, before)
	out.Against = &ladulasv1.DocumentVersion{
		Digest: digest,
		Commit: commit,
		At:     timestampOf(before.Modified),
	}

	return out, nil
}

// timestampOf is a time as the wire carries it, and nil for the zero time so
// that "no timestamp" does not read as 1970 on the other side.
func timestampOf(at time.Time) *timestamppb.Timestamp {
	if at.IsZero() {
		return nil
	}

	return timestamppb.New(at)
}
