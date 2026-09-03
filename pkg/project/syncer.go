package project

import (
	"context"
	"errors"
	"fmt"
	"path"
	"time"

	"connectrpc.com/connect"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
)

// Fetching the documentation before anybody opens it (decision AP).
//
// This is the half that makes browsing quick, and the reason the rest of
// decision AP exists. Under decision Q every open was a call to the publishing
// machine, which is correct and slow: a document three taps into a project on a
// laptop across a tailnet takes as long as the laptop takes to wake up. What
// this does is ask once for everything that differs and keep it, so that
// opening a document is a read from local disk.
//
// **The manifest is what the approver already knows**, which is what makes it
// cheap. Every page in the cache carries the digest it was stored under, so
// saying "here is what I have" costs a path and thirty-two bytes each and no
// content at all. A doc set nobody has touched since the last sync is answered
// with nothing.
//
// **A sync is idempotent and complete**, and everything else in decision AP
// leans on that. An event that was dropped, a stream that broke, a phone that
// was in a tunnel — none of them need recovering from, because the next sync
// finds the same difference. That is why events may be lost and why this is
// safe to run on a timer, on unlock, and on somebody coming back to the app.

// SyncSummary is what one project's sync did.
type SyncSummary struct {
	// Fetched and Removed are pages written and pages dropped.
	Fetched int
	Removed int
	// Bytes is what was transferred, for a log line that says whether a slow
	// sync was slow because of the network or because of the number of calls.
	Bytes int64
	// Publication is the publisher's account of the project, taken in the same
	// exchange as the documents (§6).
	Publication *ladulasv1.Publication
}

// Sync reconciles one project against its publisher.
//
// An unreachable publisher is not an error worth stopping for: it is the state
// a phone spends most of its life in, and what the approver has stays readable.
// The caller gets the error so that it can decide whether to say anything, and
// nothing in the cache is changed.
func (b *Browser) Sync(
	ctx context.Context, fingerprint, projectID string,
) (SyncSummary, error) {
	var summary SyncSummary

	publisher := b.publisher(fingerprint)
	if publisher == nil {
		return summary, fmt.Errorf(
			"project: %s publishes nothing here", fingerprint)
	}

	have := b.manifest(fingerprint, projectID)

	err := b.source.Ask(ctx, fingerprint, func(
		ctx context.Context, client ladulasv1connect.ProjectServiceClient,
	) error {
		stream, err := client.SyncProject(ctx, connect.NewRequest(
			&ladulasv1.SyncProjectRequest{
				ProjectId: projectID,
				Have:      have,
			}))
		if err != nil {
			return err //nolint:wrapcheck // the source wraps it with the address
		}

		defer func() {
			_ = stream.Close()
		}()

		return b.drain(stream, publisher, fingerprint, projectID, &summary)
	})
	if err != nil {
		return summary, err //nolint:wrapcheck // the source wraps it
	}

	return summary, nil
}

// syncStream is the half of a connect stream drain uses.
//
// It exists so that the logic below can be tested without a network. connect
// offers no way to build a ServerStreamForClient outside its generated client,
// and every rule that matters — the header first, a bad path skipped, an
// unknown kind ignored — lives in drain rather than in the transport.
type syncStream interface {
	Receive() bool
	Msg() *ladulasv1.SyncProjectEvent
	Err() error
}

// drain applies a sync stream to the cache.
//
// The publication arrives on the first event and nothing is applied before it:
// a page is kept against the commit the publisher was standing on, and keeping
// one against a commit taken from a different answer would be stitching two
// moments into one claim (§6).
func (b *Browser) drain(
	stream syncStream,
	publisher *Publisher, fingerprint, projectID string,
	summary *SyncSummary,
) error {
	for stream.Receive() {
		event := stream.Msg()

		if found := event.GetProject(); found != nil {
			summary.Publication = found

			continue
		}

		if summary.Publication == nil {
			return errors.New(
				"project: the publisher sent a change before saying what the " +
					"project was")
		}

		// A path is checked once, here, for both kinds. It is a distrusted
		// machine's string about to become a name in this cache, and one that
		// would leave it is dropped rather than refused: a single bad entry
		// should not cost the approver the rest of its sync.
		if CheckPath(event.GetPath()) != nil {
			continue
		}

		switch event.GetKind() {
		case ladulasv1.SyncChangeKind_SYNC_CHANGE_KIND_PUT:
			if err := b.put(
				publisher, fingerprint, summary.Publication, event); err != nil {
				return err
			}

			summary.Fetched++
			summary.Bytes += int64(len(event.GetContent()))

		case ladulasv1.SyncChangeKind_SYNC_CHANGE_KIND_REMOVE:
			if err := b.cache.Forget(
				fingerprint, projectID, event.GetPath()); err != nil {
				return err
			}

			summary.Removed++

		case ladulasv1.SyncChangeKind_SYNC_CHANGE_KIND_UNSPECIFIED:
			// A kind this side does not understand is skipped rather than
			// guessed at. The next sync will offer it again, and guessing wrong
			// about a change means either losing a page or keeping a stale one.
			continue
		}
	}

	if err := stream.Err(); err != nil {
		return err //nolint:wrapcheck // the source wraps it with the address
	}

	return nil
}

// put keeps one document the publisher sent.
//
// The path has already been checked by drain, which is the one place it is
// checked for either kind of change. The record is built from it rather than
// from what came back, apart from the one fact only the publisher has: a path
// is the field a compromised requester would want to choose, and it does not
// get to choose the name a page is kept under — the same rule File follows.
func (b *Browser) put(
	publisher *Publisher, fingerprint string,
	publication *ladulasv1.Publication,
	event *ladulasv1.SyncProjectEvent,
) error {
	name := event.GetPath()
	body := event.GetContent()

	entry := &ladulasv1.ProjectEntry{
		Name:     path.Base(name),
		Path:     name,
		Size:     int64(len(body)),
		Modified: event.GetFile().GetModified(),
		Readable: true,
	}

	_, err := b.cache.Keep(publisher.Name, fingerprint, publication, entry, body)

	return err
}

// manifest is what this instance holds of one project, as the publisher is told
// about it.
//
// Only the digests are sent — no sizes, no times — because the digest is the
// only one of those the publisher compares against. A manifest for a doc set is
// a few kilobytes and the answer to an unchanged one is empty.
func (b *Browser) manifest(
	fingerprint, projectID string,
) []*ladulasv1.SyncEntry {
	cached, err := b.cache.Find(fingerprint, projectID)
	if err != nil {
		return nil
	}

	out := make([]*ladulasv1.SyncEntry, 0, len(cached.GetFiles()))

	for _, file := range cached.GetFiles() {
		out = append(out, &ladulasv1.SyncEntry{
			Path:   file.GetPath(),
			Digest: file.GetDigest(),
		})
	}

	return out
}

// SyncAll reconciles every project every publisher offers.
//
// Publishers are asked one at a time rather than in parallel. A sync is not
// something anybody is waiting on — that is the whole point of doing it before
// they ask — and a phone that dialled four laptops at once to prefetch
// documentation would be spending a radio on work nobody had asked for.
//
// It returns what it managed. A publisher that could not be reached leaves the
// others alone, which is the ordinary case rather than a failure: they are
// separate machines and they sleep separately.
func (b *Browser) SyncAll(ctx context.Context) ([]SyncSummary, error) {
	if b.source == nil {
		return nil, nil
	}

	var out []SyncSummary

	for _, publisher := range b.source.Publishers() {
		projects, err := b.List(ctx, publisher.Fingerprint)
		if err != nil {
			continue
		}

		for _, overview := range projects {
			// Nothing to sync from a publisher that did not answer the listing:
			// what is here is what was read before, and the sync would be a
			// second failed call to the same sleeping machine.
			if !overview.Live {
				continue
			}

			summary, err := b.Sync(ctx, publisher.Fingerprint,
				overview.Project.GetProjectId())
			if err != nil {
				continue
			}

			out = append(out, summary)
		}

		if err := ctx.Err(); err != nil {
			return out, err //nolint:wrapcheck // the caller's own cancellation
		}
	}

	return out, nil
}

// DefaultSyncEvery is how often an instance reconciles on its own.
//
// It is a backstop rather than the mechanism. The event stream is what makes a
// change arrive in seconds; this is what makes one arrive at all after a stream
// broke, a laptop slept through an edit, or an event was dropped because
// nobody was reading. Ten minutes is far more often than documentation changes
// and far less often than anybody would notice.
const DefaultSyncEvery = 10 * time.Minute
