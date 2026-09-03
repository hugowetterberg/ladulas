package app

import (
	"context"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/peer"
	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Keeping the documentation this instance reads up to date, without anybody
// asking (decision AP).
//
// It runs with the peer channel, because reaching a publisher is what it does
// and there is nothing to reach without one. Two loops, and they answer
// different halves of the same question.
//
// **The sweep is what makes it correct.** It reconciles everything on the way
// up and then on a timer, and because a sync is idempotent and complete it does
// not matter what it missed: a laptop that slept through an edit, a stream that
// broke, an event nobody was reading for. The next sweep finds the same
// difference.
//
// **The event streams are what make it quick.** One per publisher, held open,
// reporting a document changed within a second or two of somebody saving it.
// They are an optimisation over the sweep and are treated as one — a stream
// that will not stay up costs latency and nothing else.
//
// Neither is anything a person is waiting on, which is the whole point: the
// work happens before somebody opens a document rather than while they wait for
// one.

// syncRetryFloor and syncRetryCeiling bound how hard a publisher whose event
// stream keeps failing is retried.
//
// A publisher that is simply asleep is the ordinary case and must not be dialled
// in a tight loop for the hours it stays that way, so the backoff doubles to a
// couple of minutes and sits there. The sweep is still running underneath, so
// the cost of a long backoff is latency on a change rather than missing it.
const (
	syncRetryFloor   = 5 * time.Second
	syncRetryCeiling = 2 * time.Minute
)

// startDocSync brings both loops up for the peer channel that has just started
// serving. It returns immediately; the loops end with the context.
//
// **The node is captured rather than read from the core.** Sealing and
// rebinding both set core.peer to nil under the App's lock, so a loop that
// re-read it every time round would be racing that write — and would eventually
// call a method on nil. The loops belong to one node's lifetime, the context is
// cancelled when that node stops, and holding the node they were started for is
// what makes both of those true at once.
func (a *App) startDocSync(
	ctx context.Context, node *peer.Node, cache *project.Cache,
) {
	if node == nil || cache == nil {
		return
	}

	browser := project.NewBrowser(cache, node)

	go a.sweepDocs(ctx, browser)
	go a.watchPublishers(ctx, node, browser)
}

// sweepDocs reconciles everything, now and then on a timer.
func (a *App) sweepDocs(ctx context.Context, browser *project.Browser) {
	// At once, because the peer channel has just come up and whatever changed
	// while it was down is what somebody is about to open.
	a.sweepOnce(ctx, browser)

	ticker := time.NewTicker(project.DefaultSyncEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sweepOnce(ctx, browser)
		}
	}
}

func (a *App) sweepOnce(ctx context.Context, browser *project.Browser) {
	summaries, err := browser.SyncAll(ctx)
	if err != nil && ctx.Err() == nil {
		a.log.Debug("the documentation sweep stopped early",
			"error", err.Error())
	}

	var fetched, removed int

	for _, summary := range summaries {
		fetched += summary.Fetched
		removed += summary.Removed
	}

	// Silence when there was nothing to do, which is most sweeps: a doc set
	// nobody has touched costs one manifest per project and produces no
	// content, and a line saying so every ten minutes would bury the ones that
	// matter.
	if fetched == 0 && removed == 0 {
		return
	}

	a.log.Info("documentation synced",
		"projects", len(summaries), "fetched", fetched, "removed", removed)
}

// watchPublishers keeps an event stream to each publisher, reconciling the
// project an event names.
//
// A publisher that goes away is retried with a backoff rather than abandoned,
// and the set of publishers is re-read each time round: pairing with a machine
// should not need a restart to start hearing from it.
//
// The map is this goroutine's alone. Every watcher runs until the context ends,
// so an entry is added once and never taken out — which is why there is no lock
// on it.
func (a *App) watchPublishers(
	ctx context.Context, node *peer.Node, browser *project.Browser,
) {
	watching := map[string]context.CancelFunc{}

	defer func() {
		for _, stop := range watching {
			stop()
		}
	}()

	ticker := time.NewTicker(syncRetryFloor)
	defer ticker.Stop()

	for {
		for _, publisher := range node.Publishers() {
			if _, ok := watching[publisher.Fingerprint]; ok {
				continue
			}

			streamCtx, stop := context.WithCancel(ctx)
			watching[publisher.Fingerprint] = stop

			go a.watchOne(streamCtx, node, browser, publisher)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// watchOne holds one publisher's stream up, with a backoff between attempts.
//
// It returns only when the context is cancelled, which is what lets the map in
// watchPublishers be owned by one goroutine: an entry is added when a watcher
// starts and never removed, because a watcher only stops when everything does.
// A version of this that deleted its own entry on the way out needed a mutex
// for a map that otherwise has exactly one writer.
func (a *App) watchOne(
	ctx context.Context, node *peer.Node, browser *project.Browser,
	publisher project.Publisher,
) {
	wait := syncRetryFloor

	for ctx.Err() == nil {
		err := node.WatchPublisher(ctx, publisher.Fingerprint,
			func() {
				// The first message is the stream proving it is real. Anything
				// may have changed while it was down, so this is the moment to
				// reconcile rather than waiting for the next sweep.
				a.log.Debug("watching a publisher for document changes",
					"peer", publisher.Name)

				wait = syncRetryFloor

				a.syncPublisher(ctx, browser, publisher)
			},
			func(event *ladulasv1.Event) {
				a.applyDocEvent(ctx, browser, publisher, event)
			})
		if ctx.Err() != nil {
			return
		}

		if err != nil {
			a.log.Debug("a publisher's event stream ended",
				"peer", publisher.Name, "error", err.Error(),
				"retry_in", wait.String())
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		wait *= 2

		if wait > syncRetryCeiling {
			wait = syncRetryCeiling
		}
	}
}

// applyDocEvent reconciles the project an event is about.
//
// It syncs the project rather than fetching the document the event names, and
// that is deliberate: an event is a reason to reconcile and never a delivery
// (decision AP). Reconciling costs a manifest and answers correctly whatever
// else changed in the same second; fetching the one path named would take a
// distrusted machine's word for what to ask for.
func (a *App) applyDocEvent(
	ctx context.Context, browser *project.Browser,
	publisher project.Publisher, event *ladulasv1.Event,
) {
	switch event.GetKind() {
	case ladulasv1.EventKind_EVENT_KIND_DOCUMENT_CHANGED,
		ladulasv1.EventKind_EVENT_KIND_DOCUMENT_REMOVED,
		ladulasv1.EventKind_EVENT_KIND_PROJECT_PUBLISHED,
		ladulasv1.EventKind_EVENT_KIND_PROJECT_MOVED:
		if id := event.GetProjectId(); id != "" {
			a.syncProject(ctx, browser, publisher, id)

			return
		}

		a.syncPublisher(ctx, browser, publisher)

	case ladulasv1.EventKind_EVENT_KIND_PROJECT_WITHDRAWN:
		// Nothing is taken back: there is no copy anywhere to take back
		// (decision Q), and what has been read of a withdrawn project stays
		// readable. What changes is that the listing will stop naming it, which
		// the next listing does on its own.
		a.log.Debug("a publisher withdrew a project",
			"peer", publisher.Name, "project", event.GetProjectId())

	case ladulasv1.EventKind_EVENT_KIND_HEARTBEAT,
		ladulasv1.EventKind_EVENT_KIND_UNSPECIFIED:
		// A heartbeat never reaches here, and a kind this side does not know is
		// left to the sweep — which will find whatever it was about.
	}
}

func (a *App) syncPublisher(
	ctx context.Context, browser *project.Browser, publisher project.Publisher,
) {
	projects, err := browser.List(ctx, publisher.Fingerprint)
	if err != nil {
		return
	}

	for _, overview := range projects {
		if !overview.Live {
			continue
		}

		a.syncProject(ctx, browser, publisher,
			overview.Project.GetProjectId())
	}
}

func (a *App) syncProject(
	ctx context.Context, browser *project.Browser,
	publisher project.Publisher, projectID string,
) {
	summary, err := browser.Sync(ctx, publisher.Fingerprint, projectID)
	if err != nil {
		if ctx.Err() == nil {
			a.log.Debug("a project could not be synced",
				"peer", publisher.Name, "project", projectID,
				"error", err.Error())
		}

		return
	}

	if summary.Fetched == 0 && summary.Removed == 0 {
		return
	}

	a.log.Info("documentation synced",
		"peer", publisher.Name,
		"project", summary.Publication.GetName(),
		"fetched", summary.Fetched, "removed", summary.Removed)
}
