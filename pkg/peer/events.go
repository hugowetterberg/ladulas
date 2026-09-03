package peer

import (
	"context"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Telling an approver that something changed, without telling it what
// (decision AP).
//
// **An event is a reason to reconcile and never a delivery**, and everything
// awkward about a fan-out stops mattering once that is true. A dropped event
// costs latency and not correctness, because SyncProject is idempotent and
// complete: an approver that missed a notification finds the same difference
// the next time it asks, and it asks whenever it comes to the foreground
// anyway. So a slow reader is dropped past rather than waited for, and the
// watcher never blocks on a network.
//
// The stream is opened by the approver, which is the same direction
// ProjectService runs and for the same reason: a phone cannot be dialled at
// all (§11). So the machine that wants to know does the dialling, and the
// machine that knows writes into it.

// eventBuffer is how many events one subscriber may fall behind by.
//
// Past it the oldest are dropped. Sixty-four is far more than a doc set
// produces between two reads of a stream that is being read at all — a
// subscriber that reaches it is one that has stopped reading, and what it needs
// is to reconnect and reconcile, which is exactly what it will do.
const eventBuffer = 64

// subscriber is one open Events stream.
type subscriber struct {
	// projects is the ids this subscriber asked about; empty means all.
	projects map[string]bool
	events   chan *ladulasv1.Event
}

// wants reports whether an event is one this subscriber asked for.
func (s *subscriber) wants(event *ladulasv1.Event) bool {
	if len(s.projects) == 0 {
		return true
	}

	return s.projects[event.GetProjectId()]
}

// subscribe registers a stream and hands back the way to stop.
func (n *Node) subscribe(projectIDs []string) (*subscriber, func()) {
	wanted := make(map[string]bool, len(projectIDs))

	for _, id := range projectIDs {
		wanted[id] = true
	}

	sub := &subscriber{
		projects: wanted,
		events:   make(chan *ladulasv1.Event, eventBuffer),
	}

	n.eventMu.Lock()

	if n.subscribers == nil {
		n.subscribers = make(map[*subscriber]bool)
	}

	n.subscribers[sub] = true

	n.eventMu.Unlock()

	return sub, func() {
		n.eventMu.Lock()
		delete(n.subscribers, sub)
		n.eventMu.Unlock()
	}
}

// Announce puts an event in front of every approver watching for one.
//
// It never blocks. A subscriber that is not keeping up loses the event, which
// is affordable because an event is a reason to reconcile rather than the
// content itself — and reconciling is complete regardless of what was missed.
func (n *Node) Announce(event *ladulasv1.Event) {
	if event.GetTimestamp() == nil {
		event.Timestamp = timestamppb.Now()
	}

	n.eventMu.Lock()

	subs := make([]*subscriber, 0, len(n.subscribers))

	for sub := range n.subscribers {
		subs = append(subs, sub)
	}

	n.eventMu.Unlock()

	for _, sub := range subs {
		if !sub.wants(event) {
			continue
		}

		select {
		case sub.events <- event:
		default:
			n.log.Debug(
				"an approver is not keeping up with events; it will find this "+
					"when it next reconciles",
				"kind", event.GetKind().String(),
				"project", event.GetProjectId())
		}
	}
}

// WatchEvent turns something the filesystem watcher noticed into an event for
// the peers watching.
//
// It is the seam between pkg/project, which knows about documents and knows
// nothing about peers, and this package, which is the other way round. The
// watcher calls it from its own goroutine, so it does what Announce promises
// and returns immediately.
func (n *Node) WatchEvent(event project.WatchEvent) {
	out := &ladulasv1.Event{
		ProjectId: event.ProjectID,
		Path:      event.Path,
		Head:      event.Head,
	}

	switch {
	case event.Moved:
		out.Kind = ladulasv1.EventKind_EVENT_KIND_PROJECT_MOVED
	case event.Removed:
		out.Kind = ladulasv1.EventKind_EVENT_KIND_DOCUMENT_REMOVED
	default:
		out.Kind = ladulasv1.EventKind_EVENT_KIND_DOCUMENT_CHANGED
	}

	n.Announce(out)
}

// Events holds a connection open and reports what changes here.
func (s *peerService) Events(
	ctx context.Context,
	req *connect.Request[ladulasv1.EventsRequest],
	stream *connect.ServerStream[ladulasv1.Event],
) error {
	// The same gate as the rest of project browsing: a peer that does not
	// approve for this instance has nothing here to be told about.
	if _, _, err := s.node.publisherFor(ctx); err != nil {
		return err
	}

	sub, stop := s.node.subscribe(req.Msg.GetProjectIds())
	defer stop()

	return s.node.streamEvents(ctx, sub, stream)
}

// eventSender is the half of a connect stream the loop below uses.
//
// It exists so that the loop can be tested without a network, and specifically
// so that the heartbeat-first rule can be. connect does not offer a way to
// build a ServerStream outside a handler, and a contract nothing can assert is
// a contract that will quietly stop holding.
type eventSender interface {
	Send(*ladulasv1.Event) error
}

// streamEvents beats once and then relays until the caller goes away.
func (n *Node) streamEvents(
	ctx context.Context, sub *subscriber, out eventSender,
) error {
	// **The first heartbeat goes out before anything is waited for.**
	//
	// connect hands a stream back to the caller as soon as the request has been
	// written and keeps the transport error for the first Receive, so a caller
	// that treated "no error" as a connection would count a socket nothing is
	// reading as a live link. A laptop asleep with its lid shut was reported
	// online every twenty seconds for months on exactly that mistake. The beat
	// costs one message and is what makes the far side's check possible, so it
	// is sent here rather than left to the ticker — a stream whose first beat
	// is thirty seconds away is one a caller cannot check at all.
	if err := out.Send(heartbeat()); err != nil {
		return err //nolint:wrapcheck // connect's own error, on its own stream
	}

	beat := time.NewTicker(n.heartbeatEvery())
	defer beat.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case event := <-sub.events:
			if err := out.Send(event); err != nil {
				return err //nolint:wrapcheck // connect's own error
			}

		case <-beat.C:
			if err := out.Send(heartbeat()); err != nil {
				return err //nolint:wrapcheck // connect's own error
			}
		}
	}
}

func heartbeat() *ladulasv1.Event {
	return &ladulasv1.Event{
		Kind:      ladulasv1.EventKind_EVENT_KIND_HEARTBEAT,
		Timestamp: timestamppb.Now(),
	}
}

// heartbeatEvery is how often an idle event stream ticks. It is the presence
// stream's interval, because it answers the same question — is the far side
// still there — and two different answers to that would be two things to
// reason about for no gain.
func (n *Node) heartbeatEvery() time.Duration {
	if n.heartbeat > 0 {
		return n.heartbeat
	}

	return DefaultHeartbeat
}

// eventState is the fan-out's own state, kept off the node's main mutex so that
// announcing an event never contends with a link coming up.
type eventState struct {
	eventMu     sync.Mutex
	subscribers map[*subscriber]bool
}
