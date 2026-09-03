package peer

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// recorder stands in for a connect stream. What is under test is the order and
// the content of what goes out, which is all a stream is from this side.
type recorder struct {
	sent chan *ladulasv1.Event
}

func (r *recorder) Send(event *ladulasv1.Event) error {
	select {
	case r.sent <- event:
	default:
	}

	return nil
}

func eventNode(t *testing.T) *Node {
	t.Helper()

	return &Node{
		log: slog.New(slog.DiscardHandler),
		// Long enough that no test sees a timed beat by accident: the first one
		// is sent before the ticker exists, and that is the one that matters.
		heartbeat: time.Hour,
	}
}

func next(t *testing.T, sent chan *ladulasv1.Event) *ladulasv1.Event {
	t.Helper()

	select {
	case event := <-sent:
		return event
	case <-time.After(2 * time.Second):
		t.Fatal("nothing was sent")

		return nil
	}
}

// The contract that keeps a sleeping laptop from looking linked: connect hands
// a stream back as soon as the request has been written, so a caller can only
// tell a real connection from a socket nothing is reading by receiving
// something. The beat therefore goes out before anything is waited for.
func TestTheFirstEventIsAHeartbeatBeforeAnythingHappens(t *testing.T) {
	t.Parallel()

	node := eventNode(t)
	sub, stop := node.subscribe(nil)

	defer stop()

	out := &recorder{sent: make(chan *ladulasv1.Event, 8)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = node.streamEvents(ctx, sub, out)
	}()

	first := next(t, out.sent)

	if first.GetKind() != ladulasv1.EventKind_EVENT_KIND_HEARTBEAT {
		t.Errorf("the first event was %s, want a heartbeat", first.GetKind())
	}

	if first.GetTimestamp() == nil {
		t.Error("the heartbeat carries no timestamp, so nothing can age it")
	}
}

func TestAnAnnouncedChangeReachesASubscriber(t *testing.T) {
	t.Parallel()

	node := eventNode(t)
	sub, stop := node.subscribe(nil)

	defer stop()

	out := &recorder{sent: make(chan *ladulasv1.Event, 8)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = node.streamEvents(ctx, sub, out)
	}()

	next(t, out.sent) // the opening heartbeat

	node.WatchEvent(project.WatchEvent{
		ProjectID: "docs", Path: "README.md", Head: "abc123",
	})

	event := next(t, out.sent)

	if event.GetKind() != ladulasv1.EventKind_EVENT_KIND_DOCUMENT_CHANGED {
		t.Errorf("kind = %s, want a document change", event.GetKind())
	}

	if event.GetPath() != "README.md" || event.GetProjectId() != "docs" {
		t.Errorf("event named %s in %s", event.GetPath(), event.GetProjectId())
	}

	if event.GetHead() != "abc123" {
		t.Errorf("head = %q, want abc123 — a snapshot means nothing without it",
			event.GetHead())
	}
}

// An event carries no content, and that is the contract rather than an
// omission: it is a reason to reconcile, so a reader that missed one loses
// latency and not correctness.
func TestAnEventCarriesNoContent(t *testing.T) {
	t.Parallel()

	node := eventNode(t)
	sub, stop := node.subscribe(nil)

	defer stop()

	node.WatchEvent(project.WatchEvent{
		ProjectID: "docs", Path: "README.md", Head: "abc123",
	})

	event := next(t, sub.events)

	// The message has no field for contents at all, which is the point; this
	// asserts the shape has not grown one.
	if got := event.ProtoReflect().Descriptor().Fields().ByName("content"); got != nil {
		t.Error("an Event has gained a content field")
	}
}

func TestTheThreeWatchEventsMapToTheThreeKinds(t *testing.T) {
	t.Parallel()

	for _, item := range []struct {
		name string
		in   project.WatchEvent
		want ladulasv1.EventKind
	}{
		{
			name: "a document changed",
			in:   project.WatchEvent{ProjectID: "docs", Path: "README.md"},
			want: ladulasv1.EventKind_EVENT_KIND_DOCUMENT_CHANGED,
		},
		{
			name: "a document was removed",
			in: project.WatchEvent{
				ProjectID: "docs", Path: "README.md", Removed: true,
			},
			want: ladulasv1.EventKind_EVENT_KIND_DOCUMENT_REMOVED,
		},
		{
			name: "the project moved",
			in:   project.WatchEvent{ProjectID: "docs", Moved: true},
			want: ladulasv1.EventKind_EVENT_KIND_PROJECT_MOVED,
		},
	} {
		node := eventNode(t)
		sub, stop := node.subscribe(nil)

		node.WatchEvent(item.in)

		event := next(t, sub.events)

		if event.GetKind() != item.want {
			t.Errorf("%s: kind = %s, want %s",
				item.name, event.GetKind(), item.want)
		}

		stop()
	}
}

func TestASubscriberOnlyHearsAboutTheProjectsItAskedFor(t *testing.T) {
	t.Parallel()

	node := eventNode(t)
	sub, stop := node.subscribe([]string{"docs"})

	defer stop()

	node.WatchEvent(project.WatchEvent{ProjectID: "elsewhere", Path: "a.md"})
	node.WatchEvent(project.WatchEvent{ProjectID: "docs", Path: "b.md"})

	event := next(t, sub.events)

	if event.GetProjectId() != "docs" {
		t.Errorf("heard about %s, which was not asked for",
			event.GetProjectId())
	}

	select {
	case extra := <-sub.events:
		t.Errorf("a second event arrived for %s", extra.GetProjectId())
	default:
	}
}

// The watcher must never wait on a network. A subscriber that has stopped
// reading is dropped past, because an event is a reason to reconcile and the
// reconciliation is complete whatever was missed.
func TestAnnouncingToASubscriberThatStoppedReadingDoesNotBlock(t *testing.T) {
	t.Parallel()

	node := eventNode(t)
	_, stop := node.subscribe(nil)

	defer stop()

	done := make(chan struct{})

	go func() {
		defer close(done)

		// Well past the buffer, and nothing is draining it.
		for range eventBuffer * 4 {
			node.WatchEvent(project.WatchEvent{
				ProjectID: "docs", Path: "README.md",
			})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("announcing blocked on a subscriber that was not reading")
	}
}

func TestUnsubscribingStopsDelivery(t *testing.T) {
	t.Parallel()

	node := eventNode(t)
	sub, stop := node.subscribe(nil)

	stop()

	node.WatchEvent(project.WatchEvent{ProjectID: "docs", Path: "README.md"})

	select {
	case event := <-sub.events:
		t.Errorf("an event arrived after unsubscribing: %v", event.GetKind())
	default:
	}
}

// A cancelled stream ends without an error: the reader hung up, which is the
// ordinary way one of these finishes.
func TestACancelledStreamEndsQuietly(t *testing.T) {
	t.Parallel()

	node := eventNode(t)
	sub, stop := node.subscribe(nil)

	defer stop()

	out := &recorder{sent: make(chan *ladulasv1.Event, 8)}

	ctx, cancel := context.WithCancel(context.Background())

	errs := make(chan error, 1)

	go func() {
		errs <- node.streamEvents(ctx, sub, out)
	}()

	next(t, out.sent)

	cancel()

	select {
	case err := <-errs:
		if err != nil {
			t.Errorf("a cancelled stream returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the stream did not end when the caller went away")
	}
}
