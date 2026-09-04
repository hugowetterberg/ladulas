package peer

import (
	"context"
	"net/http"
	"net/http/httptrace"
	"testing"
	"time"

	"connectrpc.com/connect"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
)

// TestCloseIdleDropsTheConnectionAndKeepsTheAddress is the phone coming back
// to the foreground: the pooled connection is the one thing known to be
// doubtful and is dropped, the address that worked is still the best guess and
// is kept, and the next call goes through on a fresh connection without a race.
func TestCloseIdleDropsTheConnectionAndKeepsTheAddress(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	waitForLink(t, headless, desktop.identity.Fingerprint())

	record, ok := desktop.store.Peer(headless.identity.Fingerprint())
	if !ok {
		t.Fatal("the desktop has no record of the headless box")
	}

	list := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		reused := false

		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				reused = info.Reused
			},
		})

		err := desktop.node.call(ctx, record, func(
			ctx context.Context, client *http.Client, baseURL string,
		) error {
			_, err := ladulasv1connect.NewProjectServiceClient(client, baseURL).
				ListProjects(ctx, connect.NewRequest(
					&ladulasv1.ListProjectsRequest{}))

			return err
		})
		if err != nil {
			t.Fatalf("list: %v", err)
		}

		return reused
	}

	if list() {
		t.Fatal("the first call reused a connection nothing had opened")
	}

	if !list() {
		t.Fatal("the second call did not reuse the warm connection")
	}

	held, err := desktop.node.dialerFor(record)
	if err != nil {
		t.Fatal(err)
	}

	held.mu.Lock()
	before := held.preferred
	held.mu.Unlock()

	if before == "" {
		t.Fatal("two calls in and no address was remembered")
	}

	desktop.node.CloseIdle()

	held.mu.Lock()
	after := held.preferred
	held.mu.Unlock()

	if after != before {
		t.Errorf("CloseIdle changed the remembered address from %q to %q",
			before, after)
	}

	if list() {
		t.Fatal("the call after CloseIdle reused the connection it was meant to drop")
	}

	if !list() {
		t.Fatal("the fresh connection was not kept warm in its turn")
	}
}
