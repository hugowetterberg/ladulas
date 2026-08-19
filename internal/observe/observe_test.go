package observe_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/internal/observe"
)

// The port answers what it promises to answer, on an address of its own.
func TestServerServesMetricsAndPprof(t *testing.T) {
	t.Parallel()

	base := serve(t, observe.Options{Addr: "127.0.0.1:0"})

	for _, path := range []string{
		"/",
		"/metrics",
		"/debug/pprof/",
		"/debug/pprof/heap?debug=1",
		"/debug/pprof/cmdline",
	} {
		body := get(t, base+path)
		if body == "" {
			t.Errorf("%s answered with nothing", path)
		}
	}

	// The runtime collectors are the ones every process has, and their absence
	// is the difference between a scrape target and an empty page.
	metrics := get(t, base+"/metrics")

	for _, want := range []string{
		"go_goroutines",
		"go_memstats_alloc_bytes",
		"process_start_time_seconds",
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("/metrics does not mention %s", want)
		}
	}
}

// A profile is a GET like any other, and the index has to link to it or nobody
// will find it without reading this package.
func TestIndexLinksTheTwoSurfaces(t *testing.T) {
	t.Parallel()

	body := get(t, serve(t, observe.Options{Addr: "127.0.0.1:0"})+"/")

	for _, want := range []string{"/metrics", "/debug/pprof/"} {
		if !strings.Contains(body, want) {
			t.Errorf("the index does not link %s", want)
		}
	}
}

// Off is not an error and not a half-built server: every method has to answer
// on the nil one, because that is what the wiring holds when nobody asked for a
// port.
func TestOffIsANilServer(t *testing.T) {
	t.Parallel()

	for _, addr := range []string{"", observe.Off} {
		server, err := observe.New(observe.Options{Addr: addr})
		if err != nil {
			t.Fatalf("build with addr %q: %v", addr, err)
		}

		if server != nil {
			t.Fatalf("addr %q built a server", addr)
		}

		if server.Registerer() == nil {
			t.Error("the discarding registerer is missing")
		}

		if got := server.Addr(); got != "" {
			t.Errorf("a server that is not there is listening on %q", got)
		}

		if err := server.Listen(); err != nil {
			t.Errorf("listen: %v", err)
		}

		if err := server.Serve(t.Context()); err != nil {
			t.Errorf("serve: %v", err)
		}

		if err := server.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}
}

// serve starts a debug server and returns its base URL.
func serve(t *testing.T, opts observe.Options) string {
	t.Helper()

	server, err := observe.New(opts)
	if err != nil {
		t.Fatalf("build the server: %v", err)
	}

	if err := server.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		done <- server.Serve(ctx)
	}()

	t.Cleanup(func() {
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("the server did not stop")
		}
	})

	return "http://" + server.Addr()
}

func get(t *testing.T, url string) string {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build a request for %s: %v", url, err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("close the body of %s: %v", url, err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s answered %s", url, resp.Status)
	}

	return string(body)
}
