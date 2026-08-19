// Package observe is the second port: Prometheus metrics and pprof, served
// away from everything that does the work.
//
// It is a separate listener rather than a path on an existing one because the
// two surfaces have nothing in common. The agent socket, the signing socket and
// the peer channel are each authenticated in their own way and each carries
// something worth protecting; this one is unauthenticated, read-only and of
// interest to a scraper. Putting it on its own address is what lets it be bound
// somewhere a scraper can reach without widening anything else by a byte — and,
// on the daemon, what lets it be left unbound entirely.
//
// It is also the only package in the tree that imports a metrics library. The
// packages that produce the numbers — approval, peer, relay — expose a seam and
// nothing more, so that the phone, which links several of them through gomobile,
// does not link a Prometheus client for a scraper that will never call it.
package observe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Off is the listen address that means "do not open the port at all". It is
// spelled the same way peering's is, so that switching a thing off looks the
// same everywhere.
const Off = "off"

// Options configures the debug server.
type Options struct {
	// Addr is where it listens. Empty or Off means it is not opened.
	Addr string
	// Registry defaults to a fresh one. It is not the default registry:
	// anything registering into a package-level variable is registering into
	// whichever process happens to link it, and the point of injecting the
	// registerer is that a test can hold its own.
	Registry *prometheus.Registry
	Logger   *slog.Logger
}

// Server is the debug listener.
type Server struct {
	addr     string
	registry *prometheus.Registry
	log      *slog.Logger

	server   *http.Server
	listener net.Listener
}

// New builds the server and registers what every process exports: the Go
// runtime, the process itself, and the build.
//
// It returns nil, and nothing else has to care, when the address says the port
// is not wanted. Every method below is safe on a nil server, so a caller wires
// it up the same way whether or not it was asked for.
func New(opts Options) (*Server, error) {
	if opts.Addr == "" || opts.Addr == Off {
		return nil, nil //nolint:nilnil // a port nobody asked for is not an error
	}

	registry := opts.Registry
	if registry == nil {
		registry = prometheus.NewRegistry()
	}

	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	err := errors.Join(
		registry.Register(collectors.NewGoCollector()),
		registry.Register(collectors.NewProcessCollector(
			collectors.ProcessCollectorOpts{})),
		registry.Register(collectors.NewBuildInfoCollector()),
	)
	if err != nil {
		return nil, fmt.Errorf("register the runtime collectors: %w", err)
	}

	return &Server{addr: opts.Addr, registry: registry, log: log}, nil
}

// Registerer is where a service's own collectors go. It answers on a nil
// server too, with a registerer that discards, so that building the metrics is
// unconditional and only serving them is a decision.
func (s *Server) Registerer() prometheus.Registerer {
	if s == nil {
		return discardRegisterer{}
	}

	return s.registry
}

// Gatherer is the registry, for a test that wants to read what was collected
// without going through HTTP.
func (s *Server) Gatherer() prometheus.Gatherer {
	if s == nil {
		return prometheus.NewRegistry()
	}

	return s.registry
}

// Listen binds the port, so that an address that cannot be had is a startup
// error rather than something discovered later by whoever went looking for a
// graph.
func (s *Server) Listen() error {
	if s == nil {
		return nil
	}

	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen for metrics on %s: %w", s.addr, err)
	}

	s.listener = listener

	// There is no authentication here and there is not going to be any: a
	// scrape is a GET, a heap profile is a GET, and a password on either would
	// be a password in a scrape configuration. What keeps them private is the
	// address, so an address that is not a local one is worth a line in the
	// log — the daemon's heap holds the store key while it is unlocked, and a
	// heap profile is a copy of the heap.
	if !loopback(listener.Addr()) {
		s.log.Warn(
			"the metrics and pprof port is reachable from off this machine",
			"address", listener.Addr().String())
	}

	s.log.Info("metrics and pprof are listening",
		"address", listener.Addr().String())

	return nil
}

// Addr is where it ended up listening, which is what a test asks after binding
// port zero. It is empty when there is no server or it has not bound.
func (s *Server) Addr() string {
	if s == nil || s.listener == nil {
		return ""
	}

	return s.listener.Addr().String()
}

// Serve serves until the context is done. It binds first if Listen was not
// called, so that a caller with nothing to fail early for can just run it.
func (s *Server) Serve(ctx context.Context) error {
	if s == nil {
		return nil
	}

	if s.listener == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}

	s.server = &http.Server{
		Handler: s.handler(),
		// A header timeout and no write timeout: `/debug/pprof/profile`
		// deliberately holds the connection open for its sampling window, and a
		// write deadline would cut off exactly the long profile somebody
		// reached for because the short one said nothing.
		ReadHeaderTimeout: 10 * time.Second,
	}

	done := make(chan error, 1)

	go func() {
		done <- s.server.Serve(s.listener)
	}()

	select {
	case err := <-done:
		// net.ErrClosed is Close having been called on the listener, which is
		// the caller taking the port down without going through the context.
		if err != nil && !errors.Is(err, http.ErrServerClosed) &&
			!errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("serve metrics: %w", err)
		}

		return nil
	case <-ctx.Done():
	}

	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.Shutdown(shutdown); err != nil {
		return fmt.Errorf("shut down the metrics server: %w", err)
	}

	return nil
}

// Close drops the listener without having served, which is what a caller that
// bound early and then failed for another reason wants.
func (s *Server) Close() error {
	if s == nil || s.listener == nil {
		return nil
	}

	if err := s.listener.Close(); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close the metrics listener: %w", err)
	}

	return nil
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /metrics", promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{
		// A collector that fails should not take the whole scrape with it: the
		// rest of the numbers are still true, and the failure is worth a line
		// in the log rather than an empty graph.
		ErrorHandling: promhttp.ContinueOnError,
		ErrorLog:      slogErrorLog{log: s.log},
	}))

	// The handlers are mounted by name rather than by importing net/http/pprof
	// for its init function. That import registers on the default mux, which is
	// the mux that ends up attached to whatever else in the process happens to
	// serve HTTP — the accident this whole package exists to avoid.
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("POST /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)

	mux.HandleFunc("GET /{$}", index)

	return mux
}

func index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	_, _ = w.Write([]byte(`<!doctype html>
<title>Ladulås debug</title>
<h1>Ladulås debug</h1>
<ul>
<li><a href="/metrics">/metrics</a></li>
<li><a href="/debug/pprof/">/debug/pprof/</a></li>
</ul>
`))
}

// loopback says whether an address is reachable only from this machine.
func loopback(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}

	return tcp.IP.IsLoopback()
}

// slogErrorLog adapts promhttp's logger, which predates slog.
type slogErrorLog struct {
	log *slog.Logger
}

func (l slogErrorLog) Println(v ...any) {
	l.log.Warn("the metrics handler had trouble", "error", fmt.Sprint(v...))
}

// discardRegisterer is what a process with no debug port registers into, so
// that building a metrics set never has to be conditional.
type discardRegisterer struct{}

func (discardRegisterer) Register(prometheus.Collector) error {
	return nil
}

func (discardRegisterer) MustRegister(...prometheus.Collector) {
}

func (discardRegisterer) Unregister(prometheus.Collector) bool {
	return true
}
