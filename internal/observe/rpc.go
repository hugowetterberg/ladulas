package observe

import (
	"context"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/prometheus/client_golang/prometheus"
)

// RPC counts calls to a connect service: how many, how long, and what they
// answered.
//
// The procedure is a safe label because it is the schema's: connect resolves a
// path against the generated handler before an interceptor ever sees it, so an
// unrouted path is a 404 and never a new time series. The code is connect's own
// enumeration, which is likewise closed.
type RPC struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewRPC builds the pair. The subsystem names the service being served, so a
// process serving two of them keeps them apart.
func NewRPC(reg prometheus.Registerer, subsystem string) (*RPC, error) {
	r := newRegistrar(reg)

	metrics := &RPC{
		requests: r.counter(subsystem, "rpc_requests_total",
			"Calls served, by procedure and the status they were answered with. "+
				"unauthenticated is a signature that did not verify, which on an "+
				"open port is ordinary background noise rather than an incident.",
			labelProcedure, labelCode),
		duration: r.histogram(subsystem, "rpc_duration_seconds",
			"Time spent serving a call, from the handler being entered to it "+
				"answering.",
			callBuckets, labelProcedure),
	}

	if err := r.Err(); err != nil {
		return nil, err
	}

	return metrics, nil
}

// Interceptor is what goes into the handler options.
func (m *RPC) Interceptor() connect.Interceptor {
	return connect.UnaryInterceptorFunc(m.wrap)
}

func (m *RPC) wrap(next connect.UnaryFunc) connect.UnaryFunc {
	return func(
		ctx context.Context, req connect.AnyRequest,
	) (connect.AnyResponse, error) {
		// Only on the handler side. A client call counted here would be counted
		// under the same names as a served one, and this process is a server.
		if req.Spec().IsClient {
			return next(ctx, req)
		}

		started := time.Now()

		resp, err := next(ctx, req)

		procedure := strings.TrimPrefix(req.Spec().Procedure, "/")

		m.duration.WithLabelValues(procedure).Observe(
			time.Since(started).Seconds())
		m.requests.WithLabelValues(procedure, codeLabel(err)).Inc()

		return resp, err
	}
}

func codeLabel(err error) string {
	if err == nil {
		return "ok"
	}

	return connect.CodeOf(err).String()
}
