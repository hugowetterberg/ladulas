package observe

import (
	"errors"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// namespace is the first word of every metric name here. Both services are
// Ladulås; the relay says so in its subsystem.
const namespace = "ladulas"

// registrar builds a metrics set as one expression and reports what went wrong
// once, at the end.
//
// Registration fails for exactly one reason worth catching — two collectors
// with the same name and labels — and it is a programming mistake rather than
// a runtime condition. Checking it after every line would bury the set the
// reader came for; not checking it at all is how a duplicate metric becomes a
// silently missing one.
type registrar struct {
	reg  prometheus.Registerer
	errs []error
}

func newRegistrar(reg prometheus.Registerer) *registrar {
	if reg == nil {
		reg = discardRegisterer{}
	}

	return &registrar{reg: reg}
}

// Err is the one check.
func (r *registrar) Err() error {
	if len(r.errs) == 0 {
		return nil
	}

	return fmt.Errorf("register metrics: %w", errors.Join(r.errs...))
}

func (r *registrar) add(c prometheus.Collector) {
	if err := r.reg.Register(c); err != nil {
		r.errs = append(r.errs, err)
	}
}

func (r *registrar) counter(
	subsystem, name, help string, labels ...string,
) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      name,
		Help:      help,
	}, labels)

	r.add(c)

	return c
}

func (r *registrar) gaugeFunc(
	subsystem, name, help string, fn func() float64,
) {
	r.add(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      name,
		Help:      help,
	}, fn))
}

func (r *registrar) histogram(
	subsystem, name, help string, buckets []float64, labels ...string,
) *prometheus.HistogramVec {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      name,
		Help:      help,
		Buckets:   buckets,
	}, labels)

	r.add(h)

	return h
}

// waitBuckets span what a person takes to answer a prompt, not what a machine
// takes to serve a request: the interesting end of an approval's latency is
// somewhere between "a grant answered it instantly" and "it sat there until it
// timed out".
var waitBuckets = []float64{
	0.001, 0.01, 0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300,
}

// callBuckets are ordinary network latencies, for a push to Apple or an RPC.
var callBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
}
