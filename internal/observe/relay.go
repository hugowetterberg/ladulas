package observe

import (
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/relay"
)

// relaySubsystem puts the relay's metrics under their own word, so that a
// Prometheus holding both halves of Ladulås can tell the daemon on somebody's
// laptop from the relay that wakes their phone.
const relaySubsystem = "relay"

// Relay is everything the wake-up relay exports. Like the daemon's set it is
// counts and states only — an instance id is a capability, and this is a port
// whose whole output is written down and kept.
type Relay struct {
	registrations *prometheus.CounterVec
	pushes        *prometheus.CounterVec
	pushDuration  *prometheus.HistogramVec
	wakeups       *prometheus.CounterVec
}

var _ relay.Metrics = (*Relay)(nil)

// RegisterRelay builds the relay's metrics and registers them. The device
// count is read from the store at scrape time, which is why the store is an
// argument rather than something the service reports as it changes.
func RegisterRelay(reg prometheus.Registerer, devices func() int) (*Relay, error) {
	r := newRegistrar(reg)

	metrics := &Relay{
		registrations: r.counter(relaySubsystem, "registrations_total",
			"Device registrations accepted, by platform. A device registers "+
				"when its push token changes, so this rises on app installs and "+
				"reinstalls rather than on use.",
			labelPlatform),
		pushes: r.counter(relaySubsystem, "pushes_total",
			"Calls to a platform's push service, by what it answered. "+
				"unregistered is a token the platform says is dead, and the "+
				"registration is dropped when it happens.",
			labelPlatform, labelOutcome),
		pushDuration: r.histogram(relaySubsystem, "push_duration_seconds",
			"Time spent waiting for a platform's push service.",
			callBuckets, labelPlatform),
		wakeups: r.counter(relaySubsystem, "wakeups_total",
			"Wake-ups by the answer they got. Only delivered means a "+
				"notification went out: throttled is a wake-up paced against a "+
				"leaked instance id, unknown is an instance no device has "+
				"registered, and unregistered is a phone whose token has died.",
			labelStyle, labelOutcome),
	}

	if devices != nil {
		r.gaugeFunc(relaySubsystem, "devices",
			"Device registrations held. It is the whole of this service's "+
				"state, so a drop to zero is a state file that went missing.",
			func() float64 {
				return float64(devices())
			})
	}

	if err := r.Err(); err != nil {
		return nil, err
	}

	return metrics, nil
}

// Registered implements relay.Metrics.
func (m *Relay) Registered(platform ladulasv1.PushPlatform) {
	m.registrations.WithLabelValues(platformLabel(platform)).Inc()
}

// Pushed implements relay.Metrics.
func (m *Relay) Pushed(
	platform ladulasv1.PushPlatform, took time.Duration, err error,
) {
	name := platformLabel(platform)

	m.pushDuration.WithLabelValues(name).Observe(took.Seconds())
	m.pushes.WithLabelValues(name, pushOutcome(err)).Inc()
}

// Woke implements relay.Metrics.
func (m *Relay) Woke(silent bool, outcome ladulasv1.WakeOutcome) {
	m.wakeups.WithLabelValues(styleLabel(silent),
		enumLabel(outcome, ladulasv1.WakeOutcome_name, "WAKE_OUTCOME_")).Inc()
}

func platformLabel(platform ladulasv1.PushPlatform) string {
	return enumLabel(platform, ladulasv1.PushPlatform_name, "PUSH_PLATFORM_")
}

// styleLabel keeps the two kinds of wake-up apart, because they are budgeted
// differently by the platform and throttled differently here: a silent one
// spends an allowance the phone will not get back.
func styleLabel(silent bool) string {
	if silent {
		return "silent"
	}

	return "alert"
}

func pushOutcome(err error) string {
	switch {
	case err == nil:
		return "sent"
	case errors.Is(err, relay.ErrUnregistered):
		return "unregistered"
	default:
		return "failed"
	}
}
