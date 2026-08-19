package observe_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/hugowetterberg/ladulas/internal/observe"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/relay"
)

func TestRelayMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewPedanticRegistry()

	devices := 3

	metrics, err := observe.RegisterRelay(reg, func() int {
		return devices
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	metrics.Registered(ladulasv1.PushPlatform_PUSH_PLATFORM_APNS)

	metrics.Pushed(ladulasv1.PushPlatform_PUSH_PLATFORM_APNS,
		120*time.Millisecond, nil)
	metrics.Pushed(ladulasv1.PushPlatform_PUSH_PLATFORM_APNS,
		90*time.Millisecond, relay.ErrUnregistered)
	metrics.Pushed(ladulasv1.PushPlatform_PUSH_PLATFORM_APNS,
		time.Second, errors.New("apns said no"))

	metrics.Woke(false, ladulasv1.WakeOutcome_WAKE_OUTCOME_DELIVERED)
	metrics.Woke(true, ladulasv1.WakeOutcome_WAKE_OUTCOME_THROTTLED)
	// The outcome that has to keep its own name: an instance nobody has
	// registered a device for, which is not the same as an outcome this build
	// has never heard of.
	metrics.Woke(true, ladulasv1.WakeOutcome_WAKE_OUTCOME_UNKNOWN)

	expect(t, reg, `
# HELP ladulas_relay_pushes_total Calls to a platform's push service, by what it answered. unregistered is a token the platform says is dead, and the registration is dropped when it happens.
# TYPE ladulas_relay_pushes_total counter
ladulas_relay_pushes_total{outcome="failed",platform="apns"} 1
ladulas_relay_pushes_total{outcome="sent",platform="apns"} 1
ladulas_relay_pushes_total{outcome="unregistered",platform="apns"} 1
`, "ladulas_relay_pushes_total")

	expect(t, reg, `
# HELP ladulas_relay_wakeups_total Wake-ups by the answer they got. Only delivered means a notification went out: throttled is a wake-up paced against a leaked instance id, unknown is an instance no device has registered, and unregistered is a phone whose token has died.
# TYPE ladulas_relay_wakeups_total counter
ladulas_relay_wakeups_total{outcome="delivered",style="alert"} 1
ladulas_relay_wakeups_total{outcome="throttled",style="silent"} 1
ladulas_relay_wakeups_total{outcome="unknown",style="silent"} 1
`, "ladulas_relay_wakeups_total")

	// The device count is read at scrape time rather than mirrored, so it
	// follows the store without anybody telling it to.
	devices = 4

	expect(t, reg, `
# HELP ladulas_relay_devices Device registrations held. It is the whole of this service's state, so a drop to zero is a state file that went missing.
# TYPE ladulas_relay_devices gauge
ladulas_relay_devices 4
`, "ladulas_relay_devices")

	lint(t, reg)
}

func TestRPCMetricsNameProceduresAndCodes(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewPedanticRegistry()

	calls, err := observe.NewRPC(reg, "relay")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if calls.Interceptor() == nil {
		t.Fatal("no interceptor")
	}

	lint(t, reg)
}

// expect compares one metric family against what it should be, help text and
// all: the help is what an operator reads at three in the morning, so it is
// part of the metric rather than a comment on it.
func expect(t *testing.T, reg prometheus.Gatherer, want string, names ...string) {
	t.Helper()

	err := testutil.GatherAndCompare(reg,
		strings.NewReader(strings.TrimPrefix(want, "\n")), names...)
	if err != nil {
		t.Error(err)
	}
}

// lint runs Prometheus' own naming checks over the whole set, which is what
// catches a counter that forgot its _total or a unit in the wrong place.
func lint(t *testing.T, reg prometheus.Gatherer) {
	t.Helper()

	problems, err := testutil.GatherAndLint(reg)
	if err != nil {
		t.Fatalf("lint: %v", err)
	}

	for _, problem := range problems {
		t.Errorf("%s: %s", problem.Metric, problem.Text)
	}
}
