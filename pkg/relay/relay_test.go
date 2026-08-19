package relay_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/relay"
)

// pusher is the platform, as far as these tests are concerned.
type pusher struct {
	mu       sync.Mutex
	sent     []bool
	subjects []ladulasv1.WakeSubject
	refuse   error
}

// lastSubject is what the relay last asked the platform to say.
func (p *pusher) lastSubject() ladulasv1.WakeSubject {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.subjects) == 0 {
		return ladulasv1.WakeSubject_WAKE_SUBJECT_UNSPECIFIED
	}

	return p.subjects[len(p.subjects)-1]
}

func (p *pusher) Push(
	_ context.Context, _ string, silent bool, subject ladulasv1.WakeSubject,
) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.refuse != nil {
		return p.refuse
	}

	p.sent = append(p.sent, silent)
	p.subjects = append(p.subjects, subject)

	return nil
}

func (p *pusher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.sent)
}

type rig struct {
	service *relay.Service
	store   relay.Store
	pusher  *pusher
	url     string
	now     func() time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()

	return newRigWith(t, relay.NewMemoryStore(), nil)
}

func newRigWith(t *testing.T, store relay.Store, now func() time.Time) *rig {
	t.Helper()

	push := &pusher{}

	service, err := relay.New(relay.Options{
		Store: store,
		Pushers: map[ladulasv1.PushPlatform]relay.Pusher{
			ladulasv1.PushPlatform_PUSH_PLATFORM_APNS: push,
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("relay: %v", err)
	}

	server := httptest.NewServer(service.Handler())
	t.Cleanup(server.Close)

	return &rig{
		service: service,
		store:   store,
		pusher:  push,
		url:     server.URL,
		now:     now,
	}
}

func (r *rig) clientFor(t *testing.T, name string) *relay.Client {
	t.Helper()

	id, _, err := identity.Generate(name)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	return &relay.Client{Identity: id}
}

func TestRegisteringAndWaking(t *testing.T) {
	rig := newRig(t)
	phone := rig.clientFor(t, "phone")
	requester := rig.clientFor(t, "desktop")

	ctx := context.Background()

	err := phone.Register(ctx, rig.url, "inst-1",
		ladulasv1.PushPlatform_PUSH_PLATFORM_APNS, "device-token")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	outcome, err := requester.Wake(ctx, rig.url, "inst-1",
		ladulasv1.WakeStyle_WAKE_STYLE_ALERT,
		ladulasv1.WakeSubject_WAKE_SUBJECT_APPROVAL)
	if err != nil {
		t.Fatalf("wake: %v", err)
	}

	if outcome != ladulasv1.WakeOutcome_WAKE_OUTCOME_DELIVERED {
		t.Fatalf("the relay answered %s", outcome)
	}

	if rig.pusher.count() != 1 {
		t.Fatalf("the platform saw %d pushes", rig.pusher.count())
	}
}

// The relay does not know who is paired with whom and is deliberately never
// told, so any signing identity may wake any instance it has the identifier
// for. The identifier is the capability; the signature is what makes an abusive
// caller countable (§11).
func TestAnyIdentityMayWakeAnInstanceItHasTheIdentifierFor(t *testing.T) {
	rig := newRig(t)
	ctx := context.Background()

	err := rig.clientFor(t, "phone").Register(ctx, rig.url, "inst-1",
		ladulasv1.PushPlatform_PUSH_PLATFORM_APNS, "device-token")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	outcome, err := rig.clientFor(t, "a stranger").Wake(
		ctx, rig.url, "inst-1", ladulasv1.WakeStyle_WAKE_STYLE_ALERT,
		ladulasv1.WakeSubject_WAKE_SUBJECT_APPROVAL)
	if err != nil {
		t.Fatalf("wake: %v", err)
	}

	if outcome != ladulasv1.WakeOutcome_WAKE_OUTCOME_DELIVERED {
		t.Fatalf("the relay answered %s", outcome)
	}
}

// Registration is the half where identity does bind, because pointing somebody
// else's identifier at your own device would redirect their wake-ups to you.
func TestAnInstanceIdBelongsToTheKeyThatClaimedIt(t *testing.T) {
	rig := newRig(t)
	ctx := context.Background()

	phone := rig.clientFor(t, "phone")

	err := phone.Register(ctx, rig.url, "inst-1",
		ladulasv1.PushPlatform_PUSH_PLATFORM_APNS, "device-token")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// The same phone with a reissued token: the ordinary case, and it works.
	err = phone.Register(ctx, rig.url, "inst-1",
		ladulasv1.PushPlatform_PUSH_PLATFORM_APNS, "a-new-token")
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}

	device, ok := rig.store.Device("inst-1")
	if !ok || device.Token != "a-new-token" {
		t.Fatalf("the registration is %+v", device)
	}

	err = rig.clientFor(t, "somebody else").Register(ctx, rig.url, "inst-1",
		ladulasv1.PushPlatform_PUSH_PLATFORM_APNS, "their-token")
	if err == nil {
		t.Fatal("another identity took over an instance id")
	}

	device, _ = rig.store.Device("inst-1")
	if device.Token != "a-new-token" {
		t.Fatalf("the registration moved to %+v", device)
	}
}

func TestWakingAnInstanceNobodyRegistered(t *testing.T) {
	rig := newRig(t)

	outcome, err := rig.clientFor(t, "desktop").Wake(context.Background(),
		rig.url, "inst-nobody", ladulasv1.WakeStyle_WAKE_STYLE_ALERT,
		ladulasv1.WakeSubject_WAKE_SUBJECT_APPROVAL)
	if err != nil {
		t.Fatalf("wake: %v", err)
	}

	if outcome != ladulasv1.WakeOutcome_WAKE_OUTCOME_UNKNOWN {
		t.Fatalf("the relay answered %s", outcome)
	}
}

// A dead token is forgotten here, so that the next caller is told UNKNOWN and
// drops the route. It is half of how a rotating token stops being knocked at.
func TestADeadTokenIsForgotten(t *testing.T) {
	rig := newRig(t)
	ctx := context.Background()

	err := rig.clientFor(t, "phone").Register(ctx, rig.url, "inst-1",
		ladulasv1.PushPlatform_PUSH_PLATFORM_APNS, "device-token")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	rig.pusher.refuse = relay.ErrUnregistered

	outcome, err := rig.clientFor(t, "desktop").Wake(ctx, rig.url, "inst-1",
		ladulasv1.WakeStyle_WAKE_STYLE_ALERT,
		ladulasv1.WakeSubject_WAKE_SUBJECT_APPROVAL)
	if err != nil {
		t.Fatalf("wake: %v", err)
	}

	if outcome != ladulasv1.WakeOutcome_WAKE_OUTCOME_UNREGISTERED {
		t.Fatalf("the relay answered %s", outcome)
	}

	if _, ok := rig.store.Device("inst-1"); ok {
		t.Fatal("the dead registration is still there")
	}
}

// Apple having a bad afternoon is not a device that has gone away.
func TestATransientFailureKeepsTheRegistration(t *testing.T) {
	rig := newRig(t)
	ctx := context.Background()

	err := rig.clientFor(t, "phone").Register(ctx, rig.url, "inst-1",
		ladulasv1.PushPlatform_PUSH_PLATFORM_APNS, "device-token")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	rig.pusher.refuse = errors.New("the push service is having a moment")

	if _, err := rig.clientFor(t, "desktop").Wake(ctx, rig.url, "inst-1",
		ladulasv1.WakeStyle_WAKE_STYLE_ALERT,
		ladulasv1.WakeSubject_WAKE_SUBJECT_APPROVAL); err == nil {
		t.Fatal("a failed push was reported as a success")
	}

	if _, ok := rig.store.Device("inst-1"); !ok {
		t.Fatal("a transient failure forgot the device")
	}
}

func TestTheThrottleBoundsALeakedIdentifier(t *testing.T) {
	rig := newRig(t)
	ctx := context.Background()

	err := rig.clientFor(t, "phone").Register(ctx, rig.url, "inst-1",
		ladulasv1.PushPlatform_PUSH_PLATFORM_APNS, "device-token")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	stranger := rig.clientFor(t, "a stranger")

	var throttled int

	for range 10 {
		outcome, err := stranger.Wake(ctx, rig.url, "inst-1",
			ladulasv1.WakeStyle_WAKE_STYLE_ALERT,
			ladulasv1.WakeSubject_WAKE_SUBJECT_APPROVAL)
		if err != nil {
			t.Fatalf("wake: %v", err)
		}

		if outcome == ladulasv1.WakeOutcome_WAKE_OUTCOME_THROTTLED {
			throttled++
		}
	}

	if throttled != 9 {
		t.Fatalf("%d of ten wake-ups were throttled", throttled)
	}

	if rig.pusher.count() != 1 {
		t.Fatalf("the platform saw %d pushes", rig.pusher.count())
	}
}

// A call with a timestamp far from the relay's own clock is a replay, or a
// clock that needs setting. Either way it is refused rather than queued.
func TestACallFromAnotherTimeIsRefused(t *testing.T) {
	var mu sync.Mutex

	now := time.Now()

	rig := newRigWith(t, relay.NewMemoryStore(), func() time.Time {
		mu.Lock()
		defer mu.Unlock()

		return now
	})

	ctx := context.Background()
	phone := rig.clientFor(t, "phone")

	err := phone.Register(ctx, rig.url, "inst-1",
		ladulasv1.PushPlatform_PUSH_PLATFORM_APNS, "device-token")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	mu.Lock()
	now = now.Add(2 * identity.RelayClockSkew)
	mu.Unlock()

	if _, err := rig.clientFor(t, "desktop").Wake(ctx, rig.url, "inst-1",
		ladulasv1.WakeStyle_WAKE_STYLE_ALERT,
		ladulasv1.WakeSubject_WAKE_SUBJECT_APPROVAL); err == nil {
		t.Fatal("a stale call was accepted")
	}
}

func TestRegistrationsSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")

	store, err := relay.OpenFileStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	rig := newRigWith(t, store, nil)

	err = rig.clientFor(t, "phone").Register(context.Background(), rig.url,
		"inst-1", ladulasv1.PushPlatform_PUSH_PLATFORM_APNS, "device-token")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	reopened, err := relay.OpenFileStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	device, ok := reopened.Device("inst-1")
	if !ok || device.Token != "device-token" {
		t.Fatalf("the reopened store holds %+v", device)
	}
}

// The relay sends one of two sentences, and the caller chooses which (§10,
// decision S). It is the only thing about an event that reaches this service.
func TestAWakeUpCarriesItsSubject(t *testing.T) {
	rig := newRig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := rig.clientFor(t, "phone").Register(ctx, rig.url, "inst-1",
		ladulasv1.PushPlatform_PUSH_PLATFORM_APNS, "device-token")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	_, err = rig.clientFor(t, "desktop").Wake(ctx, rig.url, "inst-1",
		ladulasv1.WakeStyle_WAKE_STYLE_ALERT,
		ladulasv1.WakeSubject_WAKE_SUBJECT_KEY_OFFER)
	if err != nil {
		t.Fatalf("wake: %v", err)
	}

	if got := rig.pusher.lastSubject(); got !=
		ladulasv1.WakeSubject_WAKE_SUBJECT_KEY_OFFER {
		t.Errorf("the platform was asked to say %s", got)
	}
}
