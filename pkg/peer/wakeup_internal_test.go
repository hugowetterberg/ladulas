package peer

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/relay"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// The wake-up half of M9, from both ends (§11).
//
// What every test here is really checking is one property: that nothing in it
// is load-bearing. A route that is missing, a relay that is down, a token that
// has been revoked and a phone that never registered all have to end in the
// same place as M6 — the request waits, the phone polls, and somebody answers.

// memoryWakeups is the store seam for the tests.
type memoryWakeups struct {
	mu       sync.Mutex
	routes   []*storepb.PeerWakeup
	settings *storepb.WakeupSettings
}

var _ Wakeups = (*memoryWakeups)(nil)

func (m *memoryWakeups) PeerWakeups() []*storepb.PeerWakeup {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]*storepb.PeerWakeup(nil), m.routes...)
}

func (m *memoryWakeups) PeerWakeup(fingerprint string) (*storepb.PeerWakeup, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, route := range m.routes {
		if route.GetPeerFingerprint() == fingerprint {
			return proto.CloneOf(route), true
		}
	}

	return nil, false
}

func (m *memoryWakeups) PutPeerWakeup(wakeup *storepb.PeerWakeup) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored := proto.CloneOf(wakeup)

	for i, existing := range m.routes {
		if existing.GetPeerFingerprint() == wakeup.GetPeerFingerprint() {
			m.routes[i] = stored

			return nil
		}
	}

	m.routes = append(m.routes, stored)

	return nil
}

func (m *memoryWakeups) DropPeerWakeup(fingerprint string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	kept := m.routes[:0]

	var dropped bool

	for _, route := range m.routes {
		if route.GetPeerFingerprint() == fingerprint {
			dropped = true

			continue
		}

		kept = append(kept, route)
	}

	m.routes = kept

	return dropped, nil
}

func (m *memoryWakeups) WakeupSettings() *storepb.WakeupSettings {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.settings == nil {
		return &storepb.WakeupSettings{}
	}

	return proto.CloneOf(m.settings)
}

func (m *memoryWakeups) SetWakeupSettings(settings *storepb.WakeupSettings) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.settings = proto.CloneOf(settings)

	return nil
}

// withWakeups gives an instance the store seam it was not built with.
//
// Set straight after construction, before anything is paired or parked, and
// from the same package — which is what keeps the shared harness in
// peer_internal_test.go untouched by a milestone that only some tests care
// about.
func withWakeups(instance *instance) *memoryWakeups {
	wakeups := &memoryWakeups{}
	instance.node.wakeups = wakeups

	return wakeups
}

// testRelay is a real relay service on a loopback address, which is what the
// requester's own https rule carves out — and everything below therefore
// exercises the whole path, signature and all, rather than a stub of it.
type testRelay struct {
	url      string
	store    relay.Store
	pushes   chan ladulasv1.WakeStyle
	dead     bool
	pushMu   sync.Mutex
	pushLog  []ladulasv1.WakeStyle
	subjects []ladulasv1.WakeSubject
}

// pushedSubjects is what the relay was asked to say, in order.
func (r *testRelay) pushedSubjects() []ladulasv1.WakeSubject {
	r.pushMu.Lock()
	defer r.pushMu.Unlock()

	return append([]ladulasv1.WakeSubject(nil), r.subjects...)
}

func newTestRelay(t *testing.T) *testRelay {
	t.Helper()

	rig := &testRelay{
		store:  relay.NewMemoryStore(),
		pushes: make(chan ladulasv1.WakeStyle, 8),
	}

	service, err := relay.New(relay.Options{
		Store: rig.store,
		Pushers: map[ladulasv1.PushPlatform]relay.Pusher{
			ladulasv1.PushPlatform_PUSH_PLATFORM_APNS: rig,
		},
		// A test that has to wait five seconds to see a second push is a test
		// nobody runs, and the throttle has its own test next door.
		Throttle: relay.Throttle{Alert: time.Nanosecond, Silent: time.Nanosecond},
	})
	if err != nil {
		t.Fatalf("relay: %v", err)
	}

	server := httptest.NewServer(service.Handler())
	t.Cleanup(server.Close)

	rig.url = server.URL

	return rig
}

// Push implements relay.Pusher.
func (r *testRelay) Push(
	_ context.Context, _ string, silent bool, subject ladulasv1.WakeSubject,
) error {
	r.pushMu.Lock()
	dead := r.dead
	r.pushMu.Unlock()

	if dead {
		return relay.ErrUnregistered
	}

	style := ladulasv1.WakeStyle_WAKE_STYLE_ALERT
	if silent {
		style = ladulasv1.WakeStyle_WAKE_STYLE_SILENT
	}

	r.pushMu.Lock()
	r.pushLog = append(r.pushLog, style)
	r.subjects = append(r.subjects, subject)
	r.pushMu.Unlock()

	select {
	case r.pushes <- style:
	default:
	}

	return nil
}

func (r *testRelay) waitPush(t *testing.T) ladulasv1.WakeStyle {
	t.Helper()

	select {
	case style := <-r.pushes:
		return style
	case <-time.After(10 * time.Second):
		t.Fatal("no wake-up reached the relay")

		return ladulasv1.WakeStyle_WAKE_STYLE_UNSPECIFIED
	}
}

func (r *testRelay) quiet(t *testing.T, within time.Duration) {
	t.Helper()

	select {
	case style := <-r.pushes:
		t.Fatalf("a %s wake-up was sent when none was wanted", style)
	case <-time.After(within):
	}
}

// registerPhone puts the phone's device token at the relay and configures it to
// announce that route, which is what the shell does once iOS hands a token over.
func registerPhone(
	t *testing.T, phone *instance, wakeups *memoryWakeups, rig *testRelay,
) {
	t.Helper()

	client := &relay.Client{Identity: phone.identity}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.Register(ctx, rig.url, "phone-instance",
		ladulasv1.PushPlatform_PUSH_PLATFORM_APNS, "device-token")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	err = wakeups.SetWakeupSettings(&storepb.WakeupSettings{
		Enabled:      true,
		RelayUrl:     rig.url,
		InstanceId:   "phone-instance",
		Platform:     ladulasv1.PushPlatform_PUSH_PLATFORM_APNS,
		DeviceToken:  "device-token",
		RegisteredAt: timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
}

// waitRoute waits for the requester to have learned where to knock.
func waitRoute(
	t *testing.T, wakeups *memoryWakeups, fingerprint string,
) *storepb.PeerWakeup {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		if route, ok := wakeups.PeerWakeup(fingerprint); ok {
			return route
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("the requester never learned a wake-up route")

	return nil
}

// The milestone in one test: a phone announces where it can be woken, a
// headless box parks a request with nobody polling, and the relay is knocked on.
func TestAParkedRequestKnocksOnAPhoneThatIsNotPolling(t *testing.T) {
	rig := newTestRelay(t)

	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	phoneWakeups := withWakeups(phone)
	requesterWakeups := withWakeups(requester)

	scanQR(t, requester, phone)
	registerPhone(t, phone, phoneWakeups, rig)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	phone.node.AnnounceWakeups(ctx)

	route := waitRoute(t, requesterWakeups, phone.identity.Fingerprint())
	if route.GetRoute().GetInstanceId() != "phone-instance" {
		t.Fatalf("the requester learned %+v", route.GetRoute())
	}

	requester.drop()

	go func() {
		if _, err := requester.engine.Submit(ctx, gitRequest()); err != nil &&
			ctx.Err() == nil {
			t.Errorf("submit: %v", err)
		}
	}()

	if style := rig.waitPush(t); style != ladulasv1.WakeStyle_WAKE_STYLE_ALERT {
		t.Fatalf("the phone was woken with a %s push", style)
	}
}

// The fast path §11 names: an approver with a live poll is told over the line
// it already has open, and nothing is spent on waking it.
func TestALivePollNeedsNoWakeUp(t *testing.T) {
	rig := newTestRelay(t)

	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	phoneWakeups := withWakeups(phone)
	requesterWakeups := withWakeups(requester)

	scanQR(t, requester, phone)
	registerPhone(t, phone, phoneWakeups, rig)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	phone.node.AnnounceWakeups(ctx)
	waitRoute(t, requesterWakeups, phone.identity.Fingerprint())

	requester.drop()
	phone.human.set(approveAnswer("approved on the phone"), nil)

	// The app is open, so the long poll is in flight before there is anything to
	// find — which is the whole of what "live" means for a side that cannot be
	// dialled, and the order this test exists to fix.
	collected := make(chan error, 1)

	go func() {
		collected <- phone.node.Collect(ctx, 5*time.Second)
	}()

	waitForPoller(t, requester, phone.identity.Fingerprint())

	decided := make(chan struct{})

	go func() {
		defer close(decided)

		if _, err := requester.engine.Submit(ctx, gitRequest()); err != nil &&
			ctx.Err() == nil {
			t.Errorf("submit: %v", err)
		}
	}()

	if err := <-collected; err != nil {
		t.Fatalf("collect: %v", err)
	}

	select {
	case <-decided:
	case <-time.After(10 * time.Second):
		t.Fatal("the request was never decided")
	}

	rig.quiet(t, 500*time.Millisecond)
}

// A poll that has ended must stop counting as a poll. This is the bug that
// made wake-ups look broken for a day: the waiter a poll registered was only
// ever removed by waking it, so a phone that had been force-quit — or whose
// poll had simply timed out — left one behind, and the next request found it,
// closed it, decided somebody was listening and sent nothing. The push was
// suppressed in favour of a line that had gone.
func TestAFinishedPollStopsCountingAsOne(t *testing.T) {
	rig := newTestRelay(t)

	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	phoneWakeups := withWakeups(phone)
	requesterWakeups := withWakeups(requester)

	scanQR(t, requester, phone)
	registerPhone(t, phone, phoneWakeups, rig)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	phone.node.AnnounceWakeups(ctx)
	waitRoute(t, requesterWakeups, phone.identity.Fingerprint())

	requester.drop()

	// One poll, allowed to end on its own with nothing to collect — the phone
	// going away, as far as this side can tell.
	if err := phone.node.Collect(ctx, 500*time.Millisecond); err != nil {
		t.Fatalf("collect: %v", err)
	}

	waitForNoPoller(t, requester, phone.identity.Fingerprint())

	go func() {
		if _, err := requester.engine.Submit(ctx, gitRequest()); err != nil &&
			ctx.Err() == nil {
			t.Errorf("submit: %v", err)
		}
	}()

	// The request that follows must knock. Before the fix it was swallowed by
	// the waiter the finished poll left behind.
	if style := rig.waitPush(t); style != ladulasv1.WakeStyle_WAKE_STYLE_ALERT {
		t.Fatalf("the phone was woken with a %s push", style)
	}
}

// waitForNoPoller waits until the requester is holding no poll for the peer,
// which is what a phone that has stopped asking should look like.
func waitForNoPoller(t *testing.T, requester *instance, fingerprint string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		requester.node.mu.Lock()
		waiting := len(requester.node.waiters[fingerprint])
		requester.node.mu.Unlock()

		if waiting == 0 {
			return
		}

		time.Sleep(20 * time.Millisecond)
	}

	t.Fatal("the requester still thinks a poll is open")
}

// waitForPoller waits until the requester is holding a poll open on the peer's
// behalf, which is what makes a wake-up unnecessary.
func waitForPoller(t *testing.T, requester *instance, fingerprint string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		requester.node.mu.Lock()
		_, waiting := requester.node.waiters[fingerprint]
		requester.node.mu.Unlock()

		if waiting {
			return
		}

		time.Sleep(5 * time.Millisecond)
	}

	t.Fatal("the requester never held a poll open")
}

// The carve-out (§20, M9). A request the approver has already promised to
// answer is nobody's question, so it is knocked on quietly first — and then out
// loud, because a background push is throttled, dropped when the app is not
// resident, and cannot raise the biometric prompt a locked one would need.
func TestAGrantCoveredRequestIsWokenQuietlyAndThenOutLoud(t *testing.T) {
	previous := wakeGrace
	wakeGrace = 200 * time.Millisecond

	t.Cleanup(func() {
		wakeGrace = previous
	})

	rig := newTestRelay(t)

	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	phoneWakeups := withWakeups(phone)
	requesterWakeups := withWakeups(requester)

	scanQR(t, requester, phone)
	registerPhone(t, phone, phoneWakeups, rig)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// A grant the phone made for this requester, which is what turns the next
	// request into something nobody has to be asked about.
	if err := phone.ledger.AddGrant(&ladulasv1.Grant{
		GrantId: "grant-1",
		Scope: &ladulasv1.GrantScope{
			KeyFingerprint:      "SHA256:workkey",
			Kind:                ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
			RequesterInstanceId: requester.identity.Fingerprint(),
		},
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	phone.node.AnnounceWakeups(ctx)

	route := waitRoute(t, requesterWakeups, phone.identity.Fingerprint())
	if route.GetQuietUntil() == nil {
		t.Fatal("the phone did not say it could answer without asking")
	}

	requester.drop()

	go func() {
		if _, err := requester.engine.Submit(ctx, gitRequest()); err != nil &&
			ctx.Err() == nil {
			t.Errorf("submit: %v", err)
		}
	}()

	if style := rig.waitPush(t); style != ladulasv1.WakeStyle_WAKE_STYLE_SILENT {
		t.Fatalf("the first wake-up was a %s push", style)
	}

	// Nothing collected it, so the alert that would always have been sent goes
	// out — which is the degradation the carve-out is allowed to have.
	if style := rig.waitPush(t); style != ladulasv1.WakeStyle_WAKE_STYLE_ALERT {
		t.Fatalf("the second wake-up was a %s push", style)
	}
}

// A grant that has expired is not a promise, so the wake-up is loud again.
func TestAnExpiredGrantIsWokenOutLoud(t *testing.T) {
	rig := newTestRelay(t)

	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	phoneWakeups := withWakeups(phone)
	requesterWakeups := withWakeups(requester)

	scanQR(t, requester, phone)
	registerPhone(t, phone, phoneWakeups, rig)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := phone.ledger.AddGrant(&ladulasv1.Grant{
		GrantId: "grant-1",
		Scope: &ladulasv1.GrantScope{
			KeyFingerprint:      "SHA256:workkey",
			Kind:                ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
			RequesterInstanceId: requester.identity.Fingerprint(),
		},
		ExpiresAt: timestamppb.New(time.Now().Add(-time.Minute)),
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	phone.node.AnnounceWakeups(ctx)

	route := waitRoute(t, requesterWakeups, phone.identity.Fingerprint())
	if route.GetQuietUntil() != nil {
		t.Fatalf("an expired grant was announced as quiet until %s",
			route.GetQuietUntil().AsTime())
	}

	requester.drop()

	go func() {
		if _, err := requester.engine.Submit(ctx, gitRequest()); err != nil &&
			ctx.Err() == nil {
			t.Errorf("submit: %v", err)
		}
	}()

	if style := rig.waitPush(t); style != ladulasv1.WakeStyle_WAKE_STYLE_ALERT {
		t.Fatalf("the wake-up was a %s push", style)
	}
}

// A token that has been reissued leaves the relay answering that nothing is
// registered under that identifier, and the requester drops the route rather
// than knocking at a door that has moved (§19).
func TestADeadRouteIsForgotten(t *testing.T) {
	rig := newTestRelay(t)

	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	phoneWakeups := withWakeups(phone)
	requesterWakeups := withWakeups(requester)

	scanQR(t, requester, phone)
	registerPhone(t, phone, phoneWakeups, rig)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	phone.node.AnnounceWakeups(ctx)
	waitRoute(t, requesterWakeups, phone.identity.Fingerprint())

	rig.pushMu.Lock()
	rig.dead = true
	rig.pushMu.Unlock()

	requester.drop()
	phone.human.set(approveAnswer("approved on the phone"), nil)

	decided := make(chan struct{})

	go func() {
		defer close(decided)

		if _, err := requester.engine.Submit(ctx, gitRequest()); err != nil &&
			ctx.Err() == nil {
			t.Errorf("submit: %v", err)
		}
	}()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		if _, ok := requesterWakeups.PeerWakeup(
			phone.identity.Fingerprint()); !ok {
			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	if _, ok := requesterWakeups.PeerWakeup(phone.identity.Fingerprint()); ok {
		t.Fatal("the requester is still holding a dead route")
	}

	// And the thing that matters: the request is still parked, so poll-on-open
	// still finds it.
	if err := phone.node.Collect(ctx, 5*time.Second); err != nil {
		t.Fatalf("collect: %v", err)
	}

	select {
	case <-decided:
	case <-time.After(10 * time.Second):
		t.Fatal("the request was never decided")
	}
}

// The invariant, spelled out as a test: with the relay gone, pairing still
// works and approvals still happen. Everything above is an optimization on this.
func TestLosingEveryWakeUpChannelDegradesToPollOnOpen(t *testing.T) {
	rig := newTestRelay(t)

	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	phoneWakeups := withWakeups(phone)
	requesterWakeups := withWakeups(requester)

	// Registered while the relay was up, announced while it was up, and then
	// taken away — which is what an outage looks like from here.
	scanQR(t, requester, phone)
	registerPhone(t, phone, phoneWakeups, rig)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	phone.node.AnnounceWakeups(ctx)
	waitRoute(t, requesterWakeups, phone.identity.Fingerprint())

	// A route pointing at nothing at all. Nothing here retries, nothing here
	// waits for it, and nothing here notices except the log.
	if err := requesterWakeups.PutPeerWakeup(&storepb.PeerWakeup{
		PeerFingerprint: phone.identity.Fingerprint(),
		Route: &ladulasv1.WakeupRoute{
			Kind:       ladulasv1.WakeupKind_WAKEUP_KIND_RELAY,
			RelayUrl:   "http://127.0.0.1:1",
			InstanceId: "phone-instance",
		},
	}); err != nil {
		t.Fatalf("route: %v", err)
	}

	requester.drop()
	phone.human.set(approveAnswer("approved on the phone"), nil)

	decided := make(chan *ladulasv1.ApprovalResponse, 1)

	go func() {
		resp, err := requester.engine.Submit(ctx, gitRequest())
		if err != nil && ctx.Err() == nil {
			t.Errorf("submit: %v", err)
		}

		decided <- resp
	}()

	if err := phone.node.Collect(ctx, 5*time.Second); err != nil {
		t.Fatalf("collect: %v", err)
	}

	select {
	case resp := <-decided:
		if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
			t.Fatalf("the request was %s: %s",
				resp.GetDecision(), resp.GetReason())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the request was never decided")
	}

	// And a second pairing goes through with the relay still gone, because a
	// wake-up has never been part of one (§11). The requester needs somebody at
	// it again for that, since a pairing is always confirmed by a person on both
	// sides and never passed to a peer (§7).
	t.Cleanup(requester.engine.Register(requester.human))

	second := newPhone(t, "second phone")
	withWakeups(second)

	scanQR(t, requester, second)
}

// A relay a requester will not dial is refused out loud, so the phone can say
// that this machine will not wake it rather than waiting to notice that nothing
// ever arrives.
func TestACleartextRelayIsRefused(t *testing.T) {
	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	phoneWakeups := withWakeups(phone)
	requesterWakeups := withWakeups(requester)

	scanQR(t, requester, phone)

	err := phoneWakeups.SetWakeupSettings(&storepb.WakeupSettings{
		Enabled:     true,
		RelayUrl:    "http://relay.example.com",
		InstanceId:  "phone-instance",
		Platform:    ladulasv1.PushPlatform_PUSH_PLATFORM_APNS,
		DeviceToken: "device-token",
	})
	if err != nil {
		t.Fatalf("settings: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	phone.node.AnnounceWakeups(ctx)

	time.Sleep(500 * time.Millisecond)

	if _, ok := requesterWakeups.PeerWakeup(phone.identity.Fingerprint()); ok {
		t.Fatal("the requester stored a cleartext relay")
	}
}

// The whole of what a requester will dial, stated as a table, because this is
// the one decision in the file that a peer gets to influence.
func TestWhichRelaysARequesterWillDial(t *testing.T) {
	accepted := []string{
		"https://relay.example.com",
		"https://relay.example.com:8443",
		"http://localhost:8443",
		"http://127.0.0.1:8443",
		"http://[::1]:8443",
		// The tailnet, by name and by address, v4 and v6. WireGuard is already
		// doing what TLS would be asked to do here (§11).
		"http://guppy.tail97712.ts.net:8443",
		"http://100.121.203.120:8443",
		"http://[fd7a:115c:a1e0::753b:cb78]:8443",
		// The bottom and top of 100.64.0.0/10, to catch a mask written wrong.
		"http://100.64.0.0:8443",
		"http://100.127.255.255:8443",
	}

	for _, raw := range accepted {
		if note := checkRelayURL(raw); note != "" {
			t.Errorf("%s should be dialled, got %q", raw, note)
		}
	}

	refused := []string{
		"http://relay.example.com",
		// Adjacent to the tailnet range on both sides. 100.63 and 100.128 are
		// ordinary public space, and a check written with the wrong mask lets
		// them through.
		"http://100.63.255.255:8443",
		"http://100.128.0.0:8443",
		// A name that only looks like the tailnet. The suffix has to be the
		// suffix, or a host somebody registered ends the check.
		"http://guppy.tail97712.ts.net.example.com:8443",
		"http://ts.net.attacker.example:8443",
		// Neither scheme nor host is optional.
		"http://192.168.1.1:8443",
		"http://10.0.0.1:8443",
		"ftp://relay.example.com",
		"https://",
		"not a url at all",
	}

	for _, raw := range refused {
		if checkRelayURL(raw) == "" {
			t.Errorf("%s should be refused", raw)
		}
	}
}

// Announcing is authorized by the same half of a pairing as FetchPending: a
// peer that only asks this instance for approvals has nothing waiting for it
// here, so it has nothing to be woken about.
func TestAPeerThatDoesNotApproveCannotAnnounce(t *testing.T) {
	rig := newTestRelay(t)

	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	withWakeups(desktop)
	headlessWakeups := withWakeups(headless)

	// desktop approves for headless, and headless does not approve for desktop.
	pair(t, desktop, headless)

	err := headlessWakeups.SetWakeupSettings(&storepb.WakeupSettings{
		Enabled:     true,
		RelayUrl:    rig.url,
		InstanceId:  "headless-instance",
		Platform:    ladulasv1.PushPlatform_PUSH_PLATFORM_APNS,
		DeviceToken: "device-token",
	})
	if err != nil {
		t.Fatalf("settings: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	route := &ladulasv1.WakeupRoute{
		Kind:       ladulasv1.WakeupKind_WAKEUP_KIND_RELAY,
		RelayUrl:   rig.url,
		InstanceId: "headless-instance",
	}

	record, ok := headless.store.Peer(desktop.identity.Fingerprint())
	if !ok {
		t.Fatal("the headless box kept no record of the desktop")
	}

	headless.node.announceTo(ctx, record, route, time.Time{})

	desktopWakeups, isWakeups := desktop.node.wakeups.(*memoryWakeups)
	if !isWakeups {
		t.Fatal("the desktop has no wake-up store")
	}

	if _, held := desktopWakeups.PeerWakeup(
		headless.identity.Fingerprint()); held {
		t.Fatal("a peer that does not approve announced a route")
	}
}

// Withdrawal is an announcement with no route, which is what switching wake-ups
// off and having notification permission revoked both look like from here.
func TestWithdrawingARoute(t *testing.T) {
	rig := newTestRelay(t)

	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	phoneWakeups := withWakeups(phone)
	requesterWakeups := withWakeups(requester)

	scanQR(t, requester, phone)
	registerPhone(t, phone, phoneWakeups, rig)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	phone.node.AnnounceWakeups(ctx)
	waitRoute(t, requesterWakeups, phone.identity.Fingerprint())

	err := phone.node.SetWakeups(ctx, &storepb.WakeupSettings{
		Enabled:    false,
		RelayUrl:   rig.url,
		InstanceId: "phone-instance",
	})
	if err != nil {
		t.Fatalf("switch wake-ups off: %v", err)
	}

	if _, ok := requesterWakeups.PeerWakeup(phone.identity.Fingerprint()); ok {
		t.Fatal("the requester is still holding a withdrawn route")
	}
}

// Revoking a pairing takes the route with it, for the same reason it takes the
// borrowed keys and the delegations: a capability that wakes somebody's phone
// has no business outliving the trust it arrived under.
func TestRevokingAPairingDropsTheRoute(t *testing.T) {
	rig := newTestRelay(t)

	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	phoneWakeups := withWakeups(phone)
	requesterWakeups := withWakeups(requester)

	scanQR(t, requester, phone)
	registerPhone(t, phone, phoneWakeups, rig)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	phone.node.AnnounceWakeups(ctx)
	waitRoute(t, requesterWakeups, phone.identity.Fingerprint())

	record, ok := requester.store.Peer(phone.identity.Fingerprint())
	if !ok {
		t.Fatal("the requester kept no record of the phone")
	}

	requester.node.dropPeerKeys(record)

	if _, held := requesterWakeups.PeerWakeup(
		phone.identity.Fingerprint()); held {
		t.Fatal("a revoked peer's wake-up route is still there")
	}
}
