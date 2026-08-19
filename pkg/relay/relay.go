// Package relay is the publisher-hosted wake-up relay (§11, decision G).
//
// It exists because of an honest constraint rather than a design preference:
// APNs and FCM tokens are bound to the app's Apple or Firebase project, so
// anything that wakes the store-distributed app has to hold the publisher's
// platform credentials. That is the same reason Bitwarden's self-hosted servers
// proxy through push.bitwarden.com. Self-hosting this is supported — the relay
// URL is configuration the approver announces, and nothing about it is compiled
// into a requester — but it means building the app with your own project.
//
// What the service is allowed to know is the whole design:
//
//   - an opaque instance id, minted by the device and meaningless anywhere else;
//   - a device token, which the platform issued and can revoke;
//   - the public half of the identity key that first claimed the id.
//
// It is never told a request, a fingerprint, a peer, or what any of them are
// for, and the notification it sends says the same sentence every time. A relay
// operator who reads the whole database learns which devices exist and roughly
// how often somebody signs something, and nothing else — and a relay that is
// down, hostile or replaced by a laptop with the wrong clock costs exactly the
// wake-up, because everything degrades to poll-on-open (§11).
package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
)

// Pusher is a platform's push service. APNs is the only implementation today;
// FCM arrives with Android and is another one rather than another relay.
//
// It returns apns.ErrUnregistered — or anything wrapping it — for a token the
// platform says is dead, which is what makes the registration go away without
// anybody having to notice.
type Pusher interface {
	Push(
		ctx context.Context, token string, silent bool,
		subject ladulasv1.WakeSubject,
	) error
}

// Device is one registration.
type Device struct {
	InstanceID string `json:"instanceId"`
	Platform   string `json:"platform"`
	Token      string `json:"token"`
	// PublicKey is the SSH wire format of the identity key that claimed the
	// instance id. Every later registration for that id has to be signed by it.
	PublicKey  []byte    `json:"publicKey"`
	Registered time.Time `json:"registered"`
}

// Store holds the registrations. It is small and write-rarely: a device
// registers when its token changes, and is read once per wake-up.
type Store interface {
	Device(instanceID string) (*Device, bool)
	Put(device *Device) error
	Drop(instanceID string) error
}

// Throttle bounds how often one instance id can be woken.
//
// The instance id is a capability (see the RelayService comment in the schema),
// so somebody who learns one can ask for notifications on somebody else's phone.
// The harm is bounded to begin with — the payload says nothing and the app finds
// nothing — and this bounds how annoying it can be made.
type Throttle struct {
	// Alert is the shortest gap between two visible notifications to one device.
	Alert time.Duration
	// Silent is the same for background wakes. Longer, because the platform
	// budgets them itself and spending that budget on a replay is spending it on
	// the case this exists for (§20, M9).
	Silent time.Duration
}

// DefaultThrottle is short enough that a burst of commits still each wake the
// phone, and long enough that a leaked id is a nuisance rather than an attack.
var DefaultThrottle = Throttle{
	Alert:  5 * time.Second,
	Silent: 60 * time.Second,
}

// Metrics counts what the relay does with the calls it accepts.
//
// It is an interface, and the implementation lives in internal/observe, because
// this package is also the phone's half: a mobile build links it for the client
// in client.go and has no business linking a Prometheus client for a server it
// will never run.
//
// What it does not have to cover is calls that failed. Those are counted by
// procedure and status code around the handler, where a signature that did not
// verify and a call that named no instance are already told apart.
type Metrics interface {
	// Registered is a device registration that was accepted.
	Registered(platform ladulasv1.PushPlatform)
	// Pushed is one call to a platform's push service: how long it took, and
	// what it answered.
	Pushed(platform ladulasv1.PushPlatform, took time.Duration, err error)
	// Woke is the answer a wake-up got, which is not the same thing as a push
	// having been sent — most of the outcomes are reasons one was not.
	Woke(silent bool, outcome ladulasv1.WakeOutcome)
}

// Options configures a service.
type Options struct {
	Store   Store
	Pushers map[ladulasv1.PushPlatform]Pusher
	// Throttle defaults to DefaultThrottle.
	Throttle Throttle
	// Metrics counts registrations and wake-ups. Optional; without one the
	// service counts nothing and behaves identically.
	Metrics Metrics
	// Now is the clock, for tests.
	Now    func() time.Time
	Logger *slog.Logger
}

// Service serves RelayService.
type Service struct {
	store    Store
	pushers  map[ladulasv1.PushPlatform]Pusher
	throttle Throttle
	metrics  Metrics
	now      func() time.Time
	log      *slog.Logger

	mu   sync.Mutex
	last map[string]time.Time
}

// noMetrics is what a service built without any counts into. A no-op
// implementation rather than a nil check at every call site: the counting is
// beside the thing being counted, and an `if` in front of each of them would be
// the only reason to look twice at any of those lines.
type noMetrics struct{}

func (noMetrics) Registered(ladulasv1.PushPlatform) {
}

func (noMetrics) Pushed(ladulasv1.PushPlatform, time.Duration, error) {
}

func (noMetrics) Woke(bool, ladulasv1.WakeOutcome) {
}

var _ ladulasv1connect.RelayServiceHandler = (*Service)(nil)

// New builds the service.
func New(opts Options) (*Service, error) {
	if opts.Store == nil {
		return nil, errors.New("relay: no store")
	}

	if len(opts.Pushers) == 0 {
		return nil, errors.New("relay: no push service configured")
	}

	service := &Service{
		store:    opts.Store,
		pushers:  opts.Pushers,
		throttle: opts.Throttle,
		metrics:  opts.Metrics,
		now:      opts.Now,
		log:      opts.Logger,
		last:     map[string]time.Time{},
	}

	if service.metrics == nil {
		service.metrics = noMetrics{}
	}

	if service.throttle.Alert == 0 {
		service.throttle.Alert = DefaultThrottle.Alert
	}

	if service.throttle.Silent == 0 {
		service.throttle.Silent = DefaultThrottle.Silent
	}

	if service.now == nil {
		service.now = time.Now
	}

	if service.log == nil {
		service.log = slog.Default()
	}

	return service, nil
}

// maxCallBytes caps a relay call. Everything here is a handful of fields and a
// device token; the cap is what stops an unauthenticated port from being a way
// to allocate memory.
const maxCallBytes = 64 << 10

// Handler mounts the service, wrapped in whatever the caller wants around
// every call — which today is the counting of them, and which stays out here
// because a handler is where a status code exists and the methods below only
// ever see the answer they are about to give.
func (s *Service) Handler(interceptors ...connect.Interceptor) http.Handler {
	mux := http.NewServeMux()

	mux.Handle(ladulasv1connect.NewRelayServiceHandler(s,
		connect.WithReadMaxBytes(maxCallBytes),
		connect.WithInterceptors(interceptors...)))

	return mux
}

// Register binds a device token to an instance id.
//
// The binding is trust on first use, which is the only model available: the
// relay has no directory of instances and wants none. The first key to claim an
// id owns it, and a second key claiming the same id is refused — so an instance
// id learned from somewhere cannot be pointed at somebody else's device, which
// would be both a denial of service against the real one and a way to learn when
// its owner signs things.
func (s *Service) Register(
	ctx context.Context, req *connect.Request[ladulasv1.RegisterRequest],
) (*connect.Response[ladulasv1.RegisterResponse], error) {
	call, key, err := s.verify(req.Msg.GetSigned())
	if err != nil {
		return nil, err
	}

	registration := call.GetRegister()
	if registration == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("that call is not a registration"))
	}

	if registration.GetDeviceToken() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the registration carries no device token"))
	}

	if _, ok := s.pushers[registration.GetPlatform()]; !ok {
		return nil, connect.NewError(connect.CodeUnimplemented,
			fmt.Errorf("this relay does not send %s pushes",
				registration.GetPlatform().String()))
	}

	blob := key.Marshal()

	if existing, ok := s.store.Device(call.GetInstanceId()); ok &&
		!keysEqual(existing.PublicKey, blob) {
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("that instance id belongs to another identity"))
	}

	device := &Device{
		InstanceID: call.GetInstanceId(),
		Platform:   registration.GetPlatform().String(),
		Token:      registration.GetDeviceToken(),
		PublicKey:  blob,
		Registered: s.now(),
	}

	if err := s.store.Put(device); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.metrics.Registered(registration.GetPlatform())

	// The fingerprint rather than the instance id, because the log is the one
	// place an operator debugs from and an instance id in it is a capability
	// written to disk in cleartext.
	s.log.Info("a device registered",
		"platform", device.Platform,
		"identity", ssh.FingerprintSHA256(key))

	return connect.NewResponse(&ladulasv1.RegisterResponse{}), nil
}

// Wake sends the push.
//
// The signature is checked and the key is then discarded, which is deliberate
// and is the privacy property this service exists to have: the relay does not
// learn which requesters wake which devices, so it cannot be asked who is paired
// with whom. See the schema for what that costs.
func (s *Service) Wake(
	ctx context.Context, req *connect.Request[ladulasv1.WakeRequest],
) (*connect.Response[ladulasv1.WakeResponse], error) {
	call, _, err := s.verify(req.Msg.GetSigned())
	if err != nil {
		return nil, err
	}

	wake := call.GetWake()
	if wake == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("that call is not a wake-up"))
	}

	silent := wake.GetStyle() == ladulasv1.WakeStyle_WAKE_STYLE_SILENT

	device, ok := s.store.Device(call.GetInstanceId())
	if !ok {
		s.metrics.Woke(silent, ladulasv1.WakeOutcome_WAKE_OUTCOME_UNKNOWN)

		return outcome(ladulasv1.WakeOutcome_WAKE_OUTCOME_UNKNOWN, time.Time{}), nil
	}

	if retry, allowed := s.spend(call.GetInstanceId(), silent); !allowed {
		s.metrics.Woke(silent, ladulasv1.WakeOutcome_WAKE_OUTCOME_THROTTLED)

		s.log.Info("a wake-up was throttled",
			"instance", call.GetInstanceId(), "silent", silent,
			"retry_after", time.Until(retry).String())

		return outcome(
			ladulasv1.WakeOutcome_WAKE_OUTCOME_THROTTLED, retry), nil
	}

	platform := platformOf(device.Platform)

	pusher, ok := s.pushers[platform]
	if !ok {
		return nil, connect.NewError(connect.CodeUnimplemented,
			fmt.Errorf("this relay no longer sends %s pushes", device.Platform))
	}

	// The push is the one part of this service that waits on somebody else, so
	// it is the one part worth timing: a relay that looks slow is Apple being
	// slow, or it is not, and that is the whole question.
	started := s.now()

	err = pusher.Push(ctx, device.Token, silent, wake.GetSubject())

	s.metrics.Pushed(platform, s.now().Sub(started), err)

	if err == nil {
		s.metrics.Woke(silent, ladulasv1.WakeOutcome_WAKE_OUTCOME_DELIVERED)

		// Info, not debug. Sending a push is the entire job of this service and
		// there is one line per wake-up of a phone somebody is holding, so the
		// volume is a person's volume. A relay that says nothing when it works
		// cannot be told apart from one that is never asked, which is exactly
		// the question that had to be answered by reading someone else's logs.
		s.log.Info("a wake-up went out",
			"instance", call.GetInstanceId(), "silent", silent)

		return outcome(
			ladulasv1.WakeOutcome_WAKE_OUTCOME_DELIVERED, time.Time{}), nil
	}

	if !errors.Is(err, ErrUnregistered) {
		s.log.Warn("a wake-up could not be sent",
			"instance", call.GetInstanceId(), "silent", silent,
			"error", err.Error())

		return nil, connect.NewError(connect.CodeUnavailable, err)
	}

	s.metrics.Woke(silent, ladulasv1.WakeOutcome_WAKE_OUTCOME_UNREGISTERED)

	s.log.Info("a wake-up found a dead token, and the registration is forgotten",
		"instance", call.GetInstanceId())

	// The token is dead. Forgetting it here is what makes the answer below
	// truthful the next time somebody asks, and the answer is what makes the
	// requester drop the route rather than knocking at a door that has moved.
	if err := s.store.Drop(call.GetInstanceId()); err != nil {
		s.log.Error("could not forget a dead registration", "error", err.Error())
	}

	return outcome(
		ladulasv1.WakeOutcome_WAKE_OUTCOME_UNREGISTERED, time.Time{}), nil
}

// ErrUnregistered is what a Pusher returns for a token the platform says is
// dead. It is declared here rather than imported from apns so that a second
// platform does not have to import the first one to say the same thing.
var ErrUnregistered = errors.New("relay: the device token is no longer registered")

func outcome(
	kind ladulasv1.WakeOutcome, retry time.Time,
) *connect.Response[ladulasv1.WakeResponse] {
	resp := &ladulasv1.WakeResponse{Outcome: kind}

	if !retry.IsZero() {
		resp.RetryAfter = timestamppb.New(retry)
	}

	return connect.NewResponse(resp)
}

// verify is the whole of the authentication: a signature under the relay domain
// separator, over a call whose timestamp is close to now.
func (s *Service) verify(
	signed *ladulasv1.SignedRelayCall,
) (*ladulasv1.RelayCall, ssh.PublicKey, error) {
	call, key, err := identity.VerifyRelayCall(signed)
	if err != nil {
		return nil, nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	if call.GetInstanceId() == "" {
		return nil, nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the call names no instance"))
	}

	// The window is the replay defence, together with the throttle below. There
	// is no nonce cache: a call replayed inside the window is worth one more
	// notification that says nothing, which the throttle already bounds, and a
	// cache that has to survive a restart to be worth anything is a database for
	// a threat whose whole cost is a banner.
	drift := s.now().Sub(call.GetIssuedAt().AsTime())
	if drift < -identity.RelayClockSkew || drift > identity.RelayClockSkew {
		return nil, nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("that call was issued too far from now; check the clock"))
	}

	return call, key, nil
}

// spend paces one instance id, and says when it may be tried again.
func (s *Service) spend(instanceID string, silent bool) (time.Time, bool) {
	gap := s.throttle.Alert
	if silent {
		gap = s.throttle.Silent
	}

	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	key := instanceID
	if silent {
		key += "\x00silent"
	}

	if last, seen := s.last[key]; seen && now.Sub(last) < gap {
		return last.Add(gap), false
	}

	s.last[key] = now

	return time.Time{}, true
}

func keysEqual(a, b []byte) bool {
	return len(a) == len(b) && string(a) == string(b)
}

func platformOf(name string) ladulasv1.PushPlatform {
	return ladulasv1.PushPlatform(
		ladulasv1.PushPlatform_value[name])
}
