package peer

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/relay"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// Wake-ups, from both ends of the peer channel (§11, decision G).
//
// The whole of this file is an optimization on the inbox in inbox.go, and it is
// written so that every failure in it costs nothing but time. There is no path
// here that can stop a request being parked, stop a poll finding it, or stop a
// pairing completing — a route that is missing, a relay that is down, a token
// that has been revoked and a URL this instance will not dial all end in exactly
// the same place: the phone finds the request when it is next opened, which is
// what M6 shipped and what this milestone is layered on.
//
// The two ends:
//
//   - An approver announces where it can be woken (AnnounceWakeup), because it
//     is the side that can always dial and the side whose token keeps changing.
//   - A requester knocks when it parks something and nobody is listening.

// Wakeups is what the node needs from the store for wake-ups. It is optional in
// the sense the Delegations seam is: an instance without one never learns a
// route, never sends a wake-up, and is the M6 instance.
type Wakeups interface {
	// The routes peers have announced for themselves.
	PeerWakeups() []*storepb.PeerWakeup
	PeerWakeup(fingerprint string) (*storepb.PeerWakeup, bool)
	PutPeerWakeup(wakeup *storepb.PeerWakeup) error
	DropPeerWakeup(fingerprint string) (bool, error)

	// This instance's own half: how it has asked to be woken, which only an
	// instance that cannot be dialled has any use for.
	WakeupSettings() *storepb.WakeupSettings
	SetWakeupSettings(settings *storepb.WakeupSettings) error
}

// wakeGrace is how long a silent wake-up is given to produce a poll before the
// alert that would otherwise have been sent goes out.
//
// It is the whole of the carve-out's safety net (§20, M9): a background push is
// throttled by the platform, is dropped outright when the app is not resident,
// and cannot raise the biometric prompt a terminated app would need — so it is
// never the only thing sent, only the thing sent first. Long enough for a
// resident app to wake, dial and collect; short enough that nobody waiting on a
// commit notices the difference.
//
// A var rather than a const only so that a test can shorten it; nothing changes
// it at runtime.
var wakeGrace = 12 * time.Second

// wakeTimeout bounds one call to a relay. The relay is a third party on the open
// internet and nothing is waiting for its answer.
const wakeTimeout = 10 * time.Second

// announceRefresh is how often an approver re-announces an unchanged route.
//
// The announcement is idempotent, so this is not a lease and nothing expires
// when it elapses. What it covers is the requester having forgotten — a restored
// store, a reinstall, a machine that was rebuilt — which nothing else would ever
// tell the phone about.
const announceRefresh = 6 * time.Hour

// AnnounceWakeup records how a peer that approves for this instance asks to be
// woken.
//
// Authorized by the same half of a pairing as FetchPending: the caller is a peer
// this instance agreed may approve for it. That is the right half — a route is
// only ever used to say "there is something waiting for you", and there is only
// something waiting for a peer that answers.
func (s *peerService) AnnounceWakeup(
	ctx context.Context,
	req *connect.Request[ladulasv1.AnnounceWakeupRequest],
) (*connect.Response[ladulasv1.AnnounceWakeupResponse], error) {
	peer, record, err := s.node.publisherFor(ctx)
	if err != nil {
		return nil, err
	}

	if s.node.wakeups == nil {
		return connect.NewResponse(&ladulasv1.AnnounceWakeupResponse{
			Reason: "this instance does not send wake-ups",
		}), nil
	}

	route := req.Msg.GetRoute()

	if route == nil {
		if _, err := s.node.wakeups.DropPeerWakeup(peer.Fingerprint); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}

		s.node.log.Info("a peer withdrew its wake-up route",
			"peer", record.GetName())

		return connect.NewResponse(&ladulasv1.AnnounceWakeupResponse{
			Accepted: true,
		}), nil
	}

	if refusal := checkRelayURL(route.GetRelayUrl()); refusal != "" {
		// Refused rather than stored, and said out loud rather than dropped: the
		// phone can tell somebody that this machine will not wake it, which is a
		// great deal better than nothing ever arriving.
		return connect.NewResponse(&ladulasv1.AnnounceWakeupResponse{
			Reason: refusal,
		}), nil
	}

	if route.GetInstanceId() == "" {
		return connect.NewResponse(&ladulasv1.AnnounceWakeupResponse{
			Reason: "the route names no instance at the relay",
		}), nil
	}

	err = s.node.wakeups.PutPeerWakeup(&storepb.PeerWakeup{
		PeerFingerprint: peer.Fingerprint,
		Route:           proto.CloneOf(route),
		AnnouncedAt:     timestamppb.Now(),
		QuietUntil:      req.Msg.GetQuietUntil(),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.node.log.Info("a peer said how it can be woken",
		"peer", record.GetName(), "relay", route.GetRelayUrl())

	return connect.NewResponse(&ladulasv1.AnnounceWakeupResponse{
		Accepted: true,
	}), nil
}

// checkRelayURL decides whether this instance is willing to dial what a peer
// announced.
//
// A paired approver announcing a URL is a paired approver choosing an address
// this daemon will make requests to, and a headless box on a network with
// interesting things on it should not be turned into a way to reach them. So the
// scheme has to carry its own confidentiality, or the network underneath it has
// to.
//
// Three shapes pass. https, which needs nothing said about it. http to
// loopback, which is a test and a relay running on this machine, neither of
// which reaches anything the process could not reach anyway. And http to the
// tailnet, which is the deployment this was actually built for: WireGuard is
// already doing what TLS would be asked to do, both ends are authenticated by
// the tailnet before a packet arrives, and asking for a second encryption layer
// buys a certificate to renew rather than a secret kept better.
//
// The tailnet test is a suffix or an address range, deliberately, so no name has
// to be resolved to decide it. A MagicDNS name resolves only to tailnet
// addresses, and a 100.64/10 literal needs no resolution at all — so unlike a
// check that looked up a host and then dialled it, there is no window here for
// the answer to change in between.
//
// It returns the sentence to send back rather than an error, because a refusal
// here is an answer and not a failure: the announcement arrived, was understood,
// and will not be acted on.
func checkRelayURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "that relay URL does not parse: " + err.Error()
	}

	if parsed.Host == "" {
		return "that relay URL names no host"
	}

	if parsed.Scheme == "https" {
		return ""
	}

	if parsed.Scheme == "http" {
		host := parsed.Hostname()

		if isLoopback(host) || isTailnet(host) {
			return ""
		}
	}

	return "this instance sends wake-ups to an https relay, " +
		"or to one on the tailnet"
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// isTailnet reports whether a host is inside a Tailscale network: a MagicDNS
// name, or one of the ranges Tailscale hands out.
func isTailnet(host string) bool {
	if strings.HasSuffix(host, ".ts.net") {
		return true
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}

	// 100.64.0.0/10 is the shared-address space Tailscale allocates IPv4 from,
	// and fd7a:115c:a1e0::/48 the ULA prefix it uses for IPv6.
	return netip.MustParsePrefix("100.64.0.0/10").Contains(addr) ||
		netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(addr)
}

// wakePeer is what parking a request does about an approver that is not
// listening.
//
// It runs detached, because the caller is the engine's fan-out and the answer to
// "did the push go out" changes nothing it does. Every branch that gives up here
// gives up silently for the same reason: the request is parked, and being parked
// is what makes it findable.
func (n *Node) wakePeer(fingerprint, requestID string) {
	if n.wakeups == nil {
		n.log.Debug("no wake-up was sent: this instance keeps no routes",
			"peer", fingerprint, "request_id", requestID)

		return
	}

	wakeup, ok := n.wakeups.PeerWakeup(fingerprint)
	if !ok || wakeup.GetRoute() == nil {
		// The ordinary state for a peer that has never announced one, which is
		// every desktop and any phone with wake-ups switched off.
		n.log.Debug("no wake-up was sent: that peer has announced no route",
			"peer", fingerprint, "request_id", requestID)

		return
	}

	ctx := n.lifetime()

	go n.runWake(ctx, wakeup, fingerprint, requestID)
}

// runWake sends the wake-up, quietly first when the peer said it could answer
// without asking anybody, and then out loud if that did not produce a poll.
func (n *Node) runWake(
	ctx context.Context, wakeup *storepb.PeerWakeup,
	fingerprint, requestID string,
) {
	if !n.quiet(wakeup) {
		n.log.Debug("waking a peer",
			"peer", fingerprint, "request_id", requestID, "style", "alert")

		n.sendWake(ctx, wakeup, fingerprint,
			ladulasv1.WakeStyle_WAKE_STYLE_ALERT,
			ladulasv1.WakeSubject_WAKE_SUBJECT_APPROVAL)

		return
	}

	n.log.Debug("waking a peer quietly, with an alert to follow if it stays parked",
		"peer", fingerprint, "request_id", requestID, "style", "silent",
		"grace", wakeGrace.String())

	n.sendWake(ctx, wakeup, fingerprint,
		ladulasv1.WakeStyle_WAKE_STYLE_SILENT,
		ladulasv1.WakeSubject_WAKE_SUBJECT_APPROVAL)

	// The silent push is the optimization and the alert is the floor. If the app
	// was resident it has by now dialled, collected and answered from its grant,
	// and there is nothing parked to be loud about; if it was not, this is the
	// alert that would have been sent in the first place, arriving a few seconds
	// late (§20, M9).
	timer := time.NewTimer(wakeGrace)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		n.log.Debug("no alert followed the quiet wake-up: the node is shutting down",
			"peer", fingerprint, "request_id", requestID)

		return
	case <-timer.C:
	}

	if n.parkedFor(requestID, fingerprint) == nil {
		// The carve-out working exactly as intended: the app was resident, took
		// the request off its grant and answered, and nobody was disturbed.
		n.log.Debug("no alert followed the quiet wake-up: the request was settled",
			"peer", fingerprint, "request_id", requestID)

		return
	}

	n.log.Debug("the quietly-woken request is still parked, so alerting",
		"peer", fingerprint, "request_id", requestID, "style", "alert")

	n.sendWake(ctx, wakeup, fingerprint,
		ladulasv1.WakeStyle_WAKE_STYLE_ALERT,
		ladulasv1.WakeSubject_WAKE_SUBJECT_APPROVAL)
}

// wakeForKey knocks once for a key queued for a peer that cannot be dialled.
//
// Always an alert, and never repeated. A signature has somebody's terminal
// blocked on it, which is what earns the silent-then-loud dance and the retry;
// a key handover has nobody waiting and no deadline, so the honest behaviour is
// one notification saying there is something to look at, and then the ordinary
// poll whenever the app is next opened (§11, decision S).
func (n *Node) wakeForKey(fingerprint string) {
	if n.wakeups == nil {
		return
	}

	wakeup, ok := n.wakeups.PeerWakeup(fingerprint)
	if !ok || wakeup.GetRoute() == nil {
		n.log.Debug("no wake-up was sent for a queued key: that peer has announced no route",
			"peer", fingerprint)

		return
	}

	ctx := n.lifetime()

	go n.sendWake(ctx, wakeup, fingerprint,
		ladulasv1.WakeStyle_WAKE_STYLE_ALERT,
		ladulasv1.WakeSubject_WAKE_SUBJECT_KEY_OFFER)
}

// quiet reports whether this peer said it could answer this instance without
// asking anybody, which is the only case §11's ban on background pushes is
// carved out of.
func (n *Node) quiet(wakeup *storepb.PeerWakeup) bool {
	until := wakeup.GetQuietUntil()
	if until == nil {
		return false
	}

	return until.AsTime().After(time.Now())
}

// sendWake makes one call to a relay.
func (n *Node) sendWake(
	ctx context.Context, wakeup *storepb.PeerWakeup,
	fingerprint string, style ladulasv1.WakeStyle,
	subject ladulasv1.WakeSubject,
) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), wakeTimeout)
	defer cancel()

	route := wakeup.GetRoute()
	client := &relay.Client{Identity: n.identity}

	outcome, err := client.Wake(
		ctx, route.GetRelayUrl(), route.GetInstanceId(), style, subject)
	if err != nil {
		// Debug, because a relay that cannot be reached is an ordinary state for
		// optional infrastructure to be in and a headless box should not fill its
		// log with it. What it costs is that the phone is opened by hand.
		n.log.Debug("could not send a wake-up",
			"peer", fingerprint, "error", err.Error())

		return
	}

	// The one line that says a knock actually landed, and what the relay made
	// of it. Without it the successful path is the only one with nothing to
	// show for itself.
	n.log.Debug("a wake-up reached the relay",
		"peer", fingerprint, "style", style.String(), "outcome", outcome.String())

	n.noteWoken(fingerprint, outcome)
}

// noteWoken acts on the one outcome that is a fact about the world rather than
// about this attempt.
//
// Delivered and throttled are both nothing to do: the request is parked either
// way, the relay does its own pacing, and recording when a peer was last woken
// would mean re-encrypting the whole store per push for a line nobody reads.
func (n *Node) noteWoken(fingerprint string, outcome ladulasv1.WakeOutcome) {
	if outcome != ladulasv1.WakeOutcome_WAKE_OUTCOME_UNREGISTERED &&
		outcome != ladulasv1.WakeOutcome_WAKE_OUTCOME_UNKNOWN {
		return
	}

	// The relay says nothing is registered under that identifier: the app was
	// deleted, or the platform reissued the token and this route names the old
	// one. Forgetting it is what stops a dead route being knocked at for ever,
	// and the phone announces a new one the next time it has one — which is the
	// other half of a rotating token (§19).
	dropped, err := n.wakeups.DropPeerWakeup(fingerprint)
	if err != nil {
		n.log.Error("could not forget a dead wake-up route",
			"peer", fingerprint, "error", err.Error())

		return
	}

	if dropped {
		n.log.Info("a peer's wake-up route is no longer registered",
			"peer", fingerprint)
	}
}

// AnnounceWakeups takes this instance's wake-up route to the requesters that
// have not been told it, or have been told something else.
//
// It runs from the poll loop rather than on a timer of its own, because the poll
// loop is the only thing a phone reliably does: it starts when the app comes to
// the foreground, which is also when a token arrives and when a grant has just
// been made. A grant made and then backgrounded within the same round is
// announced late, and being announced late costs an alert push instead of a
// silent one — which is the degradation, not a failure.
func (n *Node) AnnounceWakeups(ctx context.Context) {
	if n.wakeups == nil {
		return
	}

	n.announceMu.Lock()
	defer n.announceMu.Unlock()

	for _, record := range n.requesters() {
		if ctx.Err() != nil {
			return
		}

		route, quiet := n.ownRoute(record.GetFingerprint())

		if !n.shouldAnnounce(record.GetFingerprint(), route, quiet) {
			continue
		}

		n.announceTo(ctx, record, route, quiet)
	}
}

// ownRoute is what this instance would announce: its route, and until when it
// expects to answer that requester without asking anybody.
func (n *Node) ownRoute(
	fingerprint string,
) (*ladulasv1.WakeupRoute, time.Time) {
	settings := n.wakeups.WakeupSettings()

	if !settings.GetEnabled() || settings.GetInstanceId() == "" ||
		settings.GetDeviceToken() == "" {
		return nil, time.Time{}
	}

	return &ladulasv1.WakeupRoute{
		Kind:       ladulasv1.WakeupKind_WAKEUP_KIND_RELAY,
		RelayUrl:   settings.GetRelayUrl(),
		InstanceId: settings.GetInstanceId(),
	}, n.engine.QuietUntil(fingerprint)
}

// announced is what was last said to one requester.
type announced struct {
	at    time.Time
	route string
	quiet time.Time
}

// shouldAnnounce paces it. An announcement is one small RPC, and making one on
// every poll round would be making one every thirty seconds for the whole time
// an app is open — for a fact that changes when a token is reissued.
func (n *Node) shouldAnnounce(
	fingerprint string, route *ladulasv1.WakeupRoute, quiet time.Time,
) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	last, seen := n.announced[fingerprint]

	// Nothing to announce and nothing announced: the ordinary state of a desktop,
	// and of a phone that has not been asked about notifications yet.
	if route == nil && !seen {
		return false
	}

	current := announced{route: routeKey(route), quiet: quiet}

	if seen && last.route == current.route &&
		last.quiet.Equal(current.quiet) &&
		time.Since(last.at) < announceRefresh {
		return false
	}

	current.at = time.Now()
	n.announced[fingerprint] = current

	return true
}

func routeKey(route *ladulasv1.WakeupRoute) string {
	if route == nil {
		return ""
	}

	return route.GetRelayUrl() + "\x00" + route.GetInstanceId()
}

// announceTo tells one requester, and is best effort by construction: a
// requester that cannot be reached is a requester this instance is about to fail
// to collect from anyway.
func (n *Node) announceTo(
	ctx context.Context, record *storepb.TrustRecord,
	route *ladulasv1.WakeupRoute, quiet time.Time,
) {
	ctx, cancel := context.WithTimeout(ctx, announceTimeout)
	defer cancel()

	msg := &ladulasv1.AnnounceWakeupRequest{Route: route}

	if !quiet.IsZero() {
		msg.QuietUntil = timestamppb.New(quiet)
	}

	var refused string

	err := n.call(ctx, record, func(
		ctx context.Context, client *http.Client, baseURL string,
	) error {
		service := ladulasv1connect.NewWakeupServiceClient(client, baseURL)

		resp, err := service.AnnounceWakeup(ctx, connect.NewRequest(msg))
		if err != nil {
			return err //nolint:wrapcheck // call wraps it with the address
		}

		if !resp.Msg.GetAccepted() {
			refused = resp.Msg.GetReason()
		}

		return nil
	})
	if err != nil {
		// Not announced means not remembered as announced, so the next round
		// tries again rather than assuming a requester that was asleep heard it.
		n.forgetAnnouncement(record.GetFingerprint())

		n.log.Debug("could not announce a wake-up route",
			"peer", record.GetName(), "error", err.Error())

		return
	}

	if refused != "" {
		n.log.Info("a requester will not wake this instance",
			"peer", record.GetName(), "reason", refused)
	}
}

// announceTimeout bounds one announcement. Nobody is waiting for it.
const announceTimeout = 15 * time.Second

func (n *Node) forgetAnnouncement(fingerprint string) {
	n.mu.Lock()
	delete(n.announced, fingerprint)
	n.mu.Unlock()
}

// SetWakeups records this instance's own wake-up configuration and re-announces
// it, which is what turning wake-ups on, off, or pointing them at another relay
// all come down to.
//
// Switching off announces the withdrawal rather than merely stopping: a
// requester that was never told would go on knocking at a relay this instance
// has stopped registering with, and would go on being told nothing is there.
func (n *Node) SetWakeups(
	ctx context.Context, settings *storepb.WakeupSettings,
) error {
	if n.wakeups == nil {
		return errors.New("peer: this instance does not do wake-ups")
	}

	if err := n.wakeups.SetWakeupSettings(settings); err != nil {
		return err
	}

	// Marked stale rather than forgotten. Forgetting would lose the fact that a
	// requester was told something, and a requester that was told something is
	// exactly the one that has to be told the route is gone — which is what
	// switching wake-ups off comes down to.
	n.mu.Lock()

	for fingerprint, last := range n.announced {
		last.at = time.Time{}
		n.announced[fingerprint] = last
	}

	n.mu.Unlock()

	n.AnnounceWakeups(ctx)

	return nil
}

// Wakeups reports this instance's own wake-up configuration.
func (n *Node) Wakeups() *storepb.WakeupSettings {
	if n.wakeups == nil {
		return nil
	}

	return n.wakeups.WakeupSettings()
}

// PeerWakeups reports what peers have announced, for the surfaces that show
// whether an approver can be reached without somebody picking it up.
func (n *Node) PeerWakeups() []*storepb.PeerWakeup {
	if n.wakeups == nil {
		return nil
	}

	return n.wakeups.PeerWakeups()
}
