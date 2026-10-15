package peer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// The same hazard arrives a second way with the tunnel (decision AX). A
// tailcat address embeds the whole DERP region its server uses — relay host
// names and IP addresses — and a client raised against it opens DERP (HTTPS or
// WebSocket) and STUN connections to whatever is embedded. So a paired peer's
// tunnel offer is also a paired peer choosing addresses this daemon will
// connect to, and decision AQ's reassurance that the worst an advertised
// address can do is draw "connection attempts somewhere that will not
// authenticate as it" does not cover it: a DERP connection is not a pinned TLS
// dial.
//
// checkRelayRegion is the rule, beside checkRelayURL because it is the same
// rule about the same thing. It is applied to every region an address embeds,
// since a client connects to all of them. A region passes when it is one of
// this instance's own: every relay it names is a relay of one region in the
// local DERP map, by host name, with the same ports and certificate name and
// the same addresses where it gives any. A region the local map does not name
// passes only on checkRelayURL's terms for an https relay, made strict enough
// that nothing about it is left to a lookup:
//
//   - DERP over TLS, never the plain-HTTP test mode, on the default DERP port,
//     with the certificate expected to match the host name;
//   - STUN on the default port or switched off — a peer choosing the STUN port
//     is a peer choosing where this daemon sends UDP;
//   - every address given as a literal, or "none" for a family, with at least
//     one literal. An empty address field is a DNS lookup of the host name at
//     connect time, and a name that resolves to 10.0.0.5 tomorrow passes any
//     check made on the name today. A literal is checked here and connected to
//     as checked;
//   - no relay at a private, loopback, link-local, tailnet or unspecified
//     address, whether given as the host or beside it, and no host name that
//     is not a fully qualified name or that is localhost in any spelling.
//
// The region id is not part of the match, although §8 first said it would be:
// a tailcat address does not carry it. ConnInfo.Addr zeroes the region id,
// code and name to keep addresses short and ParseAddr makes up an id from the
// region's position, so an id "from the address" would be one this instance
// invented. Host names are what the address actually carries, and they are
// what a client connects to.
//
// Ports, the certificate name and the requirement for literals were added
// after review (2026-10-14). The first version read the host and the two
// addresses only, matched our own regions on the host name alone, and looked
// at the first region an address embedded: a peer could name a host that
// resolves inside this network, any port on a public address, or a second
// region pointing anywhere, and all three passed.

// relayRegion is a DERP region as the region rule reads it. It is decoded from
// the JSON Tunnel.RelayRegion and Tunnel.KnownRelays produce, because the
// tailcat types it comes from are not linked here.
type relayRegion struct {
	ID    int         `json:"id,omitempty"`
	Nodes []relayNode `json:"nodes"`
}

// relayNode is one relay in a region. IPv4 and IPv6 are what tailcfg puts
// beside the host name: empty to resolve the name, "none" to not use that
// family, or an address literal. DERPPort zero is 443; STUNPort zero is 3478
// and -1 is no STUN. CertName empty is "the certificate matches the host".
type relayNode struct {
	Host     string `json:"host"`
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	DERPPort int    `json:"derp_port,omitempty"`
	STUNPort int    `json:"stun_port,omitempty"`
	CertName string `json:"cert_name,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
}

// checkRelayRegionJSON is checkRelayRegion on the JSON a Tunnel hands over:
// every region an address embeds, each of which has to pass.
func checkRelayRegionJSON(regions, known string) string {
	var embedded []relayRegion

	if err := json.Unmarshal([]byte(regions), &embedded); err != nil {
		return "that tunnel address names a DERP region this instance " +
			"cannot read: " + err.Error()
	}

	var ours []relayRegion

	if known != "" {
		if err := json.Unmarshal([]byte(known), &ours); err != nil {
			ours = nil
		}
	}

	for _, region := range embedded {
		if refused := checkRelayRegion(region, ours); refused != "" {
			return refused
		}
	}

	return ""
}

// checkRelayRegion decides whether this instance is willing to connect to one
// DERP region a peer's tunnel address embeds, and returns the sentence to log
// when it is not.
func checkRelayRegion(region relayRegion, ours []relayRegion) string {
	if len(region.Nodes) == 0 {
		// An address that names a region by id only is resolved against this
		// instance's own DERP map by the client, which is a map this instance
		// chose; there is nothing peer-supplied to connect to.
		return ""
	}

	for _, known := range ours {
		if regionWithin(region, known) {
			return ""
		}
	}

	for _, node := range region.Nodes {
		if refused := checkRelayNode(node); refused != "" {
			return refused
		}
	}

	return ""
}

// regionWithin reports whether every relay a region names is one of a known
// region's: the same host name, ports, certificate name and test mode, and
// agreeing on any address it gives. A relay that borrows one of our host names
// with another port is not one of ours.
func regionWithin(region, known relayRegion) bool {
	for _, node := range region.Nodes {
		found := false

		for _, candidate := range known.Nodes {
			if !strings.EqualFold(node.Host, candidate.Host) ||
				node.DERPPort != candidate.DERPPort ||
				node.STUNPort != candidate.STUNPort ||
				node.CertName != candidate.CertName ||
				node.Insecure != candidate.Insecure {
				continue
			}

			if (node.IPv4 == "" || node.IPv4 == candidate.IPv4) &&
				(node.IPv6 == "" || node.IPv6 == candidate.IPv6) {
				found = true

				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}

// checkRelayNode is checkRelayURL's https rule for one relay this instance's
// own map does not name.
func checkRelayNode(node relayNode) string {
	switch {
	case node.Host == "":
		return "that DERP region names a relay with no host"
	case node.Insecure:
		return "that DERP region names a relay without TLS"
	case node.CertName != "":
		return "that DERP region names a relay whose certificate is not its host's"
	case node.DERPPort != 0 && node.DERPPort != 443:
		return fmt.Sprintf("that DERP region names a relay on port %d", node.DERPPort)
	case node.STUNPort != 0 && node.STUNPort != 3478 && node.STUNPort != -1:
		return fmt.Sprintf("that DERP region names STUN on port %d", node.STUNPort)
	}

	host, hostErr := netip.ParseAddr(node.Host)
	if hostErr != nil {
		if refused := checkRelayHostName(node.Host); refused != "" {
			return refused
		}
	} else if !publicRelayAddress(host) {
		return "that DERP region names a relay at " + node.Host +
			", which is not a public address"
	}

	literals := 0

	for _, given := range []string{node.IPv4, node.IPv6} {
		switch given {
		case "none":
			continue
		case "":
			// A host given as a literal is connected to as given; a host name
			// with an empty address beside it is resolved at connect time.
			if hostErr != nil {
				return "that DERP region names a relay by host name alone, " +
					"which would be looked up rather than checked"
			}

			continue
		}

		addr, err := netip.ParseAddr(given)
		if err != nil {
			return "that DERP region gives a relay address that is not one: " + given
		}

		if !publicRelayAddress(addr) {
			return "that DERP region names a relay at " + given +
				", which is not a public address"
		}

		literals++
	}

	if hostErr != nil && literals == 0 {
		return "that DERP region names a relay with no address to connect to"
	}

	return ""
}

// checkRelayHostName refuses a relay host name that could only mean this
// machine or this network: localhost in any spelling, and anything that is not
// a fully qualified name, which a resolver completes with its own search
// domains.
func checkRelayHostName(host string) string {
	name := strings.ToLower(strings.TrimSuffix(host, "."))

	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return "that DERP region names a relay on this machine"
	}

	if !strings.Contains(name, ".") || strings.HasSuffix(name, ".local") ||
		strings.HasSuffix(name, ".internal") || strings.HasSuffix(name, ".lan") ||
		strings.HasSuffix(name, ".home.arpa") {
		return "that DERP region names a relay at " + host +
			", which is not a public name"
	}

	if isTailnet(name) {
		return "that DERP region names a relay on the tailnet"
	}

	return ""
}

// publicRelayAddress reports whether an address is one a peer-supplied relay
// may be at: not private, loopback, link-local, multicast, unspecified, or in
// a tailnet's ranges.
func publicRelayAddress(addr netip.Addr) bool {
	addr = addr.Unmap()

	return !addr.IsPrivate() && !addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() && !addr.IsLinkLocalMulticast() &&
		!addr.IsInterfaceLocalMulticast() && !addr.IsMulticast() &&
		!addr.IsUnspecified() && !isTailnet(addr.String())
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
