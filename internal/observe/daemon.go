package observe

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/hugowetterberg/ladulas/internal/app"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Daemon is everything ladulasd exports about itself. It is one type, built in
// one place, so that the answer to "what does this daemon publish" is this
// file rather than a search.
//
// Nothing here touches a key, a payload, a fingerprint or a request id. A
// metrics port is the least protected surface an instance has — no
// authentication, scraped by something that keeps history — so what it carries
// is counts and states, and the identifying detail stays in the audit log where
// it is readable by the account that owns it and nowhere else.
type Daemon struct {
	entries   *prometheus.CounterVec
	requests  *prometheus.CounterVec
	decisions *prometheus.CounterVec
	wait      *prometheus.HistogramVec
	signature prometheus.Counter
}

// RegisterDaemon builds the daemon's metrics, registers them, and attaches
// them to the instance. It is called once, from whatever is about to serve.
func RegisterDaemon(reg prometheus.Registerer, instance *app.App) error {
	r := newRegistrar(reg)

	metrics := &Daemon{
		entries: r.counter("", "audit_entries_total",
			"Entries written to the audit log, by event. Every decision this "+
				"instance makes passes through it, so a flat line here is an "+
				"instance nothing is asking anything of.",
			labelEvent),
		requests: r.counter("", "approval_requests_total",
			"Approval requests received, by where they came from and what they "+
				"want. A rise in ssh_auth from a peer is somebody else's machine "+
				"using a key that lives here.",
			labelOrigin, labelKind),
		decisions: r.counter("", "approval_decisions_total",
			"Approval decisions, by what was decided and what decided it. "+
				"source=user is a person answering a prompt; policy and grant "+
				"are answers given in advance; no_approver and timeout are "+
				"requests nobody was there for.",
			labelOrigin, labelDecision, labelSource),
		wait: r.histogram("", "approval_wait_seconds",
			"Time from a request arriving to it being decided. The long tail is "+
				"a person walking back to their desk, not a slow machine.",
			waitBuckets, labelOrigin),
		signature: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "signatures_total",
			Help: "Signatures actually produced with a key held here. It " +
				"trails approvals: a request can be approved and then never " +
				"signed, which is what a requester giving up looks like.",
		}),
	}

	r.add(metrics.signature)
	r.add(newDaemonState(instance))

	if err := r.Err(); err != nil {
		return err
	}

	instance.Audit.Observe(metrics.record)

	return nil
}

// record turns one audit entry into counts. It is the audit log's observer, so
// it runs on whichever goroutine wrote the entry and does nothing that could
// block it.
func (d *Daemon) record(entry *ladulasv1.AuditEntry) {
	d.entries.WithLabelValues(eventLabel(entry.GetEvent())).Inc()

	switch entry.GetEvent() {
	case ladulasv1.AuditEvent_AUDIT_EVENT_REQUEST:
		d.requests.WithLabelValues(
			originLabel(entry.GetRequest()),
			kindLabel(entry.GetRequest().GetKind()),
		).Inc()
	case ladulasv1.AuditEvent_AUDIT_EVENT_DECISION:
		d.decided(entry)
	case ladulasv1.AuditEvent_AUDIT_EVENT_SIGNATURE:
		d.signature.Inc()
	case ladulasv1.AuditEvent_AUDIT_EVENT_UNSPECIFIED,
		ladulasv1.AuditEvent_AUDIT_EVENT_ERROR,
		ladulasv1.AuditEvent_AUDIT_EVENT_GRANT,
		ladulasv1.AuditEvent_AUDIT_EVENT_LIFECYCLE,
		ladulasv1.AuditEvent_AUDIT_EVENT_KEY_TRANSFER:
		// Counted by event above, which is all these need.
	}
}

func (d *Daemon) decided(entry *ladulasv1.AuditEntry) {
	resp := entry.GetResponse()
	origin := originLabel(entry.GetRequest())

	d.decisions.WithLabelValues(
		origin,
		enumLabel(resp.GetDecision(),
			ladulasv1.Decision_name, "DECISION_"),
		enumLabel(resp.GetSource(),
			ladulasv1.DecisionSource_name, "DECISION_SOURCE_"),
	).Inc()

	// A decision refused before the request was ever formed has no pair of
	// timestamps to subtract, and a clock that went backwards has no wait worth
	// recording either.
	created := entry.GetRequest().GetCreatedAt()
	decided := resp.GetDecidedAt()

	if created == nil || decided == nil {
		return
	}

	waited := decided.AsTime().Sub(created.AsTime())
	if waited < 0 {
		return
	}

	d.wait.WithLabelValues(origin).Observe(waited.Seconds())
}

// originLabel says whether the machine that asked was this one. A request with
// no requester at all is neither, and says so rather than being counted as
// remote.
func originLabel(req *ladulasv1.ApprovalRequest) string {
	requester := req.GetRequester()

	switch {
	case requester == nil:
		return other
	case requester.GetLocal():
		return "local"
	default:
		return "peer"
	}
}

func kindLabel(kind ladulasv1.RequestKind) string {
	return enumLabel(kind, ladulasv1.RequestKind_name, "REQUEST_KIND_")
}

func eventLabel(event ladulasv1.AuditEvent) string {
	return enumLabel(event, ladulasv1.AuditEvent_name, "AUDIT_EVENT_")
}

// daemonState reads the instance at scrape time rather than keeping a copy in
// step with it. Lock state, keys, peers and pairings are all things the
// instance already knows the answer to, and a mirror of them is one more thing
// that can be wrong.
type daemonState struct {
	instance *app.App
	log      *slog.Logger

	lockState  *prometheus.Desc
	stateSince *prometheus.Desc
	keys       *prometheus.Desc
	grants     *prometheus.Desc
	offers     *prometheus.Desc
	borrowed   *prometheus.Desc
	peers      *prometheus.Desc
	pairings   *prometheus.Desc
	listeners  *prometheus.Desc
}

var _ prometheus.Collector = (*daemonState)(nil)

func newDaemonState(instance *app.App) *daemonState {
	name := func(suffix string) string {
		return namespace + "_" + suffix
	}

	return &daemonState{
		instance: instance,
		log:      instance.Log(),

		lockState: prometheus.NewDesc(name("lock_state"),
			"Which lock state the store is in, 1 for the current one. sealed "+
				"means the key is not in memory and nothing here can sign; "+
				"locked means it is, but approving here is suspended and paired "+
				"approvers still answer.",
			[]string{labelState}, nil),
		stateSince: prometheus.NewDesc(
			name("lock_state_since_timestamp_seconds"),
			"When the store entered its current lock state.", nil, nil),
		keys: prometheus.NewDesc(name("keys"),
			"SSH keys held in this instance's own store.", nil, nil),
		grants: prometheus.NewDesc(name("grants"),
			"Live TTL grants, which are the approvals given in advance.",
			nil, nil),
		offers: prometheus.NewDesc(name("key_offers"),
			"Keys a peer has handed over that are waiting for somebody here to "+
				"accept or refuse them.", nil, nil),
		borrowed: prometheus.NewDesc(name("borrowed_keys"),
			"Keys that live on a paired peer, by whether they can be used right "+
				"now. unreachable is the ordinary state of a key on a phone in a "+
				"pocket rather than a fault.",
			[]string{labelState}, nil),
		peers: prometheus.NewDesc(name("peers"),
			"Paired peers, by whether a link to them is up.",
			[]string{labelState}, nil),
		pairings: prometheus.NewDesc(name("pending_pairings"),
			"Pairings waiting for somebody to answer. They do not expire, and "+
				"nothing else will ever remind anyone.", nil, nil),
		listeners: prometheus.NewDesc(name("peer_listeners"),
			"Addresses the peer channel is bound to. Zero means no peer can "+
				"reach this instance: peering off, or a sealed store.", nil, nil),
	}
}

// Describe implements prometheus.Collector.
func (s *daemonState) Describe(ch chan<- *prometheus.Desc) {
	ch <- s.lockState
	ch <- s.stateSince
	ch <- s.keys
	ch <- s.grants
	ch <- s.offers
	ch <- s.borrowed
	ch <- s.peers
	ch <- s.pairings
	ch <- s.listeners
}

// Collect implements prometheus.Collector.
func (s *daemonState) Collect(ch chan<- prometheus.Metric) {
	state, since, _ := s.instance.StateDetail()

	// Every state is emitted, not only the one it is in. A gauge that appeared
	// and disappeared would make "sealed" indistinguishable from "the daemon
	// stopped answering", which is the one distinction this metric is for.
	for value := range ladulasv1.LockState_name {
		known := ladulasv1.LockState(value)
		if known == ladulasv1.LockState_LOCK_STATE_UNSPECIFIED {
			continue
		}

		ch <- prometheus.MustNewConstMetric(s.lockState, prometheus.GaugeValue,
			boolValue(known == state),
			enumLabel(known, ladulasv1.LockState_name, "LOCK_STATE_"))
	}

	ch <- prometheus.MustNewConstMetric(s.stateSince, prometheus.GaugeValue,
		float64(since.Unix()))

	ch <- prometheus.MustNewConstMetric(s.listeners, prometheus.GaugeValue,
		float64(len(s.instance.PeerAddresses())))

	s.collectStore(ch)
	s.collectPeers(ch)
}

// collectStore is everything that needs the store open. A sealed instance
// reports none of it rather than reporting zeroes: "no keys" and "the key set
// cannot be read from here" are different answers, and a graph that read the
// second as the first would show a machine losing all its keys every time it
// was sealed.
func (s *daemonState) collectStore(ch chan<- prometheus.Metric) {
	vault := s.instance.Vault()
	if vault == nil {
		return
	}

	ch <- prometheus.MustNewConstMetric(s.keys, prometheus.GaugeValue,
		float64(len(vault.Keys())))

	ch <- prometheus.MustNewConstMetric(s.offers, prometheus.GaugeValue,
		float64(len(vault.PendingKeyOffers())))

	grants, err := vault.Grants()
	if err != nil {
		s.log.Warn("could not count the live grants for the metrics port",
			"error", err.Error())

		return
	}

	ch <- prometheus.MustNewConstMetric(s.grants, prometheus.GaugeValue,
		float64(len(grants)))
}

// collectPeers is everything the peer channel knows. It is silent with peering
// off or the store sealed, for the same reason as the store gauges above.
func (s *daemonState) collectPeers(ch chan<- prometheus.Metric) {
	node := s.instance.Peer()
	if node == nil {
		return
	}

	var online, offline int

	for _, peer := range node.PeerStatuses() {
		if peer.GetOnline() {
			online++

			continue
		}

		offline++
	}

	ch <- prometheus.MustNewConstMetric(s.peers, prometheus.GaugeValue,
		float64(online), "online")
	ch <- prometheus.MustNewConstMetric(s.peers, prometheus.GaugeValue,
		float64(offline), "offline")

	ch <- prometheus.MustNewConstMetric(s.pairings, prometheus.GaugeValue,
		float64(len(node.PendingPairingStatuses())))

	var usable, unreachable, heldHere int

	for _, key := range node.BorrowedKeys() {
		switch {
		case key.GetHeldHere():
			// A key this instance has its own copy of is not borrowed any more,
			// and counting it as waiting on a peer would overstate what depends
			// on that peer being awake.
			heldHere++
		case key.GetAvailable():
			usable++
		default:
			unreachable++
		}
	}

	ch <- prometheus.MustNewConstMetric(s.borrowed, prometheus.GaugeValue,
		float64(usable), "usable")
	ch <- prometheus.MustNewConstMetric(s.borrowed, prometheus.GaugeValue,
		float64(unreachable), "unreachable")
	ch <- prometheus.MustNewConstMetric(s.borrowed, prometheus.GaugeValue,
		float64(heldHere), "held_here")
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}

	return 0
}
