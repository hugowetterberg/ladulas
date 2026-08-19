package peer

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// memoryStore is a trust store that lives for the test. The store's own
// durability is the keystore package's business; what these tests are about is
// what the node does with the records.
type memoryStore struct {
	mu            sync.Mutex
	records       []*storepb.TrustRecord
	publications  []*ladulasv1.Publication
	pairings      []*storepb.PendingPairing
	borrowed      []*storepb.BorrowedKey
	noAutoPublish bool
}

func (m *memoryStore) AutoPublish() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return !m.noAutoPublish
}

func (m *memoryStore) SetAutoPublish(enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.noAutoPublish = !enabled

	return nil
}

func (m *memoryStore) BorrowedKeys() []*storepb.BorrowedKey {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]*storepb.BorrowedKey(nil), m.borrowed...)
}

func (m *memoryStore) SetBorrowedKeys(
	fingerprint string, keys []*ladulasv1.KeyRef, seen time.Time,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	kept := make([]*storepb.BorrowedKey, 0, len(m.borrowed)+len(keys))

	for _, borrowed := range m.borrowed {
		if borrowed.GetPeerFingerprint() != fingerprint {
			kept = append(kept, borrowed)
		}
	}

	for _, key := range keys {
		kept = append(kept, &storepb.BorrowedKey{
			PeerFingerprint: fingerprint,
			Key:             proto.CloneOf(key),
			LastSeenAt:      timestamppb.New(seen),
		})
	}

	m.borrowed = kept

	return nil
}

func (m *memoryStore) DropBorrowedKeys(fingerprint string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	kept := make([]*storepb.BorrowedKey, 0, len(m.borrowed))

	var dropped int

	for _, borrowed := range m.borrowed {
		if borrowed.GetPeerFingerprint() == fingerprint {
			dropped++

			continue
		}

		kept = append(kept, borrowed)
	}

	m.borrowed = kept

	return dropped, nil
}

func (m *memoryStore) PendingPairings() []*storepb.PendingPairing {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]*storepb.PendingPairing(nil), m.pairings...)
}

func (m *memoryStore) PendingPairing(ref string) (*storepb.PendingPairing, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, pending := range m.pairings {
		if matchesPending(pending, ref) {
			return proto.CloneOf(pending), true
		}
	}

	return nil, false
}

func (m *memoryStore) PutPendingPairing(pending *storepb.PendingPairing) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored := proto.CloneOf(pending)

	for i, existing := range m.pairings {
		if existing.GetSessionId() == stored.GetSessionId() {
			m.pairings[i] = stored

			return nil
		}
	}

	m.pairings = append(m.pairings, stored)

	return nil
}

func (m *memoryStore) RemovePendingPairing(
	ref string,
) (*storepb.PendingPairing, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, pending := range m.pairings {
		if matchesPending(pending, ref) {
			m.pairings = append(m.pairings[:i], m.pairings[i+1:]...)

			return pending, nil
		}
	}

	return nil, errNoSuchPending
}

var errNoSuchPending = errors.New("no such pending pairing")

func matchesPending(pending *storepb.PendingPairing, ref string) bool {
	return pending.GetSessionId() == ref ||
		pending.GetFingerprint() == ref ||
		strings.EqualFold(pending.GetName(), ref)
}

// Peers, Peer and the two mutators keep trust.Store's rule: a record that has
// been handed out is never written to again. The records here are shared rather
// than cloned, which is what makes keeping the rule matter — a change swaps a
// new record into the slice, so whoever is reading the old one goes on reading
// a whole, consistent record.
func (m *memoryStore) Peers() []*storepb.TrustRecord {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]*storepb.TrustRecord(nil), m.records...)
}

func (m *memoryStore) Peer(ref string) (*storepb.TrustRecord, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, record := range m.records {
		if trust.MatchesRef(record, ref) {
			return record, true
		}
	}

	return nil, false
}

func (m *memoryStore) PutPeer(record *storepb.TrustRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, existing := range m.records {
		if existing.GetFingerprint() == record.GetFingerprint() {
			m.records[i] = record

			return nil
		}
	}

	m.records = append(m.records, record)

	return nil
}

func (m *memoryStore) RemovePeer(ref string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, record := range m.records {
		if trust.MatchesRef(record, ref) {
			m.records = append(m.records[:i], m.records[i+1:]...)

			return record.GetFingerprint(), nil
		}
	}

	return "", trust.ErrNoSuchPeer
}

func (m *memoryStore) SetPeerDirections(
	ref string, directions trust.Directions,
) (*storepb.TrustRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, record := range m.records {
		if trust.MatchesRef(record, ref) {
			revised := directions.Applied(record)

			m.records[i] = revised

			return revised, nil
		}
	}

	return nil, trust.ErrNoSuchPeer
}

func (m *memoryStore) Publications() []*ladulasv1.Publication {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]*ladulasv1.Publication(nil), m.publications...)
}

func (m *memoryStore) Publication(ref string) (*ladulasv1.Publication, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, publication := range m.publications {
		if publication.GetProjectId() == ref || publication.GetName() == ref {
			return publication, true
		}
	}

	return nil, false
}

func (m *memoryStore) PutPublication(publication *ladulasv1.Publication) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, existing := range m.publications {
		if existing.GetProjectId() == publication.GetProjectId() {
			m.publications[i] = publication

			return nil
		}
	}

	m.publications = append(m.publications, publication)

	return nil
}

func (m *memoryStore) RemovePublication(ref string) (*ladulasv1.Publication, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, publication := range m.publications {
		if publication.GetProjectId() == ref || publication.GetName() == ref {
			m.publications = append(m.publications[:i], m.publications[i+1:]...)

			return publication, nil
		}
	}

	return nil, errNoSuchPublication
}

var errNoSuchPublication = errors.New("no such publication")

func (m *memoryStore) RenamePeer(ref, name string) (*storepb.TrustRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, record := range m.records {
		if trust.MatchesRef(record, ref) {
			revised := trust.Renamed(record, name)

			m.records[i] = revised

			return revised, nil
		}
	}

	return nil, trust.ErrNoSuchPeer
}

// answerer is a human, as far as the engine is concerned.
type answerer struct {
	name string

	mu      sync.Mutex
	answer  *approval.Answer
	fail    error
	seen    []*approval.Request
	blocked bool
	delay   time.Duration
}

func (a *answerer) ID() string {
	return a.name
}

func (a *answerer) Decide(
	ctx context.Context, req *approval.Request,
) (*approval.Answer, error) {
	a.mu.Lock()
	a.seen = append(a.seen, req)
	answer, fail, delay := a.answer, a.fail, a.delay
	a.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			a.mu.Lock()
			a.blocked = true
			a.mu.Unlock()

			return nil, ctx.Err()
		}
	}

	if fail != nil {
		return nil, fail
	}

	return answer, nil
}

func (a *answerer) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return len(a.seen)
}

// last is the most recent request this answerer was shown.
func (a *answerer) last() *approval.Request {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.seen) == 0 {
		return nil
	}

	return a.seen[len(a.seen)-1]
}

func (a *answerer) cancelled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.blocked
}

func (a *answerer) set(answer *approval.Answer, fail error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.answer = answer
	a.fail = fail
}

func (a *answerer) setDelay(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.delay = d
}

// silence is a card on a screen nobody is looking at: it is shown, and no
// answer ever comes back.
//
// It blocks rather than returning when the context is done, because the engine
// treats an approver that returns an error as one that could not be reached,
// and "the desktop was not there" is a different story from "nobody picked the
// phone up". The channel is closed when the test ends, which is what lets the
// goroutine go.
type silence struct {
	done  chan struct{}
	asked chan struct{}
	once  sync.Once
}

func newSilence(t *testing.T) *silence {
	t.Helper()

	s := &silence{done: make(chan struct{}), asked: make(chan struct{})}

	t.Cleanup(func() {
		close(s.done)
	})

	return s
}

func (s *silence) ID() string {
	return "nobody"
}

// wait blocks until the card has been put up, which is what a test means by
// "the phone was shown it and did nothing".
func (s *silence) wait() {
	<-s.asked
}

func (s *silence) Decide(
	_ context.Context, _ *approval.Request,
) (*approval.Answer, error) {
	s.once.Do(func() {
		close(s.asked)
	})

	<-s.done

	return nil, errors.New("the test is over")
}

func approveAnswer(reason string) *approval.Answer {
	return &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		Reason:   reason,
	}
}

func denyAnswer(reason string) *approval.Answer {
	return &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_DENY,
		Reason:   reason,
	}
}

// instance is a node with everything under it: an identity, an engine, an audit
// log and a trust store.
type instance struct {
	t        *testing.T
	node     *Node
	engine   *approval.Engine
	store    *memoryStore
	keys     *memoryKeys
	projects *project.Cache
	vault    *keystore.Vault
	identity *identity.Identity
	audit    string
	human    *answerer
	ledger   *memoryLedger
	drop     func()
}

func newInstance(t *testing.T, name string) *instance {
	t.Helper()

	return newInstanceOn(t, name, "127.0.0.1:0")
}

// newInstanceOn is the same instance on a chosen bind specification, which is
// how a test builds a phone: transport.ListenNone and no address to advertise.
func newInstanceOn(t *testing.T, name, listen string) *instance {
	t.Helper()

	id, _, err := identity.Generate(name)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	auditPath := t.TempDir() + "/audit.jsonl"

	auditLog, err := approval.OpenAuditLog(auditPath)
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}

	t.Cleanup(func() {
		if err := auditLog.Close(); err != nil {
			t.Errorf("close the audit log: %v", err)
		}
	})

	ledger := &memoryLedger{}

	engine, err := approval.New(approval.Options{
		Identity:    id,
		Policy:      approval.DefaultPolicy(),
		Grants:      ledger,
		Delegations: ledger,
		GrantUses:   ledger,
		Audit:       auditLog,
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	store := &memoryStore{}
	keys := &memoryKeys{}

	// The real store, because handing a key over is the one thing whose
	// correctness is mostly about what the store does and does not hold.
	vault, err := keystore.Create(keystore.Options{
		Dir:          t.TempDir(),
		Keyring:      &keystore.MemoryKeyring{},
		Passphrase:   func(string, bool) ([]byte, error) { return []byte("x"), nil },
		InstanceName: name,
		// Keep the suite quick; unlocking is not what these tests are about.
		ScryptWorkFactor: 10,
	})
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	projects, err := project.OpenCache(
		t.TempDir(), plainCipher{}, project.DefaultLimits)
	if err != nil {
		t.Fatalf("project cache: %v", err)
	}

	node, err := New(Options{
		Identity:    id,
		Trust:       store,
		Engine:      engine,
		Keys:        keys,
		Projects:    projects,
		Delegations: ledger,
		Handovers:   vault,
		Listen:      listen,
		// Short enough that a test does not wait on a reconnection, long enough
		// that it is still a backoff.
		Heartbeat:    50 * time.Millisecond,
		RetryFloor:   10 * time.Millisecond,
		RetryCeiling: 50 * time.Millisecond,
		// A pairing is reconciled on a human's clock in real life. A test is
		// not a human, and the only thing shortening this changes is how long a
		// side that could not reach its peer waits before trying again.
		PairingRetry: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("node: %v", err)
	}

	if err := node.Listen(); err != nil {
		t.Fatalf("bind: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)

	go func() {
		served <- node.Serve(ctx)
	}()

	t.Cleanup(func() {
		cancel()

		select {
		case err := <-served:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the node did not stop")
		}
	})

	human := &answerer{name: name + " human", answer: approveAnswer("yes")}

	return &instance{
		t:        t,
		node:     node,
		engine:   engine,
		store:    store,
		ledger:   ledger,
		keys:     keys,
		projects: projects,
		vault:    vault,
		identity: id,
		audit:    auditPath,
		human:    human,
		drop:     engine.Register(human),
	}
}

func (i *instance) address() string {
	addresses := i.node.Addresses()
	if len(addresses) != 1 {
		i.t.Fatalf("the node bound %v", addresses)
	}

	return addresses[0]
}

// memoryGrants is a grant store for the tests.
type memoryGrants struct {
	mu     sync.Mutex
	grants []*ladulasv1.Grant
}

func (m *memoryGrants) Grants() ([]*ladulasv1.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]*ladulasv1.Grant(nil), m.grants...), nil
}

func (m *memoryGrants) AddGrant(grant *ladulasv1.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.grants = append(m.grants, grant)

	return nil
}

func (m *memoryGrants) PendingRevocations(fingerprint string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []string

	for _, grant := range m.grants {
		if grant.GetRevokePending() && grant.GetDelegated() &&
			grant.GetDelegateFingerprint() == fingerprint {
			out = append(out, grant.GetGrantId())
		}
	}

	return out
}

func (m *memoryGrants) ReplaceGrant(grant *ladulasv1.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, existing := range m.grants {
		if existing.GetGrantId() == grant.GetGrantId() {
			m.grants[i] = grant

			return nil
		}
	}

	return errors.New("no such grant")
}

func (m *memoryGrants) RevokeGrant(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	kept := m.grants[:0]

	for _, grant := range m.grants {
		if grant.GetGrantId() != id {
			kept = append(kept, grant)
		}
	}

	m.grants = kept

	return nil
}

// pair runs the exchange the way the two commands do: the approver displays a
// code, the requester dials it, and both sides' users confirm.
//
// The two halves are waited for separately, because they are separate: dialling
// spends the code and returns, and the record on either side appears when that
// side's user has answered and the two have reconciled (§7).
func pair(t *testing.T, approver, requester *instance) {
	t.Helper()

	// What the approver grants the requester: it may ask, and it does not
	// approve for us.
	window, secret, err := approver.node.beginPairing(false, true)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer approver.node.closeWindow(window)

	// The typed-code path: the requester was told the address and the code, and
	// learns the identity from the handshake.
	code := &ladulasv1.PairingCode{Version: 1, Secret: string(secret)}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pending, err := requester.node.PairWith(
		ctx, approver.address(), code, true, false)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}

	if pending.GetFingerprint() != approver.identity.Fingerprint() {
		t.Fatalf("started a pairing with %s", pending.GetFingerprint())
	}

	// Both sides wrote a record down, and each says what its own user chose.
	theirs := waitPaired(t, approver, requester.identity.Fingerprint())

	if theirs.GetMayApprove() || !theirs.GetMayRequest() {
		t.Errorf("the approver recorded approve=%v request=%v",
			theirs.GetMayApprove(), theirs.GetMayRequest())
	}

	ours := waitPaired(t, requester, approver.identity.Fingerprint())

	if !ours.GetMayApprove() || ours.GetMayRequest() {
		t.Errorf("the requester recorded approve=%v request=%v",
			ours.GetMayApprove(), ours.GetMayRequest())
	}

	// And then the link, which is a third thing rather than a consequence of the
	// second. See waitLinked.
	waitLinked(t, requester, approver.identity.Fingerprint())
}

// waitLinked waits until the requester can actually reach the approver.
//
// The trust record and the link are written at different moments: pairing
// records the peer, and the reconciliation that follows builds the link,
// registers the remote approver with the engine and pings. A request submitted
// in the gap between them is not merely slow — it is denied outright, with "no
// approver is available to answer", because an engine whose fan-out is empty
// answers immediately rather than waiting for a handler to turn up.
//
// So every test that paired and then submitted was racing, at a few percent
// under load, and it never surfaced as itself: the setup request was rarely the
// one being asserted on, so the failure landed on whatever came after it. The
// grant test was the worst of them — its first submit was unchecked, so a
// denied setup left no grant behind and the failure read as "the grant did not
// answer", fifteen lines and one wrong diagnosis away from the cause.
func waitLinked(t *testing.T, requester *instance, fingerprint string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		// Online rather than merely present: the link is put in the map before it
		// is started, and it is starting that registers the approver. Waiting for
		// the ping to have come back is both the later of the two and the one the
		// test actually means.
		if l := requester.node.link(fingerprint); l != nil {
			if online, _, _ := l.State(); online {
				return
			}
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("%s never linked to %s",
		requester.identity.Name(), fingerprint)
}

// waitPaired waits for a trust record to appear, which is what completing a
// pairing now looks like from the outside: two answers and a reconciliation
// rather than the return of one call.
func waitPaired(t *testing.T, side *instance, fingerprint string) *storepb.TrustRecord {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		if record, ok := side.store.Peer(fingerprint); ok {
			return record
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("%s never wrote a record for %s",
		side.identity.Name(), fingerprint)

	return nil
}

func gitRequest() *ladulasv1.ApprovalRequest {
	return &ladulasv1.ApprovalRequest{
		Kind:    ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
		Key:     &ladulasv1.KeyRef{Fingerprint: "SHA256:workkey", Label: "work"},
		Timeout: durationpb.New(5 * time.Second),
		Operation: &ladulasv1.ApprovalRequest_Sshsig{
			Sshsig: &ladulasv1.SshsigRequest{
				Namespace:     "git",
				HashAlgorithm: "sha512",
				MessageDigest: []byte("digest"),
			},
		},
	}
}

// TestRemoteApprovalOfAHeadlessRequest is M3's acceptance in miniature: a
// machine with nobody at it gets a signature approved by the machine somebody
// is sitting at.
func TestRemoteApprovalOfAHeadlessRequest(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)

	// The headless box has nobody. It is the whole point.
	headless.drop()

	desktop.human.set(approveAnswer("approved at the desktop"), nil)

	// The pairing confirmation was a prompt too; only what follows is the
	// request under test.
	before := desktop.human.count()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := headless.engine.Submit(ctx, gitRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("decision %v: %s", resp.GetDecision(), resp.GetReason())
	}

	// The requester knows who answered, and it is the peer rather than itself.
	if resp.GetApprover().GetInstanceId() != desktop.identity.Fingerprint() {
		t.Errorf("attributed to %v", resp.GetApprover())
	}

	if resp.GetApprover().GetLocal() {
		t.Error("a remote decision was recorded as local")
	}

	// The desktop was shown a request from a named machine, not a local one.
	if asked := desktop.human.count() - before; asked != 1 {
		t.Fatalf("the desktop was asked %d times", asked)
	}

	shown := desktop.human.last().Msg.GetRequester()

	if shown.GetLocal() {
		t.Error("the desktop was shown the request as a local one")
	}

	if shown.GetInstanceId() != headless.identity.Fingerprint() {
		t.Errorf("the desktop was shown %q as the requester", shown.GetInstanceId())
	}

	if shown.GetName() != "headless" {
		t.Errorf("the desktop named the requester %q", shown.GetName())
	}

	if shown.GetRemoteAddress() == "" {
		t.Error("the desktop was not told where the request came from")
	}

	// Both ends hold the approver's signature over what was agreed.
	requireSignedDecision(t, desktop.audit, false)
	requireSignedDecision(t, headless.audit, true)
}

// TestRemoteDenialIsADecision: a refusal travels as an answer, not as a
// failure, and the requester records who refused.
func TestRemoteDenialIsADecision(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	desktop.human.set(denyAnswer("not that one"), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := headless.engine.Submit(ctx, gitRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Fatalf("decision %v", resp.GetDecision())
	}

	if !strings.Contains(resp.GetReason(), "not that one") {
		t.Errorf("the reason is %q", resp.GetReason())
	}

	if resp.GetApprover().GetInstanceId() != desktop.identity.Fingerprint() {
		t.Errorf("the refusal is attributed to %v", resp.GetApprover())
	}
}

// TestUnreachableApproverFailsRatherThanHangs is the third path a headless box
// meets: the desktop is switched off.
func TestUnreachableApproverFailsRatherThanHangs(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	if err := desktop.node.Close(); err != nil {
		t.Fatalf("stop the desktop: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	msg := gitRequest()
	msg.Timeout = durationpb.New(20 * time.Second)

	start := time.Now()

	resp, err := headless.engine.Submit(ctx, msg)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("waited %s for an approver that is not there", elapsed)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Errorf("decision %v", resp.GetDecision())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER {
		t.Errorf("source %v, want no-approver", resp.GetSource())
	}
}

// TestFirstResponseWinsAcrossTheChannel: the local prompt and the peer are the
// same fan-out, and the loser is cancelled rather than left on screen.
func TestFirstResponseWinsAcrossTheChannel(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)

	// The peer answers at once; the local approver would take far longer than
	// the test is willing to wait, and should be cancelled instead.
	desktop.human.set(approveAnswer("approved at the desktop"), nil)

	headless.human.mu.Lock()
	headless.human.delay = 30 * time.Second
	headless.human.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := headless.engine.Submit(ctx, gitRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("decision %v: %s", resp.GetDecision(), resp.GetReason())
	}

	if resp.GetApprover().GetInstanceId() != desktop.identity.Fingerprint() {
		t.Errorf("the winner was %v", resp.GetApprover())
	}

	// The loser's prompt was taken away.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !headless.human.cancelled() {
		time.Sleep(10 * time.Millisecond)
	}

	if !headless.human.cancelled() {
		t.Error("the losing approver was left waiting")
	}
}

// TestGrantOnTheApproverAnswersWithoutAsking: a grant is the approver's
// promise, kept on the approver, and spending it prompts nobody (§18).
func TestGrantOnTheApproverAnswersWithoutAsking(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	desktop.human.set(&approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		Reason:   "approved for a while",
		GrantTTL: time.Hour,
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Checked, because everything below rests on this one having left a promise
	// behind: a denial here creates no grant, and the failure then surfaces as
	// the second request reaching a human rather than as the first one going
	// wrong.
	first, err := headless.engine.Submit(ctx, gitRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if first.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("the promise was never made: %v %s",
			first.GetDecision(), first.GetReason())
	}

	// From here on the desktop answers by itself.
	desktop.human.set(denyAnswer("the human would refuse"), nil)

	before := desktop.human.count()

	resp, err := headless.engine.Submit(ctx, gitRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("the grant did not answer: %v %s",
			resp.GetDecision(), resp.GetReason())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		t.Errorf("source %v, want grant", resp.GetSource())
	}

	if desktop.human.count() != before {
		t.Error("the grant still put a prompt on the approver's screen")
	}
}

// TestRevocationSeversTheConnection: forgetting a peer drops what it is holding
// and refuses what it asks next.
func TestRevocationSeversTheConnection(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Checked for the same reason as the grant test's: what is under test is
	// that the second request is refused, and a first one that was already
	// refused would prove nothing.
	if resp, err := headless.engine.Submit(ctx, gitRequest()); err != nil {
		t.Fatalf("submit: %v", err)
	} else if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("the peer was refused before it was revoked: %v %s",
			resp.GetDecision(), resp.GetReason())
	}

	// The desktop forgets the headless box.
	fingerprint, err := desktop.store.RemovePeer(headless.identity.Fingerprint())
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	desktop.node.Disconnect(fingerprint)
	desktop.node.Reconcile()

	msg := gitRequest()
	msg.Timeout = durationpb.New(5 * time.Second)

	resp, err := headless.engine.Submit(ctx, msg)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Fatalf("a revoked peer still approved: %s", resp.GetReason())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER {
		t.Errorf("source %v, want no-approver", resp.GetSource())
	}
}

// TestWrongPairingCodeIsRefused, and enough wrong ones close the window
// altogether — which is what makes a ten-character code safe against guessing.
func TestWrongPairingCodeIsRefused(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	window, secret, err := desktop.node.beginPairing(false, true)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	wrong, err := trust.NewSecret()
	if err != nil {
		t.Fatalf("secret: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for range trust.MaxAttempts {
		_, err := headless.node.PairWith(ctx, desktop.address(),
			&ladulasv1.PairingCode{Version: 1, Secret: string(wrong)}, true, false)
		if err == nil {
			t.Fatal("a wrong code paired")
		}
	}

	if len(desktop.store.Peers()) != 0 {
		t.Error("a wrong code left a record behind")
	}

	// The window is gone, so even the right code no longer works. The person
	// who was actually pairing displays a new one.
	_, err = headless.node.PairWith(ctx, desktop.address(),
		&ladulasv1.PairingCode{Version: 1, Secret: string(secret)}, true, false)
	if err == nil {
		t.Fatal("the window survived too many wrong codes")
	}
}

// TestUnpairedIdentityIsRefusedAtTheDoor: with no pairing in progress, an
// identity nobody knows does not get past the handshake (§15).
func TestUnpairedIdentityIsRefusedAtTheDoor(t *testing.T) {
	desktop := newInstance(t, "desktop")
	stranger := newInstance(t, "stranger")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	secret, err := trust.NewSecret()
	if err != nil {
		t.Fatalf("secret: %v", err)
	}

	_, err = stranger.node.PairWith(ctx, desktop.address(),
		&ladulasv1.PairingCode{Version: 1, Secret: string(secret)}, true, false)
	if err == nil {
		t.Fatal("a stranger reached an instance that was not pairing")
	}

	if desktop.human.count() != 0 {
		t.Error("a stranger raised a prompt on somebody's desktop")
	}
}

// TestDeclinedPairingLeavesNoRecord: nothing is written until both users have
// agreed, so a pairing somebody said no to leaves neither side thinking it
// worked — and leaves neither side with an entry still waiting for an answer.
func TestDeclinedPairingLeavesNoRecord(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	window, secret, err := desktop.node.beginPairing(false, true)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	// The desktop's user agrees; the requester's does not.
	headless.human.set(denyAnswer("not this machine"), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := headless.node.PairWith(ctx, desktop.address(),
		&ladulasv1.PairingCode{Version: 1, Secret: string(secret)},
		true, false); err != nil {
		t.Fatalf("spend the code: %v", err)
	}

	waitPairingsGone(t, desktop, headless)

	if len(desktop.store.Peers()) != 0 {
		t.Errorf("the listening side kept %d records", len(desktop.store.Peers()))
	}

	if len(headless.store.Peers()) != 0 {
		t.Errorf("the dialling side kept %d records", len(headless.store.Peers()))
	}
}

// TestPairingIsRefusedAtTheListeningEnd covers the other user saying no, and
// the refusal reaching the side that dialled.
func TestPairingIsRefusedAtTheListeningEnd(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	window, secret, err := desktop.node.beginPairing(false, true)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	desktop.human.set(denyAnswer("I did not start this"), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := headless.node.PairWith(ctx, desktop.address(),
		&ladulasv1.PairingCode{Version: 1, Secret: string(secret)},
		true, false); err != nil {
		t.Fatalf("spend the code: %v", err)
	}

	waitPairingsGone(t, desktop, headless)

	if len(headless.store.Peers()) != 0 {
		t.Error("the dialling side recorded a pairing that was refused")
	}
}

// waitPairingsGone waits for every side to have nothing pending, which is what
// a pairing that ended looks like: the entry is removed on both sides, by an
// answer or by a withdrawal and never by a clock.
func waitPairingsGone(t *testing.T, sides ...*instance) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		waiting := 0

		for _, side := range sides {
			waiting += len(side.store.PendingPairings())
		}

		if waiting == 0 {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	for _, side := range sides {
		if pending := side.store.PendingPairings(); len(pending) != 0 {
			t.Errorf("%s still has %d pairings waiting",
				side.identity.Name(), len(pending))
		}
	}

	t.FailNow()
}

// TestAPairingSurvivesBothUsersTakingTheirTime: a pairing is two people reading
// two screens, and neither of them is quick. Both sides still end up agreeing,
// and the side that displayed the code is told so.
func TestAPairingSurvivesBothUsersTakingTheirTime(t *testing.T) {
	desktop := newInstance(t, "desktop")
	phone := newInstance(t, "phone")

	window, secret, err := desktop.node.beginPairing(false, true)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	desktop.human.setDelay(250 * time.Millisecond)
	phone.human.setDelay(250 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pending, err := phone.node.PairWith(ctx, desktop.address(),
		&ladulasv1.PairingCode{Version: 1, Secret: string(secret)}, true, false)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}

	if pending.GetFingerprint() != desktop.identity.Fingerprint() {
		t.Errorf("started a pairing with %s", pending.GetFingerprint())
	}

	select {
	case session := <-window.arrived:
		if session != pending.GetSessionId() {
			t.Errorf("the two sides named different sessions: %q and %q",
				session, pending.GetSessionId())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the listening side was never told a peer had arrived")
	}

	waitPaired(t, desktop, phone.identity.Fingerprint())
	waitPaired(t, phone, desktop.identity.Fingerprint())
}

// TestAPairingNobodyAnsweredIsStillThereLater is the bug the owner hit with a
// phone in one hand, and the shape of the answer to it.
//
// What happened then: the desktop's user approved, nobody answered on the
// phone, the card's deadline passed, and the pairing was gone from both ends
// with nothing to show for it. What has to happen now is that nothing happens
// at all until somebody answers — the entry is still there on both sides, the
// card can be answered whenever the phone is picked up, and answering it then
// completes the pairing.
func TestAPairingNobodyAnsweredIsStillThereLater(t *testing.T) {
	desktop := newInstance(t, "desktop")
	phone := newInstance(t, "phone")

	window, secret, err := desktop.node.beginPairing(false, true)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	// The card reaches the phone and stays there.
	phone.drop()

	quiet := newSilence(t)

	unregister := phone.engine.Register(quiet)
	defer unregister()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pending, err := phone.node.PairWith(ctx, desktop.address(),
		&ladulasv1.PairingCode{Version: 1, Secret: string(secret)}, true, false)
	if err != nil {
		t.Fatalf("spend the code: %v", err)
	}

	quiet.wait()

	// The desktop's user has answered and the phone's has not, which used to be
	// the end of it. Both sides still hold the pairing.
	waitAnswered(t, desktop, pending.GetSessionId())

	if _, ok := phone.store.PendingPairing(pending.GetSessionId()); !ok {
		t.Fatal("the phone forgot a pairing nobody had answered")
	}

	if len(desktop.store.Peers()) != 0 || len(phone.store.Peers()) != 0 {
		t.Error("a pairing only one side had answered was written down")
	}

	// The phone is picked up, and the answer is given to the pending pairing
	// rather than to a card that has long since gone.
	if _, _, _, err := phone.node.AnswerPending(
		pending.GetSessionId(), true, "yes, eventually"); err != nil {
		t.Fatalf("answer the pairing: %v", err)
	}

	waitPaired(t, phone, desktop.identity.Fingerprint())
	waitPaired(t, desktop, phone.identity.Fingerprint())
}

// waitAnswered waits for a side to have answered a pairing without it having
// completed, which is the state a pairing spends most of its life in.
func waitAnswered(t *testing.T, side *instance, session string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		pending, ok := side.store.PendingPairing(session)
		if ok && pending.GetOurAnswer() ==
			ladulasv1.PairingAnswer_PAIRING_ANSWER_ACCEPTED {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("%s never answered the pairing", side.identity.Name())
}

// TestARaisedPromptDoesNotWriteToWhatItWasGiven: a pending pairing that has
// been handed out is never written to either (§7).
//
// The prompt records which request it raised, and the entry it records it
// against is the one in the store. The message it was raised from belongs to
// somebody else — `ladulas pair` is holding the one PairWith gave it back, the
// phone renders that same message, and the reconciliation loop reads the one
// the listing handed it — and none of them takes a lock. Writing to it from the
// prompt's goroutine is a race against all three, and one the detector sees
// only when a reader happens to touch the field the prompt writes.
func TestARaisedPromptDoesNotWriteToWhatItWasGiven(t *testing.T) {
	desktop := newInstance(t, "desktop")
	phone := newInstance(t, "phone")

	window, secret, err := desktop.node.beginPairing(false, true)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	// The card reaches the phone and stays up, so the pairing stays where the
	// prompt found it.
	phone.drop()

	quiet := newSilence(t)

	unregister := phone.engine.Register(quiet)
	defer unregister()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pending, err := phone.node.PairWith(ctx, desktop.address(),
		&ladulasv1.PairingCode{Version: 1, Secret: string(secret)}, true, false)
	if err != nil {
		t.Fatalf("spend the code: %v", err)
	}

	// The card is up, which is after the prompt recorded itself.
	quiet.wait()

	stored, ok := phone.store.PendingPairing(pending.GetSessionId())
	if !ok {
		t.Fatal("the phone forgot the pairing it is showing")
	}

	if stored.GetConfirmationRequestId() == "" {
		t.Fatal("the store does not say which prompt the pairing raised")
	}

	if id := pending.GetConfirmationRequestId(); id != "" {
		t.Errorf("the prompt wrote %q into the message it was given", id)
	}
}

// TestPeerRequestsAreNotForwarded: with both instances naming each other as
// approvers, a request still stops at the first one rather than going round.
func TestPeerRequestsAreNotForwarded(t *testing.T) {
	first := newInstance(t, "first")
	second := newInstance(t, "second")

	// Pair them both ways: each may approve for the other, and each may ask.
	window, secret, err := second.node.beginPairing(true, true)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if _, err := first.node.PairWith(ctx, second.address(),
		&ladulasv1.PairingCode{Version: 1, Secret: string(secret)},
		true, true); err != nil {
		t.Fatalf("pair: %v", err)
	}

	waitPaired(t, first, second.identity.Fingerprint())
	waitPaired(t, second, first.identity.Fingerprint())

	second.node.closeWindow(window)

	// The second instance has nobody at it, so if it forwarded, it would come
	// back to the first — which would answer, and the test would pass for the
	// wrong reason. Instead it must run out of approvers.
	second.drop()

	first.human.set(approveAnswer("yes"), nil)

	// The pairing confirmations were prompts too; only what happens from here
	// is the request under test.
	before := first.human.count()

	msg := gitRequest()
	msg.Timeout = durationpb.New(5 * time.Second)

	resp, err := first.engine.Submit(ctx, msg)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("decision %v: %s", resp.GetDecision(), resp.GetReason())
	}

	// The first instance's own human answered; the second was asked and had
	// nobody, and did not pass the question back.
	if resp.GetApprover().GetLocal() != true {
		t.Errorf("answered by %v", resp.GetApprover())
	}

	if asked := first.human.count() - before; asked != 1 {
		t.Errorf("the first instance's human was asked %d times, want 1", asked)
	}
}

// requireSignedDecision checks that a log holds a decision with a verifiable
// approval artifact on it, and that a requester's log holds the approver's own
// artifact rather than only its account of events.
func requireSignedDecision(t *testing.T, path string, remote bool) {
	t.Helper()

	entries, err := approval.ReadAuditLog(path, 0)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}

	for _, entry := range entries {
		if entry.GetEvent() != ladulasv1.AuditEvent_AUDIT_EVENT_DECISION {
			continue
		}

		if entry.GetRequest().GetKind() !=
			ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN {
			continue
		}

		artifact := entry.GetSignedApproval()
		if remote {
			artifact = entry.GetRemoteApproval()
		}

		if artifact == nil {
			t.Fatalf("%s holds a decision with no %s artifact",
				path, artifactName(remote))
		}

		if _, _, err := identity.VerifyApproval(artifact); err != nil {
			t.Errorf("the artifact in %s does not verify: %v", path, err)
		}

		return
	}

	t.Fatalf("%s holds no decision about a git signature", path)
}

func artifactName(remote bool) string {
	if remote {
		return "approving peer's"
	}

	return "signed"
}

// TestAPairingSessionBelongsToOneIdentity: a session id is a name for a pending
// pairing, not a bearer token for it.
//
// This is the shape of the only thing that ends a pairing as an error rather
// than as a decision: the two ends disagreeing about who they are talking to.
// Unreachable, asleep and slow all leave the pairing exactly where it was, and
// this does not — it is refused, and the pairing it names is untouched.
func TestAPairingSessionBelongsToOneIdentity(t *testing.T) {
	desktop := newInstance(t, "desktop")
	phone := newInstance(t, "phone")
	stranger := newInstance(t, "stranger")

	window, secret, err := desktop.node.beginPairing(false, true)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	// Nobody answers on either side, so the pairing stays where it is and can
	// be interfered with.
	desktop.drop()
	phone.drop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pending, err := phone.node.PairWith(ctx, desktop.address(),
		&ladulasv1.PairingCode{Version: 1, Secret: string(secret)}, true, false)
	if err != nil {
		t.Fatalf("spend the code: %v", err)
	}

	_, err = desktop.node.settlePairingReply(
		&transport.PeerIdentity{
			PublicKey:   stranger.identity.PublicKey(),
			Fingerprint: stranger.identity.Fingerprint(),
		},
		&ladulasv1.SettlePairingRequest{
			SessionId: pending.GetSessionId(),
			Answer:    ladulasv1.PairingAnswer_PAIRING_ANSWER_ACCEPTED,
		})
	if err == nil {
		t.Fatal("a stranger settled somebody else's pairing")
	}

	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("the refusal came back as %v", connect.CodeOf(err))
	}

	held, ok := desktop.store.PendingPairing(pending.GetSessionId())
	if !ok {
		t.Fatal("the interference took the pairing away")
	}

	if held.GetTheirAnswer() !=
		ladulasv1.PairingAnswer_PAIRING_ANSWER_UNSPECIFIED {
		t.Errorf("the stranger's answer was recorded as %v", held.GetTheirAnswer())
	}

	if len(desktop.store.Peers()) != 0 {
		t.Error("the stranger got a trust record written")
	}
}

// memoryLedger is both halves of decision P for a test: the promises this
// instance made, the ones it was given, and the account it owes for them.
//
// It is one type because the real one is: keystore.Vault holds all of it, and a
// test double that split them would let the two drift out of step in a way
// production cannot.
type memoryLedger struct {
	memoryGrants

	dmu   sync.Mutex
	held  []*storepb.HeldDelegation
	owed  []*ladulasv1.GrantUse
	filed []*ladulasv1.GrantUse
}

func (m *memoryLedger) AddDelegation(
	signed *ladulasv1.SignedDelegation, d *ladulasv1.Delegation,
) error {
	m.dmu.Lock()
	defer m.dmu.Unlock()

	m.held = append(m.held, &storepb.HeldDelegation{
		Signed:     signed,
		Delegation: d,
	})

	return nil
}

func (m *memoryLedger) Delegations() ([]*storepb.HeldDelegation, error) {
	m.dmu.Lock()
	defer m.dmu.Unlock()

	return append([]*storepb.HeldDelegation(nil), m.held...), nil
}

func (m *memoryLedger) UsableDelegations() ([]*ladulasv1.Delegation, error) {
	held, err := m.Delegations()
	if err != nil {
		return nil, err
	}

	out := make([]*ladulasv1.Delegation, 0, len(held))
	for _, item := range held {
		out = append(out, item.GetDelegation())
	}

	return out, nil
}

func (m *memoryLedger) DropDelegations(ids []string) (int, error) {
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[id] = true
	}

	m.dmu.Lock()
	defer m.dmu.Unlock()

	var dropped int

	kept := m.held[:0]

	for _, item := range m.held {
		if wanted[item.GetDelegation().GetDelegationId()] {
			dropped++

			continue
		}

		kept = append(kept, item)
	}

	m.held = kept

	return dropped, nil
}

func (m *memoryLedger) DropDelegationsFrom(fingerprint string) (int, error) {
	m.dmu.Lock()
	defer m.dmu.Unlock()

	var dropped int

	kept := m.held[:0]

	for _, item := range m.held {
		if item.GetDelegation().GetApproverFingerprint() == fingerprint {
			dropped++

			continue
		}

		kept = append(kept, item)
	}

	m.held = kept

	return dropped, nil
}

func (m *memoryLedger) RecordDelegationUse(use *ladulasv1.GrantUse) error {
	m.dmu.Lock()
	defer m.dmu.Unlock()

	m.owed = append(m.owed, use)

	return nil
}

func (m *memoryLedger) UnreportedUses(fingerprint string) []*ladulasv1.GrantUse {
	m.dmu.Lock()
	defer m.dmu.Unlock()

	mine := make(map[string]bool)

	for _, item := range m.held {
		if item.GetDelegation().GetApproverFingerprint() == fingerprint {
			mine[item.GetDelegation().GetDelegationId()] = true
		}
	}

	var out []*ladulasv1.GrantUse

	for _, use := range m.owed {
		if fingerprint == "" || mine[use.GetGrantId()] {
			out = append(out, use)
		}
	}

	return out
}

func (m *memoryLedger) AcknowledgeUses(requestIDs []string) error {
	done := make(map[string]bool, len(requestIDs))
	for _, id := range requestIDs {
		done[id] = true
	}

	m.dmu.Lock()
	defer m.dmu.Unlock()

	kept := m.owed[:0]

	for _, use := range m.owed {
		if !done[use.GetRequestId()] {
			kept = append(kept, use)
		}
	}

	m.owed = kept

	return nil
}

func (m *memoryLedger) RecordGrantUses(uses []*ladulasv1.GrantUse) error {
	m.dmu.Lock()
	m.filed = append(m.filed, uses...)
	m.dmu.Unlock()

	m.recordAgainstGrants(uses)

	return nil
}

// recordAgainstGrants keeps the grant's own count and tail in step, which is
// what every surface reads.
func (m *memoryLedger) recordAgainstGrants(uses []*ladulasv1.GrantUse) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, use := range uses {
		for _, grant := range m.grants {
			if grant.GetGrantId() != use.GetGrantId() {
				continue
			}

			grant.UseCount++
			grant.RecentUses = append(grant.GetRecentUses(), use)
		}
	}
}

func (m *memoryLedger) recorded() []*ladulasv1.GrantUse {
	m.dmu.Lock()
	defer m.dmu.Unlock()

	return append([]*ladulasv1.GrantUse(nil), m.filed...)
}
