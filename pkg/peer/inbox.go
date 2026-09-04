package peer

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// The requester's half of poll-on-open (§11).
//
// A peer that may approve for this instance but advertises no address cannot be
// dialled, and the design says why: phones never listen. So instead of a link
// that pushes a request at it, there is an inbox that holds the request until it
// comes and asks. From the engine's side the two are the same thing — an
// approver in the fan-out that eventually answers or does not — which is the
// whole reason this fits in a file rather than in a second approval path.
//
// What is deliberately absent is any notion of delivery. Nothing is stored, and
// nothing outlives the request: an entry exists exactly as long as somebody is
// blocked on the answer, so a phone that opens the app an hour later finds an
// empty inbox rather than a commit nobody is making any more.

// maxFetchWait caps how long a collecting approver may hold a call open.
//
// It is a fraction of a signing timeout rather than close to it, so that a
// phone that lost its network is noticed and reconnects while the request is
// still live. The approver asks again immediately; the cost of a short cap is
// one round trip a minute.
const maxFetchWait = time.Minute

// parked is a request waiting for an approver that has to come and get it.
type parked struct {
	peer     string
	id       string
	body     []byte
	digest   []byte
	since    time.Time
	deadline time.Time
	// payload and wrapSSHSIG are set when what is waiting is a signature rather
	// than an approval (decision T): the key lives on the collector, so the
	// bytes to sign travel with the request and the signature comes back with
	// the answer.
	payload    []byte
	wrapSSHSIG bool
	// endorsement is the promise this instance holds for the key, presented to
	// whichever holder comes and collects (decision AG). It travels the parked
	// road for the same reason it travels a dialled one: a phone that has to be
	// woken is the holder most worth not waking.
	endorsement *ladulasv1.SignedEndorsement

	answer chan *collectedAnswer
	once   sync.Once
	// taken is set the moment somebody answers, and is what stops the entry
	// being offered again in the window between the answer arriving and the
	// engine unparking it. Without it a poll already on the wire when the answer
	// landed would come back with a request that has just been settled, and the
	// approver would raise a second prompt for it.
	taken atomic.Bool
}

// collectedAnswer is what an approver that came and got a request handed back.
//
// It carries the decision three times over, which is not redundancy: the answer
// is what the engine's fan-out understands, the response is what an audit entry
// records, and the artifact is the evidence that neither of the first two can be
// derived from without the approver's key.
type collectedAnswer struct {
	answer   *approval.Answer
	decision *ladulasv1.ApprovalResponse
	// signature is set when the request carried a payload: ssh.Marshal of an
	// ssh.Signature made with the key the collector holds.
	signature []byte
}

func (p *parked) settle(answer *collectedAnswer) bool {
	settled := false

	p.once.Do(func() {
		p.taken.Store(true)
		p.answer <- answer
		settled = true
	})

	return settled
}

// wantsSignature reports whether this entry is a borrowed signature rather than
// an approval.
func (p *parked) wantsSignature() bool {
	return len(p.payload) > 0
}

// InboxApprover is a paired peer that collects rather than being dialled.
//
// It is a RemoteHandler like any other peer, which is what keeps a request that
// arrived from a peer from being parked for a second one: an approver is
// somebody who has agreed to answer, not a queue to forward to.
type InboxApprover struct {
	node        *Node
	fingerprint string
	name        string
}

var _ approval.RemoteHandler = (*InboxApprover)(nil)

// ID implements approval.Handler.
func (a *InboxApprover) ID() string {
	return "peer " + a.name + " (collects)"
}

// Peer implements approval.RemoteHandler.
func (a *InboxApprover) Peer() string {
	return a.fingerprint
}

// Decide implements approval.Handler by parking the request and waiting.
//
// The context is the engine's: it ends when another approver answered first,
// when the requester gave up, or when the timeout ran out. Any of those unparks
// the request, and an approver that turns up afterwards is told there is
// nothing waiting rather than being allowed to answer a settled question.
func (a *InboxApprover) Decide(
	ctx context.Context, req *approval.Request,
) (*approval.Answer, error) {
	msg, body, err := a.node.outgoing(ctx, req)
	if err != nil {
		return nil, err
	}

	entry := &parked{
		peer:     a.fingerprint,
		id:       msg.GetRequestId(),
		body:     body,
		digest:   identity.Digest(body),
		since:    time.Now(),
		deadline: deadlineOf(ctx),
		answer:   make(chan *collectedAnswer, 1),
	}

	// While the approver is looking at this it may ask for the rest of the diff
	// the caps cut short (§5), exactly as a dialled one may. Only while, and
	// only this peer.
	defer a.node.track(entry.id, a.fingerprint,
		msg.GetSshsig().GetGitContext())()

	defer a.node.unpark(a.fingerprint, entry.id)

	a.node.park(entry)

	select {
	case answer := <-entry.answer:
		return answer.answer, nil
	case <-ctx.Done():
		return nil, ctx.Err() //nolint:wrapcheck // the engine matches on it
	}
}

func deadlineOf(ctx context.Context) time.Time {
	deadline, ok := ctx.Deadline()
	if !ok {
		return time.Time{}
	}

	return deadline
}

// parkKey is the peer as well as the request, because one request can be
// waiting on two phones at once — that is what the fan-out is — and an entry
// keyed on the request alone would leave the second inbox holding the first
// one's answer channel.
func parkKey(fingerprint, id string) string {
	return fingerprint + "\x00" + id
}

func (n *Node) park(entry *parked) {
	n.mu.Lock()
	n.parked[parkKey(entry.peer, entry.id)] = entry
	n.mu.Unlock()

	if n.wake(entry.peer) {
		// Said out loud because it is indistinguishable from a broken wake-up
		// from the outside: no push arrives, and the reason is that none was
		// needed. Somebody watching a relay log for a knock that never comes
		// should be able to find out here that the line was already open.
		n.log.Debug("a poll was open, so no wake-up was sent",
			"peer", entry.peer, "request_id", entry.id)

		return
	}

	// Nobody was holding a poll open, so nobody is looking. That is the moment a
	// wake-up exists for and the only moment it is worth anything (§11) — an
	// approver with a live poll gets the request from the line it already has
	// open, which is the "skip the wake-up" fast path.
	n.wakePeer(entry.peer, entry.id)
}

func (n *Node) unpark(fingerprint, id string) {
	n.mu.Lock()
	delete(n.parked, parkKey(fingerprint, id))
	n.mu.Unlock()
}

// wake releases everything long-polling on behalf of a peer, and says whether
// there was anything to release.
//
// The channel is closed rather than sent on, so a waiter that has not reached
// its select yet still sees it, and a new one is put in its place for the next
// request.
func (n *Node) wake(fingerprint string) bool {
	n.mu.Lock()
	waiting := n.waiters[fingerprint]
	delete(n.waiters, fingerprint)
	n.mu.Unlock()

	for released := range waiting {
		close(released)
	}

	return len(waiting) > 0
}

func (n *Node) waiter(fingerprint string) chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.waiters[fingerprint] == nil {
		n.waiters[fingerprint] = map[chan struct{}]bool{}
	}

	created := make(chan struct{})
	n.waiters[fingerprint][created] = true

	return created
}

// abandon forgets a waiter whose poll has gone, which is the difference between
// a peer that is listening and one that was.
//
// Without it a poll that ended on its own — its timer, or the connection dying
// under a phone somebody force-quit — left its channel in the map, and the next
// request found it, closed it, counted it as somebody listening and sent no
// wake-up. The push was suppressed in favour of a line that was not there.
//
// It removes only its own channel. A later poll may have arrived in the
// meantime and that one belongs to somebody.
func (n *Node) abandon(fingerprint string, waiting chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()

	waiters := n.waiters[fingerprint]
	if waiters == nil {
		return
	}

	delete(waiters, waiting)

	if len(waiters) == 0 {
		delete(n.waiters, fingerprint)
	}
}

// pendingFor is what a peer would be handed right now, oldest first.
func (n *Node) pendingFor(fingerprint string) []*parked {
	n.mu.Lock()
	defer n.mu.Unlock()

	var out []*parked

	for _, entry := range n.parked {
		if entry.peer == fingerprint {
			out = append(out, entry)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].since.Before(out[j].since)
	})

	return out
}

func (n *Node) parkedFor(id, fingerprint string) *parked {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.parked[parkKey(fingerprint, id)]
}

// FetchPending hands a collecting approver what this instance is waiting on it
// for.
func (s *peerService) FetchPending(
	ctx context.Context,
	req *connect.Request[ladulasv1.FetchPendingRequest],
) (*connect.Response[ladulasv1.FetchPendingResponse], error) {
	// The direction checked here is the one that matters: the caller is a peer
	// this instance agreed may approve for it. Whether it may also ask this
	// instance for approvals is a separate half of the pairing and irrelevant
	// to being handed something to decide.
	peer, _, err := s.node.publisherFor(ctx)
	if err != nil {
		return nil, err
	}

	waiting := s.node.collect(ctx, peer.Fingerprint, req.Msg.GetWait().AsDuration())

	return connect.NewResponse(&ladulasv1.FetchPendingResponse{
		Pending: waiting,
		// An approver that cannot be dialled has no other way to find out that
		// it is owed an account (decision P). Saying so on the poll it was
		// already making is what turns reconciliation from something done on
		// every round regardless into something done when there is a reason.
		GrantActivityWaiting: s.node.HasGrantActivityFor(peer.Fingerprint),
		// A collector has no link to hear this on, and the poll is the one
		// call it reliably makes (decision AQ).
		ListenAddresses: s.node.Advertised(),
	}), nil
}

// collect answers at once when there is something, and otherwise holds the call
// open for as long as the caller asked and the cap allows.
func (n *Node) collect(
	ctx context.Context, fingerprint string, wait time.Duration,
) []*ladulasv1.PendingApproval {
	// A call held open is the nearest thing a collector has to a link, and every
	// surface that says whether a peer is there reads it (see Node.holding).
	done := n.holding(fingerprint)
	defer done()

	if pending := n.pendingApprovals(fingerprint); len(pending) > 0 {
		return pending
	}

	if wait <= 0 {
		return nil
	}

	if wait > maxFetchWait {
		wait = maxFetchWait
	}

	// The waiter is taken before the second look, so a request parked in between
	// releases it rather than being missed until the next poll. It is given back
	// however this call ends: a waiter nobody is on is a peer that looks awake.
	woken := n.waiter(fingerprint)
	defer n.abandon(fingerprint, woken)

	if pending := n.pendingApprovals(fingerprint); len(pending) > 0 {
		return pending
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-woken:
	case <-timer.C:
	case <-ctx.Done():
	}

	return n.pendingApprovals(fingerprint)
}

func (n *Node) pendingApprovals(fingerprint string) []*ladulasv1.PendingApproval {
	now := time.Now()

	var out []*ladulasv1.PendingApproval

	for _, entry := range n.pendingFor(fingerprint) {
		if entry.taken.Load() {
			continue
		}

		pending := &ladulasv1.PendingApproval{
			RequestId:    entry.id,
			Request:      entry.body,
			WaitingSince: timestamppb.New(entry.since),
			Payload:      entry.payload,
			WrapSshsig:   entry.wrapSSHSIG,
			Endorsement:  entry.endorsement,
		}

		if !entry.deadline.IsZero() {
			remaining := entry.deadline.Sub(now)
			if remaining <= 0 {
				// About to be unparked by its own context; offering it would
				// only produce a prompt that expires as it is read.
				continue
			}

			pending.ExpiresIn = durationpb.New(remaining)
		}

		out = append(out, pending)
	}

	return out
}

// AnswerPending settles a request an approver collected.
func (s *peerService) AnswerPending(
	ctx context.Context,
	req *connect.Request[ladulasv1.AnswerPendingRequest],
) (*connect.Response[ladulasv1.AnswerPendingResponse], error) {
	peer, record, err := s.node.publisherFor(ctx)
	if err != nil {
		return nil, err
	}

	entry := s.node.parkedFor(req.Msg.GetRequestId(), peer.Fingerprint)
	if entry == nil {
		// Not an error. The request was settled by somebody else, or the
		// requester stopped waiting, and an approver that lost that race should
		// take the prompt off its screen rather than see a failure.
		return connect.NewResponse(&ladulasv1.AnswerPendingResponse{}), nil
	}

	key, err := trust.PublicKey(record)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	answer, decision, err := answerFromPeer(
		record, key, req.Msg.GetApproval(), entry.id, entry.digest)
	if err != nil {
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	}

	// A signature that was asked for and not given is not an answer this instance
	// can act on, and taking the entry off the parked set for it would leave the
	// requester waiting out its whole timeout for an approver that has already
	// spoken. Refused here so the approver hears about it and can try again.
	signature := req.Msg.GetSignature()

	if entry.wantsSignature() && len(signature) == 0 &&
		answer.Decision == ladulasv1.Decision_DECISION_APPROVE {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("this request asked for a signature, and the approval carries none"))
	}

	// A grant the approver keeps is the approver's own and stays there (§18);
	// nothing an answer carries may create one here. A delegation is the other
	// case, and is the one thing an answer may leave behind: it is signed, it
	// names this instance, and it is a promise this instance was given rather
	// than one it made (decision P).
	answer.GrantTTL = 0

	s.node.acceptDelegation(record, key, decision)

	accepted := entry.settle(&collectedAnswer{
		answer:    answer,
		decision:  decision,
		signature: signature,
	})

	if accepted {
		s.node.log.Info("a collecting approver answered",
			"request_id", entry.id, "peer", record.GetName(),
			"decision", decision.GetDecision().String())
	}

	return connect.NewResponse(&ladulasv1.AnswerPendingResponse{
		Accepted: accepted,
	}), nil
}

// inboxFor builds the approver for a peer that has no address to dial.
func (n *Node) inboxFor(record *storepb.TrustRecord) *InboxApprover {
	return &InboxApprover{
		node:        n,
		fingerprint: record.GetFingerprint(),
		name:        record.GetName(),
	}
}
