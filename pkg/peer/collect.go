package peer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// The approver's half of poll-on-open (§11).
//
// This is what the phone does when the app opens: dial every instance it has
// agreed to approve for, ask what is waiting, and decide it here. The decision
// itself is the engine's ordinary peer path — the same hard rules, the same
// policy, the same check that the commit shown is the commit being signed, and
// the same human — so what is new is only how the request arrived.
//
// Poll-on-open is the baseline that never goes away (§11): losing every wake-up
// channel degrades to this, and it needs no infrastructure at all. A wake-up
// push, when the wake-up milestone builds one, is an optimization that makes the
// app open sooner.

// DefaultCollectWait is how long a foreground poll holds each call open. It
// makes an open app a real-time approver, which is what "live connection" means
// on a platform that will not let one listen.
const DefaultCollectWait = 30 * time.Second

// Collect runs one round of poll-on-open against every requester.
//
// It returns when it has asked everybody, not when the requests it found have
// been decided: a prompt is a person, and the poll that put it on screen has no
// business waiting for them. Deciding continues on its own, and the answers are
// posted back as they arrive.
func (n *Node) Collect(ctx context.Context, wait time.Duration) error {
	_, err := n.collectRound(ctx, wait)

	return err
}

// collectRound is Collect, and also says whether any requester offered a
// request this instance already has in hand. A round that was told about
// nothing but those has nothing left to do, and coming straight back with
// another poll would only ask the same question again (see Poll).
func (n *Node) collectRound(
	ctx context.Context, wait time.Duration,
) (bool, error) {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		first    error
		withheld bool
	)

	// Off the critical path, because the poll below is what somebody opening the
	// app is waiting for and this is bookkeeping. It is here rather than on a
	// timer of its own because the poll loop is the one thing a phone reliably
	// does, and it starts at exactly the moments a route changes (see wakeup.go)
	// or somebody lends a machine a key (see announcekeys.go).
	go n.AnnounceWakeups(ctx)
	go n.AnnounceKeys(ctx)

	for _, record := range n.requesters() {
		wg.Add(1)

		go func() {
			defer wg.Done()

			// Before the long poll, because collecting a key is a short call
			// and the poll below holds the connection open for half a minute.
			// A key waiting at a peer is what the wake-up that opened the app
			// was about as often as an approval is (decision S).
			n.collectKeys(ctx, record)

			held, err := n.collectFrom(ctx, record, wait)

			mu.Lock()
			withheld = withheld || held
			mu.Unlock()

			if err == nil || ctx.Err() != nil {
				return
			}

			n.log.Debug("could not collect from a requester",
				"peer", record.GetName(), "error", err.Error())

			mu.Lock()

			if first == nil {
				first = err
			}

			mu.Unlock()
		}()
	}

	wg.Wait()

	return withheld, first
}

// reconcileOne runs the delegation round trip against one requester, on its own
// budget. It is not what the caller was waiting for, and a requester that
// cannot be reached for it is a requester still honouring what it holds.
func (n *Node) reconcileOne(ctx context.Context, record *storepb.TrustRecord) {
	if n.delegations == nil || ctx.Err() != nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	if err := n.reconcileWith(ctx, record); err != nil {
		n.log.Debug("could not reconcile delegated grants",
			"peer", record.GetName(), "error", err.Error())
	}
}

// requesters is every peer this instance has agreed to approve for and can
// reach. A peer with no address is one neither side can dial, which is two
// phones paired to each other and nothing this milestone has to solve.
func (n *Node) requesters() []*storepb.TrustRecord {
	var out []*storepb.TrustRecord

	for _, record := range n.trust.Peers() {
		if record.GetMayRequest() && len(record.GetAddresses()) > 0 {
			out = append(out, record)
		}
	}

	return out
}

// Poll keeps collecting until the context is done.
//
// It is what the app runs while it is in the foreground. Each round long-polls,
// so the loop is idle rather than busy, and a round that failed backs off the
// same way a link does — a phone that walked out of range should be approving
// again within a minute of walking back in.
//
// A requester with something parked answers a poll at once, so while somebody
// is reading a card the long poll is not one: the round that comes back with
// the request already on screen waits a beat instead, which is the difference
// between one call a second and as many as the link will carry.
func (n *Node) Poll(ctx context.Context, wait time.Duration) {
	delay := n.floor

	for {
		withheld, err := n.collectRound(ctx, wait)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(jitter(delay)):
			}

			delay *= 2
			if delay > n.ceiling {
				delay = n.ceiling
			}

			continue
		}

		delay = n.floor

		if ctx.Err() != nil {
			return
		}

		if !withheld {
			continue
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(busyPollPause):
		}
	}
}

// busyPollPause is how long the foreground loop waits before asking a requester
// that has nothing for it but the request it is already dealing with.
const busyPollPause = time.Second

// given is what this instance answered a collected request with: the signed
// decision, and the signature beside it when the request was for a key this
// instance holds and the requester does not (decision T).
//
// The two travel together for the same reason they are delivered together: a
// redelivery has to be able to repeat the whole answer, and an approval that
// arrived without the signature it promised is no use to the requester.
type given struct {
	approval  *ladulasv1.SignedApproval
	signature []byte
}

// handledRequest is what this instance has already done about a request it took
// out of an inbox.
type handledRequest struct {
	// answer is nil while somebody is still looking at the request, and is the
	// decision once there is one.
	answer *given
	// delivered says the requester has heard it, and delivering that somebody
	// is telling it right now — so that a run of polls produces one attempt
	// rather than one per poll.
	delivered  bool
	delivering bool
	// until is when the requester said it would stop waiting, and therefore
	// when this stops being an answer to anything.
	until time.Time
}

// claim asks for the right to decide a collected request, and is the whole of
// what makes delivery idempotent.
//
// The entry it leaves behind outlives the deciding, which is the point. A poll
// is answered from the requester's parked set before the approver's answer has
// reached it, and under a relayed link — a phone on 4G, which is the connection
// this is for (§11) — that response can arrive after the answer has been
// delivered and the request unparked. An approver that forgot a request the
// moment it answered would take that response for a new one and put the same
// commit in front of its owner a second time.
func (n *Node) claim(id string, until time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.forgetStale()

	if _, known := n.handled[id]; known {
		return false
	}

	n.handled[id] = &handledRequest{until: until}

	return true
}

// forgetStale drops what no requester can still be waiting for. Callers hold
// the lock.
func (n *Node) forgetStale() {
	now := time.Now()

	for id, entry := range n.handled {
		if entry.until.After(now) {
			continue
		}

		delete(n.handled, id)
	}
}

// forget takes a request back out, so that a later poll may offer it again. It
// is for the case where nobody was asked anything: a request that could not be
// put to the engine at all has not been decided, and the record of a decision
// would be a lie.
func (n *Node) forget(id string) {
	n.mu.Lock()
	delete(n.handled, id)
	n.mu.Unlock()
}

// answerGiven records the decision, which from here on is the only one this
// request will get from this instance.
func (n *Node) answerGiven(id string, answer *given) {
	n.mu.Lock()
	defer n.mu.Unlock()

	entry, known := n.handled[id]
	if !known {
		return
	}

	entry.answer = answer
}

// answerDelivered records that the requester has it.
func (n *Node) answerDelivered(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	entry, known := n.handled[id]
	if !known {
		return
	}

	entry.delivered = true
	entry.delivering = false
}

// answerToRedeliver is the decision a requester is still asking about because
// it never heard it, and claims the job of telling it. A caller that gets an
// answer owes a redeliveryDone.
func (n *Node) answerToRedeliver(id string) *given {
	n.mu.Lock()
	defer n.mu.Unlock()

	entry, known := n.handled[id]
	if !known || entry.answer == nil || entry.delivered || entry.delivering {
		return nil
	}

	entry.delivering = true

	return entry.answer
}

func (n *Node) redeliveryDone(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	entry, known := n.handled[id]
	if !known {
		return
	}

	entry.delivering = false
}

// collectFrom asks one requester what it is waiting for, and says whether it
// offered anything this instance already has in hand.
func (n *Node) collectFrom(
	ctx context.Context, record *storepb.TrustRecord, wait time.Duration,
) (bool, error) {
	var pending []*ladulasv1.PendingApproval

	var owed bool

	err := n.call(ctx, record, func(
		ctx context.Context, client *http.Client, baseURL string,
	) error {
		inbox := ladulasv1connect.NewInboxServiceClient(client, baseURL,
			connect.WithReadMaxBytes(maxRequestBytes))

		resp, err := inbox.FetchPending(ctx, connect.NewRequest(
			&ladulasv1.FetchPendingRequest{Wait: durationpb.New(wait)}))
		if err != nil {
			return err //nolint:wrapcheck // call wraps it with the address
		}

		pending = resp.Msg.GetPending()
		owed = resp.Msg.GetGrantActivityWaiting()

		return nil
	})
	if err != nil {
		return false, err
	}

	// The requester says it has done things under a delegation that this
	// instance has not been told about, so go and get them. It is bookkeeping
	// and gets its own budget: a card somebody is waiting on has already been
	// handled above.
	if owed {
		n.reconcileOne(ctx, record)
	}

	return n.handleCollected(record, pending), nil
}

// handleCollected is what a poll's answer asks for: decide what is new, deliver
// again what has been decided and not heard, and say whether there was any of
// the second kind.
func (n *Node) handleCollected(
	record *storepb.TrustRecord, pending []*ladulasv1.PendingApproval,
) bool {
	var withheld bool

	for _, item := range pending {
		id := item.GetRequestId()

		if n.claim(id, time.Now().Add(collectedTimeout(item))) {
			go n.decideCollected(record, item)

			continue
		}

		withheld = true

		// Already this instance's request. Either somebody is looking at it, or
		// it has been answered and the requester is asking again because the
		// answer never arrived — which is a delivery to retry, not a question to
		// ask twice.
		answer := n.answerToRedeliver(id)
		if answer == nil {
			continue
		}

		go n.redeliver(record, id, answer)
	}

	return withheld
}

// decideCollected puts a collected request through this instance's engine and
// posts the answer back.
//
// It runs detached from the poll that found it, under a lifetime of its own:
// the app may well be backgrounded while the prompt is up, and the answer is
// still worth delivering when it comes back.
func (n *Node) decideCollected(
	record *storepb.TrustRecord, item *ladulasv1.PendingApproval,
) {
	ctx, cancel := context.WithTimeout(n.lifetime(), collectedTimeout(item))
	defer cancel()

	answer, err := n.decideFor(ctx, record, item)
	if err != nil {
		// Nobody was asked anything, so nothing is remembered: whatever went
		// wrong here may well not go wrong at the next poll.
		n.forget(item.GetRequestId())

		n.log.Error("could not decide a collected request",
			"request_id", item.GetRequestId(),
			"peer", record.GetName(), "error", err.Error())

		return
	}

	n.answerGiven(item.GetRequestId(), answer)

	err = n.answerCollected(ctx, record, item.GetRequestId(), answer)
	if err != nil {
		// The decision stands and is kept. The request is still parked at the
		// requester, which will offer it again at the next poll, and what it is
		// owed then is the answer that has already been given rather than a
		// second question for the person who gave it.
		n.log.Error("could not deliver a decision to a requester",
			"request_id", item.GetRequestId(),
			"peer", record.GetName(), "error", err.Error())

		return
	}

	n.answerDelivered(item.GetRequestId())
}

// redeliver takes a decision back to a requester that is still asking about the
// request it answered.
func (n *Node) redeliver(
	record *storepb.TrustRecord, requestID string,
	answer *given,
) {
	defer n.redeliveryDone(requestID)

	err := n.answerCollected(n.lifetime(), record, requestID, answer)
	if err != nil {
		n.log.Error("could not deliver a decision to a requester again",
			"request_id", requestID,
			"peer", record.GetName(), "error", err.Error())

		return
	}

	n.answerDelivered(requestID)
}

// lifetime is what a decision runs under: the node's own context, since the app
// may well be backgrounded while the prompt is up and the poll that found the
// request is long gone.
func (n *Node) lifetime() context.Context {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.ctx == nil {
		return context.Background()
	}

	return n.ctx
}

// collectedTimeout is what the requester said it would wait, bounded so that a
// requester claiming a day cannot leave a prompt on a phone for one.
func collectedTimeout(item *ladulasv1.PendingApproval) time.Duration {
	remaining := item.GetExpiresIn().AsDuration()
	if remaining <= 0 || remaining > maxCollectedTimeout {
		return maxCollectedTimeout
	}

	return remaining
}

// maxCollectedTimeout is the longest a collected request stays on screen. It
// tracks the signing budget in §9: a cap below it takes the prompt off the
// phone while the requester is still waiting, which is the case the budget
// exists for — somebody away from the desk, answering on the phone they had
// with them. It was fifteen minutes against a five-minute budget, so it never
// bit; against an hour it would have been the shorter of the two.
const maxCollectedTimeout = time.Hour

// decideFor is the engine's peer path, with the requester's account of itself
// replaced by what the channel proved — the same substitution RequestApproval
// makes, for the same reason.
func (n *Node) decideFor(
	ctx context.Context, record *storepb.TrustRecord,
	item *ladulasv1.PendingApproval,
) (*given, error) {
	body := item.GetRequest()
	if len(body) == 0 {
		return nil, errors.New("peer: the collected request is empty")
	}

	var msg ladulasv1.ApprovalRequest

	if err := proto.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("peer: the collected request does not parse: %w", err)
	}

	if msg.GetRequestId() != item.GetRequestId() {
		return nil, errors.New(
			"peer: the collected request is not the one it was listed as")
	}

	// Pairing is settled by the pairing service and never by something picked up
	// out of an inbox; a requester that could raise a pairing prompt this way
	// could ask to be granted anything.
	if msg.GetKind() == ladulasv1.RequestKind_REQUEST_KIND_PAIRING {
		return nil, errors.New("peer: pairing changes are not requested this way")
	}

	requester := &ladulasv1.RequesterInfo{
		InstanceId: record.GetFingerprint(),
		Name:       record.GetName(),
		Local:      false,
		Headless:   msg.GetRequester().GetHeadless(),
		// The process behind the request is the requesting machine's word for
		// it, and it is the requesting machine we distrust (§5, §16).
		Process: msg.GetRequester().GetProcess(),
	}

	// A request that arrived with the bytes to sign is a key of this instance's
	// being borrowed by a requester that cannot hold it (decision T). It goes
	// through the same reconstruction and the same permission check a dialled
	// RemoteSign would have gone through — this is the same function — and the
	// only difference is which side dialled.
	if len(item.GetPayload()) > 0 {
		// The same statement a dialled requester presents, checked by the same
		// code before anything is decided (decision AG).
		n.acceptPresented(record.GetFingerprint(), item.GetEndorsement())

		signed, signature, err := n.signForPeer(ctx, record, requester, &msg,
			body, item.GetPayload(), item.GetWrapSshsig())
		if err != nil {
			return nil, fmt.Errorf("peer: sign a collected request: %w", err)
		}

		return &given{approval: signed, signature: signature}, nil
	}

	msg.Requester = requester

	_, signed, err := n.engine.SubmitPeer(ctx, &msg, body)
	if err != nil {
		return nil, fmt.Errorf("peer: decide a collected request: %w", err)
	}

	return &given{approval: signed}, nil
}

func (n *Node) answerCollected(
	ctx context.Context, record *storepb.TrustRecord,
	requestID string, answer *given,
) error {
	// The answer is worth a moment of its own: the decision has been made and
	// logged, and a context that expired while somebody was reading should not
	// stop it being delivered.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), answerTimeout)
	defer cancel()

	return n.call(ctx, record, func(
		ctx context.Context, client *http.Client, baseURL string,
	) error {
		inbox := ladulasv1connect.NewInboxServiceClient(client, baseURL,
			connect.WithSendMaxBytes(maxRequestBytes))

		_, err := inbox.AnswerPending(ctx, connect.NewRequest(
			&ladulasv1.AnswerPendingRequest{
				RequestId: requestID,
				Approval:  answer.approval,
				Signature: answer.signature,
			}))
		if err != nil {
			return err //nolint:wrapcheck // call wraps it with the address
		}

		return nil
	})
}

// answerTimeout bounds delivering a decision that has already been made.
const answerTimeout = 20 * time.Second
