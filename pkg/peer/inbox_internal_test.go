package peer

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// A phone: an instance that never listens, and therefore has no address to put
// in the trust record the requester keeps.
func newPhone(t *testing.T, name string) *instance {
	t.Helper()

	return newInstanceOn(t, name, transport.ListenNone)
}

// scanQR is how a phone pairs: the desktop displays the code and the phone
// dials it, which is the only direction available when one side cannot listen.
//
// It is also the stronger of the two pairings (§7). The QR carries the
// desktop's identity key, so the phone pins before it connects and the visual
// channel is the integrity root; both users still confirm on their own screens.
func scanQR(t *testing.T, requester, phone *instance) *storepb.TrustRecord {
	t.Helper()

	// What the desktop grants: the phone approves for it, and does not ask it.
	window, secret, err := requester.node.beginPairing(true, false)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer requester.node.closeWindow(window)

	code := trust.NewCode(secret, requester.identity.Name(),
		requester.identity.PublicKey(), requester.node.Addresses(),
		time.Now().Add(trust.CodeValidity))

	encoded, err := trust.EncodeCode(code)
	if err != nil {
		t.Fatalf("encode the pairing code: %v", err)
	}

	// The string above is exactly what the QR carries and what the camera hands
	// back, so the phone decodes rather than being given the message.
	scanned, err := trust.DecodeCode(encoded)
	if err != nil {
		t.Fatalf("decode the pairing code: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := phone.node.PairWith(ctx, "", scanned, false, true); err != nil {
		t.Fatalf("pair: %v", err)
	}

	// The phone is the side that cannot be dialled, so it is the side that
	// drives the pairing to its end — which is what the loop in pending.go
	// exists for, and what makes this the only order that works.
	waitPaired(t, requester, phone.identity.Fingerprint())

	return waitPaired(t, phone, requester.identity.Fingerprint())
}

// The milestone in one test: a headless box asks for a signature, the approver
// is a phone that cannot be dialled, and the phone opens the app and answers.
func TestAPhoneCollectsAndApproves(t *testing.T) {
	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	scanQR(t, requester, phone)

	// Pairing itself prompted on both sides, so what follows counts from there.
	paired := phone.human.count()

	// The requester has no address for the phone, so it cannot dial it — which
	// is exactly the situation the inbox exists for.
	record, ok := requester.store.Peer(phone.identity.Fingerprint())
	if !ok {
		t.Fatal("the requester kept no record of the phone")
	}

	if len(record.GetAddresses()) != 0 {
		t.Fatalf("the phone advertised %v", record.GetAddresses())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Nobody at the requester, so the only approver is the one that collects.
	requester.drop()

	phone.human.set(approveAnswer("approved on the phone"), nil)

	decided := make(chan *ladulasv1.ApprovalResponse, 1)

	go func() {
		resp, err := requester.engine.Submit(ctx, gitRequest())
		if err != nil {
			t.Errorf("submit: %v", err)
		}

		decided <- resp
	}()

	// The app opens: one round of poll-on-open, long enough to catch a request
	// that has not been parked yet.
	if err := phone.node.Collect(ctx, 5*time.Second); err != nil {
		t.Fatalf("collect: %v", err)
	}

	select {
	case resp := <-decided:
		if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
			t.Fatalf("the request was %s: %s",
				resp.GetDecision(), resp.GetReason())
		}

		if resp.GetApprover().GetName() != "phone" {
			t.Errorf("it was approved by %q", resp.GetApprover().GetName())
		}

		if resp.GetApprover().GetLocal() {
			t.Error("the phone was recorded as a local approver")
		}
	case <-ctx.Done():
		t.Fatal("the request was never decided")
	}

	if phone.human.count() != paired+1 {
		t.Errorf("the phone was shown %d requests after pairing",
			phone.human.count()-paired)
	}

	// And what it was shown says who is asking, with the name this instance's
	// user gave it rather than the one the machine gave itself.
	shown := phone.human.last()
	if shown.Msg.GetRequester().GetName() != "builder" {
		t.Errorf("the prompt said the requester was %q",
			shown.Msg.GetRequester().GetName())
	}

	if shown.Origin != approval.OriginPeer {
		t.Errorf("the collected request had origin %v", shown.Origin)
	}
}

// A denial is an answer, and travels the same road.
func TestAPhoneCanDeny(t *testing.T) {
	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	scanQR(t, requester, phone)
	requester.drop()

	phone.human.set(denyAnswer("not that one"), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	decided := make(chan *ladulasv1.ApprovalResponse, 1)

	go func() {
		resp, err := requester.engine.Submit(ctx, gitRequest())
		if err != nil {
			t.Errorf("submit: %v", err)
		}

		decided <- resp
	}()

	if err := phone.node.Collect(ctx, 5*time.Second); err != nil {
		t.Fatalf("collect: %v", err)
	}

	select {
	case resp := <-decided:
		if resp.GetDecision() != ladulasv1.Decision_DECISION_DENY {
			t.Fatalf("the request was %s", resp.GetDecision())
		}
	case <-ctx.Done():
		t.Fatal("the request was never decided")
	}
}

// An inbox holds nothing: a phone that opens the app after the requester gave
// up finds it empty, rather than a commit nobody is making any more.
func TestAnInboxOutlivesNothing(t *testing.T) {
	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	scanQR(t, requester, phone)

	paired := phone.human.count()

	requester.drop()

	// Nobody answers, and the request times out on its own.
	phone.drop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	msg := gitRequest()
	msg.Timeout = nil

	short, cancelShort := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancelShort()

	if _, err := requester.engine.Submit(short, msg); err != nil {
		t.Fatalf("submit: %v", err)
	}

	pending := requester.node.pendingApprovals(phone.identity.Fingerprint())
	if len(pending) != 0 {
		t.Fatalf("the requester is still holding %d requests", len(pending))
	}

	if err := phone.node.Collect(ctx, 0); err != nil {
		t.Fatalf("collect: %v", err)
	}

	if phone.human.count() != paired {
		t.Errorf("the phone was shown %d expired requests",
			phone.human.count()-paired)
	}
}

// The long poll is what makes an open app as immediate as a desktop that was
// dialled: the call is already waiting when the request arrives.
func TestALongPollIsReleasedByANewRequest(t *testing.T) {
	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	scanQR(t, requester, phone)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fingerprint := phone.identity.Fingerprint()

	collected := make(chan []*ladulasv1.PendingApproval, 1)

	go func() {
		collected <- requester.node.collect(ctx, fingerprint, 5*time.Second)
	}()

	// Give the poll time to be waiting rather than merely started.
	time.Sleep(50 * time.Millisecond)

	requester.node.park(&parked{
		peer:   fingerprint,
		id:     "req-parked",
		body:   []byte("body"),
		since:  time.Now(),
		answer: make(chan *collectedAnswer, 1),
	})

	select {
	case pending := <-collected:
		if len(pending) != 1 || pending[0].GetRequestId() != "req-parked" {
			t.Fatalf("the poll returned %v", pending)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the long poll was not released by the new request")
	}
}

// Two phones paired to the same box are two approvers in one fan-out, and the
// first to answer settles it (§9). The second is not a second question.
func TestTwoPhonesRaceForTheSameRequest(t *testing.T) {
	first := newPhone(t, "phone one")
	second := newPhone(t, "phone two")
	requester := newInstance(t, "builder")

	scanQR(t, requester, first)
	scanQR(t, requester, second)

	requester.drop()

	// Both are asked; the second one's owner is slower to look at their phone.
	first.human.set(approveAnswer("approved on the first phone"), nil)
	second.human.set(approveAnswer("approved on the second phone"), nil)

	second.human.mu.Lock()
	second.human.delay = 5 * time.Second
	second.human.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	decided := make(chan *ladulasv1.ApprovalResponse, 1)

	go func() {
		resp, err := requester.engine.Submit(ctx, gitRequest())
		if err != nil {
			t.Errorf("submit: %v", err)
		}

		decided <- resp
	}()

	// Both collect; both are offered the request.
	go func() {
		if err := second.node.Collect(ctx, 5*time.Second); err != nil {
			t.Errorf("collect on the second phone: %v", err)
		}
	}()

	if err := first.node.Collect(ctx, 5*time.Second); err != nil {
		t.Fatalf("collect on the first phone: %v", err)
	}

	select {
	case resp := <-decided:
		if resp.GetApprover().GetName() != "phone one" {
			t.Fatalf("it was answered by %q: %s",
				resp.GetApprover().GetName(), resp.GetReason())
		}
	case <-ctx.Done():
		t.Fatal("the request was never decided")
	}

	// And the loser's prompt was taken off its screen rather than left there.
	//
	// What takes it away is the request's own budget running out on the second
	// phone, so the wait here has to be longer than that budget rather than
	// equal to it — the two clocks start at slightly different moments and the
	// test is not about which of them is quicker.
	deadline := time.Now().Add(15 * time.Second)

	for !second.human.cancelled() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if !second.human.cancelled() {
		t.Error("the second phone was left holding a prompt for a settled request")
	}
}

// waitForParked blocks until the requester is waiting on a peer, and returns
// what it would hand it — the same list a FetchPending response carries.
func waitForParked(
	t *testing.T, requester *instance, fingerprint string,
) []*ladulasv1.PendingApproval {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		if pending := requester.node.pendingApprovals(fingerprint); len(pending) > 0 {
			return pending
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("%s never parked anything for %s",
		requester.identity.Name(), fingerprint)

	return nil
}

// waitForUndelivered blocks until the phone has an answer the requester has not
// heard, which is the state a dropped link leaves behind.
func waitForUndelivered(t *testing.T, phone *instance, id string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		phone.node.mu.Lock()
		entry, known := phone.node.handled[id]
		waiting := known && entry.answer != nil && !entry.delivered
		phone.node.mu.Unlock()

		if waiting {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("%s never ended up holding an undelivered answer to %s",
		phone.identity.Name(), id)
}

// unreachable is the same peer with nothing listening where it said it would
// be, which is what a phone that walked into a lift sees.
func unreachable(t *testing.T, record *storepb.TrustRecord) *storepb.TrustRecord {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("take an address: %v", err)
	}

	address := listener.Addr().String()

	if err := listener.Close(); err != nil {
		t.Fatalf("give the address back: %v", err)
	}

	gone := proto.CloneOf(record)
	gone.Addresses = []string{address}

	return gone
}

// longGitRequest is a signing request with room in it for a test to do
// something while it waits, rather than for it to expire while one does.
func longGitRequest() *ladulasv1.ApprovalRequest {
	msg := gitRequest()
	msg.Timeout = durationpb.New(30 * time.Second)

	return msg
}

// A poll is answered out of what the requester has parked, and the answer
// travels back the other way; the two cross. A response computed before the
// phone answered arrives after it has, carrying a request that has just been
// settled — and on a phone on 4G, over a relay, that gap is a round trip rather
// than nothing (§11).
//
// The phone must take that for what it is. Asking somebody to approve the same
// commit a second time is the symptom, and one answer per request id is the
// rule that removes it.
func TestARequestAlreadyAnsweredIsNotShownAgain(t *testing.T) {
	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	scanQR(t, requester, phone)
	requester.drop()

	paired := phone.human.count()

	phone.human.set(approveAnswer("approved on the phone"), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	decided := make(chan *ladulasv1.ApprovalResponse, 1)

	go func() {
		resp, err := requester.engine.Submit(ctx, longGitRequest())
		if err != nil {
			t.Errorf("submit: %v", err)
		}

		decided <- resp
	}()

	// What the poll that is already on the wire will come back with.
	stale := waitForParked(t, requester, phone.identity.Fingerprint())

	record, ok := phone.store.Peer(requester.identity.Fingerprint())
	if !ok {
		t.Fatal("the phone kept no record of the requester")
	}

	if err := phone.node.Collect(ctx, 5*time.Second); err != nil {
		t.Fatalf("collect: %v", err)
	}

	select {
	case resp := <-decided:
		if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
			t.Fatalf("the request was %s: %s",
				resp.GetDecision(), resp.GetReason())
		}
	case <-ctx.Done():
		t.Fatal("the request was never decided")
	}

	// And now the polls that were on the wire while all of that happened land,
	// one after another, each of them carrying a request that has just been
	// settled. Not one of them is a second question.
	deadline := time.Now().Add(2 * time.Second)

	for time.Now().Before(deadline) && phone.human.count() == paired+1 {
		phone.node.handleCollected(record, stale)

		time.Sleep(20 * time.Millisecond)
	}

	if shown := phone.human.count(); shown != paired+1 {
		t.Errorf("the phone was shown the same request %d times", shown-paired)
	}
}

// An answer that never reached the requester is delivered again rather than
// asked again. The person decided; a link that dropped between the question and
// the answer is not a reason to put the same commit back on their screen.
func TestAnUndeliveredAnswerIsSentAgainRatherThanAskedAgain(t *testing.T) {
	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	scanQR(t, requester, phone)
	requester.drop()

	paired := phone.human.count()

	phone.human.set(approveAnswer("approved on the phone"), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	decided := make(chan *ladulasv1.ApprovalResponse, 1)

	go func() {
		resp, err := requester.engine.Submit(ctx, longGitRequest())
		if err != nil {
			t.Errorf("submit: %v", err)
		}

		decided <- resp
	}()

	pending := waitForParked(t, requester, phone.identity.Fingerprint())

	record, ok := phone.store.Peer(requester.identity.Fingerprint())
	if !ok {
		t.Fatal("the phone kept no record of the requester")
	}

	// The poll was answered while the requester was there, and the answer is
	// ready when it is not.
	phone.node.handleCollected(unreachable(t, record), pending)

	waitForUndelivered(t, phone, pending[0].GetRequestId())

	// The requester never heard, so its next poll offers the same request.
	phone.node.handleCollected(record, pending)

	select {
	case resp := <-decided:
		if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
			t.Fatalf("the request was %s: %s",
				resp.GetDecision(), resp.GetReason())
		}
	case <-ctx.Done():
		t.Fatal("the answer was never delivered")
	}

	if shown := phone.human.count(); shown != paired+1 {
		t.Errorf("the phone asked its owner %d times", shown-paired)
	}
}

// The inbox is one half of a pairing, and a peer whose right to approve was
// taken back is refused at the door rather than handed a queue.
func TestAPeerThatDoesNotApproveHasNoInbox(t *testing.T) {
	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	scanQR(t, requester, phone)

	paired := phone.human.count()

	_, err := requester.store.SetPeerDirections(
		phone.identity.Fingerprint(),
		trust.Directions{MayApprove: false, MayRequest: true})
	if err != nil {
		t.Fatalf("set directions: %v", err)
	}

	requester.node.Reconcile()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = phone.node.Collect(ctx, 0)
	if err == nil {
		t.Fatal("the phone was allowed to collect from an instance it does not approve for")
	}

	if !strings.Contains(err.Error(), "does not approve") {
		t.Errorf("the refusal was %v", err)
	}

	if phone.human.count() != paired {
		t.Errorf("the phone was shown %d requests", phone.human.count()-paired)
	}
}
