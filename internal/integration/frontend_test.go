package integration_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/internal/frontend"
	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/bridge"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// The desktop application answering over the control socket (decision Z).
//
// This is the whole of what the tray used to be in the daemon's own process:
// the engine's fan-out reaches an approver that is somewhere else, the card is
// drawn from the bytes the signature commits to, and the answer comes back as
// an ordinary call. What is exercised here is that seam and nothing about
// Wails — the front end has no idea what a window is, which is the reason it is
// its own package.

// A commit worth approving, and the bytes the signature is over.
const desktopCommit = "tree e95bc8444bcd06692c882451e807e45dfe27b5ba\n" +
	"parent 937fa9137d03e1ca64111b86264e78dc907127e7\n" +
	"author A U Thor <author@example.test> 1786209283 +0200\n" +
	"committer A U Thor <author@example.test> 1786209283 +0200\n" +
	"\n" +
	"a commit worth approving\n"

// screen stands in for a desktop: a presenter that answers whatever it is
// shown, and remembers what it was shown and what was taken away again.
type screen struct {
	session *bridge.Session
	answer  *approval.Answer

	mu        sync.Mutex
	presented []*bridge.PendingRequest
	dismissed []string
	announced []bridge.ActivityView
	shown     chan struct{}
}

func newScreen(answer *approval.Answer) *screen {
	return &screen{answer: answer, shown: make(chan struct{}, 4)}
}

func (s *screen) Present(req *bridge.PendingRequest) {
	s.mu.Lock()
	s.presented = append(s.presented, req)
	s.mu.Unlock()

	select {
	case s.shown <- struct{}{}:
	default:
	}

	if s.answer == nil {
		return
	}

	// A real desktop answers when somebody clicks. Answering from here is the
	// same call the viewer makes through the bridge's own API.
	go func() {
		if err := s.session.Answer(req.ID, s.answer); err != nil {
			panic("answer the request: " + err.Error())
		}
	}()
}

func (s *screen) Dismiss(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.dismissed = append(s.dismissed, id)
}

func (s *screen) Announce(activity bridge.ActivityView) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.announced = append(s.announced, activity)
}

func (s *screen) cards() []*bridge.PendingRequest {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]*bridge.PendingRequest(nil), s.presented...)
}

func (s *screen) gone() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.dismissed...)
}

// attach starts a front end against a running instance and waits until the
// daemon has registered it as an approver.
func attach(t *testing.T, socket string, host *screen) *frontend.Frontend {
	t.Helper()

	attached := make(chan bool, 4)

	front, err := frontend.New(frontend.Options{
		Client:    localapi.NewClient(socket),
		Presenter: host,
		Attached:  func(up bool) { attached <- up },
	})
	if err != nil {
		t.Fatalf("build the front end: %v", err)
	}

	host.session = front.Session()

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})

	go func() {
		defer close(stopped)

		if err := front.Run(ctx); err != nil {
			t.Errorf("run the front end: %v", err)
		}
	}()

	t.Cleanup(func() {
		cancel()

		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			t.Error("the front end did not stop")
		}
	})

	select {
	case up := <-attached:
		if !up {
			t.Fatal("the front end reported that it is not attached")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the front end never attached to the instance")
	}

	return front
}

// A signature approved by a front end in another process, which is what every
// desktop approval is now.
func TestAFrontEndAnswersOverTheControlSocket(t *testing.T) {
	box := startPeerInstance(t, "desktop")

	host := newScreen(&approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		Reason:   "approved at the desktop",
	})

	attach(t, box.control, host)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := localapi.NewClient(box.control).SignPayload(ctx,
		&ladulasv1.SignPayloadRequest{
			PublicKey: box.app.Vault().KeyRefs()[0].GetPublicKey(),
			Payload:   []byte(desktopCommit),
			Namespace: "git",
			Timeout:   durationpb.New(20 * time.Second),
			GitContext: &ladulasv1.GitContext{
				RepositoryPath: "/home/hugo/Projects/ladulas",
				Branch:         "main",
				Operation:      "commit",
			},
		})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !resp.GetApproved() {
		t.Fatalf("the request was not approved: %s", resp.GetReason())
	}

	if resp.GetArmoredSignature() == "" {
		t.Error("an approved request produced no signature")
	}

	cards := host.cards()
	if len(cards) != 1 {
		t.Fatalf("%d cards reached the screen", len(cards))
	}

	// The card is drawn from the request the daemon sent, parsed on this side:
	// a prompt rendered from anything else would be a card nobody could stand
	// behind (§5, §8).
	card := cards[0]
	if card.Request.Msg.GetSshsig() == nil {
		t.Error("the card carries no signing request")
	}

	if card.Request.Prompt.Title == "" {
		t.Error("the card was drawn with no prompt rendered")
	}

	// The bytes crossed the socket intact: what the card shows is what the
	// signature covers, which is the whole of why the request travels as bytes
	// rather than as a message (§5, §8).
	object := card.Request.Msg.GetSshsig().GetGitContext().GetObject()
	if string(object) != desktopCommit {
		t.Errorf("the card was drawn from different bytes:\n%s", object)
	}

	// The window comes down whatever the outcome, and the daemon's own log says
	// who answered.
	if gone := host.gone(); len(gone) != 1 || gone[0] != card.ID {
		t.Errorf("the card was not taken off the screen: %v", gone)
	}

	entries, err := approval.ReadAuditLog(box.audit, 100)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}

	var decided bool

	for _, entry := range entries {
		if entry.GetEvent() != ladulasv1.AuditEvent_AUDIT_EVENT_DECISION {
			continue
		}

		decided = true

		if got := entry.GetResponse().GetReason(); got != "approved at the desktop" {
			t.Errorf("the log does not carry the approver's own words: %q", got)
		}
	}

	if !decided {
		t.Error("the decision never reached the audit log")
	}
}

// A front end that is not there is not a failure, and a front end that arrives
// later is attached to the instance it finds — which is what makes a desktop
// autostart and a user unit startable in either order.
func TestAFrontEndAttachesToAnInstanceThatWasAlreadyRunning(t *testing.T) {
	box := startPeerInstance(t, "desktop")

	// Nothing is attached yet, and the instance is serving.
	first := newScreen(&approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
	})

	attach(t, box.control, first)

	second := newScreen(&approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
	})

	// Two attached at once are two approvers, and the engine asks both. That is
	// the same race a phone and a desktop have always run, and the first answer
	// wins it.
	attach(t, box.control, second)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := localapi.NewClient(box.control).SignPayload(ctx,
		&ladulasv1.SignPayloadRequest{
			PublicKey: box.app.Vault().KeyRefs()[0].GetPublicKey(),
			Payload:   []byte(desktopCommit),
			Namespace: "git",
			Timeout:   durationpb.New(20 * time.Second),
		})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !resp.GetApproved() {
		t.Fatalf("the request was not approved: %s", resp.GetReason())
	}

	if len(first.cards()) == 0 && len(second.cards()) == 0 {
		t.Error("neither front end was shown the request")
	}
}

// A request nobody answers is taken off the screen rather than left on it, and
// the front end is told why.
func TestAnUnansweredRequestIsWithdrawnFromTheScreen(t *testing.T) {
	box := startPeerInstance(t, "desktop")

	// A screen that shows the card and never answers.
	host := newScreen(nil)

	attach(t, box.control, host)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := localapi.NewClient(box.control).SignPayload(ctx,
		&ladulasv1.SignPayloadRequest{
			PublicKey: box.app.Vault().KeyRefs()[0].GetPublicKey(),
			Payload:   []byte(desktopCommit),
			Namespace: "git",
			Timeout:   durationpb.New(2 * time.Second),
		})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if resp.GetApproved() {
		t.Fatal("a request nobody answered was approved")
	}

	select {
	case <-host.shown:
	default:
		t.Fatal("the card never reached the screen")
	}

	// Dismiss is what closes the window. Without it the desktop would be left
	// holding a prompt for a request the daemon has already given up on.
	deadline := time.Now().Add(5 * time.Second)
	for len(host.gone()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	if len(host.gone()) == 0 {
		t.Error("the card was left on the screen after the request ran out")
	}
}

// TestADesktopStartsAPairingAndAnswersIt is the whole of the window's half of
// §7, end to end: the intent is chosen here, the code goes out, another machine
// uses it, and the card that comes back is an ordinary approval card.
//
// The thing it would be easy to get wrong and impossible to notice in a unit
// test is that displaying a code is a *stream*: the pairing window at the
// daemon lives for exactly as long as the front end holds it open. A front end
// that made the call and returned would hand somebody a code that had already
// stopped working, and this test would be the only thing that said so.
func TestADesktopStartsAPairingAndAnswersIt(t *testing.T) {
	desk := startPeerInstance(t, "desktop")
	joiner := startPeerInstance(t, "laptop")

	host := newScreen(&approval.Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		Reason:   "confirmed at the desktop",
	})

	front := attach(t, desk.control, host)

	window := httptest.NewServer(front.Session().Handler())
	t.Cleanup(window.Close)

	view := invite(t, window, `{"intent":"approver"}`)

	if view.Code == "" || view.FullCode == "" || view.QR == "" {
		t.Fatalf("the invitation is missing a way in: %+v", view)
	}

	// The other machine reads what the QR carries, which is the code with this
	// instance's identity and addresses in it.
	code, err := trust.DecodeCode(view.FullCode)
	if err != nil {
		t.Fatalf("decode the code the window displayed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pending, err := joiner.app.Peer().PairWith(ctx, "", code)
	if err != nil {
		t.Fatalf("use the code the window displayed: %v", err)
	}

	// It declared no direction of its own and wrote down the mirror of what was
	// chosen here: the desktop's approver becomes, on that side, a machine it
	// may ask.
	if pending.GetMayApprove() || !pending.GetMayRequest() {
		t.Errorf("the joining side recorded approve=%v request=%v",
			pending.GetMayApprove(), pending.GetMayRequest())
	}

	// Both users answer: the joining side over its own control socket, and the
	// desktop by being shown a card, which is what the screen does with
	// anything it is presented.
	answerPending(t, ctx, joiner, desk.app.Vault().Identity().Fingerprint())

	waitFor(t, "the desktop pairs", func() bool {
		_, ok := desk.app.Vault().Peer(
			joiner.app.Vault().Identity().Fingerprint())

		return ok
	})

	record, _ := desk.app.Vault().Peer(
		joiner.app.Vault().Identity().Fingerprint())

	if !record.GetMayApprove() || record.GetMayRequest() {
		t.Errorf("the desktop recorded approve=%v request=%v, want the intent "+
			"it chose", record.GetMayApprove(), record.GetMayRequest())
	}

	// And the card it was shown was a one-shot: a pairing carries no offer to
	// approve anything for a while, because there is nothing a promise about it
	// could ever cover.
	var confirmed *bridge.PendingRequest

	for _, card := range host.cards() {
		if card.Request.Msg.GetKind() ==
			ladulasv1.RequestKind_REQUEST_KIND_PAIRING {
			confirmed = card
		}
	}

	if confirmed == nil {
		t.Fatal("the desktop was never shown the pairing")
	}

	if confirmed.Request.GrantMaxTTL != 0 ||
		len(confirmed.Request.GrantTTLs) != 0 {
		t.Errorf("the pairing card offered a promise: %s",
			confirmed.Request.GrantMaxTTL)
	}
}

func invite(
	t *testing.T, window *httptest.Server, body string,
) bridge.InvitationView {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		window.URL+"/api/v1/pairings/invite", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := window.Client().Do(req)
	if err != nil {
		t.Fatalf("ask the window for a code: %v", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(resp.Body)

		t.Fatalf("the window would not display a code: %d %s",
			resp.StatusCode, out)
	}

	var view bridge.InvitationView

	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatalf("read the invitation: %v", err)
	}

	return view
}

// answerPending says yes on the side that has no screen in this test, over the
// same control call `ladulas pairings approve` makes.
func answerPending(
	t *testing.T, ctx context.Context, box *peerInstance, peer string,
) {
	t.Helper()

	client := localapi.NewClient(box.control)

	_, err := client.Control().AnswerPendingPairing(ctx,
		connect.NewRequest(&ladulasv1.AnswerPendingPairingRequest{
			Pairing:  peer,
			Accepted: true,
			Reason:   "answered in a test",
		}))
	if err != nil {
		t.Fatalf("answer the pairing on %s: %v", box.name, err)
	}
}
