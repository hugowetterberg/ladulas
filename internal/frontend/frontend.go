// Package frontend is a viewer host that is not an instance: it draws what a
// running daemon tells it and answers over the daemon's control socket
// (decision Z, §12, §14).
//
// The desktop application used to be an instance with a window on it. It opened
// the store, served the agent socket and held the data encryption key in the
// same address space as a browser engine rendering commit messages somebody
// else wrote — and it collided with the daemon over the agent socket, so the
// two were alternatives and a webkit crash took the agent down with it. What is
// here instead is the window: a bridge.Session whose every answer is a call and
// whose prompts arrive on a stream.
//
// It is deliberately not in internal/gui. Nothing here knows what a window is,
// which is what makes it testable without a display and what would let a second
// shell — a different toolkit, a terminal — be written against the same seam.
// The host supplies a bridge.Presenter and nothing else.
package frontend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/bridge"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
)

// callTimeout bounds one control-socket call made on behalf of a viewer that is
// drawing something. It is short because the socket is local and the caller is
// a screen: a daemon that has not answered in two seconds is a daemon to report
// rather than one to keep waiting for.
const callTimeout = 2 * time.Second

// statusTTL is how long a Status answer is reused.
//
// One paint of the status pane asks for the keys, the peers, the pairings and
// the lock state, and four of those are fields of one Status. The window
// repaints on a timer, so without this the socket carries the same question
// several times a second to draw one page. It is short enough that the unlock
// panel still sees the store open promptly, which is the one place a stale
// answer would be noticed.
const statusTTL = 250 * time.Millisecond

// reconnectDelay is how long to wait before dialling again after the stream
// dropped.
//
// A front end outliving the daemon is ordinary rather than exceptional now:
// `systemctl --user restart ladulas` should not take the window down with it,
// and a desktop autostart may well win the race against the user unit at login.
// So there is no give-up: it keeps trying, and says on the tray that it is not
// attached.
const reconnectDelay = 2 * time.Second

// auditEntriesPerDecision is how many lines the log holds for each decision, so
// that reading back the last N decisions asks for enough lines to find them.
const auditEntriesPerDecision = 4

// Options configure a front end.
type Options struct {
	// Client is the control socket. Required.
	Client *localapi.Client
	// Presenter is the host: what showing somebody a request means here.
	Presenter bridge.Presenter
	// ID names this approver in the audit log. Defaults to "desktop".
	ID string
	// Attached is called when the approval stream comes up or goes down, for a
	// host that says so on screen. Optional, and called from the stream's own
	// goroutine.
	Attached func(bool)
	Logger   *slog.Logger
}

// Frontend is a viewer host attached to a running instance.
type Frontend struct {
	client  ladulasv1connect.ControlServiceClient
	socket  string
	id      string
	log     *slog.Logger
	session *bridge.Session
	attach  func(bool)

	mu       sync.Mutex
	lastSeen *ladulasv1.StatusResponse
	seenAt   time.Time
	// showing is the cancel function of every request currently in front of
	// somebody, so that a withdrawal from the daemon takes the card off the
	// screen the same way another approver answering used to.
	showing map[string]context.CancelFunc
	// tokens names the card this front end was given for each request, which is
	// what an answer has to carry: a request id names every card drawn for the
	// question, and an answer under one was handed to every screen showing it
	// — so the desktop's popup stayed up after the terminal had answered
	// (decision AM).
	tokens map[string]string
}

// New builds a front end. It makes no call: a desktop application starts
// whether or not a daemon is running, and says which it found.
func New(opts Options) (*Frontend, error) {
	if opts.Client == nil {
		return nil, errors.New("frontend: no control socket client")
	}

	id := opts.ID
	if id == "" {
		id = "desktop"
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	front := &Frontend{
		client:  opts.Client.Control(),
		socket:  opts.Client.SocketPath(),
		id:      id,
		log:     logger,
		attach:  opts.Attached,
		showing: map[string]context.CancelFunc{},
		tokens:  map[string]string{},
	}

	front.session = bridge.NewSession(bridge.Options{
		Name:               "Ladulås",
		Keys:               front.keys,
		GenerateKey:        front.generateKey,
		Borrowed:           front.borrowed,
		KeyOffers:          front.keyOffers,
		Endorsements:       front.endorsements,
		RetractEndorsement: front.retractEndorsement,
		AnswerKeyOffer:     front.answerKeyOffer,
		Grants:             front.grants,
		RevokeGrant:        front.revokeGrant,
		ExtendGrant:        front.extendGrant,
		Delegations:        front.delegations,
		Peers:              front.peers,
		RevokePeer:         front.revokePeer,
		Pairings:           front.pairings,
		Withdraw:           front.withdrawPairing,
		Pairing:            &pairingControl{front: front},
		Projects:           &projects{front: front},
		FetchDiff:          front.fetchDiff,
		History:            front.history,
		Reload:             front.reload,
		Lock:               &lockControl{front: front},
		Settings:           front.settings,
		SetSignTimeout:     front.setSignTimeout,
		Locations:          nil,
		Presenter:          opts.Presenter,
		ID:                 id,
		Logger:             logger,
	})

	return front, nil
}

// Session is the viewer host: the handler a webview is served from, and the
// object a request is answered through.
func (f *Frontend) Session() *bridge.Session {
	return f.session
}

// SetPresenter installs the host, for a shell built after the session is.
func (f *Frontend) SetPresenter(presenter bridge.Presenter) {
	f.session.SetPresenter(presenter)
}

// The host's own half of the surface: a menu has a Lock item and a Reload item,
// and needs to know what the store is doing before it draws either. They are
// the same calls the viewer makes, exposed so that a shell does not have to
// reach into the session to make them.

// State is what the store is doing, or that there is nothing to ask.
func (f *Frontend) State() bridge.LockView {
	return (&lockControl{front: f}).State()
}

// Lock suspends approval here, or — with seal — wipes the store key (§10).
func (f *Frontend) Lock(seal bool) error {
	return (&lockControl{front: f}).Lock(seal)
}

// Reload re-reads the store and the policy.
func (f *Frontend) Reload() error {
	return f.reload()
}

// Run attaches to the daemon and keeps the attachment up until the context is
// done. It returns nil when the context finishes: there is no failure that ends
// it, because "the daemon is not running" is a state to wait out rather than an
// error to exit on.
func (f *Frontend) Run(ctx context.Context) error {
	for {
		if err := f.watch(ctx); err != nil && ctx.Err() == nil {
			f.log.Info("not attached to a Ladulås daemon",
				"socket", f.socket, "error", err.Error())
		}

		f.setAttached(false)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(reconnectDelay):
		}
	}
}

// watch holds one attachment open.
func (f *Frontend) watch(ctx context.Context) error {
	stream, err := f.client.WatchApprovals(ctx,
		connect.NewRequest(&ladulasv1.WatchApprovalsRequest{ApproverId: f.id}))
	if err != nil {
		return fmt.Errorf("attach to the instance: %w", err)
	}

	defer func() {
		if err := stream.Close(); err != nil {
			f.log.Debug("closing the approval stream", "error", err.Error())
		}
	}()

	for stream.Receive() {
		f.event(ctx, stream.Msg())
	}

	if err := stream.Err(); err != nil {
		return fmt.Errorf("the approval stream ended: %w", err)
	}

	return nil
}

func (f *Frontend) event(ctx context.Context, event *ladulasv1.ApprovalPrompt) {
	switch event.GetKind() {
	case ladulasv1.ApprovalPromptKind_APPROVAL_PROMPT_KIND_ATTACHED:
		f.log.Info("attached to the Ladulås daemon", "socket", f.socket)
		f.setAttached(true)
	case ladulasv1.ApprovalPromptKind_APPROVAL_PROMPT_KIND_PROMPT:
		go f.prompt(ctx, event)
	case ladulasv1.ApprovalPromptKind_APPROVAL_PROMPT_KIND_WITHDRAWN:
		f.dismiss(event.GetRequestId())
	case ladulasv1.ApprovalPromptKind_APPROVAL_PROMPT_KIND_DECIDED:
		f.announce(event)
	case ladulasv1.ApprovalPromptKind_APPROVAL_PROMPT_KIND_UNSPECIFIED:
		f.log.Debug("an approval event with no kind arrived")
	}
}

// prompt puts one request in front of somebody and posts what they said.
func (f *Frontend) prompt(ctx context.Context, event *ladulasv1.ApprovalPrompt) {
	req, err := requestFromWire(event.GetRequest(), event.GetGrant())
	if err != nil {
		f.log.Error("a request could not be read",
			"request_id", event.GetRequestId(), "error", err.Error())

		return
	}

	id := req.Msg.GetRequestId()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	f.mu.Lock()
	f.showing[id] = cancel
	f.tokens[id] = event.GetPromptToken()
	f.mu.Unlock()

	defer func() {
		f.mu.Lock()
		delete(f.showing, id)
		delete(f.tokens, id)
		f.mu.Unlock()
	}()

	answer, err := f.session.Decide(ctx, req)
	if err != nil {
		// Withdrawn, or the stream went away with somebody still looking at it.
		// Either way the daemon has settled it and there is nothing to send.
		return
	}

	if err := f.answer(context.WithoutCancel(ctx), id, req, answer); err != nil {
		f.log.Error("an answer did not reach the instance",
			"request_id", id, "error", err.Error())
	}
}

func (f *Frontend) answer(
	ctx context.Context, id string,
	req *approval.Request, answer *approval.Answer,
) error {
	f.mu.Lock()
	token := f.tokens[id]
	f.mu.Unlock()

	msg := &ladulasv1.AnswerApprovalRequest{
		RequestId:   id,
		Decision:    answer.Decision,
		Reason:      answer.Reason,
		Presented:   req.Shown(),
		PromptToken: token,
	}

	if answer.GrantTTL > 0 {
		msg.GrantTtl = durationpb.New(answer.GrantTTL)
		msg.GrantReach = ladulasv1.GrantReach_GRANT_REACH_SESSION

		if answer.GrantReach == approval.GrantReachMachine {
			msg.GrantReach = ladulasv1.GrantReach_GRANT_REACH_MACHINE
		}
	}

	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	if _, err := f.client.AnswerApproval(ctx, connect.NewRequest(msg)); err != nil {
		return fmt.Errorf("send the answer: %w", err)
	}

	return nil
}

// dismiss takes a card off the screen because the daemon said so.
func (f *Frontend) dismiss(id string) {
	f.mu.Lock()
	cancel := f.showing[id]
	f.mu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// announce is a request that was decided without asking (§9).
func (f *Frontend) announce(event *ladulasv1.ApprovalPrompt) {
	req, err := requestFromWire(event.GetRequest(), event.GetGrant())
	if err != nil {
		f.log.Debug("an announcement could not be read", "error", err.Error())

		return
	}

	f.session.Notify(req, event.GetResponse())
}

func (f *Frontend) setAttached(attached bool) {
	if f.attach != nil {
		f.attach(attached)
	}
}

// requestFromWire rebuilds what the daemon sent: the bytes the digest covers,
// parsed here rather than taken as a message.
//
// The card is drawn from the same material the signature commits to, which is
// the rule the peer channel follows for the same reason (§8) — and the prompt
// is rendered by approval.RenderPrompt, the one function every surface words a
// request with.
func requestFromWire(
	body []byte, offer *ladulasv1.GrantOffer,
) (*approval.Request, error) {
	if len(body) == 0 {
		return nil, errors.New("the request is empty")
	}

	var msg ladulasv1.ApprovalRequest

	if err := proto.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("parse the request: %w", err)
	}

	req := &approval.Request{
		Msg:    &msg,
		Prompt: approval.RenderPrompt(&msg),
		Body:   body,
	}

	if offer != nil {
		req.GrantMaxTTL = offer.GetMaxTtl().AsDuration()
		req.GrantSubject = offer.GetSessionSubject()
		req.GrantMachine = offer.GetMachine()

		for _, ttl := range offer.GetTtls() {
			req.GrantTTLs = append(req.GrantTTLs, ttl.AsDuration())
		}
	}

	return req, nil
}
