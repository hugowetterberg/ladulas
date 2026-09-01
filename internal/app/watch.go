package app

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The approval stream: how a front end that is not in this process answers
// prompts (decision Z, §12, §14).
//
// The desktop application used to be an instance — it opened the store, served
// the agent socket and held the data encryption key, with a window attached.
// What is left of it here is the window: a stream registers an approver, the
// engine's fan-out reaches it like any other, and the answer comes back as an
// ordinary call. The store, the keys and the sockets stay with the process that
// owns them, which is what decision L has said all along and what the tray was
// the exception to.
//
// Nothing about a decision changes with the distance. It is the same engine,
// the same policy, the same grants and the same audit entry; the approver is
// simply one whose screen is in another process.

// watchedRequest is one prompt out on a stream, waiting for somebody.
//
// The token is what an answer names. A request id names the question and every
// card that was drawn for it; this names one of those cards, which is what an
// answer actually is (decision AM).
type watchedRequest struct {
	req    *approval.Request
	token  string
	answer chan *approval.Answer
}

// watchedRequests is every prompt this instance has out to a front end, by
// request id.
//
// It is a slice per id rather than one entry, because two front ends attached
// at once are two approvers and the engine asks both. An answer is delivered to
// every waiter for that request; the engine takes the first one that arrives
// and cancels the rest, which is the same race a phone and a tray have always
// run.
type watchedRequests struct {
	mu   sync.Mutex
	byID map[string][]*watchedRequest
}

func (w *watchedRequests) add(id string, entry *watchedRequest) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.byID == nil {
		w.byID = map[string][]*watchedRequest{}
	}

	w.byID[id] = append(w.byID[id], entry)
}

func (w *watchedRequests) remove(id string, entry *watchedRequest) {
	w.mu.Lock()
	defer w.mu.Unlock()

	waiting := w.byID[id]

	for i, existing := range waiting {
		if existing == entry {
			w.byID[id] = append(waiting[:i], waiting[i+1:]...)

			break
		}
	}

	if len(w.byID[id]) == 0 {
		delete(w.byID, id)
	}
}

// waiting is the prompts out for a request, or none. The request itself is the
// same object in every one of them, which is what lets a diff be fetched for a
// request named by nothing but its identifier.
func (w *watchedRequests) waiting(id string) []*watchedRequest {
	w.mu.Lock()
	defer w.mu.Unlock()

	return append([]*watchedRequest(nil), w.byID[id]...)
}

// answered picks the prompt an answer belongs to.
//
// With a token it is exactly one card, and the answer settles that card: the
// approver behind it returns, the engine takes the decision, and the prompts on
// the other screens are cancelled and withdrawn by the path that has always
// done that (decision AM).
//
// Without a token there is nothing to pick by, and the two cases differ. One
// prompt out is unambiguous — it is the card that was drawn, and answering it is
// what the caller meant. Several is a front end old enough not to send a token
// while another is attached, and there is no right answer: it gets the old
// behaviour, which is every prompt handed the same answer, and a line in the log
// saying that is what happened.
func (w *watchedRequests) answered(
	id, token string,
) (chosen []*watchedRequest, ambiguous bool) {
	waiting := w.waiting(id)

	if token == "" {
		return waiting, len(waiting) > 1
	}

	for _, entry := range waiting {
		if entry.token == token {
			return []*watchedRequest{entry}, false
		}
	}

	return nil, false
}

// socketApprover is one attached front end, as the engine sees it.
type socketApprover struct {
	app *App
	id  string

	// sendMu serializes writes: a connect stream is not safe for concurrent
	// use, and the engine calls Decide once per request in a goroutine of its
	// own. It also guards `gone`, which is what makes it the lock that has to be
	// held to touch the stream at all.
	sendMu sync.Mutex
	stream *connect.ServerStream[ladulasv1.ApprovalPrompt]
	// gone says the handler holding the stream open has stopped. Sending after
	// that is not an error the stream reports — it is a segmentation fault, and
	// it took the daemon down with it. See finish.
	gone bool
}

var (
	_ approval.Handler     = (*socketApprover)(nil)
	_ approval.Notifier    = (*socketApprover)(nil)
	_ approval.LocalPrompt = (*socketApprover)(nil)
)

func (s *socketApprover) ID() string {
	return s.id
}

// LocalPrompt implements approval.LocalPrompt: the screen is in another
// process, but it is a screen at this machine, and a soft lock is the claim
// that nobody is in front of it (§10).
//
// The distinction the engine draws is "answered by somebody who is here"
// rather than "answered in this process", which is why moving the window out
// of the daemon changes nothing about what a soft lock takes away.
func (s *socketApprover) LocalPrompt() {
}

// errFrontEndGone is what every send reports once the stream's handler has
// stopped. It is an ordinary outcome: a front end may be closed, killed or
// crash at any moment, and decision Z's answer to that is that the approver goes
// away and whoever else could answer does.
var errFrontEndGone = errors.New("the front end is no longer attached")

func (s *socketApprover) send(event *ladulasv1.ApprovalPrompt) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	// The stream belongs to the RPC handler and dies with it, and what is left
	// behind is not a stream that reports errors — it is an `http.response`
	// whose buffered writer has been handed back to a pool, so writing to it
	// dereferences nil and takes the whole daemon with it: the agent socket, the
	// peer links and the unlocked store, over a window that was closed. It
	// happened, from a front end killed while a prompt was on its way out
	// (ops.md). So the flag is checked here rather than the error being trusted.
	if s.gone {
		return errFrontEndGone
	}

	if err := s.stream.Send(event); err != nil {
		return fmt.Errorf("send to the front end: %w", err)
	}

	return nil
}

// finish is the handler saying it is about to return, and the stream about to
// stop existing.
//
// Taking the same lock every send takes is the whole mechanism: a send already
// under way finishes first — while the stream is still the handler's and still
// valid — and every send after this one is refused instead of writing into a
// response that has been recycled. Unregistering the approver is not enough on
// its own, because the engine has already taken its list of approvers by the
// time it prompts.
func (s *socketApprover) finish() {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	s.gone = true
}

// Decide puts the request on the stream and waits for an answer.
//
// A context that finishes first is not an answer: another approver got there,
// the requester gave up, or it ran out of time. The front end is told to take
// the card off the screen and Decide reports the same error an in-process
// window used to, which is what the engine matches on.
func (s *socketApprover) Decide(
	ctx context.Context, req *approval.Request,
) (*approval.Answer, error) {
	id := req.Msg.GetRequestId()

	entry := &watchedRequest{
		req:    req,
		token:  identity.NewRequestID(),
		answer: make(chan *approval.Answer, 1),
	}

	s.app.watched.add(id, entry)
	defer s.app.watched.remove(id, entry)

	if err := s.send(&ladulasv1.ApprovalPrompt{
		Kind:        ladulasv1.ApprovalPromptKind_APPROVAL_PROMPT_KIND_PROMPT,
		RequestId:   id,
		Request:     req.Body,
		Grant:       grantOffer(req),
		PromptToken: entry.token,
	}); err != nil {
		return nil, err
	}

	select {
	case answer := <-entry.answer:
		return answer, nil
	case <-ctx.Done():
		// Best effort, and deliberately not an error: the reason the context
		// finished is very often that the stream is gone.
		_ = s.send(&ladulasv1.ApprovalPrompt{
			Kind:      ladulasv1.ApprovalPromptKind_APPROVAL_PROMPT_KIND_WITHDRAWN,
			RequestId: id,
			Reason:    withdrawalReason(ctx.Err()),
		})

		return nil, ctx.Err() //nolint:wrapcheck // the engine matches on it
	}
}

// Notify implements approval.Notifier: a request that was decided without
// asking still reaches the screen, as an announcement rather than a card (§9).
func (s *socketApprover) Notify(
	req *approval.Request, resp *ladulasv1.ApprovalResponse,
) {
	if err := s.send(&ladulasv1.ApprovalPrompt{
		Kind:      ladulasv1.ApprovalPromptKind_APPROVAL_PROMPT_KIND_DECIDED,
		RequestId: req.Msg.GetRequestId(),
		Request:   req.Body,
		Response:  resp,
	}); err != nil {
		s.app.log.Debug("could not announce a decision to the front end",
			"error", err.Error())
	}
}

// withdrawalReason is why a card is coming off the screen, in the words to show
// on it. The engine already draws the distinction when it denies, and it is the
// whole of what somebody who did not answer needs to know.
func withdrawalReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "not answered in time"
	}

	return "answered or withdrawn elsewhere"
}

func grantOffer(req *approval.Request) *ladulasv1.GrantOffer {
	if req.GrantMaxTTL <= 0 {
		return nil
	}

	offer := &ladulasv1.GrantOffer{
		MaxTtl:         durationpb.New(req.GrantMaxTTL),
		SessionSubject: req.GrantSubject,
		Machine:        req.GrantMachine,
	}

	for _, ttl := range req.GrantTTLs {
		offer.Ttls = append(offer.Ttls, durationpb.New(ttl))
	}

	return offer
}

// WatchApprovals attaches a front end for as long as it holds the stream open.
func (s *controlService) WatchApprovals(
	ctx context.Context,
	req *connect.Request[ladulasv1.WatchApprovalsRequest],
	stream *connect.ServerStream[ladulasv1.ApprovalPrompt],
) error {
	id := req.Msg.GetApproverId()
	if id == "" {
		id = "desktop"
	}

	approver := &socketApprover{app: s.app, id: id, stream: stream}

	// Registering with the instance rather than with the engine is what lets a
	// front end attach to a sealed store and be there the moment somebody
	// unlocks it (§10) — which is the ordinary way a desktop starts, since the
	// passphrase dialog is drawn by the thing that just attached.
	unregister := s.app.RegisterApprover(approver)

	// Order matters on the way out, and both halves do: unregister first, so the
	// engine stops handing this approver requests, and then wait for whatever is
	// already being sent — because after this function returns the stream is not
	// something to write to (see finish).
	defer approver.finish()
	defer unregister()

	s.app.log.Info("a front end attached", "approver", id)
	defer s.app.log.Info("a front end detached", "approver", id)

	if err := approver.send(&ladulasv1.ApprovalPrompt{
		Kind: ladulasv1.ApprovalPromptKind_APPROVAL_PROMPT_KIND_ATTACHED,
	}); err != nil {
		return err
	}

	<-ctx.Done()

	return nil
}

// AnswerApproval settles a request the stream raised.
func (s *controlService) AnswerApproval(
	ctx context.Context, req *connect.Request[ladulasv1.AnswerApprovalRequest],
) (*connect.Response[ladulasv1.AnswerApprovalResponse], error) {
	id := req.Msg.GetRequestId()

	waiting, ambiguous := s.app.watched.answered(id, req.Msg.GetPromptToken())
	if len(waiting) == 0 {
		// Not an error about the identifier: the ordinary way to get here is to
		// answer a card that was settled while somebody was reading it.
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("request %s is not waiting for an answer", id))
	}

	if ambiguous {
		s.app.log.Warn(
			"a front end answered without saying which prompt, and it is not "+
				"the only one attached: every screen showing this request is "+
				"being given the same answer",
			"request_id", id)
	}

	answer := &approval.Answer{
		Decision: req.Msg.GetDecision(),
		Reason:   req.Msg.GetReason(),
	}

	if ttl := req.Msg.GetGrantTtl().AsDuration(); ttl > 0 {
		// The front end draws the bound; it does not own it. A promise past it
		// is refused rather than trimmed, because a promise quietly shortened is
		// a promise nobody made (decision V).
		if max := waiting[0].req.GrantMaxTTL; ttl > max {
			return nil, connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf(
					"this instance promises nothing for longer than %s",
					max))
		}

		answer.GrantTTL = ttl
		answer.GrantReach = grantReach(req.Msg.GetGrantReach())
	}

	for _, entry := range waiting {
		if presented := req.Msg.GetPresented(); presented != nil {
			entry.req.Presented(presented)
		}

		select {
		case entry.answer <- answer:
		default:
		}
	}

	return connect.NewResponse(&ladulasv1.AnswerApprovalResponse{}), nil
}

func grantReach(reach ladulasv1.GrantReach) approval.GrantReach {
	if reach == ladulasv1.GrantReach_GRANT_REACH_MACHINE {
		return approval.GrantReachMachine
	}

	return approval.GrantReachSession
}

// FetchRequestDiff asks the requester for the rest of a diff, for the front end
// drawing the card.
//
// Only a request that is on a screen right now can be asked about, which is the
// same rule the peer channel's FetchDiff has: a diff is repository content, and
// "which commits has this machine been signing" is not a question to be asked
// at leisure.
func (s *controlService) FetchRequestDiff(
	ctx context.Context, req *connect.Request[ladulasv1.FetchRequestDiffRequest],
) (*connect.Response[ladulasv1.FetchRequestDiffResponse], error) {
	waiting := s.app.watched.waiting(req.Msg.GetRequestId())
	if len(waiting) == 0 {
		return nil, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("request %s is not on screen",
				req.Msg.GetRequestId()))
	}

	diff, err := s.app.FetchDiff(ctx, waiting[0].req, req.Msg.GetPath())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}

	return connect.NewResponse(&ladulasv1.FetchRequestDiffResponse{
		Diff: diff,
	}), nil
}

// Settings reports the part of the policy a surface may show, and the bounds it
// should draw (§9).
func (s *controlService) Settings(
	_ context.Context, _ *connect.Request[ladulasv1.SettingsRequest],
) (*connect.Response[ladulasv1.SettingsResponse], error) {
	return connect.NewResponse(s.settings()), nil
}

// SetSignTimeout writes the signing budget and puts it into effect.
func (s *controlService) SetSignTimeout(
	_ context.Context, req *connect.Request[ladulasv1.SetSignTimeoutRequest],
) (*connect.Response[ladulasv1.SettingsResponse], error) {
	timeout := req.Msg.GetSignTimeout().AsDuration()

	if err := s.app.SetSignTimeout(timeout); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	return connect.NewResponse(s.settings()), nil
}

// settings is the same answer both calls give, so that a write is followed by
// what a read would now say rather than by an empty response the caller has to
// go and check.
func (s *controlService) settings() *ladulasv1.SettingsResponse {
	return &ladulasv1.SettingsResponse{
		SignTimeout:        durationpb.New(s.app.SignTimeout()),
		DefaultSignTimeout: durationpb.New(approval.DefaultSignTimeout),
		MinSignTimeout:     durationpb.New(approval.MinSignTimeout),
		MaxSignTimeout:     durationpb.New(approval.MaxSignTimeout),
		PolicyPath:         s.app.Config.PolicyPath(),
	}
}

// Reload re-reads the store and the policy, which is what SIGHUP does to the
// daemon and what the front end's menu asks for.
func (s *controlService) Reload(
	ctx context.Context, req *connect.Request[ladulasv1.ReloadRequest],
) (*connect.Response[ladulasv1.ReloadResponse], error) {
	if err := s.app.Reload(); err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}

	return connect.NewResponse(&ladulasv1.ReloadResponse{}), nil
}
