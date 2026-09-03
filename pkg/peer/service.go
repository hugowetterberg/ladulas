package peer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
)

// peerService is what a paired instance can reach over the channel.
type peerService struct {
	ladulasv1connect.UnimplementedApprovalServiceHandler
	ladulasv1connect.UnimplementedEventServiceHandler
	ladulasv1connect.UnimplementedKeyServiceHandler
	ladulasv1connect.UnimplementedPairingServiceHandler
	ladulasv1connect.UnimplementedPresenceServiceHandler
	ladulasv1connect.UnimplementedProjectServiceHandler
	ladulasv1connect.UnimplementedWakeupServiceHandler

	node *Node
}

var (
	_ ladulasv1connect.ApprovalServiceHandler = (*peerService)(nil)
	_ ladulasv1connect.EventServiceHandler    = (*peerService)(nil)
	_ ladulasv1connect.KeyServiceHandler      = (*peerService)(nil)
	_ ladulasv1connect.PairingServiceHandler  = (*peerService)(nil)
	_ ladulasv1connect.PresenceServiceHandler = (*peerService)(nil)
	_ ladulasv1connect.ProjectServiceHandler  = (*peerService)(nil)
	_ ladulasv1connect.WakeupServiceHandler   = (*peerService)(nil)
)

// RequestApproval decides a peer's request here and streams the answer back.
//
// The request arrives as bytes and is digested as bytes, so the signature that
// goes back commits to exactly what crossed the channel. It is unmarshalled for
// display and for policy, and the parts of it that say who is asking are
// replaced with what the channel proved — a paired peer does not get to name
// itself on somebody else's prompt.
func (s *peerService) RequestApproval(
	ctx context.Context,
	req *connect.Request[ladulasv1.RequestApprovalRequest],
	stream *connect.ServerStream[ladulasv1.ApprovalEvent],
) error {
	peer, record, err := s.node.authorize(ctx)
	if err != nil {
		return err
	}

	// One peer may only have so many decisions in flight at once (M3). A flood
	// of requests is how a compromised peer would bury a real prompt or wear an
	// approver down; past the cap it is told to back off rather than adding
	// another card to the pile.
	if !s.node.load.acquire(peer.Fingerprint) {
		return connect.NewError(connect.CodeResourceExhausted,
			errors.New("too many requests are already pending from this peer"))
	}

	defer s.node.load.release(peer.Fingerprint)

	body := req.Msg.GetRequest()
	if len(body) == 0 {
		return connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request is empty"))
	}

	var msg ladulasv1.ApprovalRequest

	if err := proto.Unmarshal(body, &msg); err != nil {
		return connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the request does not parse: %w", err))
	}

	// Pairing is settled by the pairing service, and a peer that could raise a
	// pairing prompt through this door could ask to be granted anything.
	if msg.GetKind() == ladulasv1.RequestKind_REQUEST_KIND_PAIRING {
		return connect.NewError(connect.CodePermissionDenied,
			errors.New("pairing changes are not requested this way"))
	}

	msg.Requester = &ladulasv1.RequesterInfo{
		InstanceId:    peer.Fingerprint,
		Name:          record.GetName(),
		Local:         false,
		Headless:      msg.GetRequester().GetHeadless(),
		RemoteAddress: peer.RemoteAddr,
		// The process behind the request is the requesting machine's word for
		// it, and it is the requesting machine we distrust (§5, §15). It is
		// carried for the log and is not shown as though it were established.
		Process: msg.GetRequester().GetProcess(),
	}

	if err := stream.Send(&ladulasv1.ApprovalEvent{
		Kind:      ladulasv1.ApprovalEventKind_APPROVAL_EVENT_KIND_ACCEPTED,
		Timestamp: timestamppb.Now(),
	}); err != nil {
		return fmt.Errorf("acknowledge the request: %w", err)
	}

	// The engine runs the whole of its own decision here: the hard rules, the
	// check that the commit shown is the commit being signed, this instance's
	// policy, this instance's grants, and finally this instance's humans.
	_, signed, err := s.node.engine.SubmitPeer(ctx, &msg, body)
	if err != nil {
		return connect.NewError(connect.CodeInternal,
			fmt.Errorf("decide the request: %w", err))
	}

	if err := stream.Send(&ladulasv1.ApprovalEvent{
		Kind:      ladulasv1.ApprovalEventKind_APPROVAL_EVENT_KIND_DECIDED,
		Timestamp: timestamppb.Now(),
		Approval:  signed,
	}); err != nil {
		return fmt.Errorf("send the decision: %w", err)
	}

	return nil
}

// CancelApproval withdraws a request out of band.
//
// Cancelling the stream is the ordinary way — it is what the engine's fan-out
// does to the losers, and it needs no message at all. This exists for the case
// the stream cannot carry: an approver reached over a connection that has since
// gone, whose prompt is still on a screen.
func (s *peerService) CancelApproval(
	ctx context.Context,
	req *connect.Request[ladulasv1.CancelApprovalRequest],
) (*connect.Response[ladulasv1.CancelApprovalResponse], error) {
	if _, _, err := s.node.authorize(ctx); err != nil {
		return nil, err
	}

	s.node.log.Debug("a peer withdrew a request",
		"request_id", req.Msg.GetRequestId(), "reason", req.Msg.GetReason())

	return connect.NewResponse(&ladulasv1.CancelApprovalResponse{}), nil
}

// Ping answers whether this instance is there and whether anybody can answer a
// prompt on it.
func (s *peerService) Ping(
	ctx context.Context,
	req *connect.Request[ladulasv1.PingRequest],
) (*connect.Response[ladulasv1.PingResponse], error) {
	if _, _, err := s.node.authorize(ctx); err != nil {
		return nil, err
	}

	return connect.NewResponse(&ladulasv1.PingResponse{
		SentAt:       req.Msg.GetSentAt(),
		InstanceName: s.node.identity.Name(),
		CanPrompt:    s.node.canPrompt(),
	}), nil
}

// Watch holds the presence stream open and heartbeats over it, so a requester
// knows whether there is anyone to ask before it has anything to ask.
func (s *peerService) Watch(
	ctx context.Context,
	_ *connect.Request[ladulasv1.WatchRequest],
	stream *connect.ServerStream[ladulasv1.PresenceEvent],
) error {
	if _, _, err := s.node.authorize(ctx); err != nil {
		return err
	}

	ticker := time.NewTicker(s.node.heartbeat)
	defer ticker.Stop()

	for {
		err := stream.Send(&ladulasv1.PresenceEvent{
			Timestamp:    timestamppb.Now(),
			InstanceName: s.node.identity.Name(),
			CanPrompt:    s.node.canPrompt(),
		})
		if err != nil {
			return fmt.Errorf("send a presence heartbeat: %w", err)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// canPrompt reports whether a human here could answer.
//
// It is deliberately about approvers rather than about the process being up: a
// daemon with no tray and no terminal is running, and is still not somewhere a
// question can be asked.
func (n *Node) canPrompt() bool {
	return n.engine.HasLocalApprover()
}
