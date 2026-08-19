package peer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// RemoteApprover is a paired peer, as the approval engine sees it: something
// that can be shown a request and will eventually say yes or no.
//
// It is registered alongside the local GUI and answers the same fan-out, which
// is the whole of "first response wins" as far as the requester is concerned.
// The peer that answers first settles the request, the losers have their
// contexts cancelled, and cancelling a streamed RPC is what takes the prompt
// off the other machine's screen.
type RemoteApprover struct {
	link *link
}

var _ approval.RemoteHandler = (*RemoteApprover)(nil)

// ID implements approval.Handler.
func (a *RemoteApprover) ID() string {
	return "peer " + a.link.Name()
}

// Peer implements approval.RemoteHandler.
func (a *RemoteApprover) Peer() string {
	return a.link.Fingerprint()
}

// Decide implements approval.Handler by asking the peer.
func (a *RemoteApprover) Decide(
	ctx context.Context, req *approval.Request,
) (*approval.Answer, error) {
	msg, body, err := a.link.node.outgoing(ctx, req)
	if err != nil {
		return nil, err
	}

	digest := identity.Digest(body)

	// While the peer is looking at this, it may ask for the rest of the diff
	// the caps cut short (§5). Only while, and only this peer.
	defer a.link.node.track(msg.GetRequestId(), a.link.Fingerprint(),
		msg.GetSshsig().GetGitContext())()

	addresses := a.link.addresses()
	if len(addresses) == 0 {
		return nil, errors.New("peer: the peer has no address to dial")
	}

	var lastErr error

	for _, address := range addresses {
		answer, err := a.ask(ctx, address, msg.GetRequestId(), body, digest)
		if err == nil {
			a.link.succeeded(address)

			return answer, nil
		}

		if ctx.Err() != nil {
			return nil, err
		}

		lastErr = err
	}

	a.link.failed(lastErr)

	return nil, lastErr
}

// outgoing builds the request as the peer should see it.
//
// It is a copy rather than the request the engine is holding, because the two
// are genuinely different documents: here it is a local operation with a
// process behind it, and there it is a request from a named machine that has no
// screen. The copy is what gets serialized and digested, so the answer that
// comes back commits to what was actually sent.
func (n *Node) outgoing(
	ctx context.Context, req *approval.Request,
) (*ladulasv1.ApprovalRequest, []byte, error) {
	msg := proto.CloneOf(req.Msg)

	requester := msg.GetRequester()
	if requester == nil {
		requester = &ladulasv1.RequesterInfo{}
		msg.Requester = requester
	}

	requester.InstanceId = n.identity.Fingerprint()
	requester.Name = n.identity.Name()
	requester.Local = false
	requester.Headless = n.headless

	// The peer should stop waiting when we do. Its own policy may allow longer,
	// and a prompt left on a screen after the requester has given up is how an
	// approver ends up approving something that is no longer happening.
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, nil, context.DeadlineExceeded
		}

		msg.Timeout = durationpb.New(remaining)
	}

	n.autoPublish(ctx, msg.GetSshsig().GetGitContext())

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("peer: serialize the request: %w", err)
	}

	return msg, body, nil
}

// autoPublish marks the project a request is about as published, on the way
// past (decision Q).
//
// This is the case the setting exists for: the moment an approver most wants a
// project's documentation is while it is being asked to sign something in it,
// and having to remember to publish in advance is how nobody ever has it. It is
// a setting rather than the only behaviour, because a machine that signs in
// repositories it would rather not name should be able to say so.
//
// A project that is already published is left alone rather than re-described.
// Nothing about the record goes stale — the branch and the commit are re-read
// every time an approver lists it — so the git invocation here happens once per
// project rather than once per signature.
func (n *Node) autoPublish(ctx context.Context, git *ladulasv1.GitContext) {
	id := git.GetProjectId()

	if id == "" || git.GetRepositoryPath() == "" || !n.trust.AutoPublish() {
		return
	}

	if _, ok := n.trust.Publication(id); ok {
		return
	}

	publication, err := project.Describe(ctx, git.GetRepositoryPath(), "")
	if err != nil {
		// Failing to publish is not a reason to fail a signature. The approver
		// gets a card that names a project it cannot open, which is what it
		// would have got before this existed.
		n.log.Debug("a project could not be published automatically",
			"path", git.GetRepositoryPath(), "error", err.Error())

		return
	}

	if err := n.trust.PutPublication(publication); err != nil {
		n.log.Error("a project could not be published automatically",
			"path", git.GetRepositoryPath(), "error", err.Error())

		return
	}

	n.engine.LogLifecycle(fmt.Sprintf(
		"published %q from %s, because a signature was asked for in it",
		publication.GetName(), publication.GetPath()))
}

// ask runs one streamed RequestApproval against one address.
func (a *RemoteApprover) ask(
	ctx context.Context, address, requestID string, body, digest []byte,
) (*approval.Answer, error) {
	client := a.link.approvalClient(address)

	stream, err := client.RequestApproval(ctx, connect.NewRequest(
		&ladulasv1.RequestApprovalRequest{Request: body}))
	if err != nil {
		return nil, fmt.Errorf("peer: ask %s: %w", a.link.Name(), err)
	}

	defer func() {
		_ = stream.Close()
	}()

	for stream.Receive() {
		event := stream.Msg()

		if event.GetKind() != ladulasv1.ApprovalEventKind_APPROVAL_EVENT_KIND_DECIDED {
			continue
		}

		answer, decision, err := a.link.answerFrom(
			event.GetApproval(), requestID, digest)
		if err != nil {
			return nil, err
		}

		// A standing permission may come back beside the answer (decision P).
		// It is a separate claim from the answer and is checked separately;
		// refusing it does not refuse the request that was approved.
		a.link.node.acceptDelegation(a.link.Record(), a.link.key, decision)

		return answer, nil
	}

	if err := stream.Err(); err != nil {
		return nil, fmt.Errorf("peer: ask %s: %w", a.link.Name(), err)
	}

	return nil, fmt.Errorf("peer: %s closed the stream without deciding",
		a.link.Name())
}

// answerFrom turns a peer's signed artifact into an answer, having checked
// every way it could be the wrong one.
//
// It lives on the link rather than on the approver because a borrowed signature
// comes back with the same artifact on it and has to survive the same checks:
// the only difference between "the peer said yes" and "the peer said yes and
// here is the signature" is what arrives beside the answer (§8).
//
// The order matters. The signature is verified first, so nothing an attacker
// controls is parsed on the strength of the artifact alone; then the key that
// signed it is checked against the trust record, because a valid signature by
// somebody else is not an approval; then the request identifier and the digest,
// because an approval of a different request is not an approval of this one.
func (l *link) answerFrom(
	signed *ladulasv1.SignedApproval, requestID string, digest []byte,
) (*approval.Answer, *ladulasv1.ApprovalResponse, error) {
	return answerFromPeer(l.Record(), l.key, signed, requestID, digest)
}

// answerFromPeer is the check itself, on nothing but a trust record and the key
// it names.
//
// It sits apart from the link because an answer does not always come back down
// the connection that asked. An approver that collects its requests rather than
// being dialled (see inbox.go) posts the same artifact through a call of its
// own, and it has to survive exactly the same suspicions.
func answerFromPeer(
	record *storepb.TrustRecord,
	key ssh.PublicKey,
	signed *ladulasv1.SignedApproval,
	requestID string,
	digest []byte,
) (*approval.Answer, *ladulasv1.ApprovalResponse, error) {
	name := record.GetName()

	if signed == nil {
		return nil, nil, fmt.Errorf("peer: %s decided without saying what", name)
	}

	resp, pub, err := identity.VerifyApproval(signed)
	if err != nil {
		return nil, nil, fmt.Errorf("peer: %s sent an unverifiable decision: %w",
			name, err)
	}

	if !bytes.Equal(pub.Marshal(), key.Marshal()) {
		return nil, nil, fmt.Errorf(
			"peer: the decision from %s was signed by %s, which is not the paired key",
			name, signed.GetApproverFingerprint())
	}

	if resp.GetRequestId() != requestID {
		return nil, nil, fmt.Errorf("peer: %s answered request %q, not %q",
			name, resp.GetRequestId(), requestID)
	}

	if !bytes.Equal(resp.GetRequestDigest(), digest) {
		return nil, nil, fmt.Errorf(
			"peer: %s answered a request whose contents differ from the one sent",
			name)
	}

	// The approver's own account of who it is is not what gets recorded. The
	// signature was checked against the trust record, so the record is what
	// names the answer — with the name this instance's user gave the peer, not
	// the one the peer gave itself.
	answer := &approval.Answer{
		Decision: resp.GetDecision(),
		Source:   resp.GetSource(),
		Reason:   fmt.Sprintf("%s: %s", record.GetName(), resp.GetReason()),
		Approver: &ladulasv1.ApproverInfo{
			InstanceId: record.GetFingerprint(),
			Name:       record.GetName(),
			Local:      false,
		},
		Signed: signed,
	}

	return answer, resp, nil
}
