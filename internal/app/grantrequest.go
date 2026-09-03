package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// RequestGrant asks for a promise ahead of the login it is about (decision AO).
//
// It is the only place a request is built that will never be signed, and the
// shape of it is dictated entirely by what has to match later: a grant's scope
// is compared for strict equality against the scope the real login derives
// (approval.covers), so every field that goes into that scope has to be the
// value the login will produce. Key, kind, username, host key and session, and
// a mistake in any one of them is a promise that covers nothing and says
// nothing about why.
//
// The session is the field worth being careful about, because it is the one
// this side supplies rather than the caller. It comes from the control socket's
// peer credentials — the session of the process that called — which is the same
// POSIX session the ssh it is about will run in, as long as `ssh-grant` stays
// in the foreground of the shell that will run it. That is why the command
// blocks rather than detaching, and it is the reason the promise made is the
// narrower of the two reaches by default (decision U).
func (s *controlService) RequestGrant(
	ctx context.Context, req *connect.Request[ladulasv1.RequestGrantRequest],
) (*connect.Response[ladulasv1.RequestGrantResponse], error) {
	if _, err := s.vault(); err != nil {
		return nil, err
	}

	msg := req.Msg

	hostKey, err := ssh.ParsePublicKey(msg.GetHostKey())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("parse the host key: %w", err))
	}

	key, err := s.findKeyRef(msg.GetPublicKey())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	if msg.GetUsername() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("no user name; a promise is scoped to one and cannot "+
				"be made without it"))
	}

	request := s.grantRequest(ctx, msg, key, hostKey)

	resp, err := s.app.Engine().Submit(ctx, request)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("approval: %w", err))
	}

	out := &ladulasv1.RequestGrantResponse{
		Decision: resp.GetDecision(),
		Reason:   resp.GetReason(),
		Grant:    resp.GetGrant(),
	}

	return connect.NewResponse(out), nil
}

// grantRequest builds the request a login would make, with nothing to sign.
//
// The host key is put in payload_destination as well as destination, because
// payload_destination is the field the scope is derived from — and the scope is
// the entire point of the exercise. Calling it that is a small lie for the
// length of this function: there is no payload. It is the right lie, because
// the alternative is a second field meaning the same thing that scopeFor would
// have to learn about, and then two ways for a promise and a login to disagree
// about which host they are talking about.
func (s *controlService) grantRequest(
	ctx context.Context,
	msg *ladulasv1.RequestGrantRequest,
	key *ladulasv1.KeyRef,
	hostKey ssh.PublicKey,
) *ladulasv1.ApprovalRequest {
	requester := s.app.requesterInfo()
	requester.Local = true
	requester.Process = localapi.PeerFrom(ctx)

	host := &ladulasv1.HostKey{
		Algorithm:   hostKey.Type(),
		Blob:        msg.GetHostKey(),
		Fingerprint: ssh.FingerprintSHA256(hostKey),
		// The caller checked it against the known_hosts files ssh itself would
		// have used, and refuses to get this far without a match. Saying so is
		// not the caller being believed about the host: it is being believed
		// about having done the check, and the check is repeated in the only
		// way that finally matters when the login happens and the fingerprint
		// has to equal the one inside the signed payload.
		Known: true,
	}

	return &ladulasv1.ApprovalRequest{
		RequestId: identity.NewRequestID(),
		CreatedAt: timestamppb.Now(),
		Requester: requester,
		// The login's own kind, because the promise has to carry it: a scope
		// pins the kind, and a request wearing one of its own would mint a
		// grant that could never cover the thing it was asked for.
		Kind:      ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH,
		Key:       key,
		GrantOnly: true,
		Operation: &ladulasv1.ApprovalRequest_SshAuth{
			SshAuth: &ladulasv1.SshAuthRequest{
				Username: msg.GetUsername(),
				Service:  "ssh-connection",
				// The method a hostbound login uses, which is the one that puts
				// the host key inside the signed bytes and therefore the only
				// one whose scope this promise can ever match (§4). A server too
				// old to offer it produces logins that scope to an empty
				// destination, and a promise made here would not cover them —
				// said plainly by the command rather than discovered later.
				Method:             "publickey-hostbound-v00@openssh.com",
				Bound:              true,
				Destination:        host,
				PayloadDestination: host,
				DestinationLabel:   msg.GetDestinationLabel(),
			},
		},
		// The length asked for is a suggestion on the offer and nothing else.
		// It deliberately does not go in Timeout: that field is how long the
		// requester will wait for an answer, and setting it from the promise
		// length would make `--for 5m` a five-minute deadline to answer in —
		// exactly the short clock this command exists to get away from.
		RequestedGrantTtl: msg.GetTtl(),
	}
}

// findKeyRef resolves the key the server accepted to the reference this
// instance knows it by, looking where the agent looks: the store first, then
// the keys a paired holder is lending (decision N).
func (s *controlService) findKeyRef(blob []byte) (*ladulasv1.KeyRef, error) {
	if len(blob) == 0 {
		return nil, errors.New("no key was named")
	}

	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	for _, ref := range vault.KeyRefs() {
		if bytes.Equal(ref.GetPublicKey(), blob) {
			return ref, nil
		}
	}

	if node := s.app.Peer(); node != nil {
		for _, ref := range node.RemoteKeyRefs() {
			if bytes.Equal(ref.GetPublicKey(), blob) {
				return ref, nil
			}
		}

		if ref, ok := node.BorrowedKey(blob); ok {
			return ref, nil
		}
	}

	return nil, errors.New(
		"the server accepted a key this instance does not hold or borrow")
}
