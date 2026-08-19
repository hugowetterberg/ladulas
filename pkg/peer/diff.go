package peer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/hugowetterberg/ladulas/pkg/gitctx"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
)

// M2 sent the diff capped with the request and left fetching the rest to M4,
// which is this.
//
// The cap is a display decision. A diff travels with something somebody is
// waiting on, to a phone as often as to a desktop, and an unbounded one is both
// a denial of service and a good place to hide a change (§5). It was never a
// statement about what an approver is allowed to see, so an approver that wants
// the rest asks for it — and asks the machine that has the repository, which is
// the requester.
//
// What bounds the question is that it can only be asked about a request that
// this instance has out to that peer at that moment. "Which commits has that
// machine been signing" is not something a paired peer gets to ask at leisure,
// and a registration that outlived the request would make it exactly that.

// outgoing is a request this instance currently has in front of a peer.
type outgoing struct {
	peer string
	git  *ladulasv1.GitContext
}

// track registers a request as being out to a peer, and returns the function
// that takes it back off the list.
func (n *Node) track(requestID, peer string, git *ladulasv1.GitContext) func() {
	if requestID == "" || git == nil {
		return func() {}
	}

	n.mu.Lock()
	n.inflight[requestID] = &outgoing{peer: peer, git: proto.CloneOf(git)}
	n.mu.Unlock()

	return func() {
		n.mu.Lock()
		delete(n.inflight, requestID)
		n.mu.Unlock()
	}
}

func (n *Node) tracked(requestID, peer string) *outgoing {
	n.mu.Lock()
	defer n.mu.Unlock()

	request := n.inflight[requestID]
	if request == nil || request.peer != peer {
		return nil
	}

	return request
}

// FetchDiff serves the rest of a diff to the approver that is looking at it.
func (s *peerService) FetchDiff(
	ctx context.Context,
	req *connect.Request[ladulasv1.FetchDiffRequest],
) (*connect.Response[ladulasv1.FetchDiffResponse], error) {
	peer, _, err := s.node.publisherFor(ctx)
	if err != nil {
		return nil, err
	}

	request := s.node.tracked(req.Msg.GetRequestId(), peer.Fingerprint)
	if request == nil {
		return nil, connect.NewError(connect.CodeNotFound,
			errors.New("this instance is not waiting on that request from you"))
	}

	// The path is a string the asking side sent, and it names a file inside a
	// repository. It is only ever handed to git after the separator that says
	// "everything after this is a path", and only when the diff already names
	// it — an approver expanding a file it was shown, rather than choosing one.
	paths, err := requestedPaths(request.git, req.Msg.GetPath())
	if err != nil {
		return nil, err
	}

	diff := gitctx.CollectDiff(ctx, request.git.GetObject(), gitctx.Options{
		Dir:   request.git.GetRepositoryPath(),
		Paths: paths,
	})

	return connect.NewResponse(&ladulasv1.FetchDiffResponse{Diff: diff}), nil
}

// requestedPaths turns the asked-for file into the argument list git gets.
func requestedPaths(git *ladulasv1.GitContext, name string) ([]string, error) {
	if name == "" {
		return nil, nil
	}

	for _, file := range git.GetDiff().GetFiles() {
		if file.GetNewPath() == name || file.GetOldPath() == name {
			return []string{name}, nil
		}
	}

	return nil, connect.NewError(connect.CodeNotFound,
		fmt.Errorf("the request's diff does not name %q", name))
}

// FetchRemoteDiff asks a requester for the rest of a diff it sent capped.
func (n *Node) FetchRemoteDiff(
	ctx context.Context, fingerprint, requestID, path string,
) (*ladulasv1.GitDiff, error) {
	record, ok := n.trust.Peer(fingerprint)
	if !ok {
		return nil, fmt.Errorf("peer: %s is not a paired peer", fingerprint)
	}

	// A diff fetch is a person waiting at a screen, so it is bounded by
	// something shorter than an approval: a requester that has gone away should
	// turn into a message rather than a spinner.
	ctx, cancel := context.WithTimeout(ctx, diffFetchTimeout)
	defer cancel()

	var diff *ladulasv1.GitDiff

	err := n.call(ctx, record, func(
		ctx context.Context, client *http.Client, baseURL string,
	) error {
		approvals := ladulasv1connect.NewApprovalServiceClient(
			client, baseURL, connect.WithReadMaxBytes(maxProjectBytes))

		resp, err := approvals.FetchDiff(ctx, connect.NewRequest(
			&ladulasv1.FetchDiffRequest{RequestId: requestID, Path: path}))
		if err != nil {
			return err //nolint:wrapcheck // call wraps it with the address
		}

		diff = resp.Msg.GetDiff()

		return nil
	})
	if err != nil {
		return nil, err
	}

	return diff, nil
}

// diffFetchTimeout bounds asking a requester for the rest of a diff.
const diffFetchTimeout = 30 * time.Second
