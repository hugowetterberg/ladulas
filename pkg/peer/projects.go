package peer

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// Project browsing runs in one direction (§6, decision Q): every call arrives
// at a requester from a peer it has agreed to be answered by, so may_approve is
// the gate on all four of them. There is nothing to authorize in the other
// direction because nothing travels in it.

// maxProjectBytes caps a browsing answer. The per-file cap on the serving side
// is well under this; the difference is room for the encoding and for nothing
// else.
const maxProjectBytes = 16 << 20

// publisherFor authorizes the direction a browsing approver comes from.
func (n *Node) publisherFor(
	ctx context.Context,
) (*transport.PeerIdentity, *storepb.TrustRecord, error) {
	peer := transport.PeerFrom(ctx)
	if peer == nil {
		return nil, nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("the connection is not authenticated"))
	}

	record, ok := n.trust.Peer(peer.Fingerprint)
	if !ok {
		return nil, nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("%s is not a paired peer", peer.Fingerprint))
	}

	if !record.GetMayApprove() {
		return nil, nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("%q does not approve for this instance, "+
				"so it has no documentation of ours to read", record.GetName()))
	}

	n.saw(peer.Fingerprint)

	return peer, record, nil
}

// ListProjects tells a browsing approver what this instance publishes.
//
// Publishing is a state (decision Q), so this is how an approver finds out
// there is anything to read at all. It describes the projects and sends none of
// their contents.
func (s *peerService) ListProjects(
	ctx context.Context,
	_ *connect.Request[ladulasv1.ListProjectsRequest],
) (*connect.Response[ladulasv1.ListProjectsResponse], error) {
	if _, _, err := s.node.publisherFor(ctx); err != nil {
		return nil, err
	}

	return connect.NewResponse(&ladulasv1.ListProjectsResponse{
		Projects: s.node.currentProjects(ctx),
	}), nil
}

// ListDirectory serves one page of one directory of a published project.
//
// A page rather than a tree (decision Q). The filter runs here rather than at
// the caller, so a directory of ten thousand files costs one page either way.
func (s *peerService) ListDirectory(
	ctx context.Context,
	req *connect.Request[ladulasv1.ListDirectoryRequest],
) (*connect.Response[ladulasv1.ListDirectoryResponse], error) {
	root, err := s.node.publishedRoot(ctx, req.Msg.GetProject())
	if err != nil {
		return nil, err
	}

	entries, next, total, err := project.ReadDir(
		root, req.Msg.GetPath(), req.Msg.GetFilter(),
		req.Msg.GetPageToken(), int(req.Msg.GetPageSize()),
		s.node.serving)
	if err != nil {
		return nil, browseError(err)
	}

	return connect.NewResponse(&ladulasv1.ListDirectoryResponse{
		Entries:       entries,
		NextPageToken: next,
		Total:         int32(total), //nolint:gosec // a directory listing
	}), nil
}

// SearchProjectFiles finds files by name across a published project.
func (s *peerService) SearchProjectFiles(
	ctx context.Context,
	req *connect.Request[ladulasv1.SearchProjectFilesRequest],
) (*connect.Response[ladulasv1.SearchProjectFilesResponse], error) {
	root, err := s.node.publishedRoot(ctx, req.Msg.GetProject())
	if err != nil {
		return nil, err
	}

	entries, next, truncated, err := project.Search(
		root, req.Msg.GetQuery(), req.Msg.GetPageToken(),
		int(req.Msg.GetPageSize()), s.node.serving)
	if err != nil {
		return nil, browseError(err)
	}

	return connect.NewResponse(&ladulasv1.SearchProjectFilesResponse{
		Entries:       entries,
		NextPageToken: next,
		Truncated:     truncated,
	}), nil
}

// FetchProjectFile serves one file out of a published project.
//
// Every open goes through an os.Root handle and only the kinds this instance
// offers are served. Between them that is §6's rail: browsing cannot be turned
// into a way to read arbitrary files from the requester.
func (s *peerService) FetchProjectFile(
	ctx context.Context,
	req *connect.Request[ladulasv1.FetchProjectFileRequest],
) (*connect.Response[ladulasv1.FetchProjectFileResponse], error) {
	root, err := s.node.publishedRoot(ctx, req.Msg.GetProjectId())
	if err != nil {
		return nil, err
	}

	body, entry, err := project.ReadFile(
		root, req.Msg.GetPath(), s.node.serving)
	if err != nil {
		return nil, browseError(err)
	}

	return connect.NewResponse(&ladulasv1.FetchProjectFileResponse{
		File:    entry,
		Content: body,
	}), nil
}

// publishedRoot authorizes a browsing call and says where the project is.
//
// Two questions, and both have to be asked every time: is the caller a peer
// this instance agreed may approve for it, and is the project one this instance
// actually publishes. A browser's next request is a browser's own choosing, so
// neither is inherited from the listing that produced it.
func (n *Node) publishedRoot(ctx context.Context, id string) (string, error) {
	if _, _, err := n.publisherFor(ctx); err != nil {
		return "", err
	}

	publication, ok := n.trust.Publication(id)
	if !ok {
		return "", connect.NewError(connect.CodeNotFound,
			errors.New("this instance publishes no such project"))
	}

	return publication.GetPath(), nil
}

// browseError keeps a path that tried to leave the project distinguishable
// from one that simply is not there, without handing back anything about the
// filesystem it failed against.
func browseError(err error) error {
	if errors.Is(err, project.ErrOutsideRoot) {
		return connect.NewError(connect.CodePermissionDenied, err)
	}

	return connect.NewError(connect.CodeNotFound, err)
}

// currentProjects re-reads what each published project is right now.
//
// The branch and the commit move whenever somebody works, and an approver is
// listing them in order to compare them against a change it is being asked to
// sign — so the answer is read at the moment of asking rather than remembered
// from the moment of publishing. It costs one git invocation per project and
// reads no file in any of them.
func (n *Node) currentProjects(ctx context.Context) []*ladulasv1.Publication {
	var out []*ladulasv1.Publication

	for _, publication := range n.trust.Publications() {
		current, err := project.Describe(
			ctx, publication.GetPath(), publication.GetName())
		if err != nil {
			// A project whose directory has gone is reported as it was recorded
			// rather than not reported at all: an approver that has read pages
			// of it should be told it is still on offer and stale, not that it
			// vanished.
			n.log.Debug("a published project could not be re-read",
				"project", publication.GetName(), "error", err.Error())

			out = append(out, publication)

			continue
		}

		current.PublishedAt = publication.GetPublishedAt()

		out = append(out, current)
	}

	return out
}

// Publishers implements project.Source: the peers that ask this instance for
// approvals are the ones with documentation it may read.
func (n *Node) Publishers() []project.Publisher {
	var out []project.Publisher

	for _, record := range n.trust.Peers() {
		if !record.GetMayRequest() {
			continue
		}

		out = append(out, project.Publisher{
			Name:        record.GetName(),
			Fingerprint: record.GetFingerprint(),
		})
	}

	return out
}

// Ask implements project.Source by running one browsing exchange against one
// peer over the pinned-TLS channel.
func (n *Node) Ask(
	ctx context.Context, fingerprint string,
	fn func(context.Context, ladulasv1connect.ProjectServiceClient) error,
) error {
	record, ok := n.trust.Peer(fingerprint)
	if !ok {
		return fmt.Errorf("peer: %s is not a paired peer", fingerprint)
	}

	return n.call(ctx, record, func(
		ctx context.Context, client *http.Client, baseURL string,
	) error {
		return fn(ctx, ladulasv1connect.NewProjectServiceClient(
			client, baseURL, connect.WithReadMaxBytes(maxProjectBytes)))
	})
}
