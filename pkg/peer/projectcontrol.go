package peer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// The projects verbs of §14. Everything the GUI could do about publishing is
// one of these three, and `ladulas projects …` is a thin client of them.
//
// They go through the daemon rather than opening the store behind its back for
// the reason every other verb does (decision L): the daemon is the one process
// that has the store open, and a second one writing to it would silently
// discard whatever the daemon has learned since.

// PublishProject marks a project as published to this instance's approvers.
//
// It sends nothing (decision Q). Publishing is a state: an approver that wants
// to read the project lists its directories, searches them, and fetches the
// files it opens, all against this instance while it is reachable. What is
// recorded here is that the project is on offer and where it lives.
func (n *Node) PublishProject(
	ctx context.Context,
	req *connect.Request[ladulasv1.PublishProjectRequest],
) (*connect.Response[ladulasv1.PublishProjectResponse], error) {
	dir := req.Msg.GetPath()
	if dir == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("no directory to publish"))
	}

	// A relative path is refused rather than resolved. This process's working
	// directory is a systemd unit's, so resolving one here would silently
	// publish some directory under the daemon's cwd — or fail to find
	// anything — while the caller believes it published the one it was
	// standing in. The caller is the only side that knows where that is.
	if !filepath.IsAbs(dir) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
			"the directory to publish must be an absolute path, got %q", dir))
	}

	// The project is still read once, to work out what it is called, where its
	// origin points and what commit it is at — the identity an approver lists
	// and a signing request is matched against. What is not read is its
	// contents.
	publication, err := project.Describe(ctx, dir, req.Msg.GetName())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}

		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	if err := n.trust.PutPublication(publication); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	n.engine.LogLifecycle(fmt.Sprintf(
		"published %q from %s",
		publication.GetName(), publication.GetPath()))

	return connect.NewResponse(&ladulasv1.PublishProjectResponse{
		Publication: publication,
	}), nil
}

// ListPublications reports both halves: what we publish, and what we have read
// of what others publish.
func (n *Node) ListPublications(
	_ context.Context,
	_ *connect.Request[ladulasv1.ListPublicationsRequest],
) (*connect.Response[ladulasv1.ListPublicationsResponse], error) {
	resp := &ladulasv1.ListPublicationsResponse{
		Published:   n.trust.Publications(),
		AutoPublish: n.trust.AutoPublish(),
	}

	if n.projects != nil {
		cached, err := n.projects.List()
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}

		resp.Cached = cached
	}

	return connect.NewResponse(resp), nil
}

// UnpublishProject withdraws one of ours, or forgets what has been read of one
// of theirs.
//
// One verb for both directions, because "stop showing me these documents" is
// one intent whichever end of a pairing it is typed at. Ours is looked for
// first: a name somebody typed is far more likely to be a project they publish
// than one they have been reading.
func (n *Node) UnpublishProject(
	_ context.Context,
	req *connect.Request[ladulasv1.UnpublishProjectRequest],
) (*connect.Response[ladulasv1.UnpublishProjectResponse], error) {
	ref := req.Msg.GetProject()

	if _, ok := n.trust.Publication(ref); ok {
		return n.withdraw(ref)
	}

	if n.projects == nil {
		return nil, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("no project %q is published from here", ref))
	}

	cached, err := n.cachedProject(ref)
	if err != nil {
		return nil, err
	}

	if err := n.projects.Drop(cached.GetKey()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	n.engine.LogLifecycle(fmt.Sprintf(
		"forgot the %d pages read of %q on %s",
		len(cached.GetFiles()), cached.GetProject().GetName(), cached.GetPeer()))

	return connect.NewResponse(&ladulasv1.UnpublishProjectResponse{
		ProjectId: cached.GetProject().GetProjectId(),
		Forgotten: int32(len(cached.GetFiles())), //nolint:gosec // a page count
	}), nil
}

// SetAutoPublish turns the default of decision Q on or off.
//
// It is recorded either way, including the answer that matches the default: a
// machine whose owner has said no should not start publishing again because a
// later version changed its mind about defaults.
func (n *Node) SetAutoPublish(
	_ context.Context,
	req *connect.Request[ladulasv1.SetAutoPublishRequest],
) (*connect.Response[ladulasv1.SetAutoPublishResponse], error) {
	if err := n.trust.SetAutoPublish(req.Msg.GetEnabled()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if req.Msg.GetEnabled() {
		n.engine.LogLifecycle(
			"projects a signature is asked for in are published automatically")
	} else {
		n.engine.LogLifecycle(
			"projects a signature is asked for in are no longer published automatically")
	}

	return connect.NewResponse(&ladulasv1.SetAutoPublishResponse{
		Enabled: req.Msg.GetEnabled(),
	}), nil
}

// withdraw stops publishing one of ours.
//
// It tells nobody, because there is nobody holding a copy to tell (decision Q).
// An approver that browses this project next asks for a listing and is told
// there is no such project; the pages it has already read stay where they are,
// which is the same as any other page it has already looked at.
func (n *Node) withdraw(
	ref string,
) (*connect.Response[ladulasv1.UnpublishProjectResponse], error) {
	publication, err := n.trust.RemovePublication(ref)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	n.engine.LogLifecycle("stopped publishing " + publication.GetName())

	return connect.NewResponse(&ladulasv1.UnpublishProjectResponse{
		ProjectId:     publication.GetProjectId(),
		PublishedHere: true,
	}), nil
}

// cachedProject finds a project something has been read of, by key, by project
// id or by name.
func (n *Node) cachedProject(ref string) (*ladulasv1.CachedProject, error) {
	cached, err := n.projects.List()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	for _, candidate := range cached {
		if candidate.GetKey() == ref ||
			candidate.GetProject().GetProjectId() == ref ||
			strings.EqualFold(candidate.GetProject().GetName(), ref) {
			return candidate, nil
		}
	}

	return nil, connect.NewError(connect.CodeNotFound,
		fmt.Errorf("no project %q is published from here or has been read here", ref))
}

// Projects is what this instance has read of other instances' projects, for an
// embedder that wants to show it — the tray does, in the same process.
func (n *Node) Projects() *project.Cache {
	return n.projects
}

// dropPeerProjects is the other half of revoking a pairing (§7): a peer that is
// no longer trusted should not still be occupying the doc browser.
func (n *Node) dropPeerProjects(record *storepb.TrustRecord) {
	if n.projects == nil {
		return
	}

	dropped, err := n.projects.DropPeer(record.GetFingerprint())
	if err != nil {
		n.log.Error("could not drop a revoked peer's documentation",
			"peer", record.GetFingerprint(), "error", err.Error())

		return
	}

	if dropped > 0 {
		n.log.Info("dropped a revoked peer's documentation",
			"peer", record.GetFingerprint(), "projects", dropped)
	}
}
