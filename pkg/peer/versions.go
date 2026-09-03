package peer

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The three calls decision AP added to ProjectService, from the publisher's
// side.
//
// They run in the same direction as the rest of the service and under the same
// gate: every one of them goes through publishedRoot, which asks both questions
// again — is the caller a peer this instance agreed may approve for it, and is
// the project one this instance actually publishes. Nothing is inherited from
// the call that produced the handle a caller is using, because a browser's next
// request is a browser's own choosing.
//
// Nothing here reaches past this machine. The version store and the repository
// are both local, and both are addressed by a project id the caller has just
// been authorized for — so there is no upstream call made with this instance's
// own credentials on a caller's behalf, and nothing to escalate.

// SyncProject reconciles what an approver holds against what this instance
// pushes, and streams the difference.
func (s *peerService) SyncProject(
	ctx context.Context,
	req *connect.Request[ladulasv1.SyncProjectRequest],
	stream *connect.ServerStream[ladulasv1.SyncProjectEvent],
) error {
	root, err := s.node.publishedRoot(ctx, req.Msg.GetProjectId())
	if err != nil {
		return err
	}

	have := make(map[string][]byte, len(req.Msg.GetHave()))

	for _, entry := range req.Msg.GetHave() {
		// A manifest is a distrusted machine's list of strings, and every one
		// of them is about to be compared against a path on this disk. One that
		// is not a plain relative path is dropped rather than refused: a single
		// bad line should not cost the approver its whole sync.
		if project.CheckPath(entry.GetPath()) != nil {
			continue
		}

		have[entry.GetPath()] = entry.GetDigest()
	}

	// The publisher's account of itself travels in the same exchange as the
	// documents, so that a caller is not stitching a commit from one answer
	// onto contents from another (§6).
	publication, ok := s.node.trust.Publication(req.Msg.GetProjectId())
	if !ok {
		return connect.NewError(connect.CodeNotFound,
			errors.New("this instance publishes no such project"))
	}

	described, err := project.Describe(
		ctx, publication.GetPath(), publication.GetName())
	if err != nil {
		described = publication
	} else {
		described.PublishedAt = publication.GetPublishedAt()
	}

	if err := stream.Send(&ladulasv1.SyncProjectEvent{
		Project: described,
	}); err != nil {
		return fmt.Errorf("send the project header: %w", err)
	}

	result, err := project.Reconcile(root, have, s.node.serving,
		func(change project.SyncChange) error {
			event := &ladulasv1.SyncProjectEvent{
				Kind: ladulasv1.SyncChangeKind_SYNC_CHANGE_KIND_PUT,
				Path: change.Path,
			}

			if change.Removed {
				event.Kind = ladulasv1.SyncChangeKind_SYNC_CHANGE_KIND_REMOVE
			} else {
				event.File = change.Entry
				event.Content = change.Content
			}

			return stream.Send(event)
		})
	if err != nil {
		return browseError(err)
	}

	if result.Truncated {
		s.node.log.Warn(
			"a project sync hit its cap and answered incompletely",
			"project", req.Msg.GetProjectId(),
			"walked", result.Walked, "bytes", result.Bytes)
	}

	return nil
}

// DocumentVersions is the two histories of one document: the working-tree
// states since the last commit, then the commits that touched it.
func (s *peerService) DocumentVersions(
	ctx context.Context,
	req *connect.Request[ladulasv1.DocumentVersionsRequest],
) (*connect.Response[ladulasv1.DocumentVersionsResponse], error) {
	root, err := s.node.publishedRoot(ctx, req.Msg.GetProjectId())
	if err != nil {
		return nil, err
	}

	rel := req.Msg.GetPath()

	if err := project.CheckPath(rel); err != nil {
		return nil, browseError(err)
	}

	serving := s.node.serving

	// A kind this instance will not hand over has no history to offer either.
	// Saying so through the same rail as a read keeps one answer to "may I see
	// this file", rather than a second one that could drift from it.
	if !serving.Policy.Serves(rel) {
		return nil, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("%s is not a kind this instance offers to read", rel))
	}

	response := &ladulasv1.DocumentVersionsResponse{}

	// The document as it stands, hashed here so that a reader can answer "is
	// what I am holding current" without another call.
	if body, _, err := project.ReadFile(root, rel, serving); err == nil {
		digest := sha256.Sum256(body)
		response.CurrentDigest = digest[:]
	}

	repo, repoErr := project.OpenRepository(root)

	if repoErr == nil {
		head, err := repo.Head()
		if err != nil {
			s.node.log.Debug("a published project's HEAD could not be read",
				"project", req.Msg.GetProjectId(), "error", err.Error())
		}

		response.Head = head
	}

	response.Versions = append(response.Versions,
		s.snapshotVersions(req.Msg.GetProjectId(), rel, response.GetHead())...)

	if repoErr == nil && serving.Policy.History(rel) != project.VersionsNone {
		limit := commitLimit(int(req.Msg.GetCommitLimit()))

		commits, err := repo.CommitsTouching(rel, limit)
		if err != nil {
			return nil, browseError(err)
		}

		for _, commit := range commits {
			response.Versions = append(response.Versions,
				&ladulasv1.DocumentVersion{
					Kind:    ladulasv1.DocumentVersionKind_DOCUMENT_VERSION_KIND_COMMIT,
					Commit:  commit.Hash,
					At:      timestamppb.New(commit.When),
					Subject: commit.Subject,
					Author:  commit.Author,
				})
		}

		response.Truncated = len(commits) == limit
	}

	return connect.NewResponse(response), nil
}

// snapshotVersions is the working-tree half, newest first.
//
// The store keeps them oldest first, because that is the order a reader walks
// forward through; a version list is read the other way round, newest at the
// top, so it is reversed here rather than stored twice.
func (s *peerService) snapshotVersions(
	projectID, rel, head string,
) []*ladulasv1.DocumentVersion {
	if s.node.versions == nil || head == "" {
		return nil
	}

	if !s.node.serving.Policy.Snapshots(rel) {
		return nil
	}

	snapshots := s.node.versions.Snapshots(projectID, rel, head)

	out := make([]*ladulasv1.DocumentVersion, 0, len(snapshots))

	for i := len(snapshots) - 1; i >= 0; i-- {
		out = append(out, &ladulasv1.DocumentVersion{
			Kind:   ladulasv1.DocumentVersionKind_DOCUMENT_VERSION_KIND_SNAPSHOT,
			Digest: snapshots[i].GetDigest(),
			Size:   snapshots[i].GetSize(),
			At:     snapshots[i].GetTakenAt(),
		})
	}

	return out
}

// FetchProjectVersion returns one version's contents.
func (s *peerService) FetchProjectVersion(
	ctx context.Context,
	req *connect.Request[ladulasv1.FetchProjectVersionRequest],
) (*connect.Response[ladulasv1.FetchProjectVersionResponse], error) {
	root, err := s.node.publishedRoot(ctx, req.Msg.GetProjectId())
	if err != nil {
		return nil, err
	}

	rel := req.Msg.GetPath()

	if err := project.CheckPath(rel); err != nil {
		return nil, browseError(err)
	}

	if !s.node.serving.Policy.Serves(rel) {
		return nil, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("%s is not a kind this instance offers to read", rel))
	}

	digest := req.Msg.GetDigest()
	commit := req.Msg.GetCommit()

	// Exactly one, because the two name different things and a request that
	// carried both would be asking this side to choose which version the reader
	// meant.
	if (len(digest) == 0) == (commit == "") {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("name either a snapshot digest or a commit, and not both"))
	}

	if len(digest) > 0 {
		return s.snapshotContent(req.Msg.GetProjectId(), rel, digest)
	}

	return s.commitContent(root, rel, commit)
}

func (s *peerService) snapshotContent(
	projectID, rel string, digest []byte,
) (*connect.Response[ladulasv1.FetchProjectVersionResponse], error) {
	if s.node.versions == nil {
		return nil, connect.NewError(connect.CodeNotFound,
			errors.New("this instance keeps no working-tree versions"))
	}

	body, err := s.node.versions.Content(projectID, digest)

	// A snapshot that expired between the list and this call is a NOT_FOUND
	// rather than the commit behind it. Substituting would hand a reader a
	// version they did not ask for, and a change tracked against the wrong
	// version shows edits nobody made.
	if errors.Is(err, project.ErrNoSuchSnapshot) {
		return nil, connect.NewError(connect.CodeNotFound,
			errors.New("that version is no longer kept: the project has moved "+
				"to another commit since it was listed"))
	}

	if err != nil {
		return nil, browseError(err)
	}

	return connect.NewResponse(&ladulasv1.FetchProjectVersionResponse{
		File: &ladulasv1.ProjectEntry{
			Name:     path.Base(rel),
			Path:     rel,
			Size:     int64(len(body)),
			Readable: true,
		},
		Content: body,
		Version: &ladulasv1.DocumentVersion{
			Kind:   ladulasv1.DocumentVersionKind_DOCUMENT_VERSION_KIND_SNAPSHOT,
			Digest: digest,
			Size:   int64(len(body)),
		},
	}), nil
}

func (s *peerService) commitContent(
	root, rel, commit string,
) (*connect.Response[ladulasv1.FetchProjectVersionResponse], error) {
	repo, err := project.OpenRepository(root)
	if err != nil {
		return nil, browseError(err)
	}

	body, err := repo.ContentAt(commit, rel)
	if err != nil {
		return nil, browseError(err)
	}

	if int64(len(body)) > s.node.serving.Caps().FileBytes {
		return nil, connect.NewError(connect.CodeResourceExhausted,
			fmt.Errorf("%s at %s is larger than this instance sends", rel, commit))
	}

	return connect.NewResponse(&ladulasv1.FetchProjectVersionResponse{
		File: &ladulasv1.ProjectEntry{
			Name:     path.Base(rel),
			Path:     rel,
			Size:     int64(len(body)),
			Readable: true,
		},
		Content: body,
		Version: &ladulasv1.DocumentVersion{
			Kind:   ladulasv1.DocumentVersionKind_DOCUMENT_VERSION_KIND_COMMIT,
			Commit: commit,
			Size:   int64(len(body)),
		},
	}), nil
}

// commitLimit bounds how far back a version list walks. The shape is
// browse.go's page size: zero means the default and anything past the maximum
// is trimmed to it, so a caller cannot ask this machine to walk a repository's
// whole history while somebody waits.
func commitLimit(want int) int {
	switch {
	case want <= 0:
		return project.DefaultCommitLimit
	case want > project.MaxCommitLimit:
		return project.MaxCommitLimit
	default:
		return want
	}
}

// kindPolicies is what this instance does with each kind of file, as an
// approver is told it (decision AP).
//
// An approver needs it to tell three silences apart: a document that has not
// been pushed yet, one that will never be pushed and has to be asked for, and a
// kind this publisher does not serve at all. Without it an empty sync answer
// and a project full of unservable files look the same.
func kindPolicies(serving project.Serving) []*ladulasv1.KindPolicy {
	kinds := serving.Kinds()

	out := make([]*ladulasv1.KindPolicy, 0, len(kinds))

	for _, kind := range kinds {
		out = append(out, &ladulasv1.KindPolicy{
			Name:       kind.Name,
			Extensions: kind.Extensions,
			Serve:      kind.Serve,
			Push:       kind.Serve && kind.Distribute == project.DistributePush,
			Versions:   string(kind.Versions),
		})
	}

	return out
}
