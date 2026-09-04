package app

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The doc browser over the control socket (§6, decision Z).
//
// Both halves of an answer are this process's: what a peer publishes is read
// over the peer channel, which needs the identity key, and what has been read
// before is kept in a cache sealed with the store key. So a front end asks and
// this answers, exactly as it asks for a key list — and the provenance travels
// with the answer, because "the publisher says so" and "this is what was read
// of it once" are different claims (decision Q).

// ErrNoBrowser is what a sealed instance has instead of a doc browser: the
// pages are sealed with the store key, and there is nothing to read until
// somebody unlocks it.
var ErrNoBrowser = errors.New("the store is sealed, so there is nothing to browse")

func (s *controlService) browser() (*project.Browser, error) {
	browser := s.app.Browser()
	if browser == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, ErrNoBrowser)
	}

	return browser, nil
}

func (s *controlService) ListPeerProjects(
	ctx context.Context, req *connect.Request[ladulasv1.ListPeerProjectsRequest],
) (*connect.Response[ladulasv1.ListPeerProjectsResponse], error) {
	browser, err := s.browser()
	if err != nil {
		return nil, err
	}

	// Kept is the list a screen draws first, without asking anybody; List is
	// the publishers' answer that replaces it (§6).
	list := browser.List
	if req.Msg.GetKeptOnly() {
		list = browser.Kept
	}

	found, err := list(ctx, req.Msg.GetFingerprint())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &ladulasv1.ListPeerProjectsResponse{}

	for _, overview := range found {
		resp.Projects = append(resp.Projects, project.OverviewWire(overview))
	}

	return connect.NewResponse(resp), nil
}

func (s *controlService) OpenPeerProject(
	ctx context.Context, req *connect.Request[ladulasv1.OpenPeerProjectRequest],
) (*connect.Response[ladulasv1.OpenPeerProjectResponse], error) {
	browser, err := s.browser()
	if err != nil {
		return nil, err
	}

	// Cached is the call a card makes: somebody is waiting in front of it, and
	// asking a machine that may be asleep is not what a card does (decision Q).
	if req.Msg.GetCachedOnly() {
		overview, ok := browser.Cached(
			req.Msg.GetFingerprint(), req.Msg.GetProjectId())

		return connect.NewResponse(&ladulasv1.OpenPeerProjectResponse{
			Project: project.OverviewWire(overview),
			Found:   ok,
		}), nil
	}

	overview, err := browser.Open(
		ctx, req.Msg.GetFingerprint(), req.Msg.GetProjectId())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	return connect.NewResponse(&ladulasv1.OpenPeerProjectResponse{
		Project: project.OverviewWire(overview),
		Found:   true,
	}), nil
}

func (s *controlService) ListPeerDirectory(
	ctx context.Context, req *connect.Request[ladulasv1.ListPeerDirectoryRequest],
) (*connect.Response[ladulasv1.ListPeerDirectoryResponse], error) {
	browser, err := s.browser()
	if err != nil {
		return nil, err
	}

	var listing *project.Listing

	if req.Msg.GetKeptOnly() {
		listing, err = browser.KeptDirectory(
			ctx, req.Msg.GetFingerprint(), req.Msg.GetProjectId(), req.Msg.GetPath(),
			req.Msg.GetFilter())
	} else {
		listing, err = browser.Directory(ctx,
			req.Msg.GetFingerprint(), req.Msg.GetProjectId(), req.Msg.GetPath(),
			req.Msg.GetFilter(), req.Msg.GetToken(), int(req.Msg.GetSize()))
	}

	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	return connect.NewResponse(&ladulasv1.ListPeerDirectoryResponse{
		Listing: project.ListingWire(listing),
	}), nil
}

func (s *controlService) SearchPeerProject(
	ctx context.Context, req *connect.Request[ladulasv1.SearchPeerProjectRequest],
) (*connect.Response[ladulasv1.SearchPeerProjectResponse], error) {
	browser, err := s.browser()
	if err != nil {
		return nil, err
	}

	listing, err := browser.Search(ctx,
		req.Msg.GetFingerprint(), req.Msg.GetProjectId(), req.Msg.GetQuery(),
		req.Msg.GetToken(), int(req.Msg.GetSize()))
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	return connect.NewResponse(&ladulasv1.SearchPeerProjectResponse{
		Listing: project.ListingWire(listing),
	}), nil
}

func (s *controlService) ReadPeerPage(
	ctx context.Context, req *connect.Request[ladulasv1.ReadPeerPageRequest],
) (*connect.Response[ladulasv1.ReadPeerPageResponse], error) {
	browser, err := s.browser()
	if err != nil {
		return nil, err
	}

	page, err := browser.File(ctx,
		req.Msg.GetFingerprint(), req.Msg.GetProjectId(), req.Msg.GetPath())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	out := &ladulasv1.ReadPeerPageResponse{Page: project.PageWire(page)}

	digest := req.Msg.GetCompareDigest()
	commit := req.Msg.GetCompareCommit()

	if len(digest) == 0 && commit == "" {
		return connect.NewResponse(out), nil
	}

	// The version to compare against is fetched here rather than by the front
	// end, because reaching a publisher needs the identity key and that is this
	// process's (decision Z). What the front end gets is two documents and the
	// job of putting them together.
	before, err := browser.FileAt(ctx, req.Msg.GetFingerprint(),
		req.Msg.GetProjectId(), req.Msg.GetPath(), digest, commit)
	if err != nil {
		// A snapshot that expired between the list and this call is the
		// ordinary way one ends. The page above is still the page, so the
		// document is answered and the comparison is not.
		out.CompareError = err.Error()

		return connect.NewResponse(out), nil //nolint:nilerr // the document is still the answer
	}

	out.ComparedTo = project.PageWire(before)
	out.Version = &ladulasv1.DocumentVersion{Digest: digest, Commit: commit}

	return connect.NewResponse(out), nil
}

// PeerDocumentVersions is what one document has been (decision AP).
func (s *controlService) PeerDocumentVersions(
	ctx context.Context,
	req *connect.Request[ladulasv1.PeerDocumentVersionsRequest],
) (*connect.Response[ladulasv1.PeerDocumentVersionsResponse], error) {
	browser, err := s.browser()
	if err != nil {
		return nil, err
	}

	list, err := browser.Versions(ctx, req.Msg.GetFingerprint(),
		req.Msg.GetProjectId(), req.Msg.GetPath(),
		int(req.Msg.GetCommitLimit()))
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	return connect.NewResponse(&ladulasv1.PeerDocumentVersionsResponse{
		Versions:      list.Versions,
		Head:          list.Head,
		CurrentDigest: list.CurrentDigest,
		Truncated:     list.Truncated,
		Live:          list.Live,
		Error:         list.Err,
	}), nil
}
