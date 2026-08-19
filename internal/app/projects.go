package app

import (
	"context"
	"errors"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/bridge"
	"github.com/hugowetterberg/ladulas/pkg/gitctx"
	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The viewer's two abilities that reach past this machine: the doc browser,
// which reads from the instance that publishes a project and keeps what it
// read (decision Q), and the deferred diff fetch, which has to know whether the
// repository is here or on the other side of a pairing.

// ProjectBrowser is what the shared viewer browses (§6). Nil when this instance
// has no store open.
func (a *App) ProjectBrowser() bridge.Projects {
	browser := a.Browser()
	if browser == nil {
		return nil
	}

	return browser
}

// Browser is the doc browser: what has been read, and the peer channel to read
// the rest over. Peering being switched off is not fatal to it — an instance
// with no channel can still read what it has read before.
func (a *App) Browser() *project.Browser {
	cache := a.Projects()
	if cache == nil {
		return nil
	}

	if a.Peer() == nil {
		return project.NewBrowser(cache, nil)
	}

	return project.NewBrowser(cache, a.Peer())
}

// FetchDiff gets the rest of a diff the caps cut short (§5).
//
// Where it comes from depends on where the repository is. A request that
// started on this machine is re-read from the working copy directly; one that
// arrived from a peer is asked of that peer, which is the machine that has the
// repository — and which will only answer about a request it currently has out
// to us.
func (a *App) FetchDiff(
	ctx context.Context, req *approval.Request, path string,
) (*ladulasv1.GitDiff, error) {
	git := req.Msg.GetSshsig().GetGitContext()
	if git == nil {
		return nil, errors.New("this request carries no commit to diff")
	}

	requester := req.Msg.GetRequester()

	if !requester.GetLocal() {
		if a.Peer() == nil {
			return nil, errors.New(
				"peering is switched off here, so the requester cannot be asked")
		}

		return a.Peer().FetchRemoteDiff(ctx,
			requester.GetInstanceId(), req.Msg.GetRequestId(), path)
	}

	if git.GetRepositoryPath() == "" {
		return nil, errors.New("this request does not say which repository it is in")
	}

	var paths []string

	if path != "" {
		if err := project.CheckPath(path); err != nil {
			return nil, err
		}

		paths = []string{path}
	}

	return gitctx.CollectDiff(ctx, git.GetObject(), gitctx.Options{
		Dir:   git.GetRepositoryPath(),
		Paths: paths,
	}), nil
}
