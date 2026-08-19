package project

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/gitctx"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Describe reads a project's identity without reading its contents.
//
// It is the whole of what publishing does (decision Q): the name, the origin,
// the branch and the commit are what an approver lists and what a signing
// request is matched against, and none of them need the tree to be walked. The
// contents are read a directory and a file at a time, when somebody asks.
//
// The repository details are asked of git and are missing rather than fatal
// when there is no repository: a directory of notes is a perfectly good thing
// to publish, it simply has no commit to be stale against.
func Describe(
	ctx context.Context, dir, name string,
) (*ladulasv1.Publication, error) {
	root, repo, err := identify(ctx, dir)
	if err != nil {
		return nil, err
	}

	if name == "" {
		name = filepath.Base(root)
	}

	return &ladulasv1.Publication{
		ProjectId:   ID(repo.OriginURL, root),
		Name:        name,
		Path:        root,
		OriginUrl:   repo.OriginURL,
		Branch:      repo.Branch,
		Commit:      repo.Head,
		PublishedAt: timestamppb.Now(),
	}, nil
}

// identify resolves the directory a project is published from, and reads what
// git knows about it.
//
// A repository is published as its top level even when the command was run
// three directories down, because that is the project the origin URL and the
// commit belong to.
func identify(
	ctx context.Context, dir string,
) (string, gitctx.Repository, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return "", gitctx.Repository{}, fmt.Errorf("project: resolve %q: %w", dir, err)
	}

	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", gitctx.Repository{}, fmt.Errorf("project: resolve %q: %w", dir, err)
	}

	info, err := os.Stat(root)
	if err != nil {
		return "", gitctx.Repository{}, fmt.Errorf("project: read %q: %w", dir, err)
	}

	if !info.IsDir() {
		return "", gitctx.Repository{}, fmt.Errorf("project: %q is not a directory", dir)
	}

	repo := gitctx.InspectRepository(ctx, gitctx.Options{Dir: root})

	if repo.Path != "" {
		root = repo.Path
	}

	return root, repo, nil
}
