package peer

import (
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"

	"github.com/hugowetterberg/ladulas/pkg/project"
)

// Switching the version watcher on, and keeping it pointed at what this
// instance publishes (decision AP).
//
// The watcher lives on the node rather than beside it, for one reason: the
// publications do. Publishing is a state in the store (decision Q) and the node
// is what writes it, so a project that starts being published is a project the
// node already knows about at the moment it happens — and a watcher owned
// anywhere else would need to be told, by a callback that could be forgotten.
//
// It follows the node's own lifetime, which is the peer channel's. That is the
// right span even though versions are a local matter: nothing can read them
// but a peer, so an instance with peering switched off has nothing to keep them
// for. Turning peering on starts the watch, and the first thing an approver
// does is reconcile, so nothing is lost by having missed the edits in between.

// startWatching brings the version watcher up for everything already
// published. It is called once, while the node is being built.
//
// A project that cannot be watched is logged and skipped rather than fatal. The
// commonest reason is a published directory that is not a git checkout, which
// is allowed — it simply has no commits for a snapshot to be relative to, so
// there is nothing to track.
func (n *Node) startWatching() {
	if n.versions == nil {
		return
	}

	watcher, err := project.NewWatcher(project.WatchOptions{
		Versions: n.versions,
		Policy:   n.serving.Policy,
		Logger:   n.log,
		Notify:   n.WatchEvent,
	})
	if err != nil {
		n.log.Warn("the document watcher could not be started; "+
			"peers will see committed versions only",
			"error", err.Error())

		return
	}

	n.docWatcher = watcher

	for _, publication := range n.trust.Publications() {
		n.watchPublication(publication)
	}
}

// watchPublication puts one project under watch, or says why it is not.
func (n *Node) watchPublication(publication *ladulasv1.Publication) {
	if n.docWatcher == nil {
		return
	}

	err := n.docWatcher.Add(publication.GetProjectId(), publication.GetPath())
	if err == nil {
		return
	}

	// Not a repository is the ordinary case and is reported quietly; anything
	// else is worth a warning, because a project somebody published and cannot
	// get versions of is a question they will ask.
	if project.IsNotARepository(err) {
		n.log.Debug("a published project keeps no working-tree versions",
			"project", publication.GetName(),
			"path", publication.GetPath(), "reason", err.Error())

		return
	}

	n.log.Warn("a published project could not be watched for changes",
		"project", publication.GetName(),
		"path", publication.GetPath(), "error", err.Error())
}

// forgetWatched stops watching a project and drops its versions.
//
// Both halves, because a publication that has been withdrawn is one no peer may
// read: leaving the snapshots on disk would keep a copy of somebody's
// uncommitted work that nothing can reach and nothing will remove.
func (n *Node) forgetWatched(projectID string) {
	if n.docWatcher != nil {
		n.docWatcher.Forget(projectID)
	}

	if n.versions == nil {
		return
	}

	if err := n.versions.Forget(projectID); err != nil {
		n.log.Warn("the versions of an unpublished project could not be removed",
			"project", projectID, "error", err.Error())
	}
}

// stopWatching shuts the watcher down with the node.
func (n *Node) stopWatching() {
	if n.docWatcher == nil {
		return
	}

	if err := n.docWatcher.Close(); err != nil {
		n.log.Warn("the document watcher did not stop cleanly",
			"error", err.Error())
	}

	n.docWatcher = nil
}
