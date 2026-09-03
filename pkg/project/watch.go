package project

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Noticing that a document changed, without noticing the thousand things that
// are not a document changing (decision AP).
//
// The naive version of this is a filesystem watch that snapshots whatever it
// sees, and it is wrong in three separate ways, each of which produces versions
// a reader would be shown as changes to their document that nobody ever made.
//
// **A checkout is not an edit.** `git checkout other-branch` rewrites every
// file that differs, which on a doc set is most of them. A watcher that
// snapshotted those would mint a version per file, all of them describing a
// tree the person switched away from within the second.
//
// **A rebase is not a series of edits.** It rewrites the working tree once per
// commit replayed, and a conflicted one leaves it half-written for as long as
// somebody takes to resolve it. Every intermediate state is a state nobody ever
// saved.
//
// **A save is not necessarily a change.** Editors write files they have not
// altered — a format-on-save that changed nothing, a touch, an atomic rename
// over identical bytes.
//
// So the debounce is not only there to coalesce keystrokes. It is the window in
// which the repository is asked what it is doing, and the answer decides
// whether anything is recorded at all: git busy means wait, and a moved HEAD
// means discard what was pending and start again from the new commit.
//
// **But the rule that actually makes this safe is a comparison, not a
// schedule.** A working-tree state identical to the committed one is not a
// version — there is nothing to record, because a reader can have those bytes
// from the commit. Every git operation that rewrites the tree ends by writing
// committed content into it, so all of them fall out of that one test at once,
// and none of them depends on noticing the operation in time. Timing alone
// cannot be made correct here: git updates HEAD *after* it writes the files, so
// a write can always land on the far side of the moment the watcher notices.
// This asks what the bytes are rather than when they arrived.
//
// The scheduling still matters — it is what stops a rebase from being read as
// two hundred edits, and what keeps the store from being written to during one
// — but it is the cheap filter in front of the correct one.

// Watch pacing.
const (
	// DefaultDebounce is how long a document has to be quiet before it is
	// snapshotted. Long enough that a save-per-keystroke editor produces one
	// version rather than forty, short enough that somebody who saves and then
	// looks at their phone finds it there.
	DefaultDebounce = 2 * time.Second

	// DefaultCeiling bounds a run of continuous edits, so that somebody typing
	// steadily for ten minutes is not one snapshot at the end of it.
	//
	// It does not bound waiting on git. A rebase that takes five minutes must
	// produce nothing at all, so a busy repository re-arms the timer however
	// long it has been — the ceiling is for edits, and a rebase is not editing.
	DefaultCeiling = 20 * time.Second
)

// WatchEvent is something the watcher noticed, for whoever wants to tell a peer
// about it.
//
// It carries no content, and that is the contract rather than an omission: a
// peer hearing about a change may not have the project open, may not have that
// kind pushed to it, and may be about to lose its connection. An event is a
// reason to reconcile, and reconciling is what actually moves bytes.
type WatchEvent struct {
	ProjectID string
	// Path is empty on Moved.
	Path string
	Head string
	// Removed says the document is gone — deleted or renamed away.
	Removed bool
	// Moved says the project is on another commit now, which retires every
	// snapshot handle a peer was holding for it.
	Moved bool
}

// WatchOptions configures a Watcher. Versions is required; the rest default.
type WatchOptions struct {
	Versions *VersionStore
	Policy   Policy
	Logger   *slog.Logger
	Debounce time.Duration
	Ceiling  time.Duration
	// Notify is called for each thing the watcher notices. Optional, and it
	// must not block: it is called from the watcher's own goroutines, and
	// whoever wants to put an event on a network is responsible for not making
	// a filesystem watch wait for one.
	Notify func(WatchEvent)
}

// Watcher keeps the version store up to date with what is being edited.
type Watcher struct {
	versions *VersionStore
	policy   Policy
	log      *slog.Logger
	debounce time.Duration
	ceiling  time.Duration
	notify   func(WatchEvent)

	fs *fsnotify.Watcher

	mu       sync.Mutex
	projects map[string]*watched
	// byDir routes an event to the project whose tree it happened in. A map
	// rather than a prefix walk because every event does this lookup and there
	// is one entry per watched directory either way.
	byDir map[string]*watched

	// settled is a test hook. It is nil in every build that is not a test, and
	// it exists because the alternative is a test that sleeps and hopes.
	settled func(projectID, path string, recorded bool)

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// watched is one project under watch.
type watched struct {
	id     string
	root   string
	gitDir string
	repo   *Repository

	// head is the commit the pending snapshots belong to. Compared on every
	// fire, and a difference is a checkout rather than an edit.
	head string

	pending map[string]*pending
}

// pending is one document waiting out its debounce.
type pending struct {
	timer *time.Timer
	// first is when this run of events started, which is what the ceiling is
	// measured from.
	first time.Time
}

// NewWatcher starts the filesystem watch. Nothing is watched until Add.
func NewWatcher(opts WatchOptions) (*Watcher, error) {
	if opts.Versions == nil {
		return nil, errors.New("project: a watcher needs somewhere to put versions")
	}

	notifier, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("project: start the filesystem watch: %w", err)
	}

	watcher := &Watcher{
		versions: opts.Versions,
		policy:   opts.Policy,
		log:      opts.Logger,
		debounce: opts.Debounce,
		ceiling:  opts.Ceiling,
		notify:   opts.Notify,
		fs:       notifier,
		projects: make(map[string]*watched),
		byDir:    make(map[string]*watched),
		done:     make(chan struct{}),
	}

	if watcher.log == nil {
		watcher.log = slog.Default()
	}

	if watcher.debounce <= 0 {
		watcher.debounce = DefaultDebounce
	}

	if watcher.ceiling <= 0 {
		watcher.ceiling = DefaultCeiling
	}

	watcher.wg.Add(1)

	go watcher.run()

	return watcher, nil
}

// Add puts a published project under watch.
//
// A project that is not a git repository is refused rather than watched
// without one: every snapshot is relative to a commit, so a tree with no
// commits to be relative to has nothing this can record.
func (w *Watcher) Add(projectID, root string) error {
	repo, err := OpenRepository(root)
	if err != nil {
		return err
	}

	head, err := repo.Head()
	if err != nil {
		return err
	}

	entry := &watched{
		id:      projectID,
		root:    root,
		gitDir:  repo.gitDir,
		repo:    repo,
		head:    head,
		pending: make(map[string]*pending),
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if _, ok := w.projects[projectID]; ok {
		return nil
	}

	w.projects[projectID] = entry

	// The repository's own directory, for HEAD moving and for the marks that
	// say git is in the middle of something. Not recursive: what is wanted is
	// the top level, where HEAD, MERGE_HEAD and index.lock live.
	if err := w.watchDir(entry, entry.gitDir); err != nil {
		return err
	}

	return w.walk(entry)
}

// Forget stops watching a project and drops what was pending for it.
func (w *Watcher) Forget(projectID string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	entry, ok := w.projects[projectID]
	if !ok {
		return
	}

	entry.discard()

	for dir, owner := range w.byDir {
		if owner != entry {
			continue
		}

		_ = w.fs.Remove(dir)

		delete(w.byDir, dir)
	}

	delete(w.projects, projectID)
}

// Close stops the watch. Pending snapshots are dropped rather than flushed: a
// version recorded on the way out belongs to a moment nobody was watching, and
// the next edit will produce one anyway.
func (w *Watcher) Close() error {
	var err error

	w.closeOnce.Do(func() {
		close(w.done)

		err = w.fs.Close()

		w.wg.Wait()

		w.mu.Lock()
		defer w.mu.Unlock()

		for _, entry := range w.projects {
			entry.discard()
		}
	})

	if err != nil {
		return fmt.Errorf("project: stop the filesystem watch: %w", err)
	}

	return nil
}

// walk adds a watch for every directory of a project worth entering. Callers
// must hold the lock.
//
// The rules are the browser's, deliberately: hidden directories and the skipped
// set are exactly what a listing leaves out (§6), and a file the browser will
// not show is not one to keep versions of. It also happens to be what keeps the
// descriptor count sane, since inotify is per directory and a node_modules is
// tens of thousands of them.
func (w *Watcher) walk(entry *watched) error {
	err := filepath.WalkDir(entry.root, func(
		path string, d fs.DirEntry, err error,
	) error {
		if err != nil {
			// A directory that cannot be read is one this cannot watch, and not
			// a reason to abandon the rest of the project.
			w.log.Debug("a directory could not be walked for watching",
				"path", path, "error", err.Error())

			return nil //nolint:nilerr // the walk continues past what it cannot read
		}

		if !d.IsDir() {
			return nil
		}

		if path != entry.root && (hidden(d.Name()) || skipped[d.Name()]) {
			return filepath.SkipDir
		}

		return w.watchDir(entry, path)
	})
	if err != nil {
		return fmt.Errorf("project: walk %s for watching: %w", entry.root, err)
	}

	return nil
}

// watchDir adds one directory. Callers must hold the lock.
func (w *Watcher) watchDir(entry *watched, dir string) error {
	if _, ok := w.byDir[dir]; ok {
		return nil
	}

	if err := w.fs.Add(dir); err != nil {
		return fmt.Errorf("project: watch %s: %w", dir, err)
	}

	w.byDir[dir] = entry

	return nil
}

// run is the event loop.
func (w *Watcher) run() {
	defer w.wg.Done()

	for {
		select {
		case <-w.done:
			return

		case event, ok := <-w.fs.Events:
			if !ok {
				return
			}

			w.event(event)

		case err, ok := <-w.fs.Errors:
			if !ok {
				return
			}

			// An overflow is the kernel saying it dropped events, which means
			// the store may now be behind the disk. It is logged rather than
			// recovered from: the next save of any document re-reads that
			// document, and a version missed is a version nobody was shown.
			w.log.Warn("the filesystem watch reported an error",
				"error", err.Error())
		}
	}
}

func (w *Watcher) event(event fsnotify.Event) {
	w.mu.Lock()
	defer w.mu.Unlock()

	entry, ok := w.byDir[filepath.Dir(event.Name)]
	if !ok {
		return
	}

	// Anything inside the repository's own directory is git talking, not
	// somebody editing. What it is worth is the schedule: HEAD moving, or a
	// lock appearing, both mean the next fire should look before it records.
	if withinGitDir(entry, event.Name) {
		w.schedule(entry, "")

		return
	}

	// A new directory is a new place documents can appear in, and it has to be
	// watched before anything is written into it — which is racy by nature, so
	// it is also walked, to pick up what landed in the gap.
	if event.Has(fsnotify.Create) {
		if info, err := os.Lstat(event.Name); err == nil && info.IsDir() {
			if hidden(info.Name()) || skipped[info.Name()] {
				return
			}

			if err := w.watchDir(entry, event.Name); err != nil {
				w.log.Debug("a new directory could not be watched",
					"path", event.Name, "error", err.Error())

				return
			}

			// Anything written into it between its creation and the watch
			// landing produced no event anybody heard, so the directory is
			// walked for what is already in it.
			w.sweepNew(entry, event.Name)

			return
		}
	}

	rel, err := filepath.Rel(entry.root, event.Name)
	if err != nil || CheckPath(rel) != nil {
		return
	}

	// The policy decides what is worth a version, and it is the reason this is
	// affordable: markdown by default, so the watch is over a doc set.
	if !w.policy.Snapshots(rel) {
		return
	}

	w.schedule(entry, rel)
}

// sweepNew schedules the documents already sitting in a directory that has just
// been created, and watches the directories under it. Callers must hold the
// lock.
//
// Creating a directory and writing into it are two operations and the watch
// lands between them, so a document written quickly enough produces no event at
// all. `mkdir -p docs/runbooks && cp deploy.md docs/runbooks/` is the ordinary
// way that happens, and it is not rare.
func (w *Watcher) sweepNew(entry *watched, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, item := range entries {
		if hidden(item.Name()) || skipped[item.Name()] {
			continue
		}

		path := filepath.Join(dir, item.Name())

		if item.IsDir() {
			if err := w.watchDir(entry, path); err == nil {
				w.sweepNew(entry, path)
			}

			continue
		}

		rel, err := filepath.Rel(entry.root, path)
		if err != nil || CheckPath(rel) != nil || !w.policy.Snapshots(rel) {
			continue
		}

		w.schedule(entry, rel)
	}
}

// withinGitDir reports whether a path is inside the repository's own directory.
func withinGitDir(entry *watched, path string) bool {
	rel, err := filepath.Rel(entry.gitDir, path)

	return err == nil && rel != ".." && !filepath.IsAbs(rel) &&
		!hasDotDotPrefix(rel)
}

func hasDotDotPrefix(rel string) bool {
	return rel == ".." || (len(rel) > 3 && rel[:3] == ".."+string(filepath.Separator))
}

// schedule arms or re-arms one document's debounce. An empty path is the
// repository itself, which schedules a look at git's state without a document
// to record. Callers must hold the lock.
func (w *Watcher) schedule(entry *watched, rel string) {
	now := time.Now()

	waiting, ok := entry.pending[rel]
	if !ok {
		waiting = &pending{first: now}
		entry.pending[rel] = waiting
	}

	// Past the ceiling the timer is left to run out rather than pushed further:
	// somebody typing steadily should not postpone their version for ever.
	if now.Sub(waiting.first) >= w.ceiling && waiting.timer != nil {
		return
	}

	if waiting.timer != nil {
		waiting.timer.Stop()
	}

	waiting.timer = time.AfterFunc(w.debounce, func() {
		w.fire(entry, rel)
	})
}

// fire is one document's debounce running out.
func (w *Watcher) fire(entry *watched, rel string) {
	w.mu.Lock()

	// Forget or Close may have happened while the timer was running.
	if _, ok := w.projects[entry.id]; !ok {
		w.mu.Unlock()

		return
	}

	repo := entry.repo

	w.mu.Unlock()

	// Asked outside the lock: it is filesystem work, and holding the lock
	// through it would make every event wait on a repository that is busy.
	if name, busy := repo.Busy(); busy {
		w.log.Debug("waiting for git to finish before recording a version",
			"project", entry.id, "operation", name)

		w.mu.Lock()

		// The ceiling does not apply to waiting on git: a long rebase must
		// produce nothing, so the run starts again from now.
		if waiting, ok := entry.pending[rel]; ok {
			waiting.first = time.Now()
		}

		w.schedule(entry, rel)
		w.mu.Unlock()

		return
	}

	head, err := repo.Head()
	if err != nil {
		w.log.Warn("a project's HEAD could not be read",
			"project", entry.id, "error", err.Error())

		return
	}

	w.mu.Lock()

	if head != entry.head {
		// A checkout, a rebase that finished, a commit. Everything pending was
		// written by that rather than by somebody editing, so it goes — and the
		// store drops what belonged to the commit we were on.
		previous := entry.head
		entry.head = head

		entry.discard()

		w.mu.Unlock()

		dropped, err := w.versions.Reset(entry.id, head)
		if err != nil {
			w.log.Warn("the versions of a moved project could not be reset",
				"project", entry.id, "error", err.Error())
		}

		w.log.Debug("a project moved to another commit",
			"project", entry.id, "from", previous, "to", head,
			"versions_dropped", dropped)

		w.announce(WatchEvent{ProjectID: entry.id, Head: head, Moved: true})

		w.signalSettled(entry.id, rel, false)

		return
	}

	delete(entry.pending, rel)

	w.mu.Unlock()

	if rel == "" || head == "" {
		w.signalSettled(entry.id, rel, false)

		return
	}

	w.record(entry, rel, head)
}

// record reads a document and puts it in the store.
func (w *Watcher) record(entry *watched, rel, head string) {
	full := filepath.Join(entry.root, rel)

	info, err := os.Lstat(full)
	if err != nil {
		// Gone, or renamed away. There is nothing to snapshot and the last
		// state of it is already in the store, so what is left to do is say so.
		w.announce(WatchEvent{
			ProjectID: entry.id, Path: rel, Head: head, Removed: true,
		})

		w.signalSettled(entry.id, rel, false)

		return
	}

	// A symlink is listed and never served (§6), so it is never versioned
	// either — the rules have to be the same or a reader could be handed a
	// history of something the browser refuses to show them.
	if info.Mode()&fs.ModeSymlink != 0 || info.IsDir() {
		w.signalSettled(entry.id, rel, false)

		return
	}

	body, err := os.ReadFile(full) //nolint:gosec // a path inside a published project
	if err != nil {
		w.log.Debug("a document could not be read for versioning",
			"project", entry.id, "path", rel, "error", err.Error())

		w.signalSettled(entry.id, rel, false)

		return
	}

	// **A working-tree state identical to the committed one is not a version.**
	//
	// This is what makes the whole thing robust rather than merely well-timed.
	// A checkout, a stash, a stash pop, a rebase and a reset all end by writing
	// the committed content of a file into the working tree, and every one of
	// them would otherwise leave a "version" behind that says the document
	// changed to exactly what git already has. Detecting those by watching for
	// the operation is a race — git updates HEAD after it writes the files, so
	// a write can always land on the far side of the moment we notice — and
	// this is not a race, because it asks what the bytes are rather than when
	// they arrived.
	//
	// A document git has never heard of has nothing to compare against and is
	// recorded, which is right: a new file is a real edit.
	if committed, err := entry.repo.ContentAt(head, rel); err == nil &&
		string(committed) == string(body) {
		w.signalSettled(entry.id, rel, false)

		return
	}

	_, recorded, err := w.versions.Record(entry.id, entry.root, rel, head, body)
	if err != nil {
		w.log.Warn("a version could not be recorded",
			"project", entry.id, "path", rel, "error", err.Error())

		w.signalSettled(entry.id, rel, false)

		return
	}

	if recorded {
		w.log.Debug("a version was recorded",
			"project", entry.id, "path", rel, "head", head)

		w.announce(WatchEvent{ProjectID: entry.id, Path: rel, Head: head})
	}

	w.signalSettled(entry.id, rel, recorded)
}

// announce hands an event to whoever asked for them, if anybody did.
func (w *Watcher) announce(event WatchEvent) {
	w.mu.Lock()
	notify := w.notify
	w.mu.Unlock()

	if notify != nil {
		notify(event)
	}
}

func (w *Watcher) signalSettled(projectID, rel string, recorded bool) {
	w.mu.Lock()
	settled := w.settled
	w.mu.Unlock()

	if settled != nil {
		settled(projectID, rel, recorded)
	}
}

// discard drops everything waiting for this project. Callers must hold the
// lock.
func (e *watched) discard() {
	for _, waiting := range e.pending {
		if waiting.timer != nil {
			waiting.timer.Stop()
		}
	}

	e.pending = make(map[string]*pending)
}

// Watch runs a watcher until the context is cancelled, which is the shape a
// daemon wants: everything above is the machinery, and this is the goroutine.
func (w *Watcher) Watch(ctx context.Context) error {
	<-ctx.Done()

	return w.Close()
}
