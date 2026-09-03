package project

import (
	"path/filepath"
	"strings"
)

// What this instance offers, how it gets to an approver, and what history it
// keeps of it — decided per file kind (§6, decision AP).
//
// Decision Q made publishing a state rather than an action: marking a project
// published sends nothing, and an approver reads what it opens. That is still
// the rule for most of a repository, and it is the right one — decision F's
// snapshot model was rejected because it paid for offline browsing by shipping
// every doc set to every approver whether or not anybody would ever open one.
//
// What is wrong with applying it to everything is that documentation is not
// most of a repository. A doc set is small, it is what an approver actually
// reads, and fetching it one page at a time down a link to somebody's laptop is
// the reason browsing is slow. So the two questions are separated: whether a
// kind may be read at all, which is what `servable` used to answer alone, and
// how its contents get to the reader.
//
// Markdown is pushed. Everything else keeps decision Q exactly — and when a
// kind is turned on later, it arrives pull-only, which is what makes turning
// one on cheap. A repository full of Go files does not become a repository that
// mirrors itself onto every phone that approves for it.
//
// The version question is separate again, and it is why the watcher is
// affordable. A pushed kind has its working-tree edits tracked, which costs a
// filesystem watch and a snapshot store; a pulled kind gets its history from
// git, which costs nothing until somebody asks. A kind that is served but not
// watched is the normal case and the cheap one.

// Distribution says how a file's contents reach an approver.
//
// It is a string rather than an integer so that it survives a log line, a JSON
// view and the exported-surface rule in §21 without anybody having to think
// about it — the same reasoning transport.Tier is a string for.
type Distribution string

const (
	// DistributePull is decision Q's model and the zero value: the file is
	// fetched when somebody opens it, and kept because they did.
	DistributePull Distribution = "pull"
	// DistributePush is sent ahead of anybody asking, so that opening it is a
	// read from local disk. What makes it affordable is that very few kinds
	// have it.
	DistributePush Distribution = "push"
)

// Versioning says what history an approver may ask for, and — for the
// publisher — what it has to keep to be able to answer.
type Versioning string

const (
	// VersionsNone is the zero value: the file has whatever version it has
	// right now and no history at all.
	VersionsNone Versioning = "none"
	// VersionsGit is the commits that touched the file, read from the
	// repository at the moment of asking. It costs nothing to offer.
	VersionsGit Versioning = "git"
	// VersionsSnapshots is VersionsGit plus the working-tree states since the
	// last commit, which is the half that needs a filesystem watch and a store
	// to put them in. Only a pushed kind is worth this: a snapshot of something
	// nobody has asked for is the cost decision F was rejected over, paid a
	// second time.
	VersionsSnapshots Versioning = "snapshots"
)

// Kind is one file kind and what this instance does with it.
type Kind struct {
	// Name is what a person calls this kind, for the sentence explaining why a
	// file was not offered.
	Name string
	// Extensions are matched against the file name, without case, with the
	// leading dot.
	Extensions []string
	// Serve is whether the contents may be handed over at all. A kind that is
	// not served is still listed — a project full of Go files is a project
	// whose listing shows Go files (§6) — and each entry says why it is not
	// readable.
	Serve bool
	// Distribute is how the contents get to a reader.
	Distribute Distribution
	// Versions is what history is offered for it.
	Versions Versioning
}

// Matches reports whether a file name belongs to this kind.
func (k Kind) Matches(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))

	for _, candidate := range k.Extensions {
		if ext == candidate {
			return true
		}
	}

	return false
}

// Policy is the set of kinds this instance has an opinion about. A file that
// matches none of them is not served, which is what keeps the default closed:
// adding a kind is a deliberate act and forgetting to mention one is not a way
// to publish it by accident.
type Policy struct {
	Kinds []Kind
}

// DefaultPolicy is what an instance uses unless it is told otherwise.
//
// It is exported rather than buried in a constructor because docs, tests and
// runbooks all need to name it, and because a fleet whose instances disagree
// about which kinds are pushed is a fleet where "the docs are stale" means
// something different on every machine.
var DefaultPolicy = Policy{
	Kinds: []Kind{{
		Name:       "markdown",
		Extensions: Markdown,
		Serve:      true,
		Distribute: DistributePush,
		Versions:   VersionsSnapshots,
	}},
}

// Kind returns the policy for a file name, and whether any kind claimed it.
func (p Policy) Kind(name string) (Kind, bool) {
	for _, kind := range p.withDefaults().Kinds {
		if kind.Matches(name) {
			return kind, true
		}
	}

	return Kind{}, false
}

// Serves reports whether the contents of this file may be handed over. It is
// the question `servable` asks before it looks at the size.
func (p Policy) Serves(name string) bool {
	kind, ok := p.Kind(name)

	return ok && kind.Serve
}

// Pushes reports whether this file is sent ahead of anybody asking for it.
//
// A kind that is pushed but not served is a contradiction and is read as not
// pushed: `Serve` is the outer door, and nothing goes through it that may not
// be handed over on request either.
func (p Policy) Pushes(name string) bool {
	kind, ok := p.Kind(name)

	return ok && kind.Serve && kind.Distribute == DistributePush
}

// Snapshots reports whether this instance has to watch the file to answer for
// its history. It is what scopes the filesystem watcher: inotify is not
// recursive and every watched directory is a descriptor, so a watch over the
// pushed kinds is a watch over a doc set, while a watch over the tree is a
// watch over somebody's node_modules.
func (p Policy) Snapshots(name string) bool {
	kind, ok := p.Kind(name)

	return ok && kind.Serve && kind.Versions == VersionsSnapshots
}

// History reports what version list may be offered for a file.
func (p Policy) History(name string) Versioning {
	kind, ok := p.Kind(name)
	if !ok || !kind.Serve {
		return VersionsNone
	}

	if kind.Versions == "" {
		return VersionsNone
	}

	return kind.Versions
}

// withDefaults resolves an unset policy to the default one. A zero Policy is
// what a caller that has not been given one holds, and treating it as "no kinds
// at all" would mean an instance that quietly stopped publishing.
func (p Policy) withDefaults() Policy {
	if len(p.Kinds) == 0 {
		return DefaultPolicy
	}

	return p
}

// Serving is what the publisher side needs to answer a browse call: how much it
// will send, and which kinds it will send at all.
//
// The two travel together everywhere on this side and nowhere on the other —
// an approver's cache is bounded by Limits and has no opinion about kinds — so
// they are one argument here and stay separate types.
type Serving struct {
	Limits Limits
	Policy Policy
}

// DefaultServing is the ordinary instance: the default caps and the default
// policy.
var DefaultServing = Serving{Limits: DefaultLimits, Policy: DefaultPolicy}

func (s Serving) withDefaults() Serving {
	s.Limits = s.Limits.withDefaults()
	s.Policy = s.Policy.withDefaults()

	return s
}
