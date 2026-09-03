// Package app wires the pieces together: the encrypted store, the approval
// engine, the audit log and the SSH agent.
//
// It exists so that the tray app, the headless daemon and the CLI are all
// consumers of the same library API rather than three assemblies of the same
// parts (docs/architecture.md §17).
//
// Since M5 the instance is in two halves, because §10 says it must be. The
// outer half is the sockets, the audit log and the lock state, and it is there
// from the moment the daemon starts; the inner half is everything that needs
// the data encryption key, and it comes and goes with unsealing and sealing.
// The doors stay open either way — a sealed instance still answers Status and
// Unlock, which is the only reason a machine reached over SSH can be told what
// is wrong with it.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/pkg/agent"
	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	"github.com/hugowetterberg/ladulas/pkg/peer"
	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// Config locates everything on disk.
type Config struct {
	// DataDir holds the encrypted store, the passphrase-wrapped key and the
	// audit log. Defaults to $XDG_DATA_HOME/ladulas.
	DataDir string
	// ConfigDir holds the policy. Defaults to $XDG_CONFIG_HOME/ladulas.
	ConfigDir string
	// SocketPath is where the agent listens.
	SocketPath string
	// ControlSocket is where the local connect-go services listen, which is
	// where ladulas-sign submits commits (§5).
	ControlSocket string
	// KnownHosts files to resolve host keys against. Defaults to OpenSSH's.
	KnownHosts []string
	// InstanceName is used when creating a store.
	InstanceName string
	// PeerListen is where the peer channel binds; see transport's
	// ResolveBindAddresses. Empty means the default port on every private and
	// tailnet address (decision H). "off" switches peering off entirely.
	PeerListen string
	// PeerAllowPublic opts in to binding addresses reachable from outside the
	// local network.
	PeerAllowPublic bool
	// Headless says this instance has no GUI, which is worth telling a peer
	// that is being asked to approve for it.
	Headless bool
	// NoKeyring leaves the platform keychain alone entirely, so that an
	// instance which has enrolled "unlock at login" can still be started
	// without it. Enrolment is opt-in either way (decision I).
	NoKeyring bool
	// Keyring overrides where the second copy of the store key is kept. It is
	// for tests and for scratch instances: enrolling is the daemon's to do now
	// (§14), so exercising it needs a keychain the test owns. Empty means the
	// platform keychain, or none at all with NoKeyring.
	Keyring keystore.Keyring
	// Passphrase prompts the user. Required to create a store, and to open one
	// that has not enrolled the keychain.
	Passphrase keystore.PassphraseFunc
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// WithDefaults fills in the paths that were left empty.
func (c Config) WithDefaults() Config {
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir()
	}

	if c.ConfigDir == "" {
		c.ConfigDir = DefaultConfigDir()
	}

	if c.SocketPath == "" {
		c.SocketPath = agent.DefaultSocketPath()
	}

	if c.ControlSocket == "" {
		c.ControlSocket = localapi.DefaultSocketPath()
	}

	if len(c.KnownHosts) == 0 {
		c.KnownHosts = agent.DefaultKnownHostsPaths()
	}

	if c.Logger == nil {
		c.Logger = slog.Default()
	}

	return c
}

// StorePath is where the encrypted store lives.
func (c Config) StorePath() string {
	return filepath.Join(c.DataDir, "store.age")
}

// PolicyPath is where the policy document lives.
func (c Config) PolicyPath() string {
	return filepath.Join(c.ConfigDir, "policy.json")
}

// AuditPath is where the audit log lives.
func (c Config) AuditPath() string {
	return filepath.Join(c.DataDir, "audit.jsonl")
}

// ProjectsDir is where the pages this instance has read of its peers' projects
// are kept. They sit beside the store rather than inside it: the contents are
// sealed with the same key, but a page is bulk content and the store document
// is rewritten whole on every change (§6, §10).
func (c Config) ProjectsDir() string {
	return filepath.Join(c.DataDir, "projects")
}

// VersionsDir is where the working-tree states of this instance's *own*
// published documents are kept (decision AP).
//
// A sibling of ProjectsDir rather than a subdirectory of it, because the two
// hold opposite things and confusing them would be bad in one direction: that
// one is what has been read of other machines' projects, and this one is what
// has not yet been committed on this one. Both are sealed with the store key.
func (c Config) VersionsDir() string {
	return filepath.Join(c.DataDir, "versions")
}

// DefaultDataDir is $XDG_DATA_HOME/ladulas, or ~/.local/share/ladulas.
func DefaultDataDir() string {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "ladulas")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "ladulas-data"
	}

	return filepath.Join(home, ".local", "share", "ladulas")
}

// DefaultConfigDir is $XDG_CONFIG_HOME/ladulas, or ~/.config/ladulas.
func DefaultConfigDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "ladulas-config"
	}

	return filepath.Join(dir, "ladulas")
}

// PeeringOff is the listen specification that switches the peer channel off.
// A machine that is only ever approved for locally has no reason to listen.
const PeeringOff = "off"

// App is an opened instance: the sockets it serves on, and — while the store is
// unlocked — everything that needs the data encryption key.
type App struct {
	Config Config
	// Audit outlives the store on purpose. Sealing is a transition worth
	// recording, and a log that went away with the key could not record it.
	Audit *approval.AuditLog
	Agent *agent.Server
	Local *localapi.Server

	log *slog.Logger

	// ready is closed once both local sockets are listening, so that whatever
	// unseals the store at start can wait for the doors to be open before it
	// asks anybody anything (§10, §14).
	ready     chan struct{}
	readyOnce sync.Once

	mu        sync.RWMutex
	state     ladulasv1.LockState
	since     time.Time
	reason    string
	prompt    string
	core      *core
	approvers []*approverSlot
	// unsealWaiters are told when the data encryption key arrives, whichever
	// way it arrived.
	unsealWaiters []chan struct{}
	// stateWaiters are told about every transition, not just that one. It is
	// what AwaitState waits on: something waiting for a particular state has to
	// hear about the ones it did not want as well, or it would sleep through a
	// store that went from sealed to locked on its way to unlocked.
	stateWaiters []chan struct{}
	// serveCtx is the lifetime Serve is running under, held so that a store
	// unsealed later can start its peer listener under the same lifetime.
	serveCtx context.Context //nolint:containedctx // see above
	// activity is the idle timer's poke, set by a lock trigger watcher.
	activity func()
	// watched is the prompts out to a front end over the control socket, which
	// is the only way anything outside this process answers one (decision Z).
	// It has its own lock: a prompt is answered on one connection while it was
	// raised on another, and neither is holding the instance's.
	watched watchedRequests
}

// core is everything that needs the data encryption key. It is created by
// unsealing and dropped by sealing, which is what makes "the DEK is not in
// memory" a statement about the process rather than a hope.
type core struct {
	vault    *keystore.Vault
	engine   *approval.Engine
	projects *project.Cache
	// versions is what this instance keeps of its own documents between
	// commits, which is the publisher's side of decision AP. projects above is
	// the approver's side, and they are not the same thing in either direction.
	versions *project.VersionStore
	// peer is nil when peering is switched off.
	peer *peer.Node
	// listen is where the peer channel was told to bind, and what said so. It
	// is on the core rather than on the App because it is settled when the
	// store opens: the stored half of it is inside the store.
	listen listenSetting
	// stop and served are the peer listener's lifetime, when one is running.
	stop   context.CancelFunc
	served chan error
}

// listenSetting is a peer-channel bind specification and where it came from.
type listenSetting struct {
	spec        string
	allowPublic bool
	source      ladulasv1.ListenSource
}

// ErrNotInitialised is returned by everything that needs a store on an
// instance that has none yet.
var ErrNotInitialised = errors.New(
	"ladulas: this instance has no store yet; run `ladulas init` to create one")

// New builds an instance without opening the store.
//
// This is what the daemon starts as, and it starts either way: with a store it
// comes up sealed and waits to be unsealed — the keychain on an instance that
// enrolled one, systemd-ask-password at service start, or `ladulas unlock` over
// the socket. With no store at all it comes up uninitialised and waits to be
// initialised, which is the same promise made one step earlier: a daemon that
// refused to start would be a daemon that could not be asked what was wrong
// with it, and — under a unit with Restart=on-failure — one that spins (§10,
// §14).
func New(cfg Config) (*App, error) {
	cfg = cfg.WithDefaults()

	return build(cfg)
}

// Create builds an instance and initialises it in one step, taking the
// passphrase from the configuration's own prompt. It is what a test or an
// embedded host does; the daemon is initialised over the control socket.
func Create(cfg Config) (*App, error) {
	instance, err := New(cfg)
	if err != nil {
		return nil, err
	}

	if _, err := instance.Initialise(cfg.InstanceName, nil); err != nil {
		if closeErr := instance.Close(); closeErr != nil {
			instance.log.Debug("could not close an instance that never opened",
				"error", closeErr.Error())
		}

		return nil, err
	}

	return instance, nil
}

// Initialise creates the store, the instance identity key and the default
// policy, and adopts the result — so the instance is unlocked and serving from
// the same process, without a restart.
//
// An empty passphrase falls back to the configuration's prompt, which is how an
// embedded host asks its own way. Over the control socket the bytes are always
// supplied, because the daemon has nobody to ask.
func (a *App) Initialise(name string, passphrase []byte) (string, error) {
	defer keystore.Wipe(passphrase)

	if a.State() != ladulasv1.LockState_LOCK_STATE_UNINITIALIZED {
		return "", keystore.ErrExists
	}

	cfg := a.Config

	if name == "" {
		name = cfg.InstanceName
	}

	// One passphrase or the other: the bytes `ladulas init` sent, and the
	// terminal prompt when it sent none.
	vault, err := keystore.Create(keystore.Options{
		Dir:             cfg.DataDir,
		Keyring:         cfg.keyring(),
		GivenPassphrase: passphrase,
		Passphrase:      cfg.Passphrase,
		InstanceName:    name,
	})
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(cfg.ConfigDir, 0o700); err != nil {
		return "", fmt.Errorf("create config directory: %w", err)
	}

	if _, err := os.Stat(cfg.PolicyPath()); errors.Is(err, os.ErrNotExist) {
		if err := approval.DefaultPolicy().Save(cfg.PolicyPath()); err != nil {
			return "", err
		}
	}

	return a.adopt(vault)
}

func (c Config) keyring() keystore.Keyring {
	if c.Keyring != nil {
		return c.Keyring
	}

	if c.NoKeyring {
		return keystore.NoKeyring{}
	}

	return keystore.SystemKeyring{}
}

// build creates the half of an instance that does not need the store.
func build(cfg Config) (*App, error) {
	// The audit log is the first file an instance has, and it exists before the
	// store does: a daemon that came up with nothing to serve still records
	// having come up, and the transition that gives it a store.
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}

	auditLog, err := approval.OpenAuditLog(cfg.AuditPath())
	if err != nil {
		return nil, err
	}

	state := ladulasv1.LockState_LOCK_STATE_SEALED
	if !keystore.Exists(cfg.DataDir) {
		state = ladulasv1.LockState_LOCK_STATE_UNINITIALIZED
	}

	instance := &App{
		Config: cfg,
		Audit:  auditLog,
		log:    cfg.Logger,
		ready:  make(chan struct{}),
		state:  state,
		since:  time.Now(),
	}

	// The servers are handed the instance itself rather than the store, so that
	// a socket does not have to be torn down and rebuilt every time the lock
	// state changes. What varies is what the instance answers, and while sealed
	// it answers nothing: no keys, no signatures, and a control surface that
	// has shrunk to Status and Unlock (§14).
	instance.Agent, err = agent.New(agent.Options{
		SocketPath: cfg.SocketPath,
		Keys:       instance,
		Approver:   instance,
		Remote:     instance,
		KnownHosts: agent.NewKnownHosts(cfg.KnownHosts...),
		Logger:     cfg.Logger,
		Identity:   instance.requesterInfo,
		OnSigned:   instance.signed,
	})
	if err != nil {
		return nil, err
	}

	instance.Local, err = localapi.New(localapi.Options{
		SocketPath: cfg.ControlSocket,
		Keys:       instance,
		Approver:   instance,
		Remote:     instance,
		Control:    &controlService{app: instance},
		Logger:     cfg.Logger,
		Identity:   instance.requesterInfo,
		OnSigned:   instance.signed,
	})
	if err != nil {
		return nil, err
	}

	return instance, nil
}

// buildCore assembles everything that needs the data encryption key.
func (a *App) buildCore(vault *keystore.Vault) (*core, error) {
	cfg := a.Config

	policy, err := approval.LoadPolicy(cfg.PolicyPath())
	if err != nil {
		return nil, err
	}

	engine, err := approval.New(approval.Options{
		Identity:     vault.Identity(),
		Policy:       policy,
		Grants:       vault,
		Delegations:  vault,
		Endorsements: vault,
		KeySigner:    vault,
		GrantUses:    vault,
		Audit:        a.Audit,
		Logger:       cfg.Logger,
	})
	if err != nil {
		return nil, err
	}

	projects, err := project.OpenCache(
		cfg.ProjectsDir(), vault, project.DefaultLimits)
	if err != nil {
		return nil, err
	}

	// The publisher's half of versions. It is opened with the store, because it
	// is sealed with the store's key and a sealed instance keeps no versions at
	// all — there would be nothing to encrypt them with and nobody able to read
	// them (decision AP).
	versions, err := project.OpenVersions(cfg.VersionsDir(), vault)
	if err != nil {
		return nil, err
	}

	built := &core{
		vault:    vault,
		engine:   engine,
		projects: projects,
		versions: versions,
	}

	built.listen = a.listenSetting(vault)

	node, err := a.buildPeerNode(built)
	if err != nil {
		return nil, err
	}

	// Nothing else can see this core yet, so the assignment needs no lock. A
	// rebind of a core that is already serving is the other caller, and it takes
	// one (see startPeerOn).
	built.peer = node

	return built, nil
}

// listenSetting works out where the peer channel is to listen, and what decided
// it (decision AH).
//
// Three sources and one order, and the order is the point. A flag wins, because
// it is the way back into a machine whose stored setting names an address that
// no longer exists — an interface renamed, a tailnet left, an address typed
// wrong — and the alternative is a daemon that cannot be told anything without
// a store it will not listen without. A stored setting beats the automatic
// policy, including a stored `auto`, which is somebody having said "choose for
// me" rather than nobody having said anything.
func (a *App) listenSetting(vault *keystore.Vault) listenSetting {
	if a.Config.PeerListen != "" {
		return listenSetting{
			spec:        a.Config.PeerListen,
			allowPublic: a.Config.PeerAllowPublic,
			source:      ladulasv1.ListenSource_LISTEN_SOURCE_FLAG,
		}
	}

	if stored := vault.PeerListen(); stored.GetSpec() != "" {
		return listenSetting{
			spec:        stored.GetSpec(),
			allowPublic: stored.GetAllowPublic(),
			source:      ladulasv1.ListenSource_LISTEN_SOURCE_STORED,
		}
	}

	return listenSetting{
		spec:        transport.ListenAuto,
		allowPublic: a.Config.PeerAllowPublic,
		source:      ladulasv1.ListenSource_LISTEN_SOURCE_AUTOMATIC,
	}
}

// buildPeerNode builds the peer node for a core's current listen setting, or
// returns nil when peering is off.
//
// It is separate from buildCore because a listen setting can change while the
// instance is running, and putting the channel somewhere else is then this
// function again rather than an unseal (§14). It returns the node rather than
// assigning it, because the core it is building for may be one that requests are
// already reaching, and which field of it holds the channel is not something to
// change without the lock.
func (a *App) buildPeerNode(built *core) (*peer.Node, error) {
	cfg := a.Config

	if built.listen.spec == PeeringOff {
		return nil, nil
	}

	node, err := peer.New(peer.Options{
		Identity: built.vault.Identity(),
		Trust:    built.vault,
		Engine:   built.engine,
		Keys:     built.vault,
		Projects: built.projects,
		Versions: built.versions,
		// Explicit rather than relying on the zero value resolving, so that the
		// policy this instance serves under is one line to find and one line to
		// change (decision AP).
		Serving:      project.DefaultServing,
		Delegations:  built.vault,
		Wakeups:      built.vault,
		Handovers:    built.vault,
		Endorsements: built.vault,
		Listen:       built.listen.spec,
		AllowPublic:  built.listen.allowPublic,
		Headless:     cfg.Headless,
		Logger:       cfg.Logger,
	})
	if err != nil {
		return nil, err
	}

	// The engine decides and the node reaches; a delegated use needs both, and
	// the node is built around the engine, so this is where the two are
	// introduced (decision P).
	built.engine.ReportDelegatedUse(node.PushGrantActivity)
	built.engine.RenewDelegations(node.RenewDelegation)

	// And a promise about a portable key has to reach the other machines that
	// hold it, or it is one they will keep and cannot see (decision AG).
	built.engine.PublishEndorsements(node.PublishEndorsement)

	return node, nil
}

// Log returns the logger the instance was built with.
func (a *App) Log() *slog.Logger {
	return a.log
}

// Vault is the open store, or nil while sealed.
func (a *App) Vault() *keystore.Vault {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.core == nil {
		return nil
	}

	return a.core.vault
}

// Engine is the approval engine, or nil while sealed. It belongs to the
// unlocked store because it signs its decisions with the identity key, which
// lives there.
func (a *App) Engine() *approval.Engine {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.core == nil {
		return nil
	}

	return a.core.engine
}

// Peer is the peer channel, or nil while sealed or with peering switched off.
func (a *App) Peer() *peer.Node {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.core == nil {
		return nil
	}

	return a.core.peer
}

// Projects is what this instance has read of the projects its peers publish,
// or nil while sealed.
func (a *App) Projects() *project.Cache {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.core == nil {
		return nil
	}

	return a.core.projects
}

func (a *App) currentCore() *core {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.core
}

// Serve listens on both local sockets and, when the store is unlocked and
// peering is on, the peer channel, and serves until the context is done.
//
// The agent socket and the control socket are two doors into the same approval
// engine: ssh and a plain ssh-keygen come through the first with a digest,
// ladulas-sign comes through the second with the whole commit (§5). The peer
// channel is a third door into the same engine, opened by a paired instance
// rather than by a process on this machine — and the one door a sealed
// instance cannot open at all, because the identity key that authenticates it
// is inside the store (§10).
//
// All of them are created before any is served, so that a caller can export
// SSH_AUTH_SOCK and know everything is there.
func (a *App) Serve(ctx context.Context) error {
	if err := a.Agent.Listen(); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	a.mu.Lock()
	a.serveCtx = ctx
	current := a.core
	a.mu.Unlock()

	// The peer listener binds before the control socket appears, so that
	// anything waiting for the socket can ask where this instance can be
	// reached and get the real answer.
	if current != nil {
		if err := a.startPeer(ctx, current); err != nil {
			return err
		}
	}

	if err := a.Local.Listen(); err != nil {
		return err
	}

	// Both doors are open, and everything that unseals a store at start waits
	// for this before it asks. A daemon that asked first would be a daemon
	// whose control socket did not exist until somebody answered, which makes
	// `ladulas unlock` unreachable exactly when it is the only way in (§14).
	a.markReady()

	a.lifecycle(fmt.Sprintf(
		"agent listening on %s, signing service on %s, peers on %s, store %s",
		a.Agent.SocketPath(), a.Local.SocketPath(),
		describeAddresses(a.PeerAddresses()), StateWord(a.State())))

	errs := make(chan error, 1)

	go func() {
		errs <- a.Local.Serve(ctx)
	}()

	err := a.Agent.Serve(ctx)

	cancel()

	if other := <-errs; other != nil && err == nil {
		err = other
	}

	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	return nil
}

// Ready is closed once the local sockets are listening, which is the sealed
// state §10 describes: nothing of the store is live, and Status and Unlock are
// answerable anyway.
func (a *App) Ready() <-chan struct{} {
	return a.ready
}

func (a *App) markReady() {
	a.readyOnce.Do(func() {
		close(a.ready)
	})
}

// startPeer binds and serves the peer channel for a core.
//
// A peer listener that dies later does not take the instance with it. Since M5
// the daemon has to survive its own store being sealed, so "peering is down" is
// an ordinary state to be in and reported rather than a reason to stop
// answering the control socket.
func (a *App) startPeer(ctx context.Context, c *core) error {
	if c.peer == nil {
		return nil
	}

	if err := c.peer.Listen(); err != nil {
		return err
	}

	peerCtx, stop := context.WithCancel(ctx)
	served := make(chan error, 1)

	go func() {
		err := c.peer.Serve(peerCtx)
		if err != nil && peerCtx.Err() == nil {
			a.log.Error("the peer channel stopped", "error", err.Error())
		}

		served <- err
	}()

	a.mu.Lock()
	c.stop = stop
	c.served = served
	a.mu.Unlock()

	// The documentation this instance reads is kept up to date with the peer
	// channel, because reaching a publisher is what that does (decision AP).
	// The node is handed over rather than the core: c.peer is nilled under the
	// lock when the channel stops, and a loop reading it would race that.
	a.startDocSync(peerCtx, c.peer, c.projects)

	return nil
}

// PeerAddresses is where paired instances can reach this one.
func (a *App) PeerAddresses() []string {
	node := a.Peer()
	if node == nil {
		return nil
	}

	return node.Addresses()
}

func describeAddresses(addresses []string) string {
	if len(addresses) == 0 {
		return "(peering off)"
	}

	return strings.Join(addresses, ", ")
}

// Reload re-reads the store and the policy, so that a `ladulas keys import` run
// against a live daemon takes effect without a restart.
func (a *App) Reload() error {
	current := a.currentCore()
	if current == nil {
		return ErrSealed
	}

	if err := current.vault.Reload(); err != nil {
		return err
	}

	policy, err := approval.LoadPolicy(a.Config.PolicyPath())
	if err != nil {
		return err
	}

	current.engine.SetPolicy(policy)

	// A trust record that changed on disk means a link to start or to stop, so
	// telling the daemon to re-read does what it looks like it does.
	if current.peer != nil {
		current.peer.Reconcile()
	}

	a.lifecycle("store and policy reloaded")

	return nil
}

// Close releases the sockets, seals the store and closes the audit log.
func (a *App) Close() error {
	var errs []error

	if err := a.Agent.Close(); err != nil {
		errs = append(errs, err)
	}

	a.tearDown(a.takeCore())

	if err := a.Local.Close(); err != nil {
		errs = append(errs, err)
	}

	if err := a.Audit.Close(); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// requesterInfo describes this instance to whoever is being asked to approve
// for it. A sealed instance has no identity key to describe itself with, and
// says only that the request is a local one.
func (a *App) requesterInfo() *ladulasv1.RequesterInfo {
	vault := a.Vault()
	if vault == nil {
		return &ladulasv1.RequesterInfo{Local: true}
	}

	return vault.Identity().RequesterInfo(true)
}

func (a *App) signed(req *ladulasv1.ApprovalRequest, key *ladulasv1.KeyRef) {
	if engine := a.Engine(); engine != nil {
		engine.Signed(req, key)
	}
}

// KeyRefs implements agent.KeyStore and localapi.KeyStore. A sealed instance
// offers nothing, which is what makes `ssh-add -l` against it say so.
func (a *App) KeyRefs() []*ladulasv1.KeyRef {
	vault := a.Vault()
	if vault == nil {
		return nil
	}

	return vault.KeyRefs()
}

// Signer implements agent.KeyStore and localapi.KeyStore.
func (a *App) Signer(
	fingerprint string,
) (ssh.Signer, *storepb.StoredKey, error) {
	vault := a.Vault()
	if vault == nil {
		return nil, nil, ErrSealed
	}

	return vault.Signer(fingerprint)
}

// RemoteKeyRefs implements the borrowed-key seam. With the store sealed there
// is no peer channel and therefore nothing borrowed.
func (a *App) RemoteKeyRefs() []*ladulasv1.KeyRef {
	node := a.Peer()
	if node == nil {
		return nil
	}

	return node.RemoteKeyRefs()
}

// RefreshKeys implements the borrowed-key seam.
func (a *App) RefreshKeys(ctx context.Context) {
	if node := a.Peer(); node != nil {
		node.RefreshKeys(ctx)
	}
}

// BorrowedKeys implements the borrowed-key seam: everything paired peers have
// offered, reachable or not (decision N). A sealed instance knows nothing,
// because what it remembers is inside the store.
func (a *App) BorrowedKeys() []*ladulasv1.BorrowedKeyStatus {
	node := a.Peer()
	if node == nil {
		return nil
	}

	return node.BorrowedKeys()
}

// BorrowedKey implements the borrowed-key seam.
func (a *App) BorrowedKey(blob []byte) (*ladulasv1.KeyRef, bool) {
	node := a.Peer()
	if node == nil {
		return nil, false
	}

	return node.BorrowedKey(blob)
}

// RemoteSign implements the borrowed-key seam.
func (a *App) RemoteSign(
	ctx context.Context,
	req *ladulasv1.ApprovalRequest,
	payload []byte,
	wrapSSHSIG bool,
) (*ladulasv1.RemoteSignResponse, error) {
	node := a.Peer()
	if node == nil {
		return nil, errSealedOrNoPeering(a.State())
	}

	return node.RemoteSign(ctx, req, payload, wrapSSHSIG)
}

// Submit implements agent.Approver.
func (a *App) Submit(
	ctx context.Context, req *ladulasv1.ApprovalRequest,
) (*ladulasv1.ApprovalResponse, error) {
	resp, _, err := a.SubmitSigned(ctx, req)

	return resp, err
}

// SubmitSigned implements localapi.Approver, and is where a sealed instance
// refuses to decide anything: there is no identity key to sign a decision with,
// and a decision that cannot be accounted for does not get to be an approval.
func (a *App) SubmitSigned(
	ctx context.Context, req *ladulasv1.ApprovalRequest,
) (*ladulasv1.ApprovalResponse, *ladulasv1.SignedApproval, error) {
	a.poke()

	engine := a.Engine()
	if engine == nil {
		reason := a.noStoreError()

		a.logSealedRefusal(req, reason)

		return &ladulasv1.ApprovalResponse{
			Decision:  ladulasv1.Decision_DECISION_DENY,
			Source:    ladulasv1.DecisionSource_DECISION_SOURCE_ERROR,
			RequestId: req.GetRequestId(),
			Reason:    reason.Error(),
		}, nil, nil
	}

	return engine.SubmitSigned(ctx, req)
}

func (a *App) logSealedRefusal(req *ladulasv1.ApprovalRequest, why error) {
	a.appendAudit(&ladulasv1.AuditEntry{
		Event:     ladulasv1.AuditEvent_AUDIT_EVENT_DECISION,
		RequestId: req.GetRequestId(),
		Request:   req,
		Detail:    "refused: " + why.Error(),
	})
}

func (a *App) appendAudit(entry *ladulasv1.AuditEntry) {
	if err := a.Audit.Append(entry); err != nil {
		a.log.Error("could not write to the audit log", "error", err.Error())
	}
}

// poke tells the idle timer that something happened.
func (a *App) poke() {
	a.mu.RLock()
	activity := a.activity
	a.mu.RUnlock()

	if activity != nil {
		activity()
	}
}
