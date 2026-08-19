// Package command is the Ladulås command tree, shared by the desktop binary
// and the headless daemon so that both understand the same commands.
package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	"github.com/hugowetterberg/ladulas/internal/app"
	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// NoArguments refuses positional arguments, and is what stops a verb nobody has
// heard of from starting something.
//
// `ladulasd` still runs the daemon with no arguments at all, because a unit
// starts it and has nothing to pass; urfave/cli spells that as a default
// command, and a default command is where everything the parser could not match
// ends up. So `ladulasd pairings list`, before that verb existed, would start a
// daemon and die saying an agent was already listening on the socket — an error
// naming something that was not the problem. `ladulas` had the same default and
// the same failure with a webkit startup banner in front of it, on a machine
// that may have had no display to put it on; it has no default command any more
// (decision Y), and this hook is what is left guarding the daemon.
//
// Neither the tray, the agent nor the daemon takes an argument, so an argument
// arriving at one is a verb that does not exist. It gets the usage and a
// non-zero exit, which is what any other command line does with one.
func NoArguments(ctx context.Context, cmd *cli.Command) (context.Context, error) {
	args := cmd.Args()
	if !args.Present() {
		return ctx, nil
	}

	root := cmd.Root()

	if err := cli.ShowRootCommandHelp(root); err != nil {
		return ctx, fmt.Errorf("show the usage: %w", err)
	}

	return ctx, fmt.Errorf("there is no %s command %q", root.Name, args.First())
}

// Usage is what a binary with no default command does when nothing was asked
// for: it prints the usage, and names the verb if there was one that nobody has
// heard of.
//
// It is the root action rather than a Before hook because that is where
// urfave/cli sends a command line it could not match once there is no default
// command to send it to. Left to itself the library answers an unknown verb
// with "No help topic for 'pairungs'" and no list of the topics there are, so
// the refusal reads the same either way (§14).
func Usage(ctx context.Context, cmd *cli.Command) error {
	_, err := NoArguments(ctx, cmd)
	if err != nil {
		return err
	}

	if err := cli.ShowRootCommandHelp(cmd.Root()); err != nil {
		return fmt.Errorf("show the usage: %w", err)
	}

	return nil
}

// GlobalFlags are the flags every command shares.
func GlobalFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "data-dir",
			Usage:   "directory holding the encrypted store and the audit log",
			Sources: cli.EnvVars("LADULAS_DATA_DIR"),
		},
		&cli.StringFlag{
			Name:    "config-dir",
			Usage:   "directory holding the policy",
			Sources: cli.EnvVars("LADULAS_CONFIG_DIR"),
		},
		&cli.StringFlag{
			Name:    "socket",
			Usage:   "path of the SSH agent socket",
			Sources: cli.EnvVars("LADULAS_AGENT_SOCK"),
		},
		&cli.StringFlag{
			Name:    "control-socket",
			Usage:   "path of the local signing socket that ladulas-sign uses",
			Sources: cli.EnvVars("LADULAS_SOCK"),
		},
		&cli.BoolFlag{
			Name: "no-keyring",
			Usage: "do not use the platform keychain; " +
				"unlock the store with the passphrase only",
			Sources: cli.EnvVars("LADULAS_NO_KEYRING"),
		},
		&cli.StringFlag{
			Name: "peer-listen",
			Usage: "where the peer channel listens: a port, a host:port, " +
				"or `off`. The default binds the machine's private and tailnet " +
				"addresses only",
			Sources: cli.EnvVars("LADULAS_PEER_LISTEN"),
		},
		&cli.BoolFlag{
			Name: "peer-listen-public",
			Usage: "allow binding addresses reachable from outside the local " +
				"network. The channel does not trust the network either way; " +
				"this exists so that it never happens by accident",
			Sources: cli.EnvVars("LADULAS_PEER_LISTEN_PUBLIC"),
		},
		&cli.StringFlag{
			Name:    "log-level",
			Usage:   "one of debug, info, warn, error",
			Value:   "info",
			Sources: cli.EnvVars("LADULAS_LOG_LEVEL"),
		},
	}
}

// ConfigFromFlags builds an app configuration from the global flags.
func ConfigFromFlags(cmd *cli.Command) app.Config {
	return app.Config{
		DataDir:         cmd.String("data-dir"),
		ConfigDir:       cmd.String("config-dir"),
		SocketPath:      cmd.String("socket"),
		ControlSocket:   cmd.String("control-socket"),
		PeerListen:      cmd.String("peer-listen"),
		PeerAllowPublic: cmd.Bool("peer-listen-public"),
		NoKeyring:       cmd.Bool("no-keyring"),
		Passphrase:      TerminalPassphrase,
		Logger:          Logger(cmd),
	}.WithDefaults()
}

// Logger builds the logger the commands share.
func Logger(cmd *cli.Command) *slog.Logger {
	var level slog.Level

	if err := level.UnmarshalText([]byte(cmd.String("log-level"))); err != nil {
		level = slog.LevelInfo
	}

	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
}

// New builds the instance without opening the store, which is what a daemon
// does: it comes up sealed — or uninitialised, with no store to seal — and is
// opened afterwards over its own control socket (§10, §14).
//
// It is the only constructor the command tree has. Nothing here opens a store:
// that is the daemon's, and only the daemon's.
func New(cmd *cli.Command) (*app.App, error) {
	// This process is the one that will hold the DEK and the portable keys in
	// its heap once it is unlocked, and it is the only one that does (decision
	// L). So it is the one to make undumpable: a crash must not spill the heap
	// into a core dump, where it would outlive the seal, and a same-uid process
	// must not be able to ptrace it out (M6). LimitCORE in the unit is the
	// portable backstop; this covers every way the daemon is launched, the dev
	// build from ~/go/bin included. Best effort — a platform without it just
	// leans on the unit.
	if err := preventMemoryInspection(); err != nil {
		Logger(cmd).Warn(
			"could not mark the process undumpable; a crash could core-dump keys",
			"error", err.Error())
	}

	instance, err := app.New(ConfigFromFlags(cmd))
	if err != nil {
		return nil, err
	}

	return instance, nil
}

// TerminalPassphrase reads a passphrase without echoing it.
func TerminalPassphrase(prompt string, confirm bool) ([]byte, error) {
	fd := int(os.Stdin.Fd())

	if !term.IsTerminal(fd) {
		return nil, errors.New(
			"a passphrase is needed but there is no terminal to ask on")
	}

	fmt.Fprintf(os.Stderr, "%s: ", prompt)

	first, err := term.ReadPassword(fd)

	fmt.Fprintln(os.Stderr)

	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}

	if !confirm {
		return first, nil
	}

	fmt.Fprint(os.Stderr, "Repeat: ")

	second, err := term.ReadPassword(fd)

	fmt.Fprintln(os.Stderr)

	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}

	defer keystore.Wipe(second)

	if !bytes.Equal(first, second) {
		keystore.Wipe(first)

		return nil, errors.New("the two passphrases do not match")
	}

	return first, nil
}

// Commands is the full command tree. Both binaries mount it, so `ladulasd
// keys list` works on a headless box exactly as `ladulas keys list` does on a
// desktop.
func Commands() []*cli.Command {
	return []*cli.Command{
		initCommand(),
		statusCommand(),
		keysCommand(),
		policyCommand(),
		grantsCommand(),
		delegationsCommand(),
		endorsementsCommand(),
		auditCommand(),
		agentCommand(),
		lockCommand(),
		unlockCommand(),
		waitCommand(),
		keyringCommand(),
		pairCommand(),
		pairingsCommand(),
		peersCommand(),
		projectsCommand(),
		versionCommand(),
	}
}

// initCommand asks the running instance to create its own store.
//
// It creates nothing itself, which is the whole of §14's rule and the reason
// there is no longer an exception to it: `ladulasd` starts with or without a
// store, and the process that will own the store is the process that makes it.
// What this side does is what only it can — read a passphrase from a person,
// twice, and say what came back.
func initCommand() *cli.Command {
	return &cli.Command{
		Name:  "init",
		Usage: "create the encrypted store and the instance identity key",
		Description: "The store is created by the running instance, so start " +
			"one first: `ladulasd run` in a terminal, or `systemctl --user " +
			"start ladulas`. A daemon with no store comes up serving anyway, " +
			"and this is what it is waiting for.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "name",
				Usage: "name for this instance, shown in prompts and to peers",
			},
			&cli.BoolFlag{
				Name: "stdin",
				Usage: "read the passphrase from standard input rather than from " +
					"the terminal, for scripts and for a shell with no tty",
			},
		},
		Action: runInit,
	}
}

func runInit(ctx context.Context, cmd *cli.Command) error {
	client := localapi.NewClient(cmd.String("control-socket"))

	status, err := client.Control().Status(ctx,
		connect.NewRequest(&ladulasv1.StatusRequest{}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	if state := status.Msg.GetLockState(); state !=
		ladulasv1.LockState_LOCK_STATE_UNINITIALIZED {
		return cli.Exit(fmt.Sprintf(
			"This instance already has a store in %s, and it is %s.",
			ConfigFromFlags(cmd).DataDir, app.StateWord(state)), 1)
	}

	// Asking, and asking twice, is this side's job: the daemon has nobody in
	// front of it.
	passphrase, err := readNewPassphrase(cmd)
	if err != nil {
		return err
	}

	defer keystore.Wipe(passphrase)

	resp, err := client.Control().Initialize(ctx,
		connect.NewRequest(&ladulasv1.InitializeRequest{
			InstanceName: cmd.String("name"),
			Passphrase:   passphrase,
		}))
	if err != nil {
		return cli.Exit(connectMessage(err), 1)
	}

	printInitialised(resp.Msg)

	return nil
}

func printInitialised(resp *ladulasv1.InitializeResponse) {
	fmt.Printf("Created %s\n", resp.GetStorePath())
	fmt.Printf("Instance %q, identity %s\n",
		resp.GetInstanceName(), resp.GetFingerprint())
	fmt.Printf("Policy written to %s\n", resp.GetPolicyPath())

	if resp.GetMessage() != "" {
		fmt.Printf("%s\n", resp.GetMessage())
	}

	fmt.Println()
	fmt.Println("The store is wrapped by that passphrase and nothing")
	fmt.Println("else. `ladulas keyring enrol` trades it for unlocking")
	fmt.Println("at login, per instance; read what that gives up first.")
	fmt.Println()
	fmt.Println("The instance is unlocked and serving already — nothing")
	fmt.Println("needs restarting. Next: add a key with `ladulas keys")
	fmt.Println("generate` or `ladulas keys import ~/path/to/id_ed25519`.")
}

func statusCommand() *cli.Command {
	return &cli.Command{
		Name:   "status",
		Usage:  "show what this instance is, where its files are, and its peers",
		Action: runStatus,
	}
}

// runStatus asks the running instance, and has nothing else to ask.
//
// The daemon owns the store — every state worth reporting is a fact about that
// process — so a status command that opened the store itself would prompt for a
// passphrase on a box whose running instance is already unlocked, which is the
// one answer a status command must never give (§14). With nothing listening,
// what is left to say is where the files are and that nothing is running, and
// that is said rather than turned into an error: "what is wrong with this box"
// is the question this command exists for.
func runStatus(ctx context.Context, cmd *cli.Command) error {
	cfg := ConfigFromFlags(cmd)

	live, liveErr := fetchStatus(ctx, cmd)
	if live != nil {
		return printLiveStatus(ctx, cmd, cfg, live)
	}

	if !offline(liveErr) {
		fmt.Fprintf(os.Stderr, "the instance answered: %v\n", liveErr)
	}

	printLocations(cfg)

	fmt.Printf("Store         nothing is running, so nothing has been read\n")
	fmt.Printf("Running       no\n")
	fmt.Println()
	fmt.Printf("Start the instance to manage it: `ladulasd run`, or\n")
	fmt.Printf("`systemctl --user start ladulas`.\n")

	return nil
}

// printLiveStatus is what a box driven over SSH sees, and it comes entirely
// from the daemon.
func printLiveStatus(
	ctx context.Context,
	cmd *cli.Command,
	cfg app.Config,
	live *ladulasv1.StatusResponse,
) error {
	if live.GetLockState() == ladulasv1.LockState_LOCK_STATE_UNINITIALIZED {
		printLocations(cfg)

		fmt.Printf("Store         not created yet\n")
		fmt.Printf("Running       yes, with nothing to serve\n")
		fmt.Println()
		fmt.Println("Run `ladulas init` to create the store. The instance makes")
		fmt.Println("it and picks it up without restarting.")

		return nil
	}

	if live.GetInstanceName() != "" {
		fmt.Printf("Instance      %s\n", live.GetInstanceName())
		fmt.Printf("Identity      %s\n", live.GetFingerprint())
	}

	printLocations(cfg)

	fmt.Printf("Store         %s%s\n",
		app.StateWord(live.GetLockState()), stateSuffix(live))
	fmt.Printf("Passphrase    %s\n", yesNo(live.GetPassphraseWrapping()))
	fmt.Printf("Login unlock  %s\n", yesNo(live.GetKeyringEnrolled()))

	if len(live.GetListenAddresses()) > 0 {
		fmt.Printf("Peer channel  %s\n",
			strings.Join(live.GetListenAddresses(), ", "))
	}

	switch live.GetLockState() {
	case ladulasv1.LockState_LOCK_STATE_SEALED:
		fmt.Printf("Running       yes, sealed — %s\n", sealedHint(live))

		return nil
	case ladulasv1.LockState_LOCK_STATE_LOCKED:
		fmt.Printf("Keys          %d\n", live.GetKeys())
		fmt.Printf("Live grants   %d\n", live.GetGrants())
		fmt.Printf("Running       yes, locked — paired approvers can still answer\n")
	case ladulasv1.LockState_LOCK_STATE_UNLOCKED,
		ladulasv1.LockState_LOCK_STATE_UNINITIALIZED,
		ladulasv1.LockState_LOCK_STATE_UNSPECIFIED:
		fmt.Printf("Keys          %d\n", live.GetKeys())
		fmt.Printf("Live grants   %d\n", live.GetGrants())
		fmt.Printf("Running       yes\n")
	}

	return printPeerStatus(ctx, cmd, live)
}

// sealedHint says how to get into a sealed instance, including the prompt it
// may already have standing somewhere.
//
// The daemon serves this call while it is asking (§14), so the two situations
// are distinguishable and worth distinguishing: one of them has a question
// waiting for an answer in another session, and the other has nothing happening
// at all.
func sealedHint(live *ladulasv1.StatusResponse) string {
	prompt := live.GetUnlockPrompt()
	if prompt == "" {
		return "`ladulas unlock` opens it"
	}

	return fmt.Sprintf(
		"asking for the passphrase on %s, or `ladulas unlock` opens it", prompt)
}

// stateSuffix says how long the instance has been in this state and what put it
// there, which is the difference between "somebody locked this" and "the lid
// was closed".
func stateSuffix(live *ladulasv1.StatusResponse) string {
	var parts []string

	if since := live.GetStateSince(); since != nil {
		parts = append(parts, "since "+
			since.AsTime().Local().Format(time.RFC3339))
	}

	if reason := live.GetStateReason(); reason != "" {
		parts = append(parts, reason)
	}

	if len(parts) == 0 {
		return ""
	}

	return " (" + strings.Join(parts, ", ") + ")"
}

func printLocations(cfg app.Config) {
	fmt.Printf("Store file    %s\n", cfg.StorePath())
	fmt.Printf("Policy        %s\n", cfg.PolicyPath())
	fmt.Printf("Audit log     %s\n", cfg.AuditPath())
	fmt.Printf("Agent socket  %s\n", cfg.SocketPath)
	fmt.Printf("Sign socket   %s\n", cfg.ControlSocket)
}

// fetchStatus asks the running instance, and treats "nothing is listening" as
// an answer rather than as a failure.
func fetchStatus(
	ctx context.Context, cmd *cli.Command,
) (*ladulasv1.StatusResponse, error) {
	client := localapi.NewClient(cmd.String("control-socket"))

	resp, err := client.Control().Status(ctx,
		connect.NewRequest(&ladulasv1.StatusRequest{}))
	if err != nil {
		return nil, err
	}

	return resp.Msg, nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}

	return "no"
}

func closeQuietly(instance *app.App) {
	if err := instance.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
}

// printPeerStatus adds the peers to `ladulas status`. They come from the
// running instance, which is the only thing that knows whether one is reachable
// right now.
func printPeerStatus(
	_ context.Context,
	_ *cli.Command,
	live *ladulasv1.StatusResponse,
) error {
	peers := live.GetPeers()

	fmt.Printf("Peers         %d\n", len(peers))

	// The keys on other machines are counted separately from this instance's
	// own, and the reachable ones separately again: "3 borrowed, 1 usable now"
	// is the state a phone-shaped pairing spends most of its life in, and it is
	// not a fault (decision N).
	//
	// A key this instance holds a copy of is counted apart from both, because it
	// is not borrowed at all any more — the copy here signs it, and counting it
	// among the ones that need a holder would overstate what depends on the
	// phone being awake (§10).
	if borrowed := live.GetBorrowedKeys(); len(borrowed) > 0 {
		var usable, alsoHere int

		for _, key := range borrowed {
			switch {
			case key.GetHeldHere():
				alsoHere++
			case key.GetAvailable():
				usable++
			}
		}

		switch {
		case alsoHere == len(borrowed):
			fmt.Printf("Borrowed keys %d, all of them held here too — "+
				"`ladulas keys list`\n", alsoHere)
		case alsoHere > 0:
			fmt.Printf("Borrowed keys %d, %d usable now, %d held here too — "+
				"`ladulas keys list`\n", len(borrowed)-alsoHere, usable, alsoHere)
		default:
			fmt.Printf("Borrowed keys %d, %d usable now — `ladulas keys list`\n",
				len(borrowed), usable)
		}
	}

	// A pairing waiting for an answer is the one thing on this listing that
	// somebody has to act on, and nothing else will ever remind them: it does
	// not expire, and the command that started it is long gone (§7).
	if waiting := live.GetPendingPairings(); waiting > 0 {
		fmt.Printf("Pairings      %d waiting — `ladulas pairings list`\n", waiting)
	}

	// The same reasoning for a key somebody has handed this machine: it is not
	// a key here until it is answered, and this is the only line that will
	// mention it on a box nobody is sitting at (decision S).
	if offers := live.GetKeyOffers(); offers > 0 {
		fmt.Printf("Keys offered  %d waiting — `ladulas keys offers`\n", offers)
	}

	if len(peers) == 0 {
		return nil
	}

	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "  NAME\tDIRECTION\tSTATE\tFINGERPRINT")

	for _, peer := range peers {
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n",
			peer.GetName(),
			directionWord(peer.GetMayApprove(), peer.GetMayRequest()),
			peerState(peer),
			peer.GetFingerprint())
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("write table: %w", err)
	}

	return nil
}
