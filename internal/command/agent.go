package command

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/internal/app"
	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// RunHeadless runs the agent with a terminal approver where there is a
// terminal. It is what `ladulasd run` and `ladulas agent` both do.
//
// Since M5 it starts the instance sealed and unseals it deliberately, rather
// than refusing to start without a passphrase. A daemon that will not come up
// until somebody types something is a daemon that cannot be asked what is wrong
// with it, and on a box reached only over SSH that is the difference between an
// inconvenience and a brick (§10, §14).
//
// The asking happens after the sockets are up, not before. A prompt that gates
// socket creation makes the daemon's own documentation untrue: the unit says
// `systemd-tty-ask-password-agent --query` and `ladulas unlock` are the same
// thing, and they only are if the control socket exists while the prompt is
// standing.
func RunHeadless(ctx context.Context, cmd *cli.Command) error {
	instance, err := New(cmd)
	if err != nil {
		return err
	}

	defer closeQuietly(instance)

	if useConsole(cmd) {
		instance.RegisterApprover(
			&approval.ConsoleHandler{In: os.Stdin, Out: os.Stderr})
	} else {
		fmt.Fprintln(os.Stderr,
			"No terminal to ask on; approvals have to come from a paired peer.")
	}

	fmt.Fprintf(os.Stderr, "export SSH_AUTH_SOCK=%s\n", instance.Config.SocketPath)
	fmt.Fprintf(os.Stderr, "signing socket %s\n", instance.Config.ControlSocket)

	watcher, err := StartLockTriggers(ctx, cmd, instance)
	if err != nil {
		return err
	}

	defer watcher.Stop()

	stopDebug, err := StartDebug(ctx, cmd, instance)
	if err != nil {
		return err
	}

	defer stopDebug()

	stopUnsealing := unsealWhenServing(ctx, cmd, instance)
	defer stopUnsealing()

	return RunAgent(ctx, instance)
}

// unsealWhenServing unseals the store once the instance is serving, and returns
// a function that gives the attempt up.
//
// Giving up does not wait for the attempt to finish: a terminal read cannot be
// interrupted, and a daemon that took its time shutting down because somebody
// walked away from a passphrase prompt would be a worse daemon than one that
// leaves a dead prompt on a terminal it is done with.
func unsealWhenServing(
	ctx context.Context, cmd *cli.Command, instance *app.App,
) func() {
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		select {
		case <-instance.Ready():
		case <-ctx.Done():
			return
		}

		unsealAtStart(ctx, cmd, instance)
	}()

	return cancel
}

// UnlockFlag chooses how the daemon asks for the passphrase at start.
//
// None of the values gate the sockets: whichever is chosen, the daemon is
// serving Status and Unlock before it asks, so `ladulas unlock` is an
// alternative to answering rather than something that has to wait for it.
func UnlockFlag() cli.Flag {
	return &cli.StringFlag{
		Name: "unlock",
		Usage: "how to ask for the passphrase once the daemon is up: `auto` " +
			"uses the terminal when there is one and systemd-ask-password " +
			"otherwise, `terminal` and `ask-password` force one of them, `none` " +
			"asks nothing and waits for `ladulas unlock`. The store is sealed " +
			"and the daemon serving either way",
		Value:   "auto",
		Sources: cli.EnvVars("LADULAS_UNLOCK"),
	}
}

// askFunc is a passphrase prompt that can be given up on, which
// keystore.PassphraseFunc cannot: it was written for a person at a terminal,
// where the only way out is answering.
type askFunc func(ctx context.Context, prompt string) ([]byte, error)

// unsealAtStart unseals the store if it can, and says why it could not if it
// could not. It never fails the daemon: a sealed instance still serves Status
// and Unlock, which is exactly what somebody who has just SSHed in needs.
func unsealAtStart(ctx context.Context, cmd *cli.Command, instance *app.App) {
	// A store that has never been created has no passphrase to ask for, and
	// asking for one would be asking a question with no right answer. The daemon
	// serves Status and Initialize instead, and waits for `ladulas init` (§10).
	if !instance.Initialised() {
		fmt.Fprintf(os.Stderr,
			"There is no store in %s yet. Run `ladulas init` to create one; "+
				"this instance will pick it up without restarting.\n",
			instance.Config.DataDir)

		return
	}

	if instance.TryKeyring() {
		return
	}

	ask, how := unlockPrompt(cmd)
	if ask == nil {
		fmt.Fprintln(os.Stderr,
			"The store is sealed. Run `ladulas unlock` to open it.")

		return
	}

	// The prompt and the control socket race on purpose, and an unlock that
	// arrives over the socket withdraws the prompt rather than leaving it
	// standing until it times out (§10, §14).
	unsealed, forget := instance.UnsealNotify()
	defer forget()

	asking, withdraw := context.WithCancel(ctx)
	defer withdraw()

	go func() {
		select {
		case <-unsealed:
			withdraw()
		case <-asking.Done():
		}
	}()

	fmt.Fprintf(os.Stderr,
		"The store is sealed; asking for the passphrase on %s. "+
			"`ladulas unlock` opens it too.\n", how)

	instance.SetUnsealPrompt(how)

	passphrase, err := ask(asking, "Passphrase for the Ladulås store")

	instance.SetUnsealPrompt("")

	if err != nil {
		if instance.Unsealed() {
			fmt.Fprintln(os.Stderr,
				"The store was unlocked over the control socket; "+
					"the passphrase prompt was withdrawn.")

			return
		}

		fmt.Fprintf(os.Stderr,
			"The store is sealed: %v\nRun `ladulas unlock` to open it.\n", err)

		return
	}

	defer keystore.Wipe(passphrase)

	// A terminal read cannot be cancelled, so an answer can arrive after
	// somebody else has already unsealed the store, or after the daemon has
	// been asked to stop. Both make the answer worth nothing except wiping.
	if ctx.Err() != nil || instance.Unsealed() {
		return
	}

	if _, err := instance.Unlock(passphrase); err != nil {
		fmt.Fprintf(os.Stderr,
			"The store stayed sealed: %v\nRun `ladulas unlock` to open it.\n", err)

		return
	}

	if addresses := instance.PeerAddresses(); len(addresses) > 0 {
		fmt.Fprintf(os.Stderr, "peer channel %s\n", strings.Join(addresses, ", "))
	}
}

// unlockPrompt picks the way to ask and what to call it, or nil for "do not
// ask".
func unlockPrompt(cmd *cli.Command) (askFunc, string) {
	terminal := term.IsTerminal(int(os.Stdin.Fd()))

	switch strings.ToLower(cmd.String("unlock")) {
	case "none", "off":
		return nil, ""
	case "terminal":
		return terminalAsk, "the terminal"
	case "ask-password", "askpassword":
		return askPasswordAsk, "systemd-ask-password"
	default:
		switch {
		case terminal:
			return terminalAsk, "the terminal"
		case AskPasswordAvailable():
			return askPasswordAsk, "systemd-ask-password"
		default:
			return nil, ""
		}
	}
}

func terminalAsk(_ context.Context, prompt string) ([]byte, error) {
	return TerminalPassphrase(prompt, false)
}

func askPasswordAsk(ctx context.Context, prompt string) ([]byte, error) {
	return AskPassword{}.Ask(ctx, prompt, false)
}

// useConsole decides whether to register the terminal approver.
//
// A daemon started by systemd has stdin on /dev/null, and registering an
// approver there would be worse than registering none: every request would go
// to something that cannot answer, and — because an instance tells its peers
// whether a human here could answer at all — it would advertise a prompt it
// cannot show. So the default follows the terminal, and the flag is for the
// cases where a supervisor hands the daemon a pipe and means it.
func useConsole(cmd *cli.Command) bool {
	switch strings.ToLower(cmd.String("console")) {
	case "on":
		return true
	case "off":
		return false
	default:
		return term.IsTerminal(int(os.Stdin.Fd()))
	}
}

// ConsoleFlag is the terminal-approver switch, mounted by the daemon's run
// command as well as by `ladulas agent`.
func ConsoleFlag() cli.Flag {
	return &cli.StringFlag{
		Name: "console",
		Usage: "whether to approve at the terminal: `auto` follows whether " +
			"stdin is one, `on` forces it, `off` leaves approvals to paired peers",
		Value:   "auto",
		Sources: cli.EnvVars("LADULAS_CONSOLE"),
	}
}

func agentCommand() *cli.Command {
	return &cli.Command{
		Name: "agent",
		Usage: "run the SSH agent, approving at the terminal " +
			"(the headless path; the desktop app runs the same agent behind a tray)",
		Flags: append([]cli.Flag{ConsoleFlag(), UnlockFlag(), DebugFlag()},
			TriggerFlags()...),
		Before: NoArguments,
		Action: RunHeadless,
	}
}

// RunAgent serves the agent until the process is asked to stop, reloading the
// store and policy on SIGHUP so that a `ladulas keys import` against a running
// daemon takes effect without a restart.
func RunAgent(ctx context.Context, instance *app.App) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	defer signal.Stop(hup)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if err := instance.Reload(); err != nil {
					fmt.Fprintf(os.Stderr, "reload failed: %v\n", err)
				}
			}
		}
	}()

	return instance.Serve(ctx)
}

func auditCommand() *cli.Command {
	return &cli.Command{
		Name:  "audit",
		Usage: "show the audit log",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "lines",
				Aliases: []string{"n"},
				Value:   20,
				Usage:   "how many entries to show, 0 for all",
			},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			cfg := ConfigFromFlags(cmd)

			entries, err := approval.ReadAuditLog(cfg.AuditPath(), cmd.Int("lines"))
			if err != nil {
				return err
			}

			if len(entries) == 0 {
				fmt.Println("The audit log is empty.")

				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

			fmt.Fprintln(w, "WHEN\tEVENT\tREQUEST\tOUTCOME\tDETAIL")

			for _, entry := range entries {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					entry.GetTimestamp().AsTime().Local().Format(time.RFC3339),
					eventName(entry.GetEvent()),
					entry.GetRequestId(),
					auditOutcome(entry),
					auditDetail(entry))
			}

			if err := w.Flush(); err != nil {
				return fmt.Errorf("write table: %w", err)
			}

			return nil
		},
	}
}

func eventName(event ladulasv1.AuditEvent) string {
	switch event {
	case ladulasv1.AuditEvent_AUDIT_EVENT_REQUEST:
		return "request"
	case ladulasv1.AuditEvent_AUDIT_EVENT_DECISION:
		return "decision"
	case ladulasv1.AuditEvent_AUDIT_EVENT_SIGNATURE:
		return "signature"
	case ladulasv1.AuditEvent_AUDIT_EVENT_ERROR:
		return "error"
	case ladulasv1.AuditEvent_AUDIT_EVENT_GRANT:
		return "grant"
	case ladulasv1.AuditEvent_AUDIT_EVENT_LIFECYCLE:
		return "lifecycle"
	case ladulasv1.AuditEvent_AUDIT_EVENT_UNSPECIFIED:
		return "unknown"
	default:
		return "unknown"
	}
}

func auditOutcome(entry *ladulasv1.AuditEntry) string {
	resp := entry.GetResponse()
	if resp == nil {
		return ""
	}

	verdict := "denied"
	if resp.GetDecision() == ladulasv1.Decision_DECISION_APPROVE {
		verdict = "approved"
	}

	return fmt.Sprintf("%s (%s)", verdict, sourceName(resp.GetSource()))
}

func sourceName(source ladulasv1.DecisionSource) string {
	switch source {
	case ladulasv1.DecisionSource_DECISION_SOURCE_USER:
		return "user"
	case ladulasv1.DecisionSource_DECISION_SOURCE_POLICY:
		return "policy"
	case ladulasv1.DecisionSource_DECISION_SOURCE_GRANT:
		return "grant"
	case ladulasv1.DecisionSource_DECISION_SOURCE_HARD_RULE:
		return "hard rule"
	case ladulasv1.DecisionSource_DECISION_SOURCE_TIMEOUT:
		return "timeout"
	case ladulasv1.DecisionSource_DECISION_SOURCE_CANCELLED:
		return "cancelled"
	case ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER:
		return "no approver"
	case ladulasv1.DecisionSource_DECISION_SOURCE_ERROR:
		return "error"
	case ladulasv1.DecisionSource_DECISION_SOURCE_UNSPECIFIED:
		return "unspecified"
	default:
		return "unspecified"
	}
}

func auditDetail(entry *ladulasv1.AuditEntry) string {
	if resp := entry.GetResponse(); resp != nil {
		return resp.GetReason()
	}

	if detail := entry.GetDetail(); detail != "" {
		return detail
	}

	if req := entry.GetRequest(); req != nil {
		return approval.RenderPrompt(req).Title
	}

	return entry.GetError()
}

// The grant verbs go through the running instance, like everything else that
// touches the store (§14).
//
// They were the last two that did not, and they had exactly the defect that
// cost the key verbs a fix: with a daemon running and unlocked, `ladulas grants
// list` asked for a passphrase on a box with no terminal to type it into. A
// grant is also live state — the engine consults the store on every decision —
// so a revocation through the daemon is in force for the next request rather
// than for the next restart.
func grantsCommand() *cli.Command {
	return &cli.Command{
		Name:  "grants",
		Usage: "list and revoke TTL grants",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "list live grants",
				Action: runGrantsList,
			},
			{
				Name:      "extend",
				Usage:     "give a grant more time, from now",
				ArgsUsage: "<grant id> <duration>",
				Action:    runGrantsExtend,
			},
			{
				Name:      "revoke",
				Usage:     "revoke a grant",
				ArgsUsage: "<grant id>",
				Action:    runGrantsRevoke,
			},
		},
	}
}

func runGrantsList(ctx context.Context, cmd *cli.Command) error {
	resp, err := control(cmd).Control().ListGrants(ctx,
		connect.NewRequest(&ladulasv1.ListGrantsRequest{}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	grants := resp.Msg.GetGrants()

	if len(grants) == 0 {
		fmt.Println("No live grants.")

		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "ID\tEXPIRES\tWHERE\tUSED\tSCOPE")

	for _, grant := range grants {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			grant.GetGrantId(),
			grant.GetExpiresAt().AsTime().Local().Format(time.RFC3339),
			grantWhere(grant),
			grantUse(grant),
			grant.GetDescription())
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("write table: %w", err)
	}

	return nil
}

// grantWhere says which of a grant's two shapes this is (decision P): one kept
// here and answered here, or one handed to a requester that applies it itself.
// The difference decides what revoking it does — ending a promise at once, or
// telling somebody to stop when they are next in touch.
func grantWhere(grant *ladulasv1.Grant) string {
	if !grant.GetDelegated() {
		return "here"
	}

	name := grant.GetDelegateName()
	if name == "" {
		name = grant.GetDelegateFingerprint()
	}

	return "delegated to " + name
}

// grantUse is what has been done under it. A delegated grant's count is what
// the requester has reported, so it lags rather than being wrong.
func grantUse(grant *ladulasv1.Grant) string {
	if grant.GetUseCount() == 0 {
		return "-"
	}

	return fmt.Sprintf("%d", grant.GetUseCount())
}

// The delegation verbs are the other side of the same question, and are a
// separate command because they are a different kind of thing (decision P).
//
// A grant is a promise made here: it can be listed here and taken back here. A
// delegation is a promise somebody else made about this instance, which this
// instance applies itself — so it can be listed and it can be allowed to run
// out, and stopping it early is the approver's to do, not this side's.
//
// Listing them is not a nicety. Until this existed, a machine could
// self-approve signatures for an hour with nothing local that named the
// permission it was using: `grants list` reads the promises made here, and a
// delegation is in another part of the store entirely. A promise that cannot be
// seen from the machine acting on it is one nobody there can audit (§9).
func delegationsCommand() *cli.Command {
	return &cli.Command{
		Name:  "delegations",
		Usage: "list the standing permissions this instance was given",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "list live delegations",
				Action: runDelegationsList,
			},
		},
	}
}

func runDelegationsList(ctx context.Context, cmd *cli.Command) error {
	resp, err := control(cmd).Control().ListDelegations(ctx,
		connect.NewRequest(&ladulasv1.ListDelegationsRequest{}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	held := resp.Msg.GetDelegations()

	if len(held) == 0 {
		fmt.Println("No delegations. Every signature here is asked for.")

		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "ID\tEXPIRES\tFROM\tUSED\tSCOPE")

	for _, item := range held {
		d := item.GetDelegation()

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			d.GetDelegationId(),
			d.GetExpiresAt().AsTime().Local().Format(time.RFC3339),
			delegationFrom(d),
			delegationUse(item),
			d.GetDescription())
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("write table: %w", err)
	}

	return nil
}

func delegationFrom(d *ladulasv1.Delegation) string {
	if name := d.GetApproverName(); name != "" {
		return name
	}

	return d.GetApproverFingerprint()
}

// delegationUse is what has been done under it, and how much of that the
// approver has not been told about yet. The second number is a machine that has
// been out of touch rather than a fault, so it is said as a note on the count
// rather than as a column of its own.
func delegationUse(item *ladulasv1.HeldDelegationInfo) string {
	if item.GetUseCount() == 0 {
		return "-"
	}

	if unreported := item.GetUnreportedUses(); unreported > 0 {
		return fmt.Sprintf("%d (%d unreported)", item.GetUseCount(), unreported)
	}

	return fmt.Sprintf("%d", item.GetUseCount())
}

// runGrantsExtend gives a promise more time, counted from now.
//
// From now rather than added to what is left, because that is what somebody
// asking for it means — "keep this going for another two hours" — and because
// it is what lets the ceiling on making a promise be the ceiling on extending
// one (decision V).
func runGrantsExtend(ctx context.Context, cmd *cli.Command) error {
	id := cmd.Args().First()
	spell := cmd.Args().Get(1)

	if id == "" || spell == "" {
		return cli.Exit(
			"Usage: ladulas grants extend <grant id> <duration>, as in 90m", 1)
	}

	extra, err := time.ParseDuration(spell)
	if err != nil {
		return cli.Exit(fmt.Sprintf(
			"%q is not a length of time. Try 45m, or 2h.", spell), 1)
	}

	resp, err := control(cmd).Control().ExtendGrant(ctx,
		connect.NewRequest(&ladulasv1.ExtendGrantRequest{
			GrantId:  id,
			ExtendBy: durationpb.New(extra),
		}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	grant := resp.Msg.GetGrant()

	fmt.Printf("%s now runs until %s\n%s\n",
		grant.GetGrantId(),
		grant.GetExpiresAt().AsTime().Local().Format(time.RFC3339),
		grant.GetDescription())

	return nil
}

func runGrantsRevoke(ctx context.Context, cmd *cli.Command) error {
	id := cmd.Args().First()
	if id == "" {
		return cli.Exit("Usage: ladulas grants revoke <grant id>", 1)
	}

	resp, err := control(cmd).Control().RevokeGrant(ctx,
		connect.NewRequest(&ladulasv1.RevokeGrantRequest{GrantId: id}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	fmt.Printf("Revoked %s\n", resp.Msg.GetGrantId())

	return nil
}

func policyCommand() *cli.Command {
	return &cli.Command{
		Name:  "policy",
		Usage: "inspect the approval policy",
		Commands: []*cli.Command{
			{
				Name:  "path",
				Usage: "print the path of the policy file",
				Action: func(_ context.Context, cmd *cli.Command) error {
					fmt.Println(ConfigFromFlags(cmd).PolicyPath())

					return nil
				},
			},
			{
				Name:  "show",
				Usage: "print the policy as it is understood",
				Action: func(_ context.Context, cmd *cli.Command) error {
					cfg := ConfigFromFlags(cmd)

					policy, err := approval.LoadPolicy(cfg.PolicyPath())
					if err != nil {
						return err
					}

					doc := policy.Document()

					fmt.Printf("SSH authentication timeout  %s\n",
						policy.Timeout(ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH))
					fmt.Printf("Signing timeout             %s\n",
						policy.Timeout(ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN))
					fmt.Printf("Rules                       %d\n\n", len(doc.GetRules()))

					for i, rule := range doc.GetRules() {
						fmt.Printf("%d. %s — %s\n", i+1, rule.GetName(),
							actionName(rule.GetAction()))

						if rule.GetDescription() != "" {
							fmt.Printf("   %s\n", rule.GetDescription())
						}
					}

					fmt.Println("\nHard rules, which no policy can override:")
					fmt.Println("  - unclassifiable payloads are denied")
					fmt.Println("  - forwarded agent requests always ask")
					fmt.Println("  - pairing changes always ask")

					return nil
				},
			},
		},
	}
}

func actionName(action ladulasv1.Action) string {
	switch action {
	case ladulasv1.Action_ACTION_APPROVE:
		return "approve"
	case ladulasv1.Action_ACTION_DENY:
		return "deny"
	case ladulasv1.Action_ACTION_PROMPT:
		return "prompt"
	case ladulasv1.Action_ACTION_UNSPECIFIED:
		return "prompt"
	default:
		return "prompt"
	}
}
