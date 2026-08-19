package command

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/internal/app"
	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The lock verbs, which are the ones a box with no display lives or dies by.
//
// They go through the control socket rather than the store, because the
// daemon is the process holding the data encryption key and nothing a second
// process does to a file on disk would take it out of the daemon's memory
// (§14). That is also why `ladulas lock` with no daemon running is an honest
// error rather than a no-op that looks like success.

func lockCommand() *cli.Command {
	return &cli.Command{
		Name: "lock",
		Usage: "suspend approval at this machine, leaving paired approvers " +
			"able to answer",
		Description: "A plain lock keeps the store's key in memory and only " +
			"takes the prompts here out of the approver set, so a desktop " +
			"reached over SSH keeps working while its screen is locked. " +
			"--seal wipes the key instead: after it the agent offers no keys, " +
			"the peer channel is down, and the passphrase is needed to get " +
			"back.",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name: "seal",
				Usage: "wipe the store's key rather than only suspending " +
					"approval here",
			},
		},
		Action: runLock,
	}
}

func runLock(ctx context.Context, cmd *cli.Command) error {
	client := localapi.NewClient(cmd.String("control-socket"))

	resp, err := client.Control().Lock(ctx, connect.NewRequest(&ladulasv1.LockRequest{
		Seal: cmd.Bool("seal"),
	}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	fmt.Printf("The store is %s.\n", app.StateWord(resp.Msg.GetState()))

	if resp.Msg.GetState() == ladulasv1.LockState_LOCK_STATE_LOCKED {
		fmt.Println("Paired approvers can still answer for it; " +
			"`ladulas unlock` takes the lock off.")
	}

	return nil
}

func unlockCommand() *cli.Command {
	return &cli.Command{
		Name:  "unlock",
		Usage: "unseal the store, or take a lock off it",
		Description: "The passphrase is read here without echoing it and sent " +
			"over the control socket, which only this account can open; the " +
			"daemon derives the store key from it and wipes what it was given. " +
			"An instance that has enrolled `ladulas keyring enrol` unlocks " +
			"without being asked for anything.",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name: "stdin",
				Usage: "read the passphrase from standard input rather than " +
					"from the terminal, for scripts and for a shell with no tty",
			},
		},
		Action: runUnlock,
	}
}

// readPassphrase asks the terminal, or reads standard input when told to.
//
// Reading a passphrase off a pipe is worth having and worth being explicit
// about: it is how `ladulas unlock` fits into a script, and it is a flag rather
// than a fallback so that a command run with its input redirected by accident
// asks rather than silently unlocking with whatever was on the pipe.
func readPassphrase(cmd *cli.Command) ([]byte, error) {
	if !cmd.Bool("stdin") {
		return TerminalPassphrase("Passphrase for the Ladulås store", false)
	}

	return readPipedPassphrase()
}

// readNewPassphrase is the same thing for a store that does not exist yet,
// where a terminal is asked twice: a passphrase nobody can check is the one
// thing a new store cannot survive getting wrong. A pipe cannot mistype, so
// --stdin reads it once.
func readNewPassphrase(cmd *cli.Command) ([]byte, error) {
	if !cmd.Bool("stdin") {
		return TerminalPassphrase("Passphrase for the Ladulås store", true)
	}

	return readPipedPassphrase()
}

func readPipedPassphrase() ([]byte, error) {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return nil, fmt.Errorf("read the passphrase: %w", err)
	}

	return []byte(strings.TrimRight(line, "\r\n")), nil
}

func runUnlock(ctx context.Context, cmd *cli.Command) error {
	client := localapi.NewClient(cmd.String("control-socket"))

	status, err := client.Control().Status(ctx,
		connect.NewRequest(&ladulasv1.StatusRequest{}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	switch status.Msg.GetLockState() {
	case ladulasv1.LockState_LOCK_STATE_UNLOCKED:
		fmt.Println("The store is already unlocked.")

		return nil
	case ladulasv1.LockState_LOCK_STATE_UNINITIALIZED:
		return cli.Exit("There is no store to unlock yet. "+
			"Run `ladulas init` to create one.", 1)
	case ladulasv1.LockState_LOCK_STATE_SEALED,
		ladulasv1.LockState_LOCK_STATE_LOCKED,
		ladulasv1.LockState_LOCK_STATE_UNSPECIFIED:
	}

	// An enrolled instance is asked to unlock from the keychain first, which is
	// the whole of what "unlock at login" buys once the daemon is up.
	if status.Msg.GetKeyringEnrolled() {
		resp, err := client.Control().Unlock(ctx,
			connect.NewRequest(&ladulasv1.UnlockRequest{}))
		if err == nil {
			reportUnlocked(resp.Msg)

			return nil
		}

		fmt.Fprintf(os.Stderr, "the keychain did not answer: %v\n", err)
	}

	passphrase, err := readPassphrase(cmd)
	if err != nil {
		return err
	}

	defer keystore.Wipe(passphrase)

	resp, err := client.Control().Unlock(ctx,
		connect.NewRequest(&ladulasv1.UnlockRequest{Passphrase: passphrase}))
	if err != nil {
		return cli.Exit(fmt.Sprintf("The store stayed %s: %v",
			app.StateWord(status.Msg.GetLockState()), connectMessage(err)), 1)
	}

	reportUnlocked(resp.Msg)

	return nil
}

func reportUnlocked(resp *ladulasv1.UnlockResponse) {
	fmt.Printf("The store is %s.\n", app.StateWord(resp.GetState()))

	if resp.GetMessage() != "" {
		fmt.Printf("%s\n", resp.GetMessage())
	}
}

// requireInstance turns "nothing is listening" into the advice that goes with
// it. Everything else is the instance's own answer and is passed through.
//
// It is what every verb ends at now: the instance owns the store, so with no
// instance there is nothing to read, nothing to change, and nothing useful to
// ask a person for. Saying so beats a passphrase prompt for a store somebody
// else may already have open, which is what the fallback this replaces did
// (§14).
func requireInstance(cmd *cli.Command, err error) error {
	if !offline(err) {
		return cli.Exit(connectMessage(err), 1)
	}

	return cli.Exit(fmt.Sprintf(
		"No Ladulås instance is listening on %s.\n"+
			"The instance owns the store, so start it and run this again:\n"+
			"  ladulasd run                     # in a terminal, to see why it fails\n"+
			"  systemctl --user start ladulas   # as a unit",
		ConfigFromFlags(cmd).ControlSocket), 1)
}

// connectMessage is the message a connect error carries, without the code and
// the package name a user has no use for.
func connectMessage(err error) string {
	var connectErr *connect.Error

	if errors.As(err, &connectErr) {
		return connectErr.Message()
	}

	return err.Error()
}

func keyringCommand() *cli.Command {
	return &cli.Command{
		Name:  "keyring",
		Usage: "unlock this instance at login, using the platform keychain",
		Description: "Ladulås wraps the store with a passphrase, and asks for " +
			"it once per boot. Enrolling the platform keychain " +
			"puts a second copy of the store key there, so the daemon starts " +
			"unsealed with nothing typed — and so that any process running as " +
			"this user can read the key out of the keychain with one call. " +
			"The approval engine still gates every use of a key; what this " +
			"gives up is the protection against the keys themselves being " +
			"taken silently. It is a per-instance decision, and reversible.",
		Commands: []*cli.Command{
			{
				Name:   "status",
				Usage:  "say whether this instance unlocks at login",
				Action: runKeyringStatus,
			},
			{
				Name:   "enrol",
				Usage:  "unlock at login from now on",
				Action: runKeyringEnrol(true),
			},
			{
				Name:   "forget",
				Usage:  "go back to being asked for the passphrase",
				Action: runKeyringEnrol(false),
			},
		},
	}
}

func runKeyringStatus(ctx context.Context, cmd *cli.Command) error {
	resp, err := localapi.NewClient(cmd.String("control-socket")).
		Control().KeyringStatus(ctx,
		connect.NewRequest(&ladulasv1.KeyringStatusRequest{}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	fmt.Printf("Unlock at login  %s\n", yesNo(resp.Msg.GetEnrolled()))
	fmt.Printf("Passphrase       %s\n", yesNo(resp.Msg.GetPassphraseWrapping()))

	return nil
}

// runKeyringEnrol changes the enrolment through the running instance.
//
// What enrolling copies into the keychain is the data encryption key, and the
// daemon is the process holding it. Opening the store here to get a second copy
// of the same key would be a second writer of the same file for no gain at all
// (§14).
func runKeyringEnrol(enrol bool) cli.ActionFunc {
	return func(ctx context.Context, cmd *cli.Command) error {
		_, err := localapi.NewClient(cmd.String("control-socket")).
			Control().SetUnlockAtLogin(ctx,
			connect.NewRequest(&ladulasv1.SetUnlockAtLoginRequest{Enrol: enrol}))
		if err != nil {
			return requireInstance(cmd, err)
		}

		if enrol {
			fmt.Println("This instance will unlock at login.")
			fmt.Println("The passphrase still works, and is still the recovery path.")

			return nil
		}

		fmt.Println("This instance will ask for its passphrase again.")
		fmt.Println("The daemon keeps the key it already has; " +
			"`ladulas lock --seal` is what takes it away.")

		return nil
	}
}
