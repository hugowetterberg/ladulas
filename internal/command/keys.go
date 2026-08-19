package command

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"
	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The key verbs go through the running instance, like every other verb that
// touches the store (§14).
//
// The instance owns the store: it has the key already, so a read through it
// needs no passphrase, and a write through it lands in the document the daemon
// is serving from rather than underneath it. There is no other path. With
// nothing running there is nothing to ask, and saying so is the whole answer.

func keysCommand() *cli.Command {
	return &cli.Command{
		Name:  "keys",
		Usage: "manage the SSH keys Ladulås holds",
		Commands: []*cli.Command{
			keysListCommand(),
			keysGenerateCommand(),
			keysImportCommand(),
			keysPublicCommand(),
			keysRemoveCommand(),
			keysEnableCommand(true),
			keysEnableCommand(false),
			keysAgentCommand(),
			keysSendCommand(),
			keysOffersCommand(),
			keysAcceptCommand(),
			keysRefuseCommand(),
		},
	}
}

// control is the client every verb here starts with.
func control(cmd *cli.Command) *localapi.Client {
	return localapi.NewClient(cmd.String("control-socket"))
}

// storedKeys asks the running instance for the keys it holds.
//
// A daemon that answers with a refusal — a sealed store, most likely — is an
// answer and is passed on. Opening the store behind a sealed daemon would be
// asking a person for a passphrase in order to work around the fact that
// nobody has given the daemon one, which is a strange thing to do to somebody.
func storedKeys(
	ctx context.Context, cmd *cli.Command,
) ([]*ladulasv1.KeyInfo, error) {
	resp, err := control(cmd).Control().ListStoredKeys(ctx,
		connect.NewRequest(&ladulasv1.ListStoredKeysRequest{}))
	if err != nil {
		return nil, requireInstance(cmd, err)
	}

	return resp.Msg.GetKeys(), nil
}

func keysListCommand() *cli.Command {
	return &cli.Command{
		Name: "list",
		Usage: "list the keys in the store, and the ones paired instances " +
			"offer this one to sign with",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			// The borrowed keys are asked of the running instance, because it
			// is the process with the store open and the links in hand (§3,
			// §14). A keyless box's whole key set is this table, and it is the
			// whole set whether or not anything can be reached.
			borrowed := borrowedKeys(ctx, cmd)

			keys, err := storedKeys(ctx, cmd)
			if err != nil {
				// A box whose store is sealed can still be told where the keys
				// its agent offers live, which on a keyless one is all there is
				// to say. Reporting what is knowable beats reporting nothing.
				if len(borrowed) == 0 {
					return err
				}

				fmt.Printf("The store could not be read: %v\n", err)
				fmt.Println("This instance holds no keys of its own that can be listed.")
				printBorrowed(borrowed)

				return nil
			}

			if len(keys) == 0 && len(borrowed) == 0 {
				fmt.Println("No keys yet. `ladulas keys generate work` makes one, " +
					"or pair with an instance that holds one.")

				return nil
			}

			if len(keys) == 0 {
				fmt.Println("This instance holds no keys of its own.")
				printBorrowed(borrowed)

				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

			fmt.Fprintln(w,
				"LABEL\tALGORITHM\tFINGERPRINT\tCOMMENT\tORIGIN\tHELD\tSTATE")

			for _, key := range keys {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					key.GetLabel(), key.GetAlgorithm(), key.GetFingerprint(),
					key.GetComment(), originName(key.GetOrigin()),
					heldWhere(key), keyState(key))
			}

			if err := w.Flush(); err != nil {
				return fmt.Errorf("write table: %w", err)
			}

			printCopies(keys)

			printBorrowed(borrowed)

			return nil
		},
	}
}

// borrowedKeys asks the running instance what its peers offer.
//
// The answer includes the keys on peers that are not there, because those are
// remembered now (decision N) — a phone is out of reach most of the time, and a
// listing that only showed what could be signed with this second would say a
// phone holds nothing almost always. Nothing running is still nothing borrowed:
// what is remembered lives in the store, and the daemon is what has it open.
func borrowedKeys(
	ctx context.Context, cmd *cli.Command,
) []*ladulasv1.BorrowedKeyStatus {
	live, err := fetchStatus(ctx, cmd)
	if err != nil {
		return nil
	}

	return live.GetBorrowedKeys()
}

func printBorrowed(borrowed []*ladulasv1.BorrowedKeyStatus) {
	if len(borrowed) == 0 {
		return
	}

	fmt.Println("\nOffered by paired instances:")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "  LABEL\tALGORITHM\tFINGERPRINT\tHELD BY\tSTATE")

	for _, key := range borrowed {
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
			key.GetKey().GetLabel(), key.GetKey().GetAlgorithm(),
			key.GetKey().GetFingerprint(), key.GetPeer(),
			borrowedState(key))
	}

	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
}

// borrowedState is the one column that decides whether the row is a key
// somebody can use or a key somebody has to go and wake a machine up for.
//
// An unusable key says when it was last there rather than only that it is not,
// because "the phone was here a minute ago" and "the phone has not been seen
// since March" are different situations with different things to do about them.
func borrowedState(key *ladulasv1.BorrowedKeyStatus) string {
	// A key that is also in the store above is not waiting on anybody, whatever
	// the holder is doing: the copy here signs it (§10). The row is worth keeping
	// because it says the key exists in two places, which is the sentence
	// somebody wants after losing one of them.
	if key.GetHeldHere() {
		return "held here too, signs locally"
	}

	if key.GetAvailable() {
		// A borrowed key that its holder keeps out of identity lists is available
		// and not offered, which is two facts and needs both words: it will sign
		// a commit that names it and ssh will never be handed it (decision T).
		if ref := key.GetKey(); ref.AgentUse != nil && !ref.GetAgentUse() {
			return "available, not in the agent"
		}

		return "available"
	}

	seen := key.GetLastSeenAt()
	if seen == nil {
		return "holder not reachable"
	}

	return fmt.Sprintf("holder not reachable, last seen %s",
		seen.AsTime().Local().Format(time.RFC1123))
}

// keyState is the one column that says whether anything will use the key, and
// distinguishes the two ways of it not being offered (decision T): a key that is
// off, and a key that is on and simply not among the identities ssh is handed.
func keyState(key *ladulasv1.KeyInfo) string {
	switch {
	case key.GetDisabled():
		return "disabled"
	case key.AgentUse != nil && !key.GetAgentUse():
		return "enabled, not in the agent"
	default:
		return "enabled, in the agent"
	}
}

func originName(origin ladulasv1.KeyOrigin) string {
	switch origin {
	case ladulasv1.KeyOrigin_KEY_ORIGIN_IMPORTED:
		return "imported"
	case ladulasv1.KeyOrigin_KEY_ORIGIN_GENERATED:
		return "generated"
	case ladulasv1.KeyOrigin_KEY_ORIGIN_RECEIVED:
		return "received"
	case ladulasv1.KeyOrigin_KEY_ORIGIN_UNSPECIFIED:
		return "unknown"
	default:
		return "unknown"
	}
}

// heldWhere says what kind of key it is, in the one word that decides what can
// be done with it: a key in a secure element cannot be handed to anybody, and a
// portable one can (decision S).
func heldWhere(key *ladulasv1.KeyInfo) string {
	if key.GetHardware() {
		return "enclave"
	}

	if len(key.GetHandedTo()) > 0 {
		return "portable, copied"
	}

	return "portable"
}

// printCopies names the keys that exist somewhere else as well.
//
// It is under the table rather than in it because it is the sentence somebody
// needs after losing a machine — which of these have to be rotated at the far
// ends — and a column could only have said how many.
func printCopies(keys []*ladulasv1.KeyInfo) {
	var copied []*ladulasv1.KeyInfo

	for _, key := range keys {
		if len(key.GetHandedTo()) > 0 || key.GetReceivedFrom() != nil {
			copied = append(copied, key)
		}
	}

	if len(copied) == 0 {
		return
	}

	fmt.Println("\nKeys that exist on more than one machine:")

	for _, key := range copied {
		fmt.Printf("\n%s\n", key.GetLabel())
		printTransfers(key)
	}
}

func keysGenerateCommand() *cli.Command {
	return &cli.Command{
		Name:      "generate",
		Usage:     "generate a fresh ed25519 key",
		ArgsUsage: "<label>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "comment",
				Usage: "comment to put in the key, usually an email address",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			label := cmd.Args().First()
			if label == "" {
				return cli.Exit("Usage: ladulas keys generate <label>", 1)
			}

			key, err := generateKey(ctx, cmd, label, cmd.String("comment"))
			if err != nil {
				return err
			}

			fmt.Printf("Generated %s\n\n", key.GetFingerprint())
			fmt.Print(publicKeyLine(key))
			fmt.Println("\nAdd that public key to GitHub, authorized_keys and")
			fmt.Println("allowed_signers wherever it should be usable.")

			return nil
		},
	}
}

func generateKey(
	ctx context.Context, cmd *cli.Command, label, comment string,
) (*ladulasv1.KeyInfo, error) {
	resp, err := control(cmd).Control().GenerateKey(ctx,
		connect.NewRequest(&ladulasv1.GenerateKeyRequest{
			Label:   label,
			Comment: comment,
		}))
	if err != nil {
		return nil, requireInstance(cmd, err)
	}

	return resp.Msg.GetKey(), nil
}

func keysImportCommand() *cli.Command {
	return &cli.Command{
		Name:      "import",
		Usage:     "import an existing OpenSSH private key, as 1Password exports it",
		ArgsUsage: "<path>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "label",
				Usage: "name for the key inside Ladulås",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			path := cmd.Args().First()
			if path == "" {
				return cli.Exit("Usage: ladulas keys import <path to private key>", 1)
			}

			keyPEM, err := os.ReadFile(path) //nolint:gosec // the user named the file
			if err != nil {
				return fmt.Errorf("read key: %w", err)
			}

			key, err := importKey(ctx, cmd, path, keyPEM)
			if err != nil {
				return err
			}

			fmt.Printf("Imported %q, %s\n", key.GetLabel(), key.GetFingerprint())
			fmt.Print(publicKeyLine(key))

			return nil
		},
	}
}

// importKey hands the key file to the daemon, and asks for the file's own
// passphrase here when the daemon says it needs one — the daemon has no
// terminal to ask on, and whoever typed the command does.
func importKey(
	ctx context.Context, cmd *cli.Command, path string, keyPEM []byte,
) (*ladulasv1.KeyInfo, error) {
	client := control(cmd)

	resp, err := client.Control().ImportKey(ctx,
		connect.NewRequest(&ladulasv1.ImportKeyRequest{
			PrivateKey: keyPEM,
			Label:      cmd.String("label"),
		}))
	if err != nil {
		return nil, requireInstance(cmd, err)
	}

	if !resp.Msg.GetPassphraseRequired() {
		return resp.Msg.GetKey(), nil
	}

	phrase, err := TerminalPassphrase(
		fmt.Sprintf("Passphrase for %s", path), false)
	if err != nil {
		return nil, err
	}

	defer keystore.Wipe(phrase)

	resp, err = client.Control().ImportKey(ctx,
		connect.NewRequest(&ladulasv1.ImportKeyRequest{
			PrivateKey: keyPEM,
			Label:      cmd.String("label"),
			Passphrase: phrase,
		}))
	if err != nil {
		return nil, cli.Exit(connectMessage(err), 1)
	}

	return resp.Msg.GetKey(), nil
}

func keysPublicCommand() *cli.Command {
	return &cli.Command{
		Name:      "public",
		Usage:     "print public keys in authorized_keys format",
		ArgsUsage: "[label or fingerprint]",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			keys, err := storedKeys(ctx, cmd)
			if err != nil {
				return err
			}

			want := cmd.Args().First()

			var printed int

			for _, key := range keys {
				if want != "" && key.GetLabel() != want && key.GetFingerprint() != want {
					continue
				}

				fmt.Print(publicKeyLine(key))

				if want != "" {
					printTransfers(key)
				}

				printed++
			}

			if printed == 0 {
				return cli.Exit("No matching key.", 1)
			}

			return nil
		},
	}
}

// publicKeyLine renders a key as an authorized_keys line. The comment carries
// the label as well, so a key pasted into GitHub can be traced back to the
// instance that holds it.
func publicKeyLine(key *ladulasv1.KeyInfo) string {
	pub, err := ssh.ParsePublicKey(key.GetPublicKey())
	if err != nil {
		return fmt.Sprintf("# unreadable key %s: %v\n", key.GetLabel(), err)
	}

	comment := key.GetComment()
	if comment == "" {
		comment = key.GetLabel()
	}

	return fmt.Sprintf("%s %s\n",
		trimNewline(string(ssh.MarshalAuthorizedKey(pub))), comment)
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}

	return s
}

func keysRemoveCommand() *cli.Command {
	return &cli.Command{
		Name:      "remove",
		Usage:     "remove a key from the store",
		ArgsUsage: "<label or fingerprint>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ref := cmd.Args().First()
			if ref == "" {
				return cli.Exit("Usage: ladulas keys remove <label or fingerprint>", 1)
			}

			resp, err := control(cmd).Control().RemoveKey(ctx,
				connect.NewRequest(&ladulasv1.RemoveKeyRequest{Key: ref}))
			if err != nil {
				return requireInstance(cmd, err)
			}

			fmt.Printf("Removed %s\n", resp.Msg.GetFingerprint())

			return nil
		},
	}
}

func keysEnableCommand(enable bool) *cli.Command {
	name, usage := "enable", "offer a key through the agent again"
	if !enable {
		name, usage = "disable", "stop offering a key through the agent"
	}

	return &cli.Command{
		Name:      name,
		Usage:     usage,
		ArgsUsage: "<label or fingerprint>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ref := cmd.Args().First()
			if ref == "" {
				return cli.Exit(
					fmt.Sprintf("Usage: ladulas keys %s <label or fingerprint>", name), 1)
			}

			_, err := control(cmd).Control().SetKeyEnabled(ctx,
				connect.NewRequest(&ladulasv1.SetKeyEnabledRequest{
					Key:     ref,
					Enabled: enable,
				}))
			if err != nil {
				return requireInstance(cmd, err)
			}

			fmt.Printf("%sd %s\n", name, ref)

			return nil
		},
	}
}

// keysAgentCommand is the per-key advertising setting (decision T), and says out
// loud what it is not: the key goes on signing either way.
func keysAgentCommand() *cli.Command {
	return &cli.Command{
		Name:      "agent",
		Usage:     "offer a key in the agent's identity list, or stop offering it",
		ArgsUsage: "<label or fingerprint>",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "off",
				Usage: "take the key out of the identity list",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ref := cmd.Args().First()
			if ref == "" {
				return cli.Exit(
					"Usage: ladulas keys agent <label or fingerprint> [--off]", 1)
			}

			use := !cmd.Bool("off")

			resp, err := control(cmd).Control().SetKeyAgentUse(ctx,
				connect.NewRequest(&ladulasv1.SetKeyAgentUseRequest{
					Key:      ref,
					AgentUse: use,
				}))
			if err != nil {
				return requireInstance(cmd, err)
			}

			key := resp.Msg.GetKey()

			if use {
				fmt.Printf("%s is in the agent's identity list.\n", key.GetLabel())

				return nil
			}

			fmt.Printf("%s is out of the agent's identity list.\n", key.GetLabel())
			fmt.Println("It still signs for anything that names it — a commit " +
				"through user.signingkey, or a peer asking for it by key.")

			return nil
		},
	}
}
