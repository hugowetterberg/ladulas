package command

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Giving a portable key to a peer, and answering one that has arrived
// (decision S).
//
// The passphrase is asked for here and checked in the daemon, which is the
// division everything else about the store already has: the terminal is what
// can ask a person, and the process holding the wrapping is the only thing that
// can say whether the answer was right.

func keysSendCommand() *cli.Command {
	return &cli.Command{
		Name:      "send",
		Usage:     "give a portable key to a paired peer, which cannot be undone",
		ArgsUsage: "<key> <peer>",
		Description: "The key's private half is copied to that peer, where " +
			"somebody has to accept it before it becomes a key there. " +
			"Afterwards it exists on both machines and there is no way to " +
			"take it back: a key sent to the wrong peer has to be rotated out " +
			"of GitHub, authorized_keys and allowed_signers, exactly like one " +
			"that leaked. A key in a secure element cannot be sent at all.",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			key := cmd.Args().Get(0)
			peer := cmd.Args().Get(1)

			if key == "" || peer == "" {
				return cli.Exit("Usage: ladulas keys send <key> <peer>", 1)
			}

			fmt.Printf("Giving %q to %q. The key will exist on both machines,\n",
				key, peer)
			fmt.Println("and sending cannot be undone.")

			phrase, err := TerminalPassphrase(
				"Store passphrase to confirm", false)
			if err != nil {
				return err
			}

			defer keystore.Wipe(phrase)

			resp, err := control(cmd).Control().SendKey(ctx,
				connect.NewRequest(&ladulasv1.SendKeyRequest{
					Key:        key,
					Peer:       peer,
					Passphrase: phrase,
				}))
			if err != nil {
				return requireInstance(cmd, err)
			}

			fmt.Printf("\nSent %s to %q.\n",
				resp.Msg.GetFingerprint(), resp.Msg.GetPeerName())
			fmt.Println("It is waiting to be accepted there. A peer that could " +
				"not be reached")
			fmt.Println("keeps it queued, and gets it when it is next around.")

			return nil
		},
	}
}

func keysOffersCommand() *cli.Command {
	return &cli.Command{
		Name:  "offers",
		Usage: "list the keys paired peers have handed this instance",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			offers, err := keyOffers(ctx, cmd)
			if err != nil {
				return err
			}

			if len(offers) == 0 {
				fmt.Println("No keys are waiting to be answered.")

				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

			fmt.Fprintln(w, "ID\tLABEL\tALGORITHM\tFINGERPRINT\tFROM\tARRIVED")

			for _, offer := range offers {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					offer.GetId(), offer.GetLabel(), offer.GetAlgorithm(),
					offer.GetFingerprint(), offer.GetPeerName(),
					offer.GetReceivedAt().AsTime().Local().Format(time.RFC1123))
			}

			if err := w.Flush(); err != nil {
				return fmt.Errorf("write table: %w", err)
			}

			fmt.Println("\n`ladulas keys accept <id>` takes one into the store, " +
				"`ladulas keys refuse <id>` forgets it.")

			return nil
		},
	}
}

func keyOffers(
	ctx context.Context, cmd *cli.Command,
) ([]*ladulasv1.KeyOfferInfo, error) {
	resp, err := control(cmd).Control().ListKeyOffers(ctx,
		connect.NewRequest(&ladulasv1.ListKeyOffersRequest{}))
	if err != nil {
		return nil, requireInstance(cmd, err)
	}

	return resp.Msg.GetOffers(), nil
}

func keysAcceptCommand() *cli.Command {
	return &cli.Command{
		Name:      "accept",
		Usage:     "take a key a peer handed over into the store",
		ArgsUsage: "<offer id>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name: "label",
				Usage: "name for the key here; the sender's label is used " +
					"when this is empty",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			id := cmd.Args().First()
			if id == "" {
				return cli.Exit("Usage: ladulas keys accept <offer id>", 1)
			}

			resp, err := control(cmd).Control().AnswerKeyOffer(ctx,
				connect.NewRequest(&ladulasv1.AnswerKeyOfferRequest{
					Id:     id,
					Accept: true,
					Label:  cmd.String("label"),
				}))
			if err != nil {
				return requireInstance(cmd, err)
			}

			key := resp.Msg.GetKey()

			fmt.Printf("Accepted %q, %s, from %q.\n\n",
				key.GetLabel(), key.GetFingerprint(),
				key.GetReceivedFrom().GetPeerName())
			fmt.Print(publicKeyLine(key))

			return nil
		},
	}
}

func keysRefuseCommand() *cli.Command {
	return &cli.Command{
		Name:      "refuse",
		Usage:     "forget a key a peer handed over",
		ArgsUsage: "<offer id>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			id := cmd.Args().First()
			if id == "" {
				return cli.Exit("Usage: ladulas keys refuse <offer id>", 1)
			}

			_, err := control(cmd).Control().AnswerKeyOffer(ctx,
				connect.NewRequest(&ladulasv1.AnswerKeyOfferRequest{
					Id:     id,
					Accept: false,
				}))
			if err != nil {
				return requireInstance(cmd, err)
			}

			fmt.Println("Forgotten. Nothing about that key is kept here.")

			return nil
		},
	}
}

// printTransfers is the part of a key listing that says the key is somewhere
// else as well, which is the one thing about a portable key that a fingerprint
// does not tell you.
func printTransfers(key *ladulasv1.KeyInfo) {
	if from := key.GetReceivedFrom(); from != nil {
		fmt.Printf("  Received from %s, %s\n", from.GetPeerName(),
			from.GetAt().AsTime().Local().Format(time.RFC1123))
	}

	for _, to := range key.GetHandedTo() {
		fmt.Printf("  Handed to %s, %s\n", to.GetPeerName(),
			to.GetAt().AsTime().Local().Format(time.RFC1123))
	}
}
