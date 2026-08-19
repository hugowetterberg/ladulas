package command

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The pairings verbs are how a pairing that outlived the command that started
// it is answered (§7, §14).
//
// `ladulas pair` is the command with a person in front of it; these are the
// commands for everything that happened while nobody was. A pairing raised
// while the tray was shut, or answered on one side and not the other, or left
// on a screen over lunch, is here until somebody does something about it —
// which is the whole promise: nothing pending is unreachable, and nothing is
// lost because time passed.
//
// Like every other management verb they go through the daemon, which is the
// only process that opens the store (decision L). A sealed instance therefore
// cannot list or answer a pending pairing, exactly as it cannot list a peer.

func pairingsCommand() *cli.Command {
	return &cli.Command{
		Name:  "pairings",
		Usage: "list, answer and call off pairings that are under way",
		Commands: []*cli.Command{
			pairingsListCommand(),
			pairingsApproveCommand(),
			pairingsRejectCommand(),
			pairingsWithdrawCommand(),
		},
	}
}

func pairingsListCommand() *cli.Command {
	return &cli.Command{
		Name:   "list",
		Usage:  "list the pairings waiting for an answer here or at the other end",
		Action: runPairingsList,
	}
}

func runPairingsList(ctx context.Context, cmd *cli.Command) error {
	pairings, err := listPairings(ctx, cmd)
	if err != nil {
		return err
	}

	if len(pairings) == 0 {
		fmt.Println("No pairings are under way.")

		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "FINGERPRINT\tNAME\tSTATE\tGRANTS\tSTARTED\tSESSION")

	for _, pairing := range pairings {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			pairing.GetFingerprint(), pairing.GetName(),
			pairingState(pairing),
			directionWord(pairing.GetMayApprove(), pairing.GetMayRequest()),
			startedWord(pairing.GetStartedAt().AsTime(),
				pairing.GetStartedAt() != nil),
			pairing.GetSessionId())
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("write table: %w", err)
	}

	// Both fingerprints belong on screen: what a pairing asks is whether the two
	// machines are showing the same pair, and a listing with only the other
	// side's leaves nothing to compare it against (§7).
	fmt.Printf("\nThis instance is %s (%s).\n",
		pairings[0].GetLocalName(), pairings[0].GetLocalFingerprint())

	if waiting := waitingHere(pairings); waiting != nil {
		fmt.Printf("\nCheck that %s is showing those two fingerprints, then:\n",
			waiting.GetName())
		fmt.Printf("  ladulas pairings approve %s\n", waiting.GetFingerprint())
	}

	return nil
}

func waitingHere(
	pairings []*ladulasv1.PendingPairingStatus,
) *ladulasv1.PendingPairingStatus {
	for _, pairing := range pairings {
		if pairing.GetOurAnswer() ==
			ladulasv1.PairingAnswer_PAIRING_ANSWER_UNSPECIFIED {
			return pairing
		}
	}

	return nil
}

// pairingState says which of the two people a pairing is waiting for, since
// that is the only thing anybody reading the list wants to know.
func pairingState(pairing *ladulasv1.PendingPairingStatus) string {
	if pairing.GetOurAnswer() ==
		ladulasv1.PairingAnswer_PAIRING_ANSWER_UNSPECIFIED {
		return "waiting for you"
	}

	return "waiting for them"
}

func startedWord(at time.Time, present bool) string {
	if !present {
		return "unknown"
	}

	return at.Local().Format(time.RFC3339)
}

func listPairings(
	ctx context.Context, cmd *cli.Command,
) ([]*ladulasv1.PendingPairingStatus, error) {
	client := localapi.NewClient(cmd.String("control-socket"))

	resp, err := client.Control().ListPendingPairings(ctx,
		connect.NewRequest(&ladulasv1.ListPendingPairingsRequest{}))
	if err != nil {
		return nil, requireInstance(cmd, err)
	}

	return resp.Msg.GetPairings(), nil
}

func pairingsApproveCommand() *cli.Command {
	return &cli.Command{
		Name: "approve",
		Usage: "agree to a pairing on this side, having checked that both " +
			"machines show the same two fingerprints",
		ArgsUsage: "<fingerprint, name or session>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return answerPairing(ctx, cmd, true, "approve")
		},
	}
}

func pairingsRejectCommand() *cli.Command {
	return &cli.Command{
		Name: "reject",
		Usage: "refuse a pairing on this side; the other end is told if it " +
			"can be reached, and finds out by asking if it cannot",
		ArgsUsage: "<fingerprint, name or session>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return answerPairing(ctx, cmd, false, "reject")
		},
	}
}

func answerPairing(
	ctx context.Context, cmd *cli.Command, accepted bool, verb string,
) error {
	ref := cmd.Args().First()
	if ref == "" {
		return cli.Exit(fmt.Sprintf(
			"Usage: ladulas pairings %s <fingerprint, name or session>", verb), 1)
	}

	client := localapi.NewClient(cmd.String("control-socket"))

	resp, err := client.Control().AnswerPendingPairing(ctx,
		connect.NewRequest(&ladulasv1.AnswerPendingPairingRequest{
			Pairing:  ref,
			Accepted: accepted,
			Reason:   "answered at the command line",
		}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	printPairingAnswer(resp.Msg)

	return nil
}

func printPairingAnswer(msg *ladulasv1.AnswerPendingPairingResponse) {
	if peer := msg.GetPeer(); peer != nil {
		printPaired(peer)

		return
	}

	fmt.Printf("%s\n", msg.GetMessage())

	if msg.GetState() !=
		ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_PENDING {
		return
	}

	// Nothing is going to chase this: the daemon reconciles it whenever the
	// other machine is reachable, and the person here is done.
	fmt.Println("Nothing needs doing here. `ladulas pairings list` says how it")
	fmt.Println("stands, and `ladulas pairings withdraw` calls it off.")
}

func pairingsWithdrawCommand() *cli.Command {
	return &cli.Command{
		Name: "withdraw",
		Usage: "call a pairing off; it is the only way one is removed " +
			"without being answered, and it clears both sides",
		ArgsUsage: "<fingerprint, name or session>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ref := cmd.Args().First()
			if ref == "" {
				return cli.Exit(
					"Usage: ladulas pairings withdraw "+
						"<fingerprint, name or session>", 1)
			}

			client := localapi.NewClient(cmd.String("control-socket"))

			resp, err := client.Control().WithdrawPairing(ctx,
				connect.NewRequest(&ladulasv1.WithdrawPairingRequest{
					Pairing: ref,
					Reason:  "called off at the command line",
				}))
			if err != nil {
				return requireInstance(cmd, err)
			}

			fmt.Printf("Called off the pairing with %s.\n",
				resp.Msg.GetFingerprint())
			fmt.Printf("%s\n", resp.Msg.GetMessage())

			return nil
		},
	}
}

// describePairingWait is what `ladulas pair` prints when its own user has
// answered and the other side has not. It is not a failure and the command
// exits reporting success: the pairing is written down on both machines.
func describePairingWait(message string) {
	fmt.Println()

	if message == "" {
		message = "waiting for the other side to confirm"
	}

	fmt.Printf("Recorded here — %s.\n", strings.TrimSpace(message))
	fmt.Println("Nothing is lost by stopping now. The pairing completes when")
	fmt.Println("the other machine's user answers; `ladulas pairings list`")
	fmt.Println("says how it stands.")
}
