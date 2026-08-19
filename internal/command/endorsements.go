package command

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The command line's part of decision AG: seeing the promises other holders of
// a key have made about a machine, and taking one back.
//
// Listing is why it exists. An endorsement is carried by the requester and
// works whether or not this instance was ever told about it, so a machine with
// no way to show what it is honouring would be signing under a promise nobody
// here could find. Everything held is listed — including the copies this
// instance is only carrying to present elsewhere, and the ones it will not act
// on with the reason why — because "not shown" and "not there" must not look
// the same.

func endorsementsCommand() *cli.Command {
	return &cli.Command{
		Name:  "endorsements",
		Usage: "promises about a key that other holders of it have made",
		Description: "A holder of a portable key can promise that one paired " +
			"machine may borrow it unattended for a while, and every other " +
			"holder of that key honours the promise (decision AG). This is " +
			"where they are read and taken back.",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "list the endorsements this instance holds",
				Action: runEndorsementsList,
			},
			{
				Name:      "retract",
				Usage:     "take a promise back and tell every holder that can be reached",
				ArgsUsage: "<endorsement id>",
				Description: "Any holder of the key may retract, including one " +
					"that did not make the promise: the machine that sees an " +
					"endorsement it did not expect is very often not the one " +
					"that made it. With --key and no identifier it takes back " +
					"every promise about that key made up to now, which is " +
					"what to reach for when a key may have leaked.\n\n" +
					"A retraction is a delivery. A holder that could not be " +
					"reached goes on honouring the promise until it expires, " +
					"and is named in the output rather than left out of it.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "key",
						Usage: "retract every promise about this key",
					},
					&cli.StringFlag{
						Name:  "reason",
						Usage: "why, for the logs at both ends",
					},
				},
				Action: runEndorsementsRetract,
			},
		},
	}
}

func runEndorsementsList(ctx context.Context, cmd *cli.Command) error {
	resp, err := control(cmd).Control().ListEndorsements(ctx,
		connect.NewRequest(&ladulasv1.ListEndorsementsRequest{}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	held := resp.Msg.GetEndorsements()
	retractions := resp.Msg.GetRetractions()

	if len(held) == 0 && len(retractions) == 0 {
		fmt.Println("No endorsements. Every borrowed signature here is asked for.")

		return nil
	}

	if len(held) > 0 {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

		fmt.Fprintln(w, "ID\tEXPIRES\tFROM\tFOR\tUSED\tSTATE\tSCOPE")

		for _, item := range held {
			e := item.GetEndorsement()

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				e.GetEndorsementId(),
				e.GetExpiresAt().AsTime().Local().Format(time.RFC3339),
				endorsementFrom(e),
				endorsementFor(e),
				endorsementUse(item),
				endorsementState(item),
				e.GetDescription())
		}

		if err := w.Flush(); err != nil {
			return fmt.Errorf("write table: %w", err)
		}
	}

	if len(retractions) > 0 {
		fmt.Printf("\nTaken back (%d):\n\n", len(retractions))

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

		fmt.Fprintln(w, "WHAT\tKEY\tBY\tUNTIL\tREASON")

		for _, item := range retractions {
			r := item.GetRetraction()

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				retractionTarget(r),
				r.GetKeyFingerprint(),
				r.GetIssuerName(),
				r.GetRememberUntil().AsTime().Local().Format(time.RFC3339),
				r.GetReason())
		}

		if err := w.Flush(); err != nil {
			return fmt.Errorf("write table: %w", err)
		}

		fmt.Println("\nRemembered until then so that a copy arriving late is " +
			"refused rather than honoured.")
	}

	return nil
}

func runEndorsementsRetract(ctx context.Context, cmd *cli.Command) error {
	id := cmd.Args().First()
	key := cmd.String("key")

	if id == "" && key == "" {
		return cli.Exit(
			"Usage: ladulas endorsements retract <id>, or --key <fingerprint>", 1)
	}

	resp, err := control(cmd).Control().RetractEndorsement(ctx,
		connect.NewRequest(&ladulasv1.RetractEndorsementRequest{
			EndorsementId:  id,
			KeyFingerprint: key,
			Reason:         cmd.String("reason"),
		}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	fmt.Printf("Taken back here, dropping %d endorsement(s).\n",
		resp.Msg.GetDropped())

	told := resp.Msg.GetTold()
	unreached := resp.Msg.GetUnreached()

	if len(told) > 0 {
		fmt.Printf("\nTold %d holder(s):\n", len(told))

		for _, holder := range told {
			fmt.Printf("  %s\n", holder)
		}
	}

	// The half that is easy to leave out and is the one worth printing. A
	// holder that was not reached is still honouring the promise, and saying so
	// is the difference between a retraction and the belief that there was one.
	if len(unreached) > 0 {
		fmt.Printf("\nCould not reach %d holder(s):\n", len(unreached))

		for _, holder := range unreached {
			fmt.Printf("  %s\n", holder)
		}

		fmt.Println("\nThey are still honouring it. The retraction reaches " +
			"them when they are next in touch — with this instance or with " +
			"any other holder that has it — and the promise runs out on its " +
			"own whether or not anybody gets through.")
	}

	if len(told) == 0 && len(unreached) == 0 {
		fmt.Println("\nNo other holder of that key is known here, so there " +
			"was nobody to tell.")
	}

	return nil
}

func endorsementFrom(e *ladulasv1.Endorsement) string {
	if name := e.GetIssuerName(); name != "" {
		return name
	}

	return e.GetIssuerFingerprint()
}

func endorsementFor(e *ladulasv1.Endorsement) string {
	if name := e.GetRequesterName(); name != "" {
		return name
	}

	return e.GetRequesterFingerprint()
}

func endorsementUse(item *ladulasv1.HeldEndorsementInfo) string {
	if item.GetUnreportedUses() == 0 {
		return fmt.Sprintf("%d", item.GetUseCount())
	}

	return fmt.Sprintf("%d (%d unreported)",
		item.GetUseCount(), item.GetUnreportedUses())
}

// endorsementState is the one column that answers what a reader came for: is
// this machine signing under that promise, and if not, why not.
func endorsementState(item *ladulasv1.HeldEndorsementInfo) string {
	if !item.GetActionable() {
		return item.GetInertBecause()
	}

	if item.GetPublished() {
		return "live"
	}

	// Worth telling apart: a promise that arrived on the request that spent it
	// was never seeable before it was spent, which is the state publishing
	// exists to avoid and cannot always achieve.
	return "live, arrived with a request"
}

func retractionTarget(r *ladulasv1.Retraction) string {
	if id := r.GetEndorsementId(); id != "" {
		return id
	}

	return fmt.Sprintf("everything up to %s",
		r.GetIssuedBefore().AsTime().Local().Format(time.RFC3339))
}
