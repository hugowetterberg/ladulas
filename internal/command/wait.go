package command

import (
	"context"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/internal/app"
	"github.com/hugowetterberg/ladulas/internal/localapi"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Waiting for somebody to unlock the store.
//
// It exists because the alternative is asking every few seconds, and something
// that has to wait for a person may have to wait for hours. The daemon knows the
// moment the state changes, so the wait belongs there and this is a call that
// stays open until it does — the same shape as an approver's inbox poll (§11),
// for the same reason.
//
// The exit status is the answer, so this is usable from a script without
// reading what it printed: 0 for the state that was waited for, 1 for a wait
// that ran out, and the ordinary failure for an instance that is not running.

func waitCommand() *cli.Command {
	return &cli.Command{
		Name:      "wait",
		Usage:     "wait until the store is in a given state",
		ArgsUsage: "[unlocked|locked|sealed|unsealed]",
		Description: "Holds until the store reaches the state, and exits 0 " +
			"when it does. `unsealed` is either unlocked or soft-locked — the " +
			"states in which the key is in memory. Without a timeout it waits " +
			"for as long as it is left running, which is what makes it usable " +
			"as something to watch a locked machine with. An instance already " +
			"in the state returns immediately.",
		Flags: []cli.Flag{
			&cli.DurationFlag{
				Name: "timeout",
				Usage: "give up after this long; zero waits for as long as " +
					"the command is left running",
			},
			&cli.BoolFlag{
				Name:  "quiet",
				Usage: "say nothing, and answer with the exit status alone",
			},
		},
		Action: runWait,
	}
}

func runWait(ctx context.Context, cmd *cli.Command) error {
	want, err := waitStates(cmd.Args().First())
	if err != nil {
		return cli.Exit(err.Error(), 2)
	}

	client := localapi.NewClient(cmd.String("control-socket"))

	resp, err := client.Control().AwaitState(ctx,
		connect.NewRequest(&ladulasv1.AwaitStateRequest{
			States:  want,
			Timeout: durationpb.New(cmd.Duration("timeout")),
		}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	state := app.StateWord(resp.Msg.GetState())

	if !resp.Msg.GetReached() {
		if !cmd.Bool("quiet") {
			fmt.Printf("Still %s after %s.\n",
				state, cmd.Duration("timeout").Round(time.Second))
		}

		return cli.Exit("", 1)
	}

	if cmd.Bool("quiet") {
		return nil
	}

	fmt.Printf("The store is %s", state)

	if reason := resp.Msg.GetStateReason(); reason != "" {
		fmt.Printf(" — %s", reason)
	}

	fmt.Println(".")

	return nil
}

// waitStates turns the word somebody typed into the states that end the wait.
//
// "unsealed" is two states rather than one because the key being in memory and
// approval being available here are different things (§10), and something
// waiting to use the agent wants the first while something waiting to be
// prompted wants the second.
func waitStates(word string) ([]ladulasv1.LockState, error) {
	switch strings.ToLower(strings.TrimSpace(word)) {
	case "", "unlocked":
		return []ladulasv1.LockState{
			ladulasv1.LockState_LOCK_STATE_UNLOCKED,
		}, nil
	case "unsealed":
		return []ladulasv1.LockState{
			ladulasv1.LockState_LOCK_STATE_UNLOCKED,
			ladulasv1.LockState_LOCK_STATE_LOCKED,
		}, nil
	case "locked":
		return []ladulasv1.LockState{
			ladulasv1.LockState_LOCK_STATE_LOCKED,
		}, nil
	case "sealed":
		return []ladulasv1.LockState{
			ladulasv1.LockState_LOCK_STATE_SEALED,
		}, nil
	default:
		return nil, fmt.Errorf(
			"%q is not a state to wait for: unlocked, unsealed, locked or sealed",
			word)
	}
}
