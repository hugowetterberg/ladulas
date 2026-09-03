package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/internal/sshprobe"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Asking for permission to log in before logging in.
//
// An SSH login is the one operation here that runs on somebody else's clock.
// sshd closes the connection after LoginGraceTime — two minutes by default, and
// not ours to change — so an approval that has to reach a phone has about ninety
// seconds to be noticed, read and answered, and the ordinary reason it is not is
// that the person is driving, or making tea, or in a meeting. The failure is
// silent from the far end and reads as a broken agent from this one.
//
// The fix is to move the question off that clock rather than to make the clock
// longer, which cannot be done from this side. Asked as its own request nothing
// is holding a handshake open: this command blocks the way git blocks on a
// commit signature, the answer has an hour, and what it produces is a grant that
// the logins afterwards fall under without asking again.
//
// It has to connect to the server to ask a useful question. A grant's scope is
// matched for strict equality against what the login derives — key, username,
// host key — and two of those are facts about the server. Which key is whichever
// one the server accepts, and with several in the agent, guessing wrong is the
// ordinary case; the connection settles it without signing anything (§4's query
// form, and internal/sshprobe).

func sshGrantCommand() *cli.Command {
	return &cli.Command{
		Name:      "ssh-grant",
		Usage:     "ask for a standing permission to log in to a server",
		ArgsUsage: "<destination>",
		Description: "Finds out what a login to the destination would look " +
			"like — which key the server accepts, as which user, under which " +
			"host key — and asks for a promise covering logins like it. It " +
			"blocks until somebody answers, which is the point: an approval " +
			"asked for during a login has only the server's login grace " +
			"period to arrive in, and this one has as long as a commit " +
			"signature does.\n\n" +
			"The destination is written the way ssh takes it, and ssh's own " +
			"configuration decides what it means: `ladulas ssh-grant " +
			"git@github.com`, `ladulas ssh-grant bastion`.\n\n" +
			"The promise is made to the session this runs in, so run it in " +
			"the shell that will do the work. The exit status is the answer: " +
			"0 granted or already covered, 1 denied or not answered.",
		Flags: []cli.Flag{
			&cli.DurationFlag{
				Name: "for",
				Usage: "how long a promise to ask for; a suggestion put in " +
					"front of the approver, who decides",
			},
			&cli.DurationFlag{
				Name:  "probe-timeout",
				Value: 15 * time.Second,
				Usage: "how long to give the connection that works out what " +
					"the login would look like",
			},
			&cli.BoolFlag{
				Name:  "quiet",
				Usage: "say nothing, and answer with the exit status alone",
			},
		},
		Action: runSSHGrant,
	}
}

func runSSHGrant(ctx context.Context, cmd *cli.Command) error {
	destination := cmd.Args().First()
	if destination == "" {
		return cli.Exit(
			"Usage: ladulas ssh-grant <destination>, as in git@github.com", 2)
	}

	cfg := ConfigFromFlags(cmd)
	quiet := cmd.Bool("quiet")

	if !quiet {
		fmt.Fprintf(os.Stderr,
			"Asking %s what a login would look like…\n", destination)
	}

	result, err := sshprobe.Probe(
		ctx, cfg.SocketPath, destination, cmd.Duration("probe-timeout"))
	if err != nil {
		return cli.Exit(err.Error(), 2)
	}

	if !quiet {
		printProbe(result)
	}

	client := localapi.NewClient(cmd.String("control-socket"))

	req := &ladulasv1.RequestGrantRequest{
		PublicKey:        result.PublicKey.Marshal(),
		Username:         result.Username,
		HostKey:          result.HostKey.Marshal(),
		DestinationLabel: result.Label,
	}

	if ttl := cmd.Duration("for"); ttl > 0 {
		req.Ttl = durationpb.New(ttl)
	}

	if !quiet {
		fmt.Fprintln(os.Stderr,
			"\nWaiting for an answer. Nothing is signed by this; "+
				"it asks how long logins like the above may go ahead.")
	}

	resp, err := client.Control().RequestGrant(ctx, connect.NewRequest(req))
	if err != nil {
		return cli.Exit(grantRequestError(err), 1)
	}

	return reportGrant(resp.Msg, quiet)
}

// printProbe shows what the promise would be about before it is asked for, so
// that somebody who typed the wrong destination finds out here rather than by
// reading a card on their phone.
func printProbe(result *sshprobe.Result) {
	fmt.Fprintf(os.Stderr, "  Server    %s\n", result.Address)
	fmt.Fprintf(os.Stderr, "  User      %s\n", result.Username)
	fmt.Fprintf(os.Stderr, "  Key       %s\n",
		ssh.FingerprintSHA256(result.PublicKey))
	fmt.Fprintf(os.Stderr, "  Host key  %s\n",
		ssh.FingerprintSHA256(result.HostKey))
}

func reportGrant(msg *ladulasv1.RequestGrantResponse, quiet bool) error {
	if msg.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		if quiet {
			return cli.Exit("", 1)
		}

		reason := msg.GetReason()
		if reason == "" {
			reason = "no reason given"
		}

		return cli.Exit("Not granted: "+reason, 1)
	}

	if quiet {
		return nil
	}

	// An approval with no grant on it is the already-covered case: a policy rule
	// or a promise still running answered without a new one being made. Worth
	// saying plainly rather than reporting a grant that does not exist — the
	// caller's next login works either way, which is what it asked about.
	grant := msg.GetGrant()
	if grant == nil {
		fmt.Printf("Already allowed: %s\n", msg.GetReason())

		return nil
	}

	fmt.Printf("Granted until %s (%s).\n",
		grant.GetExpiresAt().AsTime().Local().Format(time.RFC1123),
		grant.GetDescription())
	fmt.Printf("Take it back with `ladulas grants revoke %s`.\n",
		grant.GetGrantId())

	return nil
}

// grantRequestError turns the transport's error into the sentence the situation
// deserves. A daemon that is not running and a store that is sealed are the two
// ordinary ones, and neither is helped by a stack of RPC wrapping.
func grantRequestError(err error) string {
	var connErr *connect.Error

	if errors.As(err, &connErr) {
		switch connErr.Code() {
		case connect.CodeUnavailable:
			return "nothing is listening on the control socket; " +
				"start the instance with `systemctl --user start ladulas`"
		case connect.CodeFailedPrecondition:
			return connErr.Message() +
				"\nA sealed store has no keys to promise anything about; " +
				"run `ladulas unlock`."
		default:
			return connErr.Message()
		}
	}

	return err.Error()
}
