package command

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// The peer commands talk to the running instance rather than to the store.
//
// Some of them could not be done any other way: pairing needs the listener the
// daemon owns and a confirmation that reaches the terminal that started it, and
// revoking has to drop the connection the peer is holding, which only the
// process holding it can do. The rest — listing, renaming, changing directions
// — go the same way for the reason §14 gives for everything else: the trust
// records live in the store, and the instance owns the store.

func peersCommand() *cli.Command {
	return &cli.Command{
		Name:  "peers",
		Usage: "list, adjust and revoke paired instances",
		Commands: []*cli.Command{
			peersListCommand(),
			peersAllowCommand(),
			peersRenameCommand(),
			peersRevokeCommand(),
		},
	}
}

func peersListCommand() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "list paired instances and whether they can be reached",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			peers, err := listPeers(ctx, cmd)
			if err != nil {
				return err
			}

			if len(peers) == 0 {
				fmt.Println("No paired instances yet. `ladulas pair --listen`" +
					" on one machine and `ladulas pair <host:port>` on the other.")

				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

			fmt.Fprintln(w, "NAME\tFINGERPRINT\tDIRECTION\tKEYS\tSTATE\tADDRESSES")

			for _, peer := range peers {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					peer.GetName(), peer.GetFingerprint(),
					directionWord(peer.GetMayApprove(), peer.GetMayRequest()),
					keyWord(peer),
					peerState(peer),
					strings.Join(peer.GetAddresses(), " "))
			}

			if err := w.Flush(); err != nil {
				return fmt.Errorf("write table: %w", err)
			}

			return nil
		},
	}
}

// listPeers asks the running instance, which is the only thing that knows
// whether a peer is reachable — and, since the trust records live in the store,
// the only thing that can list them at all.
func listPeers(
	ctx context.Context, cmd *cli.Command,
) ([]*ladulasv1.PeerStatus, error) {
	live, err := fetchStatus(ctx, cmd)
	if err != nil {
		return nil, requireInstance(cmd, err)
	}

	if live.GetLockState() == ladulasv1.LockState_LOCK_STATE_SEALED {
		// The trust records are inside the store, so a sealed instance has
		// nothing to list. Saying "no peers" would be a lie of exactly the kind
		// that costs an evening (§10).
		return nil, cli.Exit(errSealedStore.Error(), 1)
	}

	if live.GetLockState() == ladulasv1.LockState_LOCK_STATE_UNINITIALIZED {
		return nil, cli.Exit(errNoStoreYet.Error(), 1)
	}

	return live.GetPeers(), nil
}

// errSealedStore is what every listing says when the running instance cannot
// read its own store.
var errSealedStore = errors.New(
	"the store is sealed, so there is nothing to list; run `ladulas unlock`")

// errNoStoreYet is the other reason there is nothing to list, and the one with
// a different remedy.
var errNoStoreYet = errors.New(
	"this instance has no store yet; run `ladulas init` to create one")

// offline reports whether an error means there is nothing listening, as
// distinct from an instance that answered with a refusal.
func offline(err error) bool {
	if errors.Is(err, localapi.ErrNoInstance) {
		return true
	}

	// A build with peering switched off serves no control service, which is a
	// different thing from no instance at all but has the same remedy.
	return connect.CodeOf(err) == connect.CodeUnimplemented ||
		connect.CodeOf(err) == connect.CodeUnavailable
}

func directionWord(mayApprove, mayRequest bool) string {
	switch {
	case mayApprove && mayRequest:
		return "both"
	case mayApprove:
		return "approves for us"
	case mayRequest:
		return "asks us"
	default:
		return "none"
	}
}

// keyWord says how much of this instance's key material a peer may borrow.
func keyWord(peer *ladulasv1.PeerStatus) string {
	switch {
	case peer.GetAllKeys():
		return "all"
	case len(peer.GetAllowedKeys()) == 0:
		return "none"
	default:
		return fmt.Sprintf("%d", len(peer.GetAllowedKeys()))
	}
}

// lastSeenOf is the peer's last contact, and the zero time when there has been
// none — which `AsTime()` alone would render as the epoch.
func lastSeenOf(peer *ladulasv1.PeerStatus) time.Time {
	if peer.GetLastSeenAt() == nil {
		return time.Time{}
	}

	return peer.GetLastSeenAt().AsTime()
}

// peerState is trust.DescribeState over the wire type. The words are that
// package's so that a listing here and a pill in the window cannot disagree
// about whether a phone in somebody's pocket is missing.
func peerState(peer *ladulasv1.PeerStatus) string {
	return trust.DescribeState(
		peer.GetOnline(),
		peer.GetAddresses(),
		peer.GetMayApprove(),
		peer.GetLastError(),
		lastSeenOf(peer),
		time.Now(),
	)
}

// peersAllowCommand sets a peer's permissions from the flags, and the flags
// describe the state wanted rather than a change to make: a call that leaves
// --key out takes away whatever keys the peer had. That is worth a sentence in
// the usage, because the alternative — flags that only ever add — makes taking
// a permission away something you cannot do at all.
func peersAllowCommand() *cli.Command {
	return &cli.Command{
		Name: "allow",
		Usage: "set what a peer may do: --approve lets it approve for this " +
			"instance, --request lets it ask this instance to approve, and " +
			"--key lets it sign with one of this instance's keys. The flags say " +
			"what the peer may do afterwards, so anything left out is withdrawn",
		ArgsUsage: "<name or fingerprint>",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "approve",
				Usage: "the peer may approve signing requests for this instance",
			},
			&cli.BoolFlag{
				Name:  "request",
				Usage: "the peer may ask this instance to approve its requests",
			},
			&cli.StringSliceFlag{
				Name: "key",
				Usage: "a key the peer may ask this instance to sign with, " +
					"by `label` or fingerprint. Repeatable",
			},
			&cli.BoolFlag{
				Name: "all-keys",
				Usage: "the peer may sign with every key this instance holds, " +
					"including keys generated later",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ref := cmd.Args().First()
			if ref == "" {
				return cli.Exit(
					"Usage: ladulas peers allow <name or fingerprint> "+
						"[--approve] [--request] [--key <label>] [--all-keys]", 1)
			}

			directions := trust.Directions{
				MayApprove:  cmd.Bool("approve"),
				MayRequest:  cmd.Bool("request"),
				AllowedKeys: cmd.StringSlice("key"),
				AllKeys:     cmd.Bool("all-keys"),
			}

			client := localapi.NewClient(cmd.String("control-socket"))

			resp, err := client.Control().SetPeerDirections(ctx,
				connect.NewRequest(&ladulasv1.SetPeerDirectionsRequest{
					Peer:        ref,
					MayApprove:  directions.MayApprove,
					MayRequest:  directions.MayRequest,
					AllowedKeys: directions.AllowedKeys,
					AllKeys:     directions.AllKeys,
				}))
			if err != nil {
				return requireInstance(cmd, err)
			}

			printAllowed(resp.Msg.GetPeer().GetName(),
				directions, resp.Msg.GetPeer().GetAllowedKeys())

			return nil
		},
	}
}

func printAllowed(name string, directions trust.Directions, keys []string) {
	fmt.Printf("%s now %s\n", name,
		trust.Describe(directions.MayApprove, directions.MayRequest))

	switch {
	case directions.AllKeys:
		fmt.Println("It may sign with every key this instance holds.")
	case len(keys) == 0:
		fmt.Println("It may not sign with any of this instance's keys.")
	default:
		fmt.Printf("It may sign with %s\n", strings.Join(keys, ", "))
	}
}

func peersRenameCommand() *cli.Command {
	return &cli.Command{
		Name: "rename",
		Usage: "change the name a peer is known by here; " +
			"the name is this side's own label and nobody else sees it",
		ArgsUsage: "<name or fingerprint> <new name>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ref := cmd.Args().Get(0)
			name := cmd.Args().Get(1)

			if ref == "" || name == "" {
				return cli.Exit(
					"Usage: ladulas peers rename <name or fingerprint> <new name>", 1)
			}

			client := localapi.NewClient(cmd.String("control-socket"))

			resp, err := client.Control().RenamePeer(ctx,
				connect.NewRequest(&ladulasv1.RenamePeerRequest{
					Peer: ref,
					Name: name,
				}))
			if err != nil {
				return requireInstance(cmd, err)
			}

			fmt.Printf("%s is now %s\n",
				resp.Msg.GetPeer().GetFingerprint(), resp.Msg.GetPeer().GetName())

			return nil
		},
	}
}

func peersRevokeCommand() *cli.Command {
	return &cli.Command{
		Name: "revoke",
		Usage: "forget a peer and drop the connection it is holding; " +
			"this side alone decides, and the peer is not asked",
		ArgsUsage: "<name or fingerprint>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ref := cmd.Args().First()
			if ref == "" {
				return cli.Exit("Usage: ladulas peers revoke <name or fingerprint>", 1)
			}

			client := localapi.NewClient(cmd.String("control-socket"))

			resp, err := client.Control().RevokePeer(ctx,
				connect.NewRequest(&ladulasv1.RevokePeerRequest{Peer: ref}))
			if err != nil {
				return requireInstance(cmd, err)
			}

			fmt.Printf("Revoked %s and dropped its connections.\n",
				resp.Msg.GetFingerprint())

			return nil
		},
	}
}

func pairCommand() *cli.Command {
	return &cli.Command{
		Name: "pair",
		Usage: "pair with another instance: --listen to display a code, " +
			"or give the other instance's host:port to use one",
		ArgsUsage: "[host:port]",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "listen",
				Usage: "display a pairing code and wait for the other instance",
			},
			&cli.StringFlag{
				Name: "code",
				Usage: "the code the other instance is displaying, " +
					"or the full code it printed",
			},
			&cli.StringFlag{
				Name: "role",
				Usage: "what the peer may do: `approver` (it approves for this " +
					"instance), `requester` (it asks this instance), or `both`",
				Value: "both",
			},
			&cli.BoolFlag{
				Name:  "yes",
				Usage: "answer the confirmation automatically; for scripts only",
			},
		},
		Action: runPair,
	}
}

func runPair(ctx context.Context, cmd *cli.Command) error {
	mayApprove, mayRequest, err := parseRole(cmd.String("role"))
	if err != nil {
		return err
	}

	client := localapi.NewClient(cmd.String("control-socket"))
	address := cmd.Args().First()

	var stream *connect.ServerStreamForClient[ladulasv1.PairingProgress]

	switch {
	case cmd.Bool("listen"):
		stream, err = client.Control().BeginPairing(ctx,
			connect.NewRequest(&ladulasv1.BeginPairingRequest{
				PeerMayApprove: mayApprove,
				PeerMayRequest: mayRequest,
			}))
	case address != "" || cmd.String("code") != "":
		stream, err = client.Control().PairWithPeer(ctx,
			connect.NewRequest(&ladulasv1.PairWithPeerRequest{
				Address:        address,
				Code:           cmd.String("code"),
				PeerMayApprove: mayApprove,
				PeerMayRequest: mayRequest,
			}))
	default:
		return cli.Exit(
			"Usage: ladulas pair --listen, or ladulas pair <host:port> --code <code>", 1)
	}

	if err != nil {
		return requireInstance(cmd, err)
	}

	defer func() {
		_ = stream.Close()
	}()

	return followPairing(ctx, cmd, client, stream)
}

func parseRole(role string) (mayApprove, mayRequest bool, err error) {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "", "both":
		return true, true, nil
	case "approver":
		return true, false, nil
	case "requester":
		return false, true, nil
	default:
		return false, false, cli.Exit(fmt.Sprintf(
			"Unknown role %q. Use approver, requester or both.", role), 1)
	}
}

// followPairing prints the exchange as it happens and answers the confirmation.
func followPairing(
	ctx context.Context,
	cmd *cli.Command,
	client *localapi.Client,
	stream *connect.ServerStreamForClient[ladulasv1.PairingProgress],
) error {
	for stream.Receive() {
		progress := stream.Msg()

		switch progress.GetKind() {
		case ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_CODE:
			printPairingCode(progress)
		case ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_CONFIRM:
			if err := answerConfirmation(ctx, cmd, client, progress); err != nil {
				return err
			}
		case ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_DONE:
			printPaired(progress.GetPeer())

			return nil
		case ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_WAITING:
			describePairingWait(progress.GetMessage())

			return nil
		case ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_FAILED:
			return cli.Exit("Not paired: "+progress.GetMessage(), 1)
		case ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_UNSPECIFIED:
		}
	}

	if err := stream.Err(); err != nil {
		return fmt.Errorf("pairing: %w", err)
	}

	return nil
}

func printPairingCode(progress *ladulasv1.PairingProgress) {
	fmt.Printf("Pairing code   %s\n", progress.GetCode())

	if addresses := progress.GetListenAddresses(); len(addresses) > 0 {
		fmt.Printf("Address        %s\n", strings.Join(addresses, "\n               "))
	}

	if expires := progress.GetExpiresAt(); expires != nil {
		fmt.Printf("Valid until    %s\n",
			expires.AsTime().Local().Format(time.Kitchen))
	}

	fmt.Println()
	fmt.Println("On the other machine:")
	fmt.Printf("  ladulas pair %s --code %s\n",
		firstAddress(progress.GetListenAddresses()), progress.GetCode())

	// The full code is what a QR carries (§7): the secret, this instance's
	// identity key and its addresses, so the far side pins before it connects
	// and there is nothing left for a person to compare character by character.
	// It is printed rather than drawn because a headless box's terminal is not
	// somewhere Ladulås gets to choose the pixels; feeding it to qrencode is
	// what turns it into something a phone camera can read.
	if full := progress.GetFullCode(); full != "" {
		fmt.Println()
		fmt.Println("On a phone, scan this — or paste it into the app:")
		fmt.Printf("  %s\n", full)
		fmt.Println()
		fmt.Printf("  qrencode -t ansiutf8 %q\n", full)
	}

	fmt.Println()
	fmt.Println("Waiting…")
}

func firstAddress(addresses []string) string {
	if len(addresses) == 0 {
		return "<host:port>"
	}

	return addresses[0]
}

// answerConfirmation shows both fingerprints and asks.
//
// Both, because the whole integrity story of a pairing is that the two screens
// agree: a prompt showing only the other side's fingerprint gives the user
// nothing to compare it against.
func answerConfirmation(
	ctx context.Context,
	cmd *cli.Command,
	client *localapi.Client,
	progress *ladulasv1.PairingProgress,
) error {
	msg := progress.GetConfirmation()
	pairing := msg.GetPairing()

	fmt.Println()
	fmt.Println(approval.RenderPrompt(msg).Text())
	fmt.Println()
	fmt.Printf("  This instance   %s (%s)\n",
		pairing.GetLocalName(), pairing.GetLocalFingerprint())
	fmt.Printf("  The other one   %s (%s)\n",
		pairing.GetPeerName(), pairing.GetPeerFingerprint())
	fmt.Println()
	fmt.Println("  Both machines should be showing these two fingerprints.")

	if pairing.GetKeyFromCode() {
		fmt.Println("  The code carried the other instance's identity, " +
			"so it has already been checked.")
	}

	fmt.Printf("\n  It %s\n\n",
		trust.Describe(pairing.GetPeerMayApprove(), pairing.GetPeerMayRequest()))

	accepted := cmd.Bool("yes")

	if !accepted {
		fmt.Print("Pair with it? [y/N] ")

		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("read the answer: %w", err)
		}

		answer := strings.TrimSpace(strings.ToLower(line))
		accepted = answer == "y" || answer == "yes"
	}

	_, err := client.Control().AnswerPairing(ctx,
		connect.NewRequest(&ladulasv1.AnswerPairingRequest{
			RequestId: msg.GetRequestId(),
			Accepted:  accepted,
			Reason:    "answered at the command line",
		}))
	if err != nil {
		return fmt.Errorf("send the answer: %w", err)
	}

	return nil
}

func printPaired(peer *ladulasv1.PeerStatus) {
	fmt.Printf("\nPaired with %s (%s).\n",
		peer.GetName(), peer.GetFingerprint())
	fmt.Printf("It %s\n",
		trust.Describe(peer.GetMayApprove(), peer.GetMayRequest()))
}
