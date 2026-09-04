package command

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// `ladulas listen` is where the peer channel's addresses are managed, and it
// goes through the daemon like everything else: the addresses are the running
// process's, and the setting is in the store the process owns (decisions K, AH).
//
// It exists because the automatic policy is a policy and will sometimes be
// wrong. A machine on a tailnet binds its tailnet addresses and nothing else,
// which is right almost always and wrong on the box whose LAN is how a phone
// reaches it; a bridge called something this code has never heard of is skipped
// as a container's; an address that only exists on Tuesdays is nobody's to
// guess. The answer to all three is the same one, and it is one command rather
// than a unit file to edit and a daemon to restart.

func listenCommand() *cli.Command {
	return &cli.Command{
		Name:  "listen",
		Usage: "show or change where the peer channel listens",
		Description: "With no arguments it shows what is bound, what peers " +
			"are told to dial, and every address the automatic policy passed " +
			"over with the reason it did.",
		Action: runListen,
		Commands: []*cli.Command{
			listenSetCommand(),
			listenClearCommand(),
		},
	}
}

func listenSetCommand() *cli.Command {
	return &cli.Command{
		Name:      "set",
		Usage:     "listen on these addresses, and keep doing so",
		ArgsUsage: "<address|auto|off> [address...]",
		Description: "An address is a host, a host:port, or a bare port. " +
			"Several are taken together, and so is a comma-separated list. " +
			"`auto` asks for the automatic policy: the machine's tailnet " +
			"addresses if it has any, otherwise its local network ones, " +
			"otherwise loopback — skipping container and virtual machine " +
			"interfaces. `off` switches peering off entirely.\n\n" +
			"The change takes effect at once: the channel is rebound, and if " +
			"the new addresses cannot be bound the previous ones come back " +
			"and this says so. It is remembered in the store and survives a " +
			"restart — but a --peer-listen flag on the daemon still wins, and " +
			"this says that too.",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name: "public",
				Usage: "allow an address reachable from outside the local " +
					"network. The channel does not trust the network either " +
					"way; this exists so it never happens by accident",
			},
		},
		Action: runListenSet,
	}
}

func listenClearCommand() *cli.Command {
	return &cli.Command{
		Name:  "clear",
		Usage: "forget the stored setting and go back to the flag or the policy",
		Description: "Clearing is not the same as `set auto`: a stored `auto` " +
			"is somebody having asked for the automatic policy and outranks " +
			"a daemon started with no flag, while a cleared setting leaves " +
			"the decision where it was before anybody said anything.",
		Before: NoArguments,
		Action: runListenClear,
	}
}

func runListen(ctx context.Context, cmd *cli.Command) error {
	if _, err := NoArguments(ctx, cmd); err != nil {
		return err
	}

	state, err := fetchListen(ctx, cmd)
	if err != nil {
		return requireInstance(cmd, err)
	}

	printListen(state)

	return nil
}

func runListenSet(ctx context.Context, cmd *cli.Command) error {
	spec := strings.Join(cmd.Args().Slice(), ",")
	if spec == "" {
		return cli.Exit(
			"Say where to listen: an address, `auto`, or `off`.\n"+
				"`ladulas listen` shows what is bound now.", 1)
	}

	client := localapi.NewClient(cmd.String("control-socket"))

	resp, err := client.Control().SetPeerListen(ctx,
		connect.NewRequest(&ladulasv1.SetPeerListenRequest{
			Spec:        spec,
			AllowPublic: cmd.Bool("public"),
		}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	fmt.Printf("%s.\n\n", capitalise(resp.Msg.GetDetail()))
	printListen(resp.Msg.GetState())

	return nil
}

func runListenClear(ctx context.Context, cmd *cli.Command) error {
	client := localapi.NewClient(cmd.String("control-socket"))

	resp, err := client.Control().SetPeerListen(ctx,
		connect.NewRequest(&ladulasv1.SetPeerListenRequest{Clear: true}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	fmt.Printf("The stored setting is gone. %s.\n\n",
		capitalise(resp.Msg.GetDetail()))
	printListen(resp.Msg.GetState())

	return nil
}

func fetchListen(
	ctx context.Context, cmd *cli.Command,
) (*ladulasv1.PeerListenState, error) {
	client := localapi.NewClient(cmd.String("control-socket"))

	resp, err := client.Control().PeerListen(ctx,
		connect.NewRequest(&ladulasv1.PeerListenRequest{}))
	if err != nil {
		return nil, err
	}

	return resp.Msg.GetState(), nil
}

// printListen puts the bound addresses above the advertised ones, and the skips
// under both.
//
// The advertised list is not a repetition of the bound one and is printed even
// when it looks like one: a tailnet name in front of an address is the thing a
// person is meant to see on the other machine, and loopback appearing there is
// the tell that this instance has nothing better and its peers are recording an
// address that will reach themselves.
func printListen(state *ladulasv1.PeerListenState) {
	fmt.Printf("Setting       %s (%s)\n",
		state.GetSpec(), sourceWord(state.GetSource()))

	if stored := state.GetStoredSpec(); stored != "" &&
		state.GetSource() != ladulasv1.ListenSource_LISTEN_SOURCE_STORED {
		fmt.Printf("Stored        %s — not in force\n", stored)
	}

	if state.GetAllowPublic() {
		fmt.Printf("Public        allowed\n")
	}

	if tier := state.GetTier(); tier != "" {
		fmt.Printf("Chose         %s\n", tierWord(tier, state.GetBound()))
	}

	if len(state.GetBound()) > 0 {
		fmt.Printf("Bound         %s\n", strings.Join(state.GetBound(), ", "))
	}

	if len(state.GetAdvertised()) > 0 {
		fmt.Printf("Peers dial    %s\n",
			strings.Join(state.GetAdvertised(), ", "))
	}

	if detail := state.GetDetail(); detail != "" {
		fmt.Printf("Not bound     %s\n", detail)
	}

	printSkipped(state.GetSkipped())
}

func printSkipped(skipped []*ladulasv1.SkippedListenAddress) {
	if len(skipped) == 0 {
		return
	}

	fmt.Println()
	fmt.Println("Passed over:")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "  ADDRESS\tINTERFACE\tWHY")

	for _, one := range skipped {
		fmt.Fprintf(w, "  %s\t%s\t%s\n",
			one.GetAddress(), one.GetInterface(), one.GetReason())
	}

	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "write table: %v\n", err)
	}

	fmt.Println()
	fmt.Println("`ladulas listen set <address>` binds one of them anyway.")
}

func sourceWord(source ladulasv1.ListenSource) string {
	switch source {
	case ladulasv1.ListenSource_LISTEN_SOURCE_FLAG:
		return "--peer-listen on the daemon"
	case ladulasv1.ListenSource_LISTEN_SOURCE_STORED:
		return "`ladulas listen set`"
	case ladulasv1.ListenSource_LISTEN_SOURCE_AUTOMATIC,
		ladulasv1.ListenSource_LISTEN_SOURCE_UNSPECIFIED:
		return "nobody has said, so the policy decides"
	}

	return "unknown"
}

// tierWord says what was chosen and, for the tiers that mean something is
// missing, what that costs.
//
// The local tier is one tier covering two kinds of address (decision AR), and
// which kinds this machine actually has is the thing worth reading, so the
// bound list is looked at rather than the tier name repeated.
func tierWord(tier string, bound []string) string {
	switch tier {
	case "local":
		return localTierWord(bound)
	case "loopback":
		if len(bound) == 0 {
			return "loopback"
		}

		return "loopback only — no peer on another machine can reach this " +
			"instance"
	case "explicit":
		return "the addresses given"
	case "none":
		return "nothing"
	}

	return tier
}

// localTierWord says which of the tailnet and the local network the bound list
// actually holds, since the tier is the same word whether it holds both or one.
func localTierWord(bound []string) string {
	var tailnet, lan bool

	for _, address := range bound {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}

		ip := net.ParseIP(host)

		switch {
		case ip == nil:
			continue
		case transport.IsTailnetIP(ip):
			tailnet = true
		default:
			lan = true
		}
	}

	switch {
	case tailnet && lan:
		return "the tailnet and the local network addresses"
	case tailnet:
		return "the tailnet addresses; there is no local network address here"
	case lan:
		return "the local network addresses; there is no tailnet here"
	}

	return "the tailnet and local network addresses"
}

// capitalise makes a sentence of a clause the daemon wrote lower case, since
// the daemon's half is a fragment and this side is printing it as a line.
func capitalise(s string) string {
	if s == "" {
		return s
	}

	return strings.ToUpper(s[:1]) + s[1:]
}
