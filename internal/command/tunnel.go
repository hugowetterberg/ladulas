package command

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// `ladulas tunnel` is the tunnel upgrade's switch (decision AX), through the
// daemon like everything else: the setting and the keys are in the store the
// daemon owns, and the server is the running process's.
//
// Turning it on is a public exposure in decision H's sense, and the command
// says so in the daemon's own words every time it shows the setting, beside
// what the DERP operator learns. Neither sentence is behind a --verbose: the
// switch and its price are one screen.

func tunnelCommand() *cli.Command {
	return &cli.Command{
		Name:  "tunnel",
		Usage: "show or change the tunnel upgrade",
		Description: "With no arguments it shows whether the upgrade is on, " +
			"whether the server is up and in which DERP region, and what " +
			"turning it on exposes. Paired machines that both have it on " +
			"exchange tunnel keys over the pinned channel; the tunnel carries " +
			"the same pinned TLS as a direct connection.",
		Action: runTunnel,
		Commands: []*cli.Command{
			{
				Name:   "on",
				Usage:  "turn the upgrade on, generating its keys the first time",
				Before: NoArguments,
				Action: func(ctx context.Context, cmd *cli.Command) error {
					on := true

					return setTunnel(ctx, cmd, &ladulasv1.SetTunnelRequest{Enabled: &on})
				},
			},
			{
				Name: "off",
				Usage: "turn the upgrade off and tell every peer to drop " +
					"what it holds for this machine",
				Before: NoArguments,
				Action: func(ctx context.Context, cmd *cli.Command) error {
					off := false

					return setTunnel(ctx, cmd, &ladulasv1.SetTunnelRequest{Enabled: &off})
				},
			},
			{
				Name:      "derp-map",
				Usage:     "pick the DERP region from a self-hosted map, or `default`",
				ArgsUsage: "<url|default>",
				Description: "The region is picked once, the first time the " +
					"server starts, and kept: a tunnel address embeds it, and " +
					"a paired machine with no direct path has no way to hear " +
					"about a new one. So a new map is used for the next pick, " +
					"which happens only with --repick — and --repick strands " +
					"every pair whose only way to reach this machine is the " +
					"tunnel.",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "repick",
						Usage: "forget the region and pick again from this map",
					},
				},
				Action: runTunnelDERPMap,
			},
		},
	}
}

func runTunnel(ctx context.Context, cmd *cli.Command) error {
	if _, err := NoArguments(ctx, cmd); err != nil {
		return err
	}

	client := localapi.NewClient(cmd.String("control-socket"))

	resp, err := client.Control().Tunnel(ctx,
		connect.NewRequest(&ladulasv1.TunnelRequest{}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	printTunnel(resp.Msg.GetState())

	return nil
}

func runTunnelDERPMap(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 1 {
		return cli.Exit("Say which DERP map: a URL, or `default`.", 1)
	}

	url := cmd.Args().First()
	if url == "default" {
		url = ""
	}

	return setTunnel(ctx, cmd, &ladulasv1.SetTunnelRequest{
		DerpMapUrl:    url,
		SetDerpMapUrl: true,
		RepickRegion:  cmd.Bool("repick"),
	})
}

func setTunnel(ctx context.Context, cmd *cli.Command, msg *ladulasv1.SetTunnelRequest) error {
	client := localapi.NewClient(cmd.String("control-socket"))

	resp, err := client.Control().SetTunnel(ctx, connect.NewRequest(msg))
	if err != nil {
		return requireInstance(cmd, err)
	}

	printTunnel(resp.Msg.GetState())

	return nil
}

func printTunnel(state *ladulasv1.TunnelState) {
	switch {
	case !state.GetAvailable():
		fmt.Println("Tunnel        not in this build")
	case state.GetEnabled():
		fmt.Println("Tunnel        on")
	default:
		fmt.Println("Tunnel        off")
	}

	if state.GetEnabled() {
		switch {
		case state.GetRunning():
			fmt.Printf("Server        up, DERP region %s, version %d\n",
				state.GetRegion(), state.GetVersion())
		case state.GetDetail() != "":
			fmt.Printf("Server        not up: %s\n", state.GetDetail())
		default:
			fmt.Println("Server        starting")
		}
	} else if detail := state.GetDetail(); detail != "" && !state.GetAvailable() {
		fmt.Printf("              %s\n", detail)
	}

	if url := state.GetDerpMapUrl(); url != "" {
		fmt.Printf("DERP map      %s\n", url)
	} else {
		fmt.Printf("DERP map      %s (the default)\n", state.GetDefaultDerpMapUrl())
	}

	fmt.Printf("\n%s\n\n%s\n", state.GetExposure(), state.GetMetadata())
}
