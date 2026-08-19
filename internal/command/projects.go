package command

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The projects verbs of §14, as a thin client of the control service.
//
// There are three of them rather than four (decision Q). `refresh` is gone
// because there is nothing to refresh: a project's branch and commit are read
// afresh every time an approver lists them, and a page is read from the machine
// that has it every time somebody opens it. What was a push and a pull is now
// one question asked at the moment somebody wants the answer.
//
// There is no store fallback here, for the reason decision L gives: the daemon
// is the process holding the store open, and a second one writing to it would
// discard whatever the daemon has learned since.

func projectsCommand() *cli.Command {
	return &cli.Command{
		Name: "projects",
		Usage: "publish a project to the instances that approve for this one, " +
			"and see what has been read of theirs",
		Commands: []*cli.Command{
			projectsPublishCommand(),
			projectsListCommand(),
			projectsUnpublishCommand(),
			projectsAutoCommand(),
		},
	}
}

func projectsPublishCommand() *cli.Command {
	return &cli.Command{
		Name: "publish",
		Usage: "mark a project as readable by the paired instances that " +
			"approve for this one",
		ArgsUsage: "[directory]",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "name",
				Usage: "what to call the project; defaults to the directory name",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			dir := cmd.Args().First()
			if dir == "" {
				dir = "."
			}

			// Resolved here, against the shell's working directory, because
			// the daemon has a different one — it is a systemd unit, and its
			// cwd is wherever it happened to start. `publish ../notes` typed
			// in a project has to mean the sibling of that project, and only
			// this process knows where that is.
			dir, err := filepath.Abs(dir)
			if err != nil {
				return fmt.Errorf("resolve %q: %w", dir, err)
			}

			client := localapi.NewClient(cmd.String("control-socket"))

			resp, err := client.Control().PublishProject(ctx,
				connect.NewRequest(&ladulasv1.PublishProjectRequest{
					Path: dir,
					Name: cmd.String("name"),
				}))
			if err != nil {
				return projectError(cmd, err)
			}

			printPublication(resp.Msg.GetPublication())

			return nil
		},
	}
}

func projectsListCommand() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "list what this instance publishes and what it has read",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			client := localapi.NewClient(cmd.String("control-socket"))

			resp, err := client.Control().ListPublications(ctx,
				connect.NewRequest(&ladulasv1.ListPublicationsRequest{}))
			if err != nil {
				return projectError(cmd, err)
			}

			printPublished(resp.Msg.GetPublished())
			printCached(resp.Msg.GetCached())
			printAutoPublish(resp.Msg.GetAutoPublish())

			return nil
		},
	}
}

func printPublished(published []*ladulasv1.Publication) {
	if len(published) == 0 {
		fmt.Println("This instance publishes nothing. " +
			"`ladulas projects publish .` in a project offers it to the " +
			"instances that approve for this one.")

		return
	}

	fmt.Println("Published from here:")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "  NAME\tBRANCH\tCOMMIT\tPATH")

	for _, publication := range published {
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n",
			publication.GetName(),
			publication.GetBranch(),
			shortCommit(publication.GetCommit()),
			publication.GetPath())
	}

	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
}

// printCached is what this instance has read of other instances' projects,
// which is the only sense in which it holds any of them (decision Q).
func printCached(cached []*ladulasv1.CachedProject) {
	if len(cached) == 0 {
		return
	}

	fmt.Println("\nRead from other instances:")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "  NAME\tFROM\tPAGES\tAT\tLAST READ")

	for _, project := range cached {
		fmt.Fprintf(w, "  %s\t%s\t%d\t%s\t%s\n",
			project.GetProject().GetName(),
			project.GetPeer(),
			len(project.GetFiles()),
			shortCommit(project.GetProject().GetCommit()),
			project.GetLastReadAt().AsTime().Local().Format(time.RFC3339))
	}

	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
}

func projectsUnpublishCommand() *cli.Command {
	return &cli.Command{
		Name: "unpublish",
		Usage: "stop publishing a project, or forget what has been read of " +
			"somebody else's",
		ArgsUsage: "<name or project id>",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ref := cmd.Args().First()
			if ref == "" {
				return cli.Exit(
					"Usage: ladulas projects unpublish <name or project id>", 1)
			}

			client := localapi.NewClient(cmd.String("control-socket"))

			resp, err := client.Control().UnpublishProject(ctx,
				connect.NewRequest(&ladulasv1.UnpublishProjectRequest{
					Project: ref,
				}))
			if err != nil {
				return projectError(cmd, err)
			}

			if !resp.Msg.GetPublishedHere() {
				fmt.Printf("Forgot the %d pages read of %s.\n",
					resp.Msg.GetForgotten(), ref)

				return nil
			}

			fmt.Printf("Stopped publishing %s.\n", ref)
			fmt.Println("  Nobody was told: there is no copy anywhere to take " +
				"back, and an approver that asks next is told there is no " +
				"such project.")

			return nil
		},
	}
}

// projectsAutoCommand is the setting decision Q gives publishing a default for.
func projectsAutoCommand() *cli.Command {
	return &cli.Command{
		Name: "auto",
		Usage: "publish, automatically, any project this instance asks for a " +
			"signature in; with no argument, say whether it does",
		ArgsUsage: "[on|off]",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			client := localapi.NewClient(cmd.String("control-socket"))

			switch cmd.Args().First() {
			case "":
				resp, err := client.Control().ListPublications(ctx,
					connect.NewRequest(&ladulasv1.ListPublicationsRequest{}))
				if err != nil {
					return projectError(cmd, err)
				}

				printAutoPublish(resp.Msg.GetAutoPublish())

				return nil
			case "on", "off":
			default:
				return cli.Exit("Usage: ladulas projects auto [on|off]", 1)
			}

			resp, err := client.Control().SetAutoPublish(ctx,
				connect.NewRequest(&ladulasv1.SetAutoPublishRequest{
					Enabled: cmd.Args().First() == "on",
				}))
			if err != nil {
				return projectError(cmd, err)
			}

			printAutoPublish(resp.Msg.GetEnabled())

			return nil
		},
	}
}

func printAutoPublish(enabled bool) {
	if enabled {
		fmt.Println("\nProjects this instance asks for a signature in are " +
			"published automatically.\n" +
			"  `ladulas projects auto off` stops that.")

		return
	}

	fmt.Println("\nProjects this instance asks for a signature in are not " +
		"published automatically.\n" +
		"  `ladulas projects auto on` is the default, and is what makes a " +
		"project readable\n  at the moment somebody is being asked to sign " +
		"in it.")
}

// printPublication says what is now on offer.
//
// It says nothing about delivery, because there is none (decision Q):
// publishing marks a project as available and an approver reads it by asking,
// so what there is to report is what was marked and where it is.
func printPublication(publication *ladulasv1.Publication) {
	fmt.Printf("Published %s from %s\n",
		publication.GetName(), publication.GetPath())

	fmt.Printf("  at %s\n", shortCommit(publication.GetCommit()))
	fmt.Println("  Approvers can browse it while this instance is reachable.")
}

func shortCommit(commit string) string {
	const shown = 10

	if commit == "" {
		return "no commit"
	}

	if len(commit) > shown {
		return commit[:shown]
	}

	return commit
}

// projectError says what a failed call to the instance means. The publication
// record lives in the store the daemon holds open (decision L), so "nothing is
// listening" gets the same advice every other verb gives.
func projectError(cmd *cli.Command, err error) error {
	if strings.Contains(err.Error(), "unavailable") && !offline(err) {
		return cli.Exit(err.Error(), 1)
	}

	return requireInstance(cmd, err)
}
