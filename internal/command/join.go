package command

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// `ladulas pair --join` is the headless half of decision AW: the list a
// joining desktop's Add a machine screen shows, in a terminal. It asks the
// instance to browse, prints what answers, lets somebody pick one by number,
// asks for the PIN, and then joins exactly as `--address --pin` would — except
// that the address is the one the instance checked for that entry, and nobody
// typed it.
//
// The instance browses only while this holds its stream open, and this lets
// go of it as soon as the join has been answered.

// joinLook is how long the list is given to fill before it is first printed.
// An announcing machine answers a query within a second or so, and twice that
// covers a busy Wi-Fi without making somebody wait at an empty prompt.
const joinLook = 2 * time.Second

// nearbyList holds the latest list the instance sent.
type nearbyList struct {
	mu      sync.Mutex
	entries []*ladulasv1.NearbyPairing
	err     error
	ended   bool
}

func (l *nearbyList) snapshot() ([]*ladulasv1.NearbyPairing, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.entries, l.ended, l.err
}

func runJoin(
	ctx context.Context, cmd *cli.Command, client *localapi.Client, pin trust.PIN,
) error {
	browseCtx, stopBrowsing := context.WithCancel(ctx)
	defer stopBrowsing()

	browse, err := client.Control().BrowsePairings(browseCtx,
		connect.NewRequest(&ladulasv1.BrowsePairingsRequest{}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	list := &nearbyList{}

	go func() {
		for browse.Receive() {
			list.mu.Lock()
			list.entries = browse.Msg().GetPairings()
			list.mu.Unlock()
		}

		list.mu.Lock()
		list.err = browse.Err()
		list.ended = true
		list.mu.Unlock()
	}()

	in := bufio.NewReader(os.Stdin)

	fmt.Println("Looking for machines showing a pairing PIN on the local network…")

	entry, err := pickNearby(ctx, cmd, in, list)
	if err != nil {
		return err
	}

	if pin == "" {
		if pin, err = askPIN(in, entry.GetName()); err != nil {
			return err
		}
	}

	stream, err := client.Control().PairWithPeer(ctx,
		connect.NewRequest(&ladulasv1.PairWithPeerRequest{
			Nearby: entry.GetId(),
			Code:   string(pin),
		}))
	if err != nil {
		return requireInstance(cmd, err)
	}

	defer func() {
		_ = stream.Close()
	}()

	// The instance resolved the entry when the join started, so the list has
	// done its job once the join says anything at all; browsing on through a
	// confirmation nobody is picking from would be listening for nothing.
	return followPairing(ctx, cmd, client, stream, stopBrowsing)
}

// pickNearby prints the list and reads a choice, until somebody picks one.
// Enter on its own looks again.
func pickNearby(
	ctx context.Context, cmd *cli.Command, in *bufio.Reader, list *nearbyList,
) (*ladulasv1.NearbyPairing, error) {
	for {
		select {
		case <-time.After(joinLook):
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		entries, ended, err := list.snapshot()
		if ended {
			if err != nil {
				return nil, requireInstance(cmd, err)
			}

			return nil, cli.Exit("The instance stopped looking.", 1)
		}

		printNearby(os.Stdout, entries)

		if len(entries) == 0 {
			fmt.Print("Press Enter to look again: ")
		} else {
			fmt.Printf("Pick a machine [1-%d], or press Enter to look again: ",
				len(entries))
		}

		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return nil, fmt.Errorf("read the choice: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		choice, err := strconv.Atoi(line)
		if err != nil || choice < 1 || choice > len(entries) {
			fmt.Println("That is not one of the numbers above.")

			continue
		}

		picked := entries[choice-1]

		if picked.GetDuplicate() {
			fmt.Printf("\nMore than one machine is calling itself %q. Only one of "+
				"them is the one you mean: check the name on its screen, and "+
				"compare the fingerprints on both cards before agreeing.\n",
				picked.GetName())
		}

		return picked, nil
	}
}

// printNearby is the list, or why it might be empty.
func printNearby(out io.Writer, entries []*ladulasv1.NearbyPairing) {
	fmt.Fprintln(out)

	if len(entries) == 0 {
		fmt.Fprintln(out, "Nothing found yet. On the other machine, run "+
			"`ladulas pair --listen` or open Add a machine, and keep its PIN on "+
			"screen.")
		fmt.Fprintln(out, "If it is showing one and still does not appear, "+
			"something between the two is dropping multicast DNS — a firewall "+
			"without UDP 5353 open, Wi-Fi client isolation, or a VPN. "+
			"`avahi-browse -r _ladulas-pair._tcp` here tells you which side it is. "+
			"`ladulas pair --address <host:port> --pin <PIN>` and the full code "+
			"both still work.")
		fmt.Fprintln(out)

		return
	}

	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)

	duplicates := false

	for i, entry := range entries {
		note := ""
		if entry.GetDuplicate() {
			note = "another machine has this name"
			duplicates = true
		}

		fmt.Fprintf(table, "  %d\t%s\t%s on %s\t%s\n", i+1, entry.GetName(),
			entry.GetAddress(), entry.GetInterface(), note)
	}

	_ = table.Flush()

	if duplicates {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Two machines claim one name, and anything on this "+
			"network can announce any name. If you are not sure which is the "+
			"one you mean, pick neither and use the full code instead.")
	}

	fmt.Fprintln(out)
}

// askPIN reads the PIN. A mistyped one is asked for again here, before
// anything is sent, because only a PIN that reaches the other machine costs
// one of its attempts.
func askPIN(in *bufio.Reader, name string) (trust.PIN, error) {
	for {
		fmt.Printf("The PIN %s is showing: ", name)

		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read the PIN: %w", err)
		}

		pin, err := trust.ParsePIN(strings.TrimSpace(line))
		if err == nil {
			return pin, nil
		}

		fmt.Println("A pairing PIN is the six digits on the other machine's screen.")
	}
}
