package command

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/internal/app"
	"github.com/hugowetterberg/ladulas/internal/observe"
)

// DebugFlag opens the metrics and pprof port, and is mounted by the commands
// that run an instance rather than by the ones that ask it something.
//
// It is off unless it is asked for, which is the opposite of the relay's
// default and for two reasons. One is that this daemon is one process per
// logged-in account: a port in the flag's default would be a port two people on
// the same box fight over, and a daemon that would not start because somebody
// else was already logged in. The other is what is in the heap — while the store
// is unlocked it holds the data encryption key, and a heap profile is a copy of
// the heap, so the port is worth a decision rather than a default.
func DebugFlag() cli.Flag {
	return &cli.StringFlag{
		Name: "debug-listen",
		Usage: "address to serve Prometheus metrics and pprof on, e.g. " +
			"`127.0.0.1:9855`. Off unless set: it is unauthenticated, and a " +
			"heap profile of an unlocked instance contains the store key",
		Sources: cli.EnvVars("LADULAS_DEBUG_ADDR"),
	}
}

// StartDebug opens the port, if one was asked for, and returns the function
// that closes it again.
//
// Binding happens here rather than in the goroutine below, so that an address
// already in use is an instance that refuses to start and says which address it
// was. Everything else about the port is best-effort: a scrape target that goes
// away is not a reason to stop signing anything.
func StartDebug(
	ctx context.Context, cmd *cli.Command, instance *app.App,
) (func(), error) {
	server, err := observe.New(observe.Options{
		Addr:   cmd.String("debug-listen"),
		Logger: instance.Log(),
	})
	if err != nil {
		return nil, err
	}

	if server == nil {
		return func() {}, nil
	}

	if err := observe.RegisterDaemon(server.Registerer(), instance); err != nil {
		return nil, err
	}

	if err := server.Listen(); err != nil {
		return nil, err
	}

	serving, stop := context.WithCancel(ctx)
	done := make(chan struct{})

	go func() {
		defer close(done)

		if err := server.Serve(serving); err != nil {
			fmt.Fprintf(os.Stderr, "the metrics port stopped: %v\n", err)
		}
	}()

	return func() {
		stop()
		<-done
	}, nil
}
