// Command ladulas-relay is the publisher-hosted wake-up relay
// (docs/architecture.md §11, decision G).
//
// It is optional infrastructure and nothing depends on it: an instance with no
// relay, or one whose relay is down, approves exactly as it did before — the
// phone finds the request when it is next opened. What it buys is that the phone
// is opened sooner.
//
// Every credential is configuration. There is no key, no key id, no team id and
// no topic compiled in, because self-hosting means running this against your own
// Apple project and a value in the binary would be a value to fork.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/internal/observe"
	"github.com/hugowetterberg/ladulas/internal/version"
	"github.com/hugowetterberg/ladulas/pkg/apns"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/relay"
)

func main() {
	cmd := &cli.Command{
		Name:    "ladulas-relay",
		Usage:   "the Ladulås wake-up relay: empty pushes, keyed by opaque ids",
		Version: version.String(),
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "listen",
				Value:   ":8443",
				Usage:   "address to serve on",
				Sources: cli.EnvVars("LISTEN_ADDR"),
			},
			&cli.StringFlag{
				Name:    "state",
				Usage:   "file holding the device registrations",
				Value:   "devices.json",
				Sources: cli.EnvVars("STATE_FILE"),
			},
			&cli.StringFlag{
				Name: "debug-listen",
				Usage: "address for Prometheus metrics and pprof, or `off`. " +
					"It is a second port because it is unauthenticated: a heap " +
					"profile is a copy of everything this process holds, and " +
					"this one holds a push key and a device list",
				Value:   "127.0.0.1:8444",
				Sources: cli.EnvVars("DEBUG_ADDR"),
			},
			&cli.StringFlag{
				Name: "apns-host",
				// Production, because that is where a TestFlight build's tokens
				// live and TestFlight is the only way onto a device here. The
				// sandbox host answers BadDeviceToken for every one of them, which
				// looks exactly like a bug in this service.
				Value:   apns.Production,
				Usage:   "APNs provider host",
				Sources: cli.EnvVars("APNS_HOST"),
			},
			&cli.StringFlag{
				Name:    "apns-topic",
				Usage:   "APNs topic, which is the app's bundle identifier",
				Sources: cli.EnvVars("APNS_TOPIC"),
			},
			&cli.StringFlag{
				Name:    "apns-key-id",
				Usage:   "the key id of the .p8 signing key",
				Sources: cli.EnvVars("APNS_KEY_ID"),
			},
			&cli.StringFlag{
				Name:    "apns-team-id",
				Usage:   "the Apple Developer team id",
				Sources: cli.EnvVars("APNS_TEAM_ID"),
			},
			&cli.StringFlag{
				Name: "apns-key",
				Usage: "the .p8 signing key itself, in PEM; " +
					"prefer this to a path, so the key never reaches a disk",
				Sources: cli.EnvVars("APNS_KEY"),
			},
			&cli.StringFlag{
				Name:    "apns-key-file",
				Usage:   "path to the .p8 signing key, when it is on a disk",
				Sources: cli.EnvVars("APNS_KEY_FILE"),
			},
		},
		Action: run,
	}

	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := cmd.Run(ctx, os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "ladulas-relay: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd *cli.Command) error {
	log := slog.Default()

	sender, err := pushService(cmd)
	if err != nil {
		return err
	}

	store, err := relay.OpenFileStore(filepath.Clean(cmd.String("state")))
	if err != nil {
		return err
	}

	// The debug server is built before anything it measures, because it owns
	// the registry everything else registers into. With the port switched off
	// it is a nil server whose registerer discards, so the wiring below does
	// not change shape.
	debug, err := observe.New(observe.Options{
		Addr:   cmd.String("debug-listen"),
		Logger: log,
	})
	if err != nil {
		return err
	}

	defer func() {
		if err := debug.Close(); err != nil {
			log.Warn("could not close the metrics listener", "error", err.Error())
		}
	}()

	metrics, err := observe.RegisterRelay(debug.Registerer(), store.Len)
	if err != nil {
		return err
	}

	calls, err := observe.NewRPC(debug.Registerer(), "relay")
	if err != nil {
		return err
	}

	service, err := relay.New(relay.Options{
		Store: store,
		Pushers: map[ladulasv1.PushPlatform]relay.Pusher{
			ladulasv1.PushPlatform_PUSH_PLATFORM_APNS: &relay.APNs{Sender: sender},
		},
		Metrics: metrics,
		Logger:  log,
	})
	if err != nil {
		return err
	}

	// Unencrypted HTTP/2 as well as HTTP/1, because connect's clients will use
	// either and this service is expected to sit behind something that
	// terminates TLS. Running it with its own certificate is a deployment
	// decision and not this binary's to make — it holds a push key and a device
	// list, and neither is helped by it also holding a web server's private key.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	server := &http.Server{
		Addr:              cmd.String("listen"),
		Handler:           service.Handler(calls.Interceptor()),
		Protocols:         protocols,
		ReadHeaderTimeout: 10 * time.Second,
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", server.Addr, err)
	}

	// Both ports are bound before either is served, so an address that cannot
	// be had is a relay that did not start rather than one that started and is
	// missing half of itself.
	if err := debug.Listen(); err != nil {
		return err
	}

	log.Info("the wake-up relay is listening",
		"address", listener.Addr().String(),
		"apns_host", cmd.String("apns-host"),
		"topic", cmd.String("apns-topic"))

	done := make(chan error, 1)

	go func() {
		done <- server.Serve(listener)
	}()

	go func() {
		if err := debug.Serve(ctx); err != nil {
			log.Error("the metrics port stopped", "error", err.Error())
		}
	}()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}

		return nil
	case <-ctx.Done():
	}

	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdown); err != nil {
		return fmt.Errorf("shut down: %w", err)
	}

	return nil
}

// pushService builds the APNs sender from configuration, and refuses to start
// without all of it. A relay that came up with no key would be a relay that
// answers every wake-up with a failure, which reads to everybody upstream as the
// phone being unreachable.
func pushService(cmd *cli.Command) (*apns.Sender, error) {
	pem := []byte(cmd.String("apns-key"))

	if len(pem) == 0 {
		path := cmd.String("apns-key-file")
		if path == "" {
			return nil, errors.New(
				"no APNs signing key: set APNS_KEY or APNS_KEY_FILE")
		}

		body, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil, fmt.Errorf("read the APNs signing key: %w", err)
		}

		pem = body
	}

	key, err := apns.ParseKey(pem)
	if err != nil {
		return nil, err
	}

	return apns.New(apns.Options{
		Host:   cmd.String("apns-host"),
		Topic:  cmd.String("apns-topic"),
		KeyID:  cmd.String("apns-key-id"),
		TeamID: cmd.String("apns-team-id"),
		Key:    key,
	})
}
