package command

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/hugowetterberg/ladulas/internal/app"
	"github.com/hugowetterberg/ladulas/internal/logind"
)

// The automatic locks of decision J, wired to the login manager.
//
// The defaults are the decision: suspend and session lock both soft-lock, the
// idle timeout is off. Every one of them can be turned up to `seal` or off
// entirely, because the trade is real in both directions — sealing on suspend
// is the answer to a stolen sleeping laptop, and it is also what stops a
// desktop signing for its owner's phone until somebody walks back to it.

// TriggerFlags are the automatic-lock switches, mounted by the commands that
// run an instance.
func TriggerFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name: "on-suspend",
			Usage: "what happens when the machine suspends: `lock`, `seal` " +
				"or `off`. Sealing takes a logind inhibitor so the store key " +
				"is wiped before the machine goes down",
			Value:   string(logind.ActionLock),
			Sources: cli.EnvVars("LADULAS_ON_SUSPEND"),
		},
		&cli.StringFlag{
			Name: "on-session-lock",
			Usage: "what happens when the session is locked: `lock`, `seal` " +
				"or `off`",
			Value:   string(logind.ActionLock),
			Sources: cli.EnvVars("LADULAS_ON_SESSION_LOCK"),
		},
		&cli.DurationFlag{
			Name: "idle-lock",
			Usage: "lock after this long with nothing decided; zero, the " +
				"default, leaves the store alone",
			Sources: cli.EnvVars("LADULAS_IDLE_LOCK"),
		},
		&cli.StringFlag{
			Name:    "idle-lock-action",
			Usage:   "what an idle timeout does: `lock`, `seal` or `off`",
			Value:   string(logind.ActionLock),
			Sources: cli.EnvVars("LADULAS_IDLE_LOCK_ACTION"),
		},
	}
}

// Triggers is a started watcher, or a stand-in for one that was never started.
// Callers stop it either way, which is what keeps the caller free of "if the
// triggers are on" branches.
type Triggers struct {
	watcher *logind.Watcher
}

// Stop releases the inhibitor and stops watching.
func (t Triggers) Stop() {
	if t.watcher != nil {
		t.watcher.Stop()
	}
}

// StartLockTriggers wires the login manager to the instance.
//
// A machine with no login manager is not an error: the CLI verbs still work,
// and the daemon says once that the automatic locks are not running rather than
// refusing to start over it. A misconfigured action is an error, because a
// typo'd `--on-suspend=sael` that silently meant "off" would be a security
// setting that quietly did nothing.
func StartLockTriggers(
	ctx context.Context, cmd *cli.Command, instance *app.App,
) (Triggers, error) {
	suspend, err := logind.ParseAction(cmd.String("on-suspend"), logind.ActionLock)
	if err != nil {
		return Triggers{}, err
	}

	session, err := logind.ParseAction(
		cmd.String("on-session-lock"), logind.ActionLock)
	if err != nil {
		return Triggers{}, err
	}

	idleAction, err := logind.ParseAction(
		cmd.String("idle-lock-action"), logind.ActionLock)
	if err != nil {
		return Triggers{}, err
	}

	idle := cmd.Duration("idle-lock")

	if suspend == logind.ActionOff && session == logind.ActionOff &&
		(idle <= 0 || idleAction == logind.ActionOff) {
		return Triggers{}, nil
	}

	bus, err := logind.NewSystemBus(instance.Log())
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"no login manager here, so nothing locks the store automatically: %v\n",
			err)

		return Triggers{}, nil
	}

	watcher, err := logind.Start(ctx, logind.Options{
		Bus:         bus,
		Target:      instance,
		Suspend:     suspend,
		SessionLock: session,
		Idle:        idle,
		IdleAction:  idleAction,
		Logger:      instance.Log(),
	})
	if err != nil {
		return Triggers{}, err
	}

	instance.SetActivityHook(watcher.Poke)

	fmt.Fprintf(os.Stderr, "automatic locks: suspend %s, session lock %s%s\n",
		suspend, session, describeIdle(idle, idleAction))

	return Triggers{watcher: watcher}, nil
}

func describeIdle(idle time.Duration, action logind.Action) string {
	if idle <= 0 || action == logind.ActionOff {
		return ", no idle timeout"
	}

	return fmt.Sprintf(", %s idle %s", idle, action)
}
