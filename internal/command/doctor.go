package command

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/urfave/cli/v3"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/hugowetterberg/ladulas/internal/app"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Checking the wiring around the daemon rather than the daemon itself.
//
// `status` answers "what is this instance", and every fact in it is a fact the
// daemon knows about itself. This answers the other question — whether the
// programs on this machine will actually reach it — and none of that is
// something the daemon can see. It is a separate command for that reason and
// not out of tidiness: an unset SSH_AUTH_SOCK is invisible from inside a
// process that has its own.
//
// It exists because every failure in this area surfaces somewhere else, in
// words that name neither Ladulås nor the cause. `ssh-add` says "Could not open
// a connection to your authentication agent", `ssh` says "agent refused
// operation", git signs with a poorer prompt and says nothing at all, and a
// second agent holding the variable answers cheerfully with the wrong keys.
// Four different sentences from four programs, one underlying question.
//
// The exit status is the answer, as it is for `wait`: 0 when nothing is wrong,
// 1 when something is. A problem is something that will not work; a warning is
// something that works less well than it could.

// checkLevel is how bad a finding is.
type checkLevel int

const (
	checkOK checkLevel = iota
	checkWarn
	checkProblem
)

func (l checkLevel) word() string {
	switch l {
	case checkOK:
		return "ok"
	case checkWarn:
		return "warning"
	case checkProblem:
		return "problem"
	}

	return "?"
}

// check is one finding: what was looked at, what was found, and — when
// something is wrong — what to do about it.
type check struct {
	level  checkLevel
	name   string
	found  string
	remedy []string
}

func doctorCommand() *cli.Command {
	return &cli.Command{
		Name:  "doctor",
		Usage: "check that ssh, git and the rest of this machine can reach the agent",
		Description: "Looks at the wiring around the daemon rather than at the " +
			"daemon: whether SSH_AUTH_SOCK points here, whether the agent " +
			"answers, whether `ladulas-sign` is on the PATH, and whether git " +
			"is configured to sign through it. Exits 0 when nothing is wrong " +
			"and 1 when something is, so it is usable from a script.",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "quiet",
				Usage: "print only the findings that are not ok",
			},
		},
		Action: runDoctor,
	}
}

func runDoctor(ctx context.Context, cmd *cli.Command) error {
	cfg := ConfigFromFlags(cmd)

	live, _ := fetchStatus(ctx, cmd)

	checks := []check{checkDaemon(cfg, live)}

	if live != nil {
		checks = append(checks, checkStore(live))
	}

	keys, agentCheck := checkAgentSocket(cfg)
	checks = append(checks,
		checkAuthSock(cfg),
		agentCheck,
		checkSigner(),
	)
	checks = append(checks, checkGit(ctx, keys)...)

	return reportChecks(checks, cmd.Bool("quiet"))
}

// reportChecks prints the findings and turns them into an exit status.
func reportChecks(checks []check, quiet bool) error {
	var problems, warnings int

	for _, c := range checks {
		switch c.level {
		case checkProblem:
			problems++
		case checkWarn:
			warnings++
		case checkOK:
		}

		if quiet && c.level == checkOK {
			continue
		}

		fmt.Printf("%-8s  %-15s %s\n", c.level.word(), c.name, c.found)

		for _, line := range c.remedy {
			fmt.Printf("%-8s  %-15s %s\n", "", "", line)
		}
	}

	if problems == 0 && warnings == 0 {
		if !quiet {
			fmt.Println()
			fmt.Println("Nothing is wrong with the wiring on this machine.")
		}

		return nil
	}

	fmt.Println()

	if problems > 0 {
		return cli.Exit(fmt.Sprintf(
			"%s and %s",
			plural(problems, "problem"), plural(warnings, "warning")), 1)
	}

	fmt.Printf("%s, and nothing that will stop working.\n",
		plural(warnings, "warning"))

	return nil
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}

	return fmt.Sprintf("%d %ss", n, word)
}

// checkDaemon reports whether anything is listening on the control socket.
func checkDaemon(cfg app.Config, live *ladulasv1.StatusResponse) check {
	if live == nil {
		return check{
			level: checkProblem,
			name:  "Daemon",
			found: "nothing is listening on " + cfg.ControlSocket,
			remedy: []string{
				"Start it with `systemctl --user start ladulas`, or",
				"`ladulasd run` in a terminal.",
			},
		}
	}

	name := live.GetInstanceName()
	if name == "" {
		name = "running"
	}

	return check{level: checkOK, name: "Daemon", found: name}
}

// checkStore reports a store state that stops signatures happening, which is
// not a wiring fault but is the first thing somebody running this wants to know.
func checkStore(live *ladulasv1.StatusResponse) check {
	switch live.GetLockState() {
	case ladulasv1.LockState_LOCK_STATE_UNINITIALIZED:
		return check{
			level:  checkProblem,
			name:   "Store",
			found:  "not created yet",
			remedy: []string{"Run `ladulas init`."},
		}
	case ladulasv1.LockState_LOCK_STATE_SEALED:
		return check{
			level: checkProblem,
			name:  "Store",
			found: "sealed — the daemon holds no key, so the agent offers nothing",
			remedy: []string{
				"Run `ladulas unlock`. A restart seals the store unless login",
				"unlock is enrolled.",
			},
		}
	case ladulasv1.LockState_LOCK_STATE_LOCKED:
		return check{
			level: checkWarn,
			name:  "Store",
			found: "locked — this machine will not approve, paired peers still can",
			remedy: []string{
				"Run `ladulas unlock` to approve here again.",
			},
		}
	case ladulasv1.LockState_LOCK_STATE_UNLOCKED,
		ladulasv1.LockState_LOCK_STATE_UNSPECIFIED:
	}

	return check{
		level: checkOK,
		name:  "Store",
		found: fmt.Sprintf("unlocked, %s", plural(int(live.GetKeys()), "key")),
	}
}

// checkAuthSock is the finding this command was written for.
//
// The variable is contended — GnuPG's gpg-agent-ssh.socket, 1Password and
// Secretive all want it — and the interesting failure is not that it is unset
// but that it is set to somebody else's agent, which answers, so every tool
// works and lists the wrong keys.
func checkAuthSock(cfg app.Config) check {
	sock, set := os.LookupEnv("SSH_AUTH_SOCK")

	remedy := []string{
		"Run `make install-env` for sessions systemd starts, and add",
		"    export SSH_AUTH_SOCK=" + cfg.SocketPath,
		"to your shell rc for the ones it does not reach — an ssh into this",
		"box, or a bare TTY login.",
	}

	if !set || sock == "" {
		return check{
			level:  checkProblem,
			name:   "SSH_AUTH_SOCK",
			found:  "unset — ssh, ssh-add and git will not find the agent",
			remedy: remedy,
		}
	}

	if sock == cfg.SocketPath {
		return check{level: checkOK, name: "SSH_AUTH_SOCK", found: sock}
	}

	return check{
		level: checkProblem,
		name:  "SSH_AUTH_SOCK",
		found: fmt.Sprintf("points at %s (%s), not at Ladulås",
			sock, otherAgent(sock)),
		remedy: remedy,
	}
}

// otherAgent guesses whose socket this is, from the path. A guess is worth
// making because the name is what tells somebody why their key list looks
// plausible and wrong.
func otherAgent(sock string) string {
	switch {
	case strings.Contains(sock, "gnupg"):
		return "gpg-agent"
	case strings.Contains(sock, "1password"), strings.Contains(sock, "1Password"):
		return "1Password"
	case strings.Contains(sock, "secretive"), strings.Contains(sock, "Secretive"):
		return "Secretive"
	case strings.Contains(sock, "keyring"):
		return "gnome-keyring"
	default:
		return "another agent"
	}
}

// checkAgentSocket connects to the agent the way ssh does, and returns the keys
// it offers so that the signing-key check can be made against them.
func checkAgentSocket(cfg app.Config) ([]*sshagent.Key, check) {
	conn, err := net.Dial("unix", cfg.SocketPath)
	if err != nil {
		return nil, check{
			level: checkProblem,
			name:  "Agent socket",
			found: fmt.Sprintf("%s does not answer: %v", cfg.SocketPath, err),
			remedy: []string{
				"The daemon creates it at startup; check that one is running.",
			},
		}
	}

	defer conn.Close()

	keys, err := sshagent.NewClient(conn).List()
	if err != nil {
		return nil, check{
			level: checkProblem,
			name:  "Agent socket",
			found: fmt.Sprintf("connected, but listing keys failed: %v", err),
		}
	}

	if len(keys) == 0 {
		return keys, check{
			level: checkWarn,
			name:  "Agent socket",
			found: "answering, but offering no keys",
			remedy: []string{
				"A sealed store offers nothing. So does an unlocked one with no",
				"keys — `ladulas keys generate <name>` — and one whose keys are",
				"all kept out of the identity list (`ladulas keys list`).",
			},
		}
	}

	return keys, check{
		level: checkOK,
		name:  "Agent socket",
		found: fmt.Sprintf("answering, offering %s", plural(len(keys), "key")),
	}
}

// checkSigner looks for ladulas-sign, which is an enrichment rather than a
// requirement: without it git still signs through the agent, with a prompt that
// can only name a digest (§5).
func checkSigner() check {
	path, err := exec.LookPath("ladulas-sign")
	if err != nil {
		return check{
			level: checkWarn,
			name:  "ladulas-sign",
			found: "not on the PATH — commit prompts will name a digest, not a commit",
			remedy: []string{
				"`make install` puts it in $GOBIN. Git needs it named as",
				"gpg.ssh.program to use it.",
			},
		}
	}

	return check{level: checkOK, name: "ladulas-sign", found: path}
}

// checkGit reads the three git settings that decide whether commits get signed
// here at all, and whether they get the rich prompt.
func checkGit(ctx context.Context, keys []*sshagent.Key) []check {
	if _, err := exec.LookPath("git"); err != nil {
		return []check{{
			level: checkWarn,
			name:  "git",
			found: "not on the PATH, so nothing about signing was checked",
		}}
	}

	checks := []check{checkGitFormat(ctx)}

	if program := gitConfig(ctx, "gpg.ssh.program"); program == "" {
		checks = append(checks, check{
			level: checkWarn,
			name:  "gpg.ssh.program",
			found: "unset — git will sign through the agent with a poorer prompt",
			remedy: []string{
				"`git config --global gpg.ssh.program ladulas-sign`",
			},
		})
	} else {
		checks = append(checks, check{
			level: checkOK, name: "gpg.ssh.program", found: program,
		})
	}

	return append(checks, checkSigningKey(ctx, keys))
}

func checkGitFormat(ctx context.Context) check {
	format := gitConfig(ctx, "gpg.format")
	if format == "ssh" {
		return check{level: checkOK, name: "gpg.format", found: "ssh"}
	}

	found := "unset, so git will look for a GPG key"
	if format != "" {
		found = format + ", so git will not sign with an SSH key"
	}

	return check{
		level:  checkProblem,
		name:   "gpg.format",
		found:  found,
		remedy: []string{"`git config --global gpg.format ssh`"},
	}
}

// checkSigningKey checks that user.signingkey names a key this agent actually
// offers. A signing key that no longer matches is the quiet failure here: git
// says "Load key: error in libcrypto" or asks the agent for something it does
// not have, and neither sentence mentions the key.
func checkSigningKey(ctx context.Context, keys []*sshagent.Key) check {
	key := gitConfig(ctx, "user.signingkey")
	if key == "" {
		return check{
			level: checkProblem,
			name:  "user.signingkey",
			found: "unset, so git has nothing to sign with",
			remedy: []string{
				"`git config --global user.signingkey \"key::$(ladulas keys public <name>)\"`",
			},
		}
	}

	fingerprint, err := signingKeyFingerprint(key)
	if err != nil {
		return check{
			level: checkWarn,
			name:  "user.signingkey",
			found: fmt.Sprintf("%s — not a literal key, so it was not checked "+
				"against the agent", key),
		}
	}

	for _, k := range keys {
		if ssh.FingerprintSHA256(k) == fingerprint {
			return check{
				level: checkOK,
				name:  "user.signingkey",
				found: fmt.Sprintf("%s (%s)", fingerprint, k.Comment),
			}
		}
	}

	return check{
		level: checkProblem,
		name:  "user.signingkey",
		found: fingerprint + " — the agent does not offer this key",
		remedy: []string{
			"`ladulas keys list` says what there is. A key kept out of the",
			"identity list still signs when named, so check that it exists at",
			"all before changing the setting.",
		},
	}
}

// signingKeyFingerprint reads git's literal-key form, `key::<authorized_keys
// line>`, which is what the README tells people to set and the only form that
// can be checked from here — a path names a file whose contents git reads, and
// a bare fingerprint is already the answer.
func signingKeyFingerprint(setting string) (string, error) {
	literal, ok := strings.CutPrefix(setting, "key::")
	if !ok {
		return "", errors.New("not a literal key")
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(literal))
	if err != nil {
		return "", fmt.Errorf("parse the key: %w", err)
	}

	return ssh.FingerprintSHA256(pub), nil
}

// gitConfig reads one setting, treating "not set" and "git would not answer"
// alike: both mean there is nothing configured to report.
func gitConfig(ctx context.Context, key string) string {
	out, err := exec.CommandContext(ctx, "git", "config", "--get", key).Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}
