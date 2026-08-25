package signcli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/pkg/gitctx"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
)

// Environment variables. ssh-keygen owns the flag namespace, so everything this
// program can be told is told through the environment.
const (
	// SSHKeygenEnv names the program that unsupported invocations are handed
	// to. Defaults to ssh-keygen on the PATH.
	SSHKeygenEnv = "LADULAS_SSH_KEYGEN"
	// TimeoutEnv is how long to wait for an approval, as a Go duration.
	TimeoutEnv = "LADULAS_SIGN_TIMEOUT"
	// NoDiffEnv skips diff collection when set to anything non-empty, for a
	// repository where running git diff is too slow to want on every commit.
	NoDiffEnv = "LADULAS_SIGN_NO_DIFF"
	// DiffBytesEnv overrides the cap on the collected diff.
	DiffBytesEnv = "LADULAS_SIGN_DIFF_BYTES"
)

// waitNotice is how long a request may take before the user is told that
// something is waiting for them. Long enough that an auto-approved commit says
// nothing at all, short enough that a blocked git never looks hung.
const waitNotice = time.Second

// Options configure a run. The zero value is what the real program uses.
type Options struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// SocketPath overrides the instance socket.
	SocketPath string
	// SSHKeygen is the fallback program. Empty means the environment, then
	// ssh-keygen on the PATH.
	SSHKeygen string
	// Timeout bounds the approval wait. Zero means the environment, then the
	// instance's own policy default, which for signing is generous (§9).
	Timeout time.Duration
	// Limits caps the collected diff.
	Limits gitctx.Limits
	// NoDiff skips diff collection.
	NoDiff bool
	// Dir is where git runs. Empty means the working directory, which is where
	// git puts a signing program.
	Dir string
	// Exec hands the command line to another program. The real one replaces
	// this process; a test runs it as a child so it can watch what happened.
	Exec func(path string, argv []string) error
	// Env is the environment for the git subprocesses. Empty means inheriting.
	Env []string
}

func (o Options) withDefaults() Options {
	if o.Stdin == nil {
		o.Stdin = os.Stdin
	}

	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}

	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}

	if o.SSHKeygen == "" {
		o.SSHKeygen = os.Getenv(SSHKeygenEnv)
	}

	if o.Timeout == 0 {
		if d, err := time.ParseDuration(os.Getenv(TimeoutEnv)); err == nil {
			o.Timeout = d
		}
	}

	if !o.NoDiff {
		o.NoDiff = os.Getenv(NoDiffEnv) != ""
	}

	if o.Limits.Bytes == 0 {
		if n, err := strconv.Atoi(os.Getenv(DiffBytesEnv)); err == nil && n > 0 {
			o.Limits.Bytes = n
		}
	}

	if o.Exec == nil {
		o.Exec = execProgram
	}

	return o
}

// Run is the whole program. It returns the process exit status.
func Run(ctx context.Context, args []string, opts Options) int {
	opts = opts.withDefaults()

	operation, carriesOperation := operationOf(args)

	if !carriesOperation {
		// Every command line git builds for gpg.ssh.program names an operation
		// with -Y, so one without it was typed by a person, and there is
		// nothing worth handing over: ssh-keygen with no operation flag
		// *generates a key*. `ladulas-sign -h` opened a prompt to write a new
		// private key rather than saying what the program was, and `-help`,
		// which is -h -e -l -p, opened one to change the passphrase on an
		// existing one (decision AI, §5).
		if isHelpRequest(args) {
			Usage(opts.Stderr)

			return 0
		}

		// No arguments at all is somebody typing the binary's name to see what
		// it is, and there is nothing to name back at them.
		if len(args) > 0 {
			fmt.Fprintf(opts.Stderr,
				"ladulas-sign: %s is not a command line git builds, and is not"+
					" passed on to ssh-keygen — run ssh-keygen itself for that.\n\n",
				strings.Join(args, " "))
		}

		Usage(opts.Stderr)

		return 1
	}

	if operation != "sign" {
		// find-principals, verify, check-novalidate, everything else git asks
		// for: not ours. git calls the same program for verification when
		// gpg.ssh.program is set, so this path is exercised on every
		// `git log --show-signature`.
		return handOver(args, opts, "")
	}

	inv, err := parseSign(args)
	if err != nil {
		return handOver(args, opts, err.Error())
	}

	publicKey, err := resolvePublicKey(inv.keyFile)
	if err != nil {
		return handOver(args, opts, err.Error())
	}

	client := localapi.NewClient(opts.SocketPath)

	for _, file := range inv.files {
		status := signFile(ctx, client, inv, publicKey, file, opts)
		if status != 0 {
			return status
		}
	}

	return 0
}

func signFile(
	ctx context.Context,
	client *localapi.Client,
	inv *invocation,
	publicKey ssh.PublicKey,
	file string,
	opts Options,
) int {
	payload, err := readPayload(file, opts.Stdin)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "ladulas-sign: %v\n", err)

		return 1
	}

	git := collectContext(ctx, payload, inv.namespace, opts)

	request := &ladulasv1.SignPayloadRequest{
		PublicKey:  publicKey.Marshal(),
		Payload:    payload,
		Namespace:  inv.namespace,
		GitContext: git,
	}

	if opts.Timeout > 0 {
		request.Timeout = durationpb.New(opts.Timeout)
	}

	stop := noticeAfter(opts.Stderr, waitNotice, git)
	resp, err := client.SignPayload(ctx, request)

	stop()

	if err != nil {
		// A machine with no instance running, or an instance that does not hold
		// this key, still has to be able to commit: that is the fallback §5
		// promises, and it is the same key through the agent socket.
		if isFallbackWorthy(err) {
			return handOverOne(inv, file, opts, err.Error())
		}

		fmt.Fprintf(opts.Stderr, "ladulas-sign: %s\n", message(err))

		return 1
	}

	if !resp.GetApproved() {
		// A denial is an answer, not a failure to reach anyone, so it is not
		// retried through ssh-keygen.
		fmt.Fprintf(opts.Stderr, "ladulas-sign: the signature was refused: %s\n",
			resp.GetReason())

		return 1
	}

	if err := writeSignature(file, resp.GetArmoredSignature(), opts.Stdout); err != nil {
		fmt.Fprintf(opts.Stderr, "ladulas-sign: %v\n", err)

		return 1
	}

	return 0
}

// collectContext gathers what makes the prompt worth reading. Only git
// signatures get it; a signature in another namespace has no repository behind
// it worth asserting.
func collectContext(
	ctx context.Context, payload []byte, namespace string, opts Options,
) *ladulasv1.GitContext {
	if namespace != sshsig.GitNamespace {
		return nil
	}

	return gitctx.Collect(ctx, payload, gitctx.Options{
		Dir:       opts.Dir,
		Operation: operationName(payload),
		Limits:    opts.Limits,
		SkipDiff:  opts.NoDiff,
		Env:       opts.Env,
	})
}

func operationName(payload []byte) string {
	object, err := gitctx.ParseObject(payload)
	if err != nil {
		return ""
	}

	return object.GetType()
}

func readPayload(file string, stdin io.Reader) ([]byte, error) {
	if file == "-" {
		body, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read the payload from standard input: %w", err)
		}

		return body, nil
	}

	body, err := os.ReadFile(file) //nolint:gosec // the path is git's, not ours
	if err != nil {
		return nil, fmt.Errorf("read the payload: %w", err)
	}

	return body, nil
}

// writeSignature puts the signature where ssh-keygen would: next to the payload
// with a .sig suffix, or on standard output when the payload came from standard
// input.
func writeSignature(file, armoured string, stdout io.Writer) error {
	if file == "-" {
		if _, err := io.WriteString(stdout, armoured); err != nil {
			return fmt.Errorf("write the signature: %w", err)
		}

		return nil
	}

	if err := os.WriteFile(file+".sig", []byte(armoured), 0o600); err != nil {
		return fmt.Errorf("write the signature: %w", err)
	}

	return nil
}

// noticeAfter tells the user that something is waiting for them, but only if it
// is. Returns a function that cancels the notice.
func noticeAfter(stderr io.Writer, after time.Duration, git *ladulasv1.GitContext) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})

	go func() {
		defer close(stopped)

		select {
		case <-done:
		case <-time.After(after):
			what := "a signature"

			if object, err := gitctx.ParseObject(git.GetObject()); err == nil {
				what = fmt.Sprintf("%q", object.GetSubject())
			}

			fmt.Fprintf(stderr,
				"ladulas-sign: waiting for approval to sign %s…\n", what)
		}
	}()

	return func() {
		close(done)
		<-stopped
	}
}

// message renders an error for somebody reading a terminal.
//
// A connect error's Error() carries its status code, which is a fact about a
// socket rather than about a signature: "failed_precondition:" in front of a
// sentence saying that the machine holding the key is asleep helps nobody, and
// reads like a refusal, which it is not. The code still decides whether to fall
// back — it is only kept out of the sentence.
func message(err error) string {
	var connectErr *connect.Error

	if errors.As(err, &connectErr) {
		return connectErr.Message()
	}

	return err.Error()
}

// isFallbackWorthy says whether a failure is one that the stock ssh-keygen
// might still get past: no instance running, or an instance that does not hold
// the key. A denial is neither.
func isFallbackWorthy(err error) bool {
	if errors.Is(err, localapi.ErrNoInstance) {
		return true
	}

	switch connect.CodeOf(err) {
	case connect.CodeNotFound, connect.CodeUnimplemented, connect.CodeUnavailable:
		return true
	default:
		return false
	}
}

// handOver replaces this process with the real ssh-keygen.
func handOver(args []string, opts Options, why string) int {
	path, err := keygenPath(opts.SSHKeygen)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "ladulas-sign: %v\n", err)

		return 1
	}

	if why != "" {
		fmt.Fprintf(opts.Stderr, "ladulas-sign: %s; using %s\n", why, path)
	}

	if err := opts.Exec(path, append([]string{path}, args...)); err != nil {
		fmt.Fprintf(opts.Stderr, "ladulas-sign: run %s: %v\n", path, err)

		return 1
	}

	// Only a test's Exec returns; the real one does not come back.
	return 0
}

// handOverOne rebuilds the command line for a single payload, since a
// hand-over in the middle of a multi-file run must not sign the earlier files
// again.
func handOverOne(inv *invocation, file string, opts Options, why string) int {
	args := []string{"-Y", "sign", "-n", inv.namespace, "-f", inv.keyFile}

	if inv.useAgent {
		args = append(args, "-U")
	}

	return handOver(append(args, file), opts, why)
}

func keygenPath(configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}

	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return "", fmt.Errorf("no ssh-keygen to fall back to: %w", err)
	}

	return path, nil
}

// execProgram replaces this process, so that the caller sees the exit status
// and the output of the program that actually did the work.
func execProgram(path string, argv []string) error {
	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		return fmt.Errorf("exec %s: %w", path, err)
	}

	return nil
}

// resolvePublicKey works out which key a -f argument names.
//
// git passes one of two things: a file holding a literal public key, when
// user.signingkey is a key:: value and the signature goes through an agent, or
// the path of a private key. Only the public half is ever needed here — the
// signature is made inside Ladulås, and a private key file that Ladulås does
// not hold is a reason to hand the whole thing to ssh-keygen.
func resolvePublicKey(path string) (ssh.PublicKey, error) {
	body, err := os.ReadFile(path) //nolint:gosec // the path is git's, not ours
	if err != nil {
		return nil, fmt.Errorf("read the key %s: %w", path, err)
	}

	if pub, _, _, _, err := ssh.ParseAuthorizedKey(body); err == nil {
		return pub, nil
	}

	if pub, err := readPublicKeyFile(path + ".pub"); err == nil {
		return pub, nil
	}

	signer, err := ssh.ParsePrivateKey(body)
	if err != nil {
		return nil, fmt.Errorf("the key %s is not one this program can identify: %w",
			path, err)
	}

	return signer.PublicKey(), nil
}

func readPublicKeyFile(path string) (ssh.PublicKey, error) {
	body, err := os.ReadFile(path) //nolint:gosec // derived from git's own path
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(body)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	return pub, nil
}

// Usage is what the program prints when run by a person rather than by git.
func Usage(stderr io.Writer) {
	fmt.Fprint(stderr, strings.TrimLeft(`
ladulas-sign signs git commits and tags through Ladulås.

It implements the ssh-keygen -Y sign command line, so it is configured as
git's signing program rather than run by hand:

    git config --global gpg.format ssh
    git config --global gpg.ssh.program ladulas-sign
    git config --global user.signingkey "key::$(ladulas keys public work)"
    git config --global commit.gpgsign true

The other command lines git builds — -Y find-principals and -Y verify — are
passed to ssh-keygen unchanged, which is what keeps git log --show-signature
working. A command line with no -Y is not one of git's and is not passed on:
ssh-keygen with no operation flag generates a key, and this program will not
open that prompt on your behalf. Run ssh-keygen itself for that.

Environment:
    LADULAS_SOCK             the instance socket to sign through
    LADULAS_SIGN_TIMEOUT     how long to wait for approval, e.g. 10m
    LADULAS_SIGN_NO_DIFF     set to skip collecting the diff
    LADULAS_SIGN_DIFF_BYTES  cap on the collected diff, in bytes
    LADULAS_SSH_KEYGEN       the ssh-keygen to fall back to
`, "\n"))
}
