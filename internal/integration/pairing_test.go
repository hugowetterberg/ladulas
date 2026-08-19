package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/internal/app"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// What running M6 on a real phone found, and what these tests are about.
//
// The desktop displayed a code, the phone scanned it, the desktop's user
// approved — and then nothing. No trust record on either side, `Peers 0`, and
// the phone showing a card that had quietly been taken away. Everything about
// the pairing lived inside the two calls that ran it, so anything that
// interrupted a person interrupted the pairing itself.
//
// So the properties below are all the same property said five ways: a pairing
// is written down before anybody is asked about it, and nothing but a person
// ever ends one. The command that started it can be killed, the daemon on
// either side can be restarted, the peer can be unreachable at the moment
// somebody says yes, and the answer still lands. What does end a pairing is
// somebody saying no, somebody calling it off, and the two machines disagreeing
// about who they are talking to.

// pairingBox is an instance driven the way a person drives one: the daemon in
// this process, and the real command line as a subprocess against its socket.
//
// It binds a port of its own choosing rather than one the kernel picks, because
// half of what is being tested is a restart, and a peer that came back on a
// different port would be a different peer as far as the pending pairing is
// concerned.
type pairingBox struct {
	t       *testing.T
	cli     string
	name    string
	cfg     app.Config
	address string

	// fingerprint is remembered rather than read, because half these tests ask
	// what a box is while its daemon is stopped.
	fp string

	mu      sync.Mutex
	running *app.App
	cancel  context.CancelFunc
	served  chan error
}

func startPairingBox(t *testing.T, cli, name string) *pairingBox {
	t.Helper()

	runtime := shortDir(t)

	box := &pairingBox{
		t:       t,
		cli:     cli,
		name:    name,
		address: freeAddress(t),
	}

	box.cfg = app.Config{
		DataDir:       t.TempDir(),
		ConfigDir:     t.TempDir(),
		SocketPath:    filepath.Join(runtime, "agent.sock"),
		ControlSocket: filepath.Join(runtime, "control.sock"),
		InstanceName:  name,
		PeerListen:    box.address,
		NoKeyring:     true,
		Passphrase: func(string, bool) ([]byte, error) {
			return []byte(testPassphrase), nil
		},
	}

	box.start(true)

	box.fp = box.instance().Vault().Identity().Fingerprint()

	t.Cleanup(box.stop)

	return box
}

// start brings the daemon up the way `ladulasd run` does: serving first, sealed
// or uninitialised, and opened afterwards.
func (b *pairingBox) start(first bool) {
	b.t.Helper()

	instance, err := app.New(b.cfg)
	if err != nil {
		b.t.Fatalf("build %s: %v", b.name, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)

	go func() {
		served <- instance.Serve(ctx)
	}()

	select {
	case <-instance.Ready():
	case <-time.After(10 * time.Second):
		cancel()
		b.t.Fatalf("%s never started serving", b.name)
	}

	if first {
		if _, err := instance.Initialise(b.name, []byte(testPassphrase)); err != nil {
			cancel()
			b.t.Fatalf("initialise %s: %v", b.name, err)
		}
	} else if _, err := instance.Unlock([]byte(testPassphrase)); err != nil {
		cancel()
		b.t.Fatalf("unlock %s: %v", b.name, err)
	}

	b.mu.Lock()
	b.running = instance
	b.cancel = cancel
	b.served = served
	b.mu.Unlock()

	waitForSocket(b.t, b.cfg.ControlSocket)
}

func (b *pairingBox) stop() {
	b.mu.Lock()
	instance, cancel, served := b.running, b.cancel, b.served
	b.running, b.cancel, b.served = nil, nil, nil
	b.mu.Unlock()

	if instance == nil {
		return
	}

	if err := instance.Close(); err != nil {
		b.t.Errorf("close %s: %v", b.name, err)
	}

	cancel()

	select {
	case err := <-served:
		if err != nil {
			b.t.Errorf("serve %s: %v", b.name, err)
		}
	case <-time.After(10 * time.Second):
		b.t.Errorf("%s did not stop", b.name)
	}
}

// restart is the daemon going away and coming back, which is the thing a
// pairing used not to survive at all.
func (b *pairingBox) restart() {
	b.t.Helper()

	b.stop()
	b.start(false)
}

func (b *pairingBox) instance() *app.App {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.running
}

func (b *pairingBox) fingerprint() string {
	return b.fp
}

// command builds a run of the real command line against this box.
func (b *pairingBox) command(args ...string) *exec.Cmd {
	cmd := exec.Command(b.cli, args...) //nolint:gosec // the path is one this test built
	cmd.Env = append(os.Environ(), "LADULAS_SOCK="+b.cfg.ControlSocket)

	return cmd
}

func (b *pairingBox) run(args ...string) (string, error) {
	out, err := b.command(args...).CombinedOutput()

	return string(out), err
}

func (b *pairingBox) mustRun(args ...string) string {
	b.t.Helper()

	out, err := b.run(args...)
	if err != nil {
		b.t.Fatalf("%s: ladulas %s: %v\n%s",
			b.name, strings.Join(args, " "), err, out)
	}

	return out
}

// pairings is what the management surface says is under way here.
func (b *pairingBox) pairings() []*ladulasv1.PendingPairingStatus {
	node := b.instance().Peer()
	if node == nil {
		b.t.Fatalf("%s has no peer channel", b.name)
	}

	return node.PendingPairingStatuses()
}

// freeAddress picks a loopback port and gives it straight back, so that a box
// can be restarted onto the same one.
func freeAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}

	address := listener.Addr().String()

	if err := listener.Close(); err != nil {
		t.Fatalf("release the port: %v", err)
	}

	return address
}

// lockedBuffer collects a subprocess's output from the goroutines os/exec
// writes it from and from the one this test reads it with.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	n, err := b.buf.Write(p)
	if err != nil {
		return n, fmt.Errorf("collect output: %w", err)
	}

	return n, nil
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// listening is `ladulas pair --listen` with nobody at the keyboard: it prints a
// code and then shows a confirmation that never gets an answer, which is the
// state a terminal somebody walked away from is in.
type listening struct {
	t    *testing.T
	cmd  *exec.Cmd
	code string

	stdin io.WriteCloser
	out   *lockedBuffer
	done  chan struct{}
}

func startListening(t *testing.T, box *pairingBox, role string) *listening {
	t.Helper()

	cmd := box.command("pair", "--listen", "--role", role)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout: %v", err)
	}

	session := &listening{
		t:     t,
		cmd:   cmd,
		stdin: stdin,
		out:   &lockedBuffer{},
		done:  make(chan struct{}),
	}

	cmd.Stderr = session.out

	if err := cmd.Start(); err != nil {
		t.Fatalf("start `pair --listen` on %s: %v", box.name, err)
	}

	codes := make(chan string, 1)

	go func() {
		defer close(session.done)

		scanner := bufio.NewScanner(stdout)

		for scanner.Scan() {
			if _, err := session.out.Write(
				[]byte(scanner.Text() + "\n")); err != nil {
				t.Errorf("collect the listening side's output: %v", err)
			}

			if match := codePattern.FindStringSubmatch(scanner.Text()); match != nil {
				codes <- match[1]
			}
		}

		select {
		case codes <- "":
		default:
		}
	}()

	select {
	case session.code = <-codes:
	case <-time.After(30 * time.Second):
		t.Fatal("the listening side printed no pairing code")
	}

	if session.code == "" {
		t.Fatalf("the listening side printed no pairing code\n%s", session.text())
	}

	t.Cleanup(session.kill)

	return session
}

func (l *listening) text() string {
	return l.out.String()
}

// kill is the terminal going away — the laptop lid closing, the ssh session
// dropping, somebody hitting ctrl-c on a prompt they did not want to answer.
func (l *listening) kill() {
	if l.cmd.Process == nil {
		return
	}

	_ = l.stdin.Close()
	_ = l.cmd.Process.Kill()
	_ = l.cmd.Wait()

	<-l.done
}

// dialling is `ladulas pair <address> --code <code> --yes` running in the
// background: its user answers at once, and the command goes on reporting until
// the other side answers too.
type dialling struct {
	t    *testing.T
	cmd  *exec.Cmd
	out  *lockedBuffer
	done chan error
}

func startDialling(
	t *testing.T, box *pairingBox, address, code, role string,
) *dialling {
	t.Helper()

	return dial(t, box, box.command(
		"pair", address, "--code", code, "--role", role, "--yes"))
}

// startDiallingUnanswered spends the code and then shows a confirmation nobody
// answers, which is the other half of a pairing left on two screens.
func startDiallingUnanswered(
	t *testing.T, box *pairingBox, address, code, role string,
) *dialling {
	t.Helper()

	cmd := box.command("pair", address, "--code", code, "--role", role)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}

	t.Cleanup(func() {
		_ = stdin.Close()
	})

	return dial(t, box, cmd)
}

func dial(t *testing.T, box *pairingBox, cmd *exec.Cmd) *dialling {
	t.Helper()

	session := &dialling{
		t:    t,
		cmd:  cmd,
		out:  &lockedBuffer{},
		done: make(chan error, 1),
	}

	cmd.Stdout = session.out
	cmd.Stderr = session.out

	if err := cmd.Start(); err != nil {
		t.Fatalf("start `pair` on %s: %v", box.name, err)
	}

	go func() {
		session.done <- cmd.Wait()
	}()

	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})

	return session
}

func (d *dialling) wait() (string, error) {
	d.t.Helper()

	select {
	case err := <-d.done:
		return d.out.String(), err
	case <-time.After(60 * time.Second):
		d.t.Fatalf("the dialling side never finished:\n%s", d.out.String())

		return "", nil
	}
}

// waitPairing waits for a box to hold a pairing in a state, which is how every
// step of a resumable pairing is observed: by looking at what is written down
// rather than by waiting on a call.
func waitPairing(
	t *testing.T, box *pairingBox, want func(*ladulasv1.PendingPairingStatus) bool,
) *ladulasv1.PendingPairingStatus {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		for _, pairing := range box.pairings() {
			if want(pairing) {
				return pairing
			}
		}

		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("%s never reached the pairing state the test wanted", box.name)

	return nil
}

func unanswered(pairing *ladulasv1.PendingPairingStatus) bool {
	return pairing.GetOurAnswer() ==
		ladulasv1.PairingAnswer_PAIRING_ANSWER_UNSPECIFIED
}

func answeredHere(pairing *ladulasv1.PendingPairingStatus) bool {
	return pairing.GetOurAnswer() ==
		ladulasv1.PairingAnswer_PAIRING_ANSWER_ACCEPTED
}

func theirsAccepted(pairing *ladulasv1.PendingPairingStatus) bool {
	return pairing.GetTheirAnswer() ==
		ladulasv1.PairingAnswer_PAIRING_ANSWER_ACCEPTED
}

func anyPairing(*ladulasv1.PendingPairingStatus) bool {
	return true
}

// waitNoPairings waits for a box to have nothing under way.
func waitNoPairings(t *testing.T, boxes ...*pairingBox) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		waiting := 0

		for _, box := range boxes {
			waiting += len(box.pairings())
		}

		if waiting == 0 {
			return
		}

		time.Sleep(20 * time.Millisecond)
	}

	for _, box := range boxes {
		if pairings := box.pairings(); len(pairings) != 0 {
			t.Errorf("%s still has %d pairings under way",
				box.name, len(pairings))
		}
	}

	t.FailNow()
}

// waitPaired waits for a box to hold a trust record for an identity.
func waitPairedWith(t *testing.T, box *pairingBox, fingerprint string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		if _, ok := box.instance().Vault().Peer(fingerprint); ok {
			return
		}

		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("%s never wrote a record for %s", box.name, fingerprint)
}

// requirePairedBothWays is the thing the owner did not get on a real phone.
func requirePairedBothWays(t *testing.T, first, second *pairingBox) {
	t.Helper()

	waitPairedWith(t, first, second.fingerprint())
	waitPairedWith(t, second, first.fingerprint())
	waitNoPairings(t, first, second)
}

// TestAPairingIsAnsweredLongAfterTheCommandThatRaisedItIsGone is the M6 failure
// with the timing left in.
//
// The desktop displays a code, the phone uses it and its user says yes, and
// then the terminal that was displaying the code goes away without anybody
// having answered on that side. Everything about that used to be fatal: the
// pending record was in the memory of a process that no longer exists, the
// confirmation was a card on a deadline, and the call that would have reported
// the answer had been cancelled with the terminal.
//
// What has to be true instead is that the pairing is simply still there, on
// both sides, and that answering it whenever somebody gets round to it works.
func TestAPairingIsAnsweredLongAfterTheCommandThatRaisedItIsGone(t *testing.T) {
	cli := buildCLI(t)

	desk := startPairingBox(t, cli, "desk")
	phone := startPairingBox(t, cli, "phone")

	listen := startListening(t, desk, "requester")
	dial := startDialling(t, phone, desk.address, listen.code, "approver")

	// The exchange has happened: the code is spent and both sides have written
	// the pairing down.
	waitPairing(t, desk, anyPairing)
	waitPairing(t, phone, answeredHere)

	// And now the terminal goes away, unanswered.
	listen.kill()

	waiting := waitPairing(t, desk, unanswered)

	if waiting.GetName() != "phone" {
		t.Errorf("the desk is waiting on %q", waiting.GetName())
	}

	// The management surface can see it and can answer it, which is the whole
	// of what §14 promised and did not have.
	listed := desk.mustRun("pairings", "list")

	if !strings.Contains(listed, "waiting for you") {
		t.Errorf("`pairings list` does not say it is waiting:\n%s", listed)
	}

	if !strings.Contains(listed, phone.fingerprint()) {
		t.Errorf("`pairings list` does not name the peer:\n%s", listed)
	}

	// Both fingerprints have to be on screen, because the question a pairing
	// asks is whether two machines agree about them.
	if !strings.Contains(listed, desk.fingerprint()) {
		t.Errorf("`pairings list` does not say what this instance is:\n%s", listed)
	}

	answered := desk.mustRun("pairings", "approve", phone.fingerprint())

	if !strings.Contains(answered, "Paired with") {
		t.Errorf("approving did not complete the pairing:\n%s", answered)
	}

	requirePairedBothWays(t, desk, phone)

	out, err := dial.wait()
	if err != nil {
		t.Fatalf("the dialling side failed: %v\n%s", err, out)
	}

	if !strings.Contains(out, "Paired with") {
		t.Errorf("the dialling side did not report a pairing:\n%s", out)
	}
}

// TestAPairingSurvivesADaemonRestartOnEitherSide: the state is in the encrypted
// store, so stopping and starting the process it lives in changes nothing but
// how long it takes.
func TestAPairingSurvivesADaemonRestartOnEitherSide(t *testing.T) {
	cli := buildCLI(t)

	desk := startPairingBox(t, cli, "desk")
	phone := startPairingBox(t, cli, "phone")

	listen := startListening(t, desk, "requester")
	dial := startDialling(t, phone, desk.address, listen.code, "approver")

	waitPairing(t, desk, anyPairing)
	waitPairing(t, phone, answeredHere)

	listen.kill()
	waitPairing(t, desk, unanswered)

	// The side that has not answered restarts. It comes back still holding a
	// pairing waiting for its user, which is the state a person walks back to.
	desk.restart()

	after := waitPairing(t, desk, unanswered)

	if after.GetFingerprint() != phone.fingerprint() {
		t.Errorf("the desk came back holding a pairing with %s",
			after.GetFingerprint())
	}

	// And the side that has answered restarts too, so that neither of them is
	// the process the pairing began in.
	phone.restart()

	kept := waitPairing(t, phone, answeredHere)

	if kept.GetFingerprint() != desk.fingerprint() {
		t.Errorf("the phone came back holding a pairing with %s",
			kept.GetFingerprint())
	}

	desk.mustRun("pairings", "approve", phone.fingerprint())

	requirePairedBothWays(t, desk, phone)

	// The dialling command was killed along with its daemon; what completed the
	// pairing was the two records, not the two commands.
	if _, err := dial.wait(); err == nil {
		t.Log("the dialling command outlived its daemon, which is fine too")
	}
}

// TestAnAnswerConvergesAfterThePeerWasUnreachable: an answer given while the
// other machine is off is not lost, and the two agree again when it comes back
// without anybody being asked anything a second time.
func TestAnAnswerConvergesAfterThePeerWasUnreachable(t *testing.T) {
	cli := buildCLI(t)

	desk := startPairingBox(t, cli, "desk")
	phone := startPairingBox(t, cli, "phone")

	listen := startListening(t, desk, "requester")
	startDiallingUnanswered(t, phone, desk.address, listen.code, "approver")

	// Neither user has answered yet, and both machines are holding the pairing.
	waitPairing(t, desk, unanswered)
	waitPairing(t, phone, unanswered)

	// The desk answers while the phone is still there, so the phone knows. It
	// is the phone learning it that matters, not the desk recording it, since
	// what comes next is the desk becoming unreachable.
	desk.mustRun("pairings", "approve", phone.fingerprint())
	waitPairing(t, desk, answeredHere)
	waitPairing(t, phone, theirsAccepted)

	// And then the desk goes away entirely: shut, asleep, restarting, off.
	listen.kill()
	desk.stop()

	// The phone's user answers into a peer that is not there. It has both
	// answers, so it completes on its own; what it cannot do is tell the desk.
	answered := phone.mustRun("pairings", "approve", desk.fingerprint())

	if !strings.Contains(answered, "Paired with") {
		t.Errorf("the phone did not complete its own half:\n%s", answered)
	}

	waitPairedWith(t, phone, desk.fingerprint())

	// The desk comes back holding an answer and no news. Nobody touches it, and
	// it finds out by asking — which is the whole of what makes a pairing
	// resumable rather than merely durable.
	desk.start(false)

	waitPairedWith(t, desk, phone.fingerprint())
	waitNoPairings(t, desk, phone)
}

// TestWithdrawingFromEitherSideClearsBoth: withdrawal is manual, it is the only
// way a pairing leaves the list without being answered, and it takes the entry
// off both machines.
func TestWithdrawingFromEitherSideClearsBoth(t *testing.T) {
	cli := buildCLI(t)

	for _, from := range []string{"the dialling side", "the listening side"} {
		t.Run(from, func(t *testing.T) {
			desk := startPairingBox(t, cli, "desk")
			phone := startPairingBox(t, cli, "phone")

			listen := startListening(t, desk, "requester")
			dial := startDialling(t, phone, desk.address, listen.code, "approver")

			waitPairing(t, desk, anyPairing)
			waitPairing(t, phone, answeredHere)

			listen.kill()
			waitPairing(t, desk, unanswered)

			box, ref := phone, desk.fingerprint()
			if from == "the listening side" {
				box, ref = desk, phone.fingerprint()
			}

			out := box.mustRun("pairings", "withdraw", ref)

			if !strings.Contains(out, "Called off") {
				t.Errorf("withdrawing said:\n%s", out)
			}

			// Both sides, not just the one the command was run on.
			waitNoPairings(t, desk, phone)

			if len(desk.instance().Vault().Peers()) != 0 ||
				len(phone.instance().Vault().Peers()) != 0 {
				t.Error("a withdrawn pairing was written down anyway")
			}

			if _, err := dial.wait(); err == nil {
				t.Log("the dialling command reported the withdrawal itself")
			}
		})
	}
}

// TestAPairingCodeThatDoesNotMatchIsAnError is the other half of the rule:
// unreachable, asleep and slow are not errors, and disagreeing about the code
// is.
func TestAPairingCodeThatDoesNotMatchIsAnError(t *testing.T) {
	cli := buildCLI(t)

	desk := startPairingBox(t, cli, "desk")
	phone := startPairingBox(t, cli, "phone")

	listen := startListening(t, desk, "requester")

	// A code of the right shape and the wrong value, which is what a mistyped
	// one looks like and what a guess looks like.
	wrong := wrongCode(listen.code)

	out, err := phone.run("pair", desk.address,
		"--code", wrong, "--role", "approver", "--yes")
	if err == nil {
		t.Fatalf("a wrong code paired:\n%s", out)
	}

	if !strings.Contains(out, "does not match") {
		t.Errorf("the error does not say the code was wrong:\n%s", out)
	}

	// And nothing was written down anywhere as a result.
	if pairings := desk.pairings(); len(pairings) != 0 {
		t.Errorf("a wrong code left %d pairings on the desk", len(pairings))
	}

	if pairings := phone.pairings(); len(pairings) != 0 {
		t.Errorf("a wrong code left %d pairings on the phone", len(pairings))
	}
}

// wrongCode changes one character of a code into another character of the same
// alphabet, so that what fails is the proof rather than the parsing.
func wrongCode(code string) string {
	changed := []byte(code)

	for i := len(changed) - 1; i >= 0; i-- {
		if changed[i] == '-' {
			continue
		}

		if changed[i] == '2' {
			changed[i] = '3'
		} else {
			changed[i] = '2'
		}

		break
	}

	return string(changed)
}

// TestPairingsAreBoundedAndRefusedWhileSealed covers the two things §7 says
// about the pending set that are not about a single pairing: a sealed instance
// cannot see it, and it cannot grow without limit.
func TestPairingsAreBoundedAndRefusedWhileSealed(t *testing.T) {
	cli := buildCLI(t)

	desk := startPairingBox(t, cli, "desk")
	phone := startPairingBox(t, cli, "phone")

	listen := startListening(t, desk, "requester")
	startDialling(t, phone, desk.address, listen.code, "approver")

	waitPairing(t, desk, anyPairing)
	listen.kill()

	// The pending pairings live in the store with the trust records, so sealing
	// takes them away with everything else. That is the cost of putting them
	// there, and it is stated rather than worked around (§7, §10).
	if err := desk.instance().Lock(true, "the test sealed it"); err != nil {
		t.Fatalf("seal the desk: %v", err)
	}

	out, err := desk.run("pairings", "list")
	if err == nil {
		t.Fatalf("a sealed instance listed its pairings:\n%s", out)
	}

	if !strings.Contains(strings.ToLower(out), "sealed") &&
		!strings.Contains(strings.ToLower(out), "unlock") {
		t.Errorf("a sealed instance said something unhelpful:\n%s", out)
	}

	if _, err := desk.instance().Unlock([]byte(testPassphrase)); err != nil {
		t.Fatalf("unlock the desk: %v", err)
	}

	waitPairing(t, desk, unanswered)
}

// TestASecondAttemptFromOneMachineReplacesTheFirst: the pending set is bounded,
// and the first bound is the one that matters — a machine that pairs twice is a
// person retrying, not two questions.
func TestASecondAttemptFromOneMachineReplacesTheFirst(t *testing.T) {
	cli := buildCLI(t)

	desk := startPairingBox(t, cli, "desk")
	phone := startPairingBox(t, cli, "phone")

	first := startListening(t, desk, "requester")
	startDialling(t, phone, desk.address, first.code, "approver")

	one := waitPairing(t, desk, anyPairing)

	first.kill()

	// The same two machines start again, which is what somebody does when they
	// walked away from the first attempt.
	second := startListening(t, desk, "requester")
	startDialling(t, phone, desk.address, second.code, "approver")

	waitPairing(t, desk, func(pairing *ladulasv1.PendingPairingStatus) bool {
		return pairing.GetSessionId() != one.GetSessionId()
	})

	second.kill()

	if pairings := desk.pairings(); len(pairings) != 1 {
		t.Errorf("two attempts from one machine left %d entries", len(pairings))
	}

	if pairings := phone.pairings(); len(pairings) != 1 {
		t.Errorf("two attempts left the phone with %d entries", len(pairings))
	}
}
