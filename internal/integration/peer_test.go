package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/internal/app"
	"github.com/hugowetterberg/ladulas/internal/testutil"
	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// This is M3's acceptance, driven the way it will actually be used: two
// instances in their own directories, paired by running the real command line
// on both sides and answering the confirmation on each, and then a commit
// signed on a machine with nobody at it and approved on the machine somebody is
// sitting at.
//
// The pairing runs as subprocesses because the command line is part of what is
// being tested — the code it prints, the confirmation it shows, the answer it
// sends back over the control socket. The approver on the desktop side is a
// handler registered with the engine, which is exactly what the tray is; what
// the tray adds on top of it has tests of its own in pkg/bridge.

// testPassphrase is what every instance in these tests is created with, so
// that a test can seal one and unlock it again the way a person would.
const testPassphrase = "integration test passphrase"

// peerInstance is a full instance: store, agent, signing socket and peer
// channel, in its own directories.
type peerInstance struct {
	t         *testing.T
	app       *app.App
	name      string
	publicKey string
	control   string
	audit     string
	address   string
}

func startPeerInstance(t *testing.T, name string) *peerInstance {
	t.Helper()

	return startInstanceWithKeys(t, name, true)
}

// startKeylessInstance is M4's headless requester: a box that holds no private
// key at all and gets its signatures from a paired holder (§3).
func startKeylessInstance(t *testing.T, name string) *peerInstance {
	t.Helper()

	return startInstanceWithKeys(t, name, false)
}

// startInstanceWithKeyring is the same instance with a keychain it owns, for
// the verbs that enrol one. Enrolment is the daemon's since the store stopped
// having a second opener (§14), so exercising it needs a keyring the test can
// hand the instance.
func startInstanceWithKeyring(
	t *testing.T, name string, kr keystore.Keyring,
) *peerInstance {
	t.Helper()

	return startPeerInstanceWith(t, name, true, kr)
}

func startInstanceWithKeys(t *testing.T, name string, withKey bool) *peerInstance {
	t.Helper()

	return startPeerInstanceWith(t, name, withKey, nil)
}

func startPeerInstanceWith(
	t *testing.T, name string, withKey bool, kr keystore.Keyring,
) *peerInstance {
	t.Helper()

	runtime := shortDir(t)

	cfg := app.Config{
		DataDir:       t.TempDir(),
		ConfigDir:     t.TempDir(),
		SocketPath:    filepath.Join(runtime, "agent.sock"),
		ControlSocket: filepath.Join(runtime, "control.sock"),
		InstanceName:  name,
		// A loopback port picked by the kernel: two instances have to be able to
		// run at once, and neither should claim the real one.
		PeerListen: "127.0.0.1:0",
		NoKeyring:  kr == nil,
		Keyring:    kr,
		Passphrase: func(string, bool) ([]byte, error) {
			return []byte(testPassphrase), nil
		},
	}

	instance, err := app.Create(cfg)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}

	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Errorf("close %s: %v", name, err)
		}
	})

	var publicKey string

	if withKey {
		key, err := instance.Vault().GenerateKey("work", name+"@example.test")
		if err != nil {
			t.Fatalf("generate a key on %s: %v", name, err)
		}

		pub, err := ssh.ParsePublicKey(key.GetPublicKey())
		if err != nil {
			t.Fatalf("parse the public key: %v", err)
		}

		publicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)

	go func() {
		served <- instance.Serve(ctx)
	}()

	t.Cleanup(func() {
		cancel()

		select {
		case err := <-served:
			if err != nil {
				t.Errorf("serve %s: %v", name, err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("%s did not stop", name)
		}
	})

	waitForSocket(t, cfg.ControlSocket)

	addresses := instance.PeerAddresses()
	if len(addresses) != 1 {
		t.Fatalf("%s bound %v", name, addresses)
	}

	return &peerInstance{
		t:         t,
		app:       instance,
		name:      name,
		publicKey: publicKey,
		control:   cfg.ControlSocket,
		audit:     instance.Config.AuditPath(),
		address:   addresses[0],
	}
}

func (p *peerInstance) fingerprint() string {
	return p.app.Vault().Identity().Fingerprint()
}

// handHandler stands in for the tray: a human who answers.
//
// It leaves pairing alone. A real tray would show a pairing confirmation as
// well — that is the point of the card in pkg/bridge — but here the
// command line is the thing being exercised, and two approvers racing to answer
// the same prompt would make it a coin toss which one did.
type handHandler struct {
	name string

	mu     sync.Mutex
	answer *approval.Answer
	seen   []*approval.Request
}

var errNotOurs = errors.New("the test's approver leaves pairings to the command line")

func (h *handHandler) ID() string {
	return h.name
}

func (h *handHandler) Decide(
	_ context.Context, req *approval.Request,
) (*approval.Answer, error) {
	if req.Msg.GetKind() == ladulasv1.RequestKind_REQUEST_KIND_PAIRING {
		return nil, errNotOurs
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.seen = append(h.seen, req)

	return h.answer, nil
}

func (h *handHandler) last() *approval.Request {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.seen) == 0 {
		return nil
	}

	return h.seen[len(h.seen)-1]
}

// buildCLI compiles the ladulas command line, which the pairing is driven with.
func buildCLI(t *testing.T) string {
	t.Helper()

	testutil.RequireTool(t, "go")

	path := filepath.Join(shortDir(t), "ladulas")

	cmd := exec.Command("go", "build", "-o", path,
		"github.com/hugowetterberg/ladulas/cmd/ladulas")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build ladulas: %v\n%s", err, out)
	}

	return path
}

// codePattern picks the pairing code out of what `ladulas pair --listen` prints.
var codePattern = regexp.MustCompile(`Pairing code\s+([0-9a-z]{5}-[0-9a-z]{5})`)

// pairOverTheCommandLine runs the real flow: the approver displays a code, the
// requester uses it, and a user answers the confirmation on each side.
func pairOverTheCommandLine(t *testing.T, cli string, approver, requester *peerInstance) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The approver's side: display a code, and say what the pairing is for —
	// this instance approves for the machine that joins (decision AD). The
	// dialling side is not asked, and records the mirror of it.
	listen := exec.CommandContext(ctx, cli,
		"pair", "--listen", "--intent", "requester")
	listen.Env = append(os.Environ(), "LADULAS_SOCK="+approver.control)
	listen.Stdin = strings.NewReader("y\n")

	stdout, err := listen.StdoutPipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	var listenErr bytes.Buffer

	listen.Stderr = &listenErr

	if err := listen.Start(); err != nil {
		t.Fatalf("start the listening side: %v", err)
	}

	listened := make(chan string, 1)
	scanned := make(chan struct{})

	go func() {
		defer close(scanned)

		var seen bytes.Buffer
		scanner := bufio.NewScanner(io.TeeReader(stdout, &seen))

		for scanner.Scan() {
			if match := codePattern.FindStringSubmatch(scanner.Text()); match != nil {
				listened <- match[1]
			}
		}

		select {
		case listened <- "":
		default:
		}

		t.Logf("%s pair --listen said:\n%s", approver.name, seen.String())
	}()

	var code string

	select {
	case code = <-listened:
	case <-time.After(30 * time.Second):
		t.Fatal("the listening side printed no pairing code")
	}

	if code == "" {
		t.Fatalf("the listening side printed no pairing code\n%s", listenErr.String())
	}

	// The requester's side: use the code. What it grants is what the other
	// machine already chose, which it sees on the confirmation.
	dial := exec.CommandContext(ctx, cli,
		"pair", approver.address, "--code", code)
	dial.Env = append(os.Environ(), "LADULAS_SOCK="+requester.control)
	dial.Stdin = strings.NewReader("y\n")

	out, err := dial.CombinedOutput()
	if err != nil {
		t.Fatalf("pair from %s: %v\n%s", requester.name, err, out)
	}

	if !strings.Contains(string(out), "Paired with") {
		t.Fatalf("the dialling side did not report a pairing:\n%s", out)
	}

	if err := listen.Wait(); err != nil {
		t.Fatalf("the listening side failed: %v\n%s", err, listenErr.String())
	}

	<-scanned

	// Each side wrote down its own half.
	theirs, ok := approver.app.Vault().Peer(requester.fingerprint())
	if !ok {
		t.Fatalf("%s kept no record of %s", approver.name, requester.name)
	}

	if !theirs.GetMayRequest() || theirs.GetMayApprove() {
		t.Errorf("%s recorded approve=%v request=%v", approver.name,
			theirs.GetMayApprove(), theirs.GetMayRequest())
	}

	ours, ok := requester.app.Vault().Peer(approver.fingerprint())
	if !ok {
		t.Fatalf("%s kept no record of %s", requester.name, approver.name)
	}

	if !ours.GetMayApprove() || ours.GetMayRequest() {
		t.Errorf("%s recorded approve=%v request=%v", requester.name,
			ours.GetMayApprove(), ours.GetMayRequest())
	}
}

// signOn drives a real git commit on an instance, through ladulas-sign.
func signOn(t *testing.T, inst *peerInstance, signer, gitPath, message string) (string, error) {
	t.Helper()

	return signIn(t, t.TempDir(), inst, signer, gitPath, message)
}

// signIn is signOn against a repository the caller keeps, which is what a test
// about grants needs: a TTL grant is scoped to a repository (see scopeFor), so
// two commits in two temporary directories are two different scopes and a grant
// covering the first has no business covering the second.
//
// The repository is set up once and committed to as many times as it is called.
func signIn(
	t *testing.T,
	repo string,
	inst *peerInstance,
	signer, gitPath, message string,
) (string, error) {
	t.Helper()

	env := testutil.Env("LADULAS_SOCK=" + inst.control)

	run := func(args ...string) (string, error) {
		cmd := exec.Command(gitPath, args...)
		cmd.Dir = repo
		cmd.Env = env

		out, err := cmd.CombinedOutput()

		return string(out), err
	}

	must := func(args ...string) string {
		t.Helper()

		out, err := run(args...)
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}

		return out
	}

	if _, err := os.Stat(filepath.Join(repo, ".git")); os.IsNotExist(err) {
		must("init", "-q", "-b", "main", ".")
		must("remote", "add", "origin", "git@github.com:example/ladulas.git")
		must("config", "user.name", "Test Author")
		must("config", "user.email", "author@example.test")
		must("config", "gpg.format", "ssh")
		must("config", "gpg.ssh.program", signer)
		must("config", "user.signingkey", "key::"+inst.publicKey)

		write(t, repo, "README.md", "first\n")
		must("add", ".")
		must("commit", "-q", "-m", "the first commit")
	}

	write(t, repo, "socket-"+strconv.Itoa(len(message))+".go",
		"package main\n\n// "+message+"\nfunc main() {}\n")
	must("add", ".")

	if out, err := run("commit", "-q", "-S", "-m", message); err != nil {
		return out, fmt.Errorf("git commit: %w", err)
	}

	allowed := filepath.Join(repo, "allowed_signers")

	err := os.WriteFile(allowed,
		[]byte("author@example.test "+inst.publicKey+"\n"), 0o600)
	if err != nil {
		t.Fatalf("write allowed signers: %v", err)
	}

	must("config", "gpg.ssh.allowedSignersFile", allowed)

	return must("log", "--show-signature", "-1"), nil
}

// TestHeadlessCommitApprovedFromTheDesktop is the milestone: a box with nobody
// at it gets a commit signed because somebody at another machine said yes.
func TestHeadlessCommitApprovedFromTheDesktop(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)
	signer := buildSigner(t)

	desktop := startPeerInstance(t, "desktop")
	headless := startPeerInstance(t, "headless")

	// The desktop has a human; the headless box has nobody at all — no tray, no
	// terminal, and no policy that would approve.
	human := &handHandler{
		name: "desktop",
		answer: &approval.Answer{
			Decision: ladulasv1.Decision_DECISION_APPROVE,
			Reason:   "approved at the desktop",
		},
	}
	defer desktop.app.RegisterApprover(human)()

	pairOverTheCommandLine(t, cli, desktop, headless)

	verified, err := signOn(t, headless, signer, git,
		"tighten the socket permissions\n\nThe agent socket was 0644.")
	if err != nil {
		t.Fatalf("the commit was not signed: %v\n%s", err, verified)
	}

	if !strings.Contains(verified, `Good "git" signature`) {
		t.Fatalf("git did not verify the signature:\n%s", verified)
	}

	// The desktop was shown the commit, from a named machine, and checked for
	// itself that the commit shown is the one being signed (§5) — which is the
	// check that matters most when the requester is a machine nobody is at.
	shown := human.last()
	if shown == nil {
		t.Fatal("the desktop was never asked")
	}

	if shown.Msg.GetRequester().GetLocal() {
		t.Error("the desktop was shown the request as a local one")
	}

	if shown.Msg.GetRequester().GetInstanceId() != headless.fingerprint() {
		t.Errorf("the desktop was shown %q as the requester",
			shown.Msg.GetRequester().GetInstanceId())
	}

	git2 := shown.Msg.GetSshsig().GetGitContext()

	if !git2.GetVerifiedAgainstPayload() {
		t.Error("the desktop did not verify the commit against the payload")
	}

	if git2.GetParsed().GetSubject() != "tighten the socket permissions" {
		t.Errorf("the desktop was shown %q", git2.GetParsed().GetSubject())
	}

	if git2.GetDiff().GetFilesChanged() == 0 {
		t.Error("the desktop was shown no diff")
	}

	// Both logs hold the decision, and the requester's holds the approver's own
	// signature over it rather than only its account of events.
	requireApprovedDecision(t, desktop.audit, false, desktop.fingerprint())
	requireApprovedDecision(t, headless.audit, true, desktop.fingerprint())

	// And the key that signed the approval is the key in the trust record, so
	// the requester acted on an identity it had actually agreed to.
	record, ok := headless.app.Vault().Peer(desktop.fingerprint())
	if !ok {
		t.Fatal("the headless box has no record of the desktop")
	}

	entry := lastRemoteDecision(t, headless.audit)

	if entry.GetRemoteApproval().GetApproverFingerprint() != record.GetFingerprint() {
		t.Errorf("the approval was signed by %s, the record names %s",
			entry.GetRemoteApproval().GetApproverFingerprint(),
			record.GetFingerprint())
	}

	pub, err := ssh.ParsePublicKey(entry.GetRemoteApproval().GetApproverPublicKey())
	if err != nil {
		t.Fatalf("parse the approver's key: %v", err)
	}

	if !bytes.Equal(pub.Marshal(), record.GetIdentityPublicKey()) {
		t.Error("the approving key is not the paired key")
	}
}

// TestRemoteDenialStopsTheCommit: a refusal on the desktop is a refusal on the
// headless box, and git is told so rather than left waiting.
func TestRemoteDenialStopsTheCommit(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)
	signer := buildSigner(t)

	desktop := startPeerInstance(t, "desktop")
	headless := startPeerInstance(t, "headless")

	human := &handHandler{
		name: "desktop",
		answer: &approval.Answer{
			Decision: ladulasv1.Decision_DECISION_DENY,
			Reason:   "I did not make that commit",
		},
	}
	defer desktop.app.RegisterApprover(human)()

	pairOverTheCommandLine(t, cli, desktop, headless)

	out, err := signOn(t, headless, signer, git, "a commit nobody wants")
	if err == nil {
		t.Fatalf("the commit was signed despite the refusal:\n%s", out)
	}

	if !strings.Contains(out, "I did not make that commit") {
		t.Errorf("git was not told why:\n%s", out)
	}

	entry := lastDecision(t, headless.audit)

	if entry.GetResponse().GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Errorf("the refusal was recorded as %v", entry.GetResponse().GetDecision())
	}

	if entry.GetResponse().GetApprover().GetInstanceId() != desktop.fingerprint() {
		t.Errorf("the refusal is attributed to %v", entry.GetResponse().GetApprover())
	}
}

// TestUnreachableApproverStopsTheCommit: with the desktop switched off, the
// headless box gives up rather than sitting out the whole signing timeout.
func TestUnreachableApproverStopsTheCommit(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)
	signer := buildSigner(t)

	desktop := startPeerInstance(t, "desktop")
	headless := startPeerInstance(t, "headless")

	pairOverTheCommandLine(t, cli, desktop, headless)

	if err := desktop.app.Peer().Close(); err != nil {
		t.Fatalf("stop the desktop's peer channel: %v", err)
	}

	start := time.Now()

	out, err := signOn(t, headless, signer, git, "a commit with nobody to ask")
	if err == nil {
		t.Fatalf("the commit was signed with no approver:\n%s", out)
	}

	// The signing timeout is minutes (§9). Reaching a peer that is not there
	// should fail in seconds, so that a switched-off desktop is a quick error
	// rather than a hang.
	if elapsed := time.Since(start); elapsed > 90*time.Second {
		t.Errorf("waited %s for an approver that is not there", elapsed)
	}

	entry := lastDecision(t, headless.audit)

	if entry.GetResponse().GetSource() !=
		ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER {
		t.Errorf("the outcome was recorded as %v",
			entry.GetResponse().GetSource())
	}
}

// requireApprovedDecision checks a log for an approved git signature with an
// artifact on it that verifies under the approver's own key.
func requireApprovedDecision(t *testing.T, path string, remote bool, approver string) {
	t.Helper()

	entries, err := approval.ReadAuditLog(path, 0)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	for _, entry := range entries {
		if entry.GetEvent() != ladulasv1.AuditEvent_AUDIT_EVENT_DECISION ||
			entry.GetRequest().GetKind() !=
				ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN {
			continue
		}

		if entry.GetResponse().GetDecision() !=
			ladulasv1.Decision_DECISION_APPROVE {
			t.Fatalf("%s recorded the signature as %v",
				path, entry.GetResponse().GetDecision())
		}

		artifact := entry.GetSignedApproval()
		if remote {
			artifact = entry.GetRemoteApproval()
		}

		if artifact == nil {
			t.Fatalf("%s holds no approval artifact for the signature", path)
		}

		resp, _, err := identity.VerifyApproval(artifact)
		if err != nil {
			t.Fatalf("the artifact in %s does not verify: %v", path, err)
		}

		if remote && artifact.GetApproverFingerprint() != approver {
			t.Errorf("%s holds an artifact signed by %s, want %s",
				path, artifact.GetApproverFingerprint(), approver)
		}

		if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
			t.Errorf("the artifact in %s says %v", path, resp.GetDecision())
		}

		return
	}

	t.Fatalf("%s holds no decision about a git signature", path)
}

// lastRemoteDecision finds the newest decision a peer answered.
func lastRemoteDecision(t *testing.T, path string) *ladulasv1.AuditEntry {
	t.Helper()

	entries, err := approval.ReadAuditLog(path, 0)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].GetRemoteApproval() != nil {
			return entries[i]
		}
	}

	t.Fatalf("%s holds no decision made by a peer", path)

	return nil
}

// runCLI runs a Ladulås command against an instance's control socket.
func runCLI(t *testing.T, cli string, inst *peerInstance, args ...string) string {
	t.Helper()

	cmd := exec.Command(cli, args...)
	cmd.Env = append(os.Environ(),
		"LADULAS_SOCK="+inst.control,
		"LADULAS_DATA_DIR="+inst.app.Config.DataDir,
		"LADULAS_CONFIG_DIR="+inst.app.Config.ConfigDir,
		"LADULAS_NO_KEYRING=1")

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ladulas %s: %v\n%s", strings.Join(args, " "), err, out)
	}

	return string(out)
}

// TestPeerCommandsReportAndRevoke walks the commands somebody actually types
// after pairing: what am I paired with, is it there, and forget it.
func TestPeerCommandsReportAndRevoke(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)
	signer := buildSigner(t)

	desktop := startPeerInstance(t, "desktop")
	headless := startPeerInstance(t, "headless")

	human := &handHandler{
		name: "desktop",
		answer: &approval.Answer{
			Decision: ladulasv1.Decision_DECISION_APPROVE,
			Reason:   "approved at the desktop",
		},
	}
	defer desktop.app.RegisterApprover(human)()

	pairOverTheCommandLine(t, cli, desktop, headless)

	// The headless box dials the desktop, so it is the side with something to
	// say about reachability. Give the link a moment to come up.
	var listing string

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		listing = runCLI(t, cli, headless, "peers", "list")
		if strings.Contains(listing, "connected") {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Logf("headless: ladulas peers list\n%s", listing)

	if !strings.Contains(listing, "desktop") {
		t.Errorf("the peer listing does not name the desktop:\n%s", listing)
	}

	if !strings.Contains(listing, "connected") {
		t.Errorf("the peer listing never showed the link as up:\n%s", listing)
	}

	if !strings.Contains(listing, "approves for us") {
		t.Errorf("the peer listing does not say what the peer may do:\n%s", listing)
	}

	status := runCLI(t, cli, headless, "status")

	t.Logf("headless: ladulas status\n%s", status)

	if !strings.Contains(status, "Peers         1") {
		t.Errorf("status does not count the peer:\n%s", status)
	}

	// The desktop's own listing describes the other direction, and it never
	// dials the headless box, so it has no reachability to claim.
	theirs := runCLI(t, cli, desktop, "peers", "list")

	t.Logf("desktop: ladulas peers list\n%s", theirs)

	if !strings.Contains(theirs, "asks us") {
		t.Errorf("the desktop's listing does not say what the peer may do:\n%s", theirs)
	}

	// And revoking on the desktop is enough on its own: the headless box still
	// believes in the pairing, and gets nowhere with it.
	revoked := runCLI(t, cli, desktop, "peers", "revoke", "headless")

	t.Logf("desktop: ladulas peers revoke headless\n%s", revoked)

	if !strings.Contains(revoked, "dropped its connections") {
		t.Errorf("revoking said %q", revoked)
	}

	if _, ok := headless.app.Vault().Peer(desktop.fingerprint()); !ok {
		t.Error("revoking on one side removed the other side's record")
	}

	out, err := signOn(t, headless, signer, git, "a commit after the revocation")
	if err == nil {
		t.Fatalf("a revoked peer still approved a signature:\n%s", out)
	}
}

// seenRequests is every request this approver was asked about, which is how a
// test says "and nobody was asked the second time".
func (h *handHandler) seenRequests() []*approval.Request {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]*approval.Request(nil), h.seen...)
}
