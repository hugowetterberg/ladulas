// Package integration holds the tests that drive the whole thing the way a
// user does: a real repository, a real git, the real signing binary, and an
// instance behind it.
//
// They are the ones that catch a contract drifting — the .sig file in the wrong
// place, a command line git builds differently from what was assumed, an
// armoured signature ssh-keygen will not read. Everything they need is guarded,
// so a machine without git or ssh-keygen skips rather than fails.
package integration_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/hugowetterberg/ladulas/internal/app"
	"github.com/hugowetterberg/ladulas/internal/testutil"
	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// instance is a running Ladulås with one key and an auto-approving policy.
type instance struct {
	app       *app.App
	publicKey string
	socket    string
	auditPath string
}

func startInstance(t *testing.T) *instance {
	t.Helper()

	dataDir := t.TempDir()
	configDir := t.TempDir()
	runtime := shortDir(t)

	cfg := app.Config{
		DataDir:       dataDir,
		ConfigDir:     configDir,
		SocketPath:    filepath.Join(runtime, "agent.sock"),
		ControlSocket: filepath.Join(runtime, "control.sock"),
		InstanceName:  "integration",
		// An ephemeral loopback port, so that several instances can run at once
		// and none of them claims the real one.
		PeerListen: "127.0.0.1:0",
		NoKeyring:  true,
		Passphrase: func(string, bool) ([]byte, error) {
			return []byte(testPassphrase), nil
		},
	}

	instanceApp, err := app.Create(cfg)
	if err != nil {
		t.Fatalf("create the instance: %v", err)
	}

	t.Cleanup(func() {
		if err := instanceApp.Close(); err != nil {
			t.Errorf("close the instance: %v", err)
		}
	})

	key, err := instanceApp.Vault().GenerateKey("work", "work@example.test")
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	// A policy that approves git signing without asking: the test has nobody to
	// answer a prompt, and the auto-approve path is the one a dogfooding user
	// reaches for first anyway.
	policy := approval.NewPolicy(&ladulasv1.PolicyDocument{
		Version: 1,
		Rules: []*ladulasv1.Rule{{
			Name:   "auto-approve git signing in tests",
			Match:  &ladulasv1.Match{Kinds: []ladulasv1.RequestKind{ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN}},
			Action: ladulasv1.Action_ACTION_APPROVE,
		}},
	})

	if err := policy.Save(instanceApp.Config.PolicyPath()); err != nil {
		t.Fatalf("write the policy: %v", err)
	}

	if err := instanceApp.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)

	go func() {
		served <- instanceApp.Serve(ctx)
	}()

	t.Cleanup(func() {
		cancel()

		select {
		case err := <-served:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the instance did not stop")
		}
	})

	waitForSocket(t, cfg.ControlSocket)

	pub, err := ssh.ParsePublicKey(key.GetPublicKey())
	if err != nil {
		t.Fatalf("parse the public key: %v", err)
	}

	return &instance{
		app:       instanceApp,
		publicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		socket:    cfg.ControlSocket,
		auditPath: instanceApp.Config.AuditPath(),
	}
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("nothing appeared at %s", path)
}

// shortDir is a temporary directory outside the test tree; a unix socket
// address does not have room for a long one.
func shortDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "ladulas")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}

	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})

	return dir
}

// buildSigner compiles ladulas-sign into a scratch directory. Building it is
// the point: the test drives the binary git would run, not a function call that
// resembles it.
func buildSigner(t *testing.T) string {
	t.Helper()

	testutil.RequireTool(t, "go")

	path := filepath.Join(shortDir(t), "ladulas-sign")

	cmd := exec.Command("go", "build", "-o", path,
		"github.com/hugowetterberg/ladulas/cmd/ladulas-sign")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build ladulas-sign: %v\n%s", err, out)
	}

	return path
}

// TestGitCommitSignedThroughLadulasSign is the whole of M2 in one test: git
// signs a commit through ladulas-sign, git verifies it afterwards through the
// same program, and the audit log holds the commit that was signed rather than
// a digest.
func TestGitCommitSignedThroughLadulasSign(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	inst := startInstance(t)
	signer := buildSigner(t)

	repo := t.TempDir()
	env := testutil.Env("LADULAS_SOCK=" + inst.socket)

	run := func(args ...string) string {
		t.Helper()

		cmd := exec.Command(git, args...)
		cmd.Dir = repo
		cmd.Env = env

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}

		return string(out)
	}

	run("init", "-q", "-b", "main", ".")
	run("remote", "add", "origin", "git@github.com:example/ladulas.git")
	run("config", "user.name", "Test Author")
	run("config", "user.email", "author@example.test")
	run("config", "gpg.format", "ssh")
	run("config", "gpg.ssh.program", signer)
	run("config", "user.signingkey", "key::"+inst.publicKey)

	write(t, repo, "README.md", "first\n")
	run("add", "README.md")
	run("commit", "-q", "-m", "the first commit")

	write(t, repo, "README.md", "first\nsecond\n")
	write(t, repo, "socket.go", "package main\n\nfunc main() {}\n")
	run("add", ".")

	// The commit git signs, driven exactly as a user would drive it.
	run("commit", "-q", "-S", "-m",
		"tighten the socket permissions\n\nThe agent socket was 0644.")

	body := run("cat-file", "commit", "HEAD")

	if !strings.Contains(body, "gpgsig -----BEGIN SSH SIGNATURE-----") {
		t.Fatalf("the commit carries no signature:\n%s", body)
	}

	// And git verifies it, which runs ladulas-sign again with -Y find-principals
	// and -Y verify and therefore exercises the hand-over to ssh-keygen.
	allowed := filepath.Join(repo, "allowed_signers")

	err := os.WriteFile(allowed,
		[]byte("author@example.test "+inst.publicKey+"\n"), 0o600)
	if err != nil {
		t.Fatalf("write allowed signers: %v", err)
	}

	run("config", "gpg.ssh.allowedSignersFile", allowed)

	verified := run("log", "--show-signature", "-1")

	if !strings.Contains(verified, `Good "git" signature`) {
		t.Fatalf("git did not verify the signature:\n%s", verified)
	}

	// The audit log has to hold the commit, not a digest: that is the whole
	// difference between M1's prompt and M2's.
	entry := lastDecision(t, inst.auditPath)

	git2 := entry.GetRequest().GetSshsig().GetGitContext()
	if git2 == nil {
		t.Fatal("the audited request carries no git context")
	}

	if !git2.GetVerifiedAgainstPayload() {
		t.Error("the context was not verified against the payload")
	}

	object := git2.GetParsed()

	if object.GetSubject() != "tighten the socket permissions" {
		t.Errorf("the audited subject is %q", object.GetSubject())
	}

	if !strings.Contains(object.GetMessage(), "The agent socket was 0644.") {
		t.Errorf("the audited message is %q", object.GetMessage())
	}

	if object.GetAuthor().GetEmail() != "author@example.test" {
		t.Errorf("the audited author is %+v", object.GetAuthor())
	}

	if git2.GetOriginUrl() != "git@github.com:example/ladulas.git" {
		t.Errorf("the audited origin is %q", git2.GetOriginUrl())
	}

	if git2.GetBranch() != "main" {
		t.Errorf("the audited branch is %q", git2.GetBranch())
	}

	diff := git2.GetDiff()

	if diff.GetFilesChanged() != 2 {
		t.Errorf("the audited diff covers %d files, want 2", diff.GetFilesChanged())
	}

	var paths []string
	for _, file := range diff.GetFiles() {
		paths = append(paths, file.GetNewPath())
	}

	if !contains(paths, "socket.go") || !contains(paths, "README.md") {
		t.Errorf("the audited diff covers %v", paths)
	}

	// And the hunks are there, so the approving device has something to show.
	for _, file := range diff.GetFiles() {
		if file.GetNewPath() != "socket.go" {
			continue
		}

		if len(file.GetHunks()) == 0 {
			t.Fatal("socket.go has no hunks")
		}

		found := false

		for _, line := range file.GetHunks()[0].GetLines() {
			if line.GetText() == "package main" &&
				line.GetKind() == ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_ADDED {
				found = true
			}
		}

		if !found {
			t.Errorf("the added lines of socket.go are missing: %+v",
				file.GetHunks()[0].GetLines())
		}
	}

	if entry.GetResponse().GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Errorf("the decision was %v", entry.GetResponse().GetDecision())
	}

	if !strings.Contains(entry.GetPromptShown(), "tighten the socket permissions") {
		t.Errorf("the recorded prompt is:\n%s", entry.GetPromptShown())
	}
}

// TestGitTagSignedThroughLadulasSign covers the other object git signs.
func TestGitTagSignedThroughLadulasSign(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	inst := startInstance(t)
	signer := buildSigner(t)

	repo := t.TempDir()
	env := testutil.Env("LADULAS_SOCK=" + inst.socket)

	run := func(args ...string) string {
		t.Helper()

		cmd := exec.Command(git, args...)
		cmd.Dir = repo
		cmd.Env = env

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}

		return string(out)
	}

	run("init", "-q", "-b", "main", ".")
	run("config", "user.name", "Test Author")
	run("config", "user.email", "author@example.test")
	run("config", "gpg.format", "ssh")
	run("config", "gpg.ssh.program", signer)
	run("config", "user.signingkey", "key::"+inst.publicKey)

	write(t, repo, "README.md", "first\n")
	run("add", ".")
	run("commit", "-q", "-m", "the first commit")

	run("tag", "-s", "-m", "the first release", "v1.0")

	body := run("cat-file", "tag", "v1.0")

	if !strings.Contains(body, "-----BEGIN SSH SIGNATURE-----") {
		t.Fatalf("the tag carries no signature:\n%s", body)
	}

	entry := lastDecision(t, inst.auditPath)
	object := entry.GetRequest().GetSshsig().GetGitContext().GetParsed()

	if object.GetType() != "tag" {
		t.Errorf("the audited object is a %q", object.GetType())
	}

	if object.GetTag() != "v1.0" {
		t.Errorf("the audited tag is %q", object.GetTag())
	}

	// git tags as the committer identity, which the test environment sets.
	if object.GetTagger().GetEmail() != "committer@example.test" {
		t.Errorf("the audited tagger is %+v", object.GetTagger())
	}

	if object.GetSubject() != "the first release" {
		t.Errorf("the audited tag message is %q", object.GetSubject())
	}
}

// TestPlainSshKeygenStillSigns is the fallback of §5: a machine configured with
// nothing but SSH_AUTH_SOCK keeps working, with a poorer prompt.
func TestPlainSshKeygenStillSigns(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	inst := startInstance(t)

	// The M1 policy for this path: approve git signing whatever it arrives as.
	repo := t.TempDir()
	env := testutil.Env("SSH_AUTH_SOCK=" + inst.app.Config.SocketPath)

	run := func(args ...string) string {
		t.Helper()

		cmd := exec.Command(git, args...)
		cmd.Dir = repo
		cmd.Env = env

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}

		return string(out)
	}

	run("init", "-q", "-b", "main", ".")
	run("config", "user.name", "Test Author")
	run("config", "user.email", "author@example.test")
	run("config", "gpg.format", "ssh")
	run("config", "user.signingkey", "key::"+inst.publicKey)

	write(t, repo, "README.md", "first\n")
	run("add", ".")
	run("commit", "-q", "-S", "-m", "signed by the plain agent")

	body := run("cat-file", "commit", "HEAD")

	if !strings.Contains(body, "gpgsig -----BEGIN SSH SIGNATURE-----") {
		t.Fatalf("the commit carries no signature:\n%s", body)
	}

	// The agent only ever saw a digest, and the prompt says as much.
	entry := lastDecision(t, inst.auditPath)

	if entry.GetRequest().GetSshsig().GetGitContext() != nil {
		t.Error("a plain agent request arrived with a git context")
	}

	if !strings.Contains(entry.GetPromptShown(), "Digest") {
		t.Errorf("the recorded prompt is:\n%s", entry.GetPromptShown())
	}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}

	return false
}

// lastDecision reads the newest decision entry out of the audit log.
func lastDecision(t *testing.T, path string) *ladulasv1.AuditEntry {
	t.Helper()

	file, err := os.Open(path) //nolint:gosec // a path this test created
	if err != nil {
		t.Fatalf("open the audit log: %v", err)
	}

	defer func() {
		_ = file.Close()
	}()

	var last *ladulasv1.AuditEntry

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)

	for scanner.Scan() {
		line := scanner.Bytes()
		if !json.Valid(line) {
			continue
		}

		var entry ladulasv1.AuditEntry

		if err := protojson.Unmarshal(line, &entry); err != nil {
			t.Fatalf("parse an audit entry: %v", err)
		}

		if entry.GetEvent() == ladulasv1.AuditEvent_AUDIT_EVENT_DECISION {
			last = &entry
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("read the audit log: %v", err)
	}

	if last == nil {
		t.Fatal("the audit log holds no decision")
	}

	return last
}
