package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/internal/testutil"
	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/bridge"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// M4's acceptance, driven the way it will be used: a build box that holds no
// private key at all, a desktop that holds one and lends it, and a project
// published from the box so that whoever is at the desktop can read what it is
// for before saying yes.
//
// The pairing and the key grant run through the real command line, because
// that is the management surface §14 says it is. What stands in for the tray is
// a handler registered with the engine, which is exactly what the tray is.

// signOnWith drives a real git commit on an instance with a key that lives
// somewhere else, which is the whole of the keyless story from git's side: it
// is configured with a public key and never notices where the private half is.
func signOnWith(
	t *testing.T, inst *peerInstance, publicKey, signer, gitPath, message string,
) (string, string, error) {
	t.Helper()

	repo := t.TempDir()
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

	must("init", "-q", "-b", "main", ".")
	must("remote", "add", "origin", "git@github.com:example/ladulas.git")
	must("config", "user.name", "Test Author")
	must("config", "user.email", "author@example.test")
	must("config", "gpg.format", "ssh")
	must("config", "gpg.ssh.program", signer)
	must("config", "user.signingkey", "key::"+publicKey)

	write(t, repo, "README.md", "# ladulas-build\n\nThe box that builds it.\n")
	must("add", ".")
	must("commit", "-q", "-m", "the first commit")

	write(t, repo, "socket.go", "package main\n\nfunc main() {}\n")
	must("add", ".")

	if out, err := run("commit", "-q", "-S", "-m", message); err != nil {
		return repo, out, fmt.Errorf("git commit: %w", err)
	}

	allowed := filepath.Join(repo, "allowed_signers")

	err := os.WriteFile(allowed,
		[]byte("author@example.test "+publicKey+"\n"), 0o600)
	if err != nil {
		t.Fatalf("write allowed signers: %v", err)
	}

	must("config", "gpg.ssh.allowedSignersFile", allowed)

	return repo, must("log", "--show-signature", "-1"), nil
}

// waitForBorrowedKey blocks until the requester knows the holder is offering a
// key.
//
// It asks rather than waiting for the heartbeat to bring the news, which is
// what the signing path itself does when it is looking for a key it has not
// been told about: the grant is the holder's to make and there is nothing for
// it to announce over.
func waitForBorrowedKey(t *testing.T, inst *peerInstance, fingerprint string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	deadline := time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		inst.app.Peer().RefreshKeys(ctx)

		for _, ref := range inst.app.Peer().RemoteKeyRefs() {
			if ref.GetFingerprint() == fingerprint {
				return
			}
		}

		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("%s never learned that a peer offers %s", inst.name, fingerprint)
}

// TestKeylessBoxSignsWithTheDesktopsKey is the milestone: a machine with no
// private key commits, because the machine that has one signed for it.
func TestKeylessBoxSignsWithTheDesktopsKey(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)
	signer := buildSigner(t)

	desktop := startPeerInstance(t, "desktop")
	headless := startKeylessInstance(t, "headless")

	human := &handHandler{
		name: "desktop",
		answer: &approval.Answer{
			Decision: ladulasv1.Decision_DECISION_APPROVE,
			Reason:   "approved at the desktop",
		},
	}
	defer desktop.app.RegisterApprover(human)()

	pairOverTheCommandLine(t, cli, desktop, headless)

	keys := desktop.app.Vault().KeyRefs()
	if len(keys) != 1 {
		t.Fatalf("the desktop holds %d keys", len(keys))
	}

	// Pairing granted directions, never keys. Lending one is a third decision
	// and a separate command (§7).
	if refs := headless.app.Peer().RemoteKeyRefs(); len(refs) != 0 {
		t.Fatalf("a freshly paired box already borrows %d keys", len(refs))
	}

	granted := runCLI(t, cli, desktop,
		"peers", "allow", "headless", "--request", "--key", "work")

	t.Logf("desktop: ladulas peers allow headless --request --key work\n%s", granted)

	if !strings.Contains(granted, "may sign with") {
		t.Errorf("the grant said %q", granted)
	}

	waitForBorrowedKey(t, headless, keys[0].GetFingerprint())

	// The headless box's own listing says where the key it can use lives.
	listing := runCLI(t, cli, headless, "keys", "list")

	t.Logf("headless: ladulas keys list\n%s", listing)

	if !strings.Contains(listing, "no keys of its own") {
		t.Errorf("the keyless box claims keys of its own:\n%s", listing)
	}

	if !strings.Contains(listing, "desktop") {
		t.Errorf("the keyless box does not say where its key lives:\n%s", listing)
	}

	_, verified, err := signOnWith(t, headless, desktop.publicKey, signer, git,
		"tighten the socket permissions\n\nThe agent socket was 0644.")
	if err != nil {
		t.Fatalf("the commit was not signed: %v\n%s", err, verified)
	}

	if !strings.Contains(verified, `Good "git" signature`) {
		t.Fatalf("git did not verify the signature:\n%s", verified)
	}

	// The desktop was shown the commit from a named machine, and checked for
	// itself that the commit shown is the one being signed (§5).
	shown := human.last()
	if shown == nil {
		t.Fatal("the desktop was never asked")
	}

	if shown.Msg.GetRequester().GetInstanceId() != headless.fingerprint() {
		t.Errorf("the desktop was shown %q as the requester",
			shown.Msg.GetRequester().GetInstanceId())
	}

	git2 := shown.Msg.GetSshsig().GetGitContext()

	if !git2.GetVerifiedAgainstPayload() {
		t.Errorf("the holder did not verify the commit: %s",
			git2.GetVerificationError())
	}

	if git2.GetParsed().GetSubject() != "tighten the socket permissions" {
		t.Errorf("the desktop was shown %q", git2.GetParsed().GetSubject())
	}

	// Both logs hold the decision, and the requester's holds the holder's own
	// signature over it rather than only its account of what happened.
	requireApprovedDecision(t, desktop.audit, false, desktop.fingerprint())
	requireApprovedDecision(t, headless.audit, true, desktop.fingerprint())
}

// TestPublishedDocumentationReachesThePrompt is §6 end to end: the build box
// publishes what it is, and the prompt on the desktop links to it and says how
// current it is.
func TestPublishedDocumentationReachesThePrompt(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)
	signer := buildSigner(t)

	desktop := startPeerInstance(t, "desktop")
	headless := startKeylessInstance(t, "headless")

	// The desktop's viewer, as the tray would build it, served over HTTP the way
	// a webview reaches it.
	session := bridge.NewSession(bridge.Options{
		Name:        "desktop",
		Fingerprint: desktop.fingerprint(),
		Projects:    desktop.app.ProjectBrowser(),
		FetchDiff:   desktop.app.FetchDiff,
		Presenter:   &recordingPresenter{},
	})

	server := httptest.NewServer(session.Handler())
	defer server.Close()

	human := &viewerHandler{
		session: session,
		server:  server,
		answer: &approval.Answer{
			Decision: ladulasv1.Decision_DECISION_APPROVE,
			Reason:   "approved at the desktop",
		},
	}
	defer desktop.app.RegisterApprover(human)()

	pairOverTheCommandLine(t, cli, desktop, headless)

	keys := desktop.app.Vault().KeyRefs()

	runCLI(t, cli, desktop,
		"peers", "allow", "headless", "--request", "--key", "work")
	waitForBorrowedKey(t, headless, keys[0].GetFingerprint())

	// A repository on the build box, published before anything is signed.
	repo := t.TempDir()

	testutil.Run(t, repo, git, "init", "-q", "-b", "main", ".")
	testutil.Run(t, repo, git, "remote", "add", "origin",
		"git@github.com:example/ladulas.git")
	write(t, repo, "README.md",
		"# ladulas-build\n\nThe box that builds it. See "+
			"[the runbook](docs/runbook.md).\n")

	if err := os.MkdirAll(filepath.Join(repo, "docs"), 0o700); err != nil {
		t.Fatalf("create docs: %v", err)
	}

	write(t, repo, "docs/runbook.md",
		"# Runbook\n\nIt builds nightly and signs the tag.\n")
	testutil.Run(t, repo, git, "add", ".")
	testutil.Run(t, repo, git, "commit", "-q", "-m", "first")

	published := runCLI(t, cli, headless, "projects", "publish", repo)

	t.Logf("headless: ladulas projects publish\n%s", published)

	if !strings.Contains(published, "Approvers can browse it") {
		t.Fatalf("the project was not published:\n%s", published)
	}

	// Publishing sends nothing (decision Q). The desktop holds no copy, and
	// what it has is the ability to ask.
	held, err := desktop.app.Projects().List()
	if err != nil {
		t.Fatalf("list what the desktop holds: %v", err)
	}

	if len(held) != 0 {
		t.Fatalf("publishing delivered %d projects to the desktop", len(held))
	}

	// The requester's own listing says what is on offer.
	listing := runCLI(t, cli, headless, "projects", "list")

	t.Logf("headless: ladulas projects list\n%s", listing)

	if !strings.Contains(listing, "Published from here") {
		t.Errorf("the headless box does not list what it publishes:\n%s", listing)
	}

	// Now a commit in that repository, signed with the desktop's key.
	env := testutil.Env("LADULAS_SOCK=" + headless.control)

	config := func(args ...string) {
		t.Helper()

		cmd := exec.Command(git, append([]string{"config"}, args...)...)
		cmd.Dir = repo
		cmd.Env = env

		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git config %v: %v\n%s", args, err, out)
		}
	}

	config("user.name", "Test Author")
	config("user.email", "author@example.test")
	config("gpg.format", "ssh")
	config("gpg.ssh.program", signer)
	config("user.signingkey", "key::"+desktop.publicKey)

	write(t, repo, "socket.go", "package main\n")
	testutil.Run(t, repo, git, "add", ".")

	commit := exec.Command(git, "commit", "-q", "-S", "-m", "harden the socket")
	commit.Dir = repo
	commit.Env = env

	if out, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("the commit was not signed: %v\n%s", err, out)
	}

	// The prompt the desktop's viewer rendered names the project the change
	// belongs to, and nothing of it has been read yet — which is the ordinary
	// state under decision Q and still a way in, because the link is a pull.
	view := human.lastView()
	if view.Project == nil {
		t.Fatal("the prompt did not name a project")
	}

	if view.Project.Known {
		t.Error("the prompt claims to hold documentation nobody has read")
	}

	if view.Project.Fingerprint == "" || view.Project.ProjectID == "" {
		t.Fatalf("the prompt cannot link to the project: %+v", view.Project)
	}

	// So follow the link, the way the viewer does: list the directory the
	// project root holds, and open the runbook the README points at.
	where := url.Values{
		"peer":    {view.Project.Fingerprint},
		"project": {view.Project.ProjectID},
	}

	var root bridge.ProjectListingView

	browserGet(t, server, "/api/v1/projects/directory?"+where.Encode(), &root)

	if !root.Live || root.Name != filepath.Base(repo) {
		t.Fatalf("the directory listing is %+v", root.ProjectView)
	}

	var names []string
	for _, entry := range root.Entries {
		names = append(names, entry.Name)
	}

	if strings.Join(names, ",") != "docs,README.md,socket.go" {
		t.Errorf("the project root listed %v", names)
	}

	var found bridge.ProjectListingView

	browserGet(t, server,
		"/api/v1/projects/search?"+where.Encode()+"&q=runbook", &found)

	if len(found.Entries) != 1 || found.Entries[0].Path != "docs/runbook.md" {
		t.Fatalf("the search found %+v", found.Entries)
	}

	var page bridge.ProjectPageView

	browserGet(t, server,
		"/api/v1/projects/file?"+where.Encode()+"&path=docs/runbook.md", &page)

	if page.Title != "Runbook" || !page.Live {
		t.Fatalf("the runbook came back as %+v", page)
	}

	// And that page is now readable with no signal, which is the whole of what
	// keeping what you read buys (decision Q).
	cached, err := desktop.app.Projects().List()
	if err != nil {
		t.Fatalf("list what the desktop has read: %v", err)
	}

	if len(cached) != 1 || len(cached[0].GetFiles()) != 1 {
		t.Fatalf("the desktop kept %+v", cached)
	}

	if cached[0].GetFiles()[0].GetPath() != "docs/runbook.md" {
		t.Errorf("the desktop kept %q", cached[0].GetFiles()[0].GetPath())
	}
}

// browserGet fetches one of the browsing calls the way the bundle does.
func browserGet(
	t *testing.T, server *httptest.Server, path string, into any,
) {
	t.Helper()

	resp, err := server.Client().Get(server.URL + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get %s: status %d", path, resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

// recordingPresenter is a host that shows nothing: the bridge does the waiting
// and this test reads the rendered view rather than looking at a window.
type recordingPresenter struct{}

func (*recordingPresenter) Present(*bridge.PendingRequest) {}

func (*recordingPresenter) Dismiss(string) {}

// viewerHandler answers through the bridge, so what the test inspects is what
// the viewer would have been sent rather than the request behind it.
type viewerHandler struct {
	session *bridge.Session
	server  *httptest.Server
	answer  *approval.Answer

	view bridge.RequestView
}

// render fetches the request the way the bundle does: an HTTP GET against the
// bridge, decoded as the JSON the viewer draws from.
func (v *viewerHandler) render(id string) (bridge.RequestView, bool) {
	var view bridge.RequestView

	resp, err := v.server.Client().Get(
		v.server.URL + "/api/v1/requests/" + id)
	if err != nil {
		return view, false
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return view, false
	}

	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		return view, false
	}

	return view, true
}

func (v *viewerHandler) ID() string {
	return "desktop viewer"
}

func (v *viewerHandler) Decide(
	ctx context.Context, req *approval.Request,
) (*approval.Answer, error) {
	if req.Msg.GetKind() == ladulasv1.RequestKind_REQUEST_KIND_PAIRING {
		return nil, errNotOurs
	}

	answers := make(chan *approval.Answer, 1)

	go func() {
		answer, err := v.session.Decide(ctx, req)
		if err != nil {
			answers <- nil

			return
		}

		answers <- answer
	}()

	// Read the view the viewer would have fetched, then answer as it would.
	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		if view, ok := v.render(req.Msg.GetRequestId()); ok {
			v.view = view

			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	if err := v.session.Answer(req.Msg.GetRequestId(), v.answer); err != nil {
		return nil, err
	}

	return <-answers, nil
}

func (v *viewerHandler) lastView() bridge.RequestView {
	return v.view
}
