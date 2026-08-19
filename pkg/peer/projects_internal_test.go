package peer

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// plainCipher is the sealing a peer test does not care about. What the store
// does with the bytes is the project package's business and is tested there;
// what these tests are about is which peer may send and read what.
type plainCipher struct{}

func (plainCipher) Seal(plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (plainCipher) Unseal(ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

func writeDoc(t *testing.T, dir, name, body string) {
	t.Helper()

	path := filepath.Join(dir, filepath.FromSlash(name))

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(path), err)
	}

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// publish runs the control verb the command line drives.
func publish(t *testing.T, inst *instance, dir, name string) *ladulasv1.Publication {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := inst.node.PublishProject(ctx, connect.NewRequest(
		&ladulasv1.PublishProjectRequest{Path: dir, Name: name}))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	return resp.Msg.GetPublication()
}

// TestPublishRefusesRelativePath keeps the daemon from resolving a caller's
// path against its own working directory, which is a systemd unit's and not
// the shell's. The caller resolves; the daemon refuses what it cannot.
func TestPublishRefusesRelativePath(t *testing.T) {
	inst := newInstance(t, "desktop")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err := inst.node.PublishProject(ctx, connect.NewRequest(
		&ladulasv1.PublishProjectRequest{Path: "../notes"}))
	if err == nil {
		t.Fatal("publishing a relative path should have been refused")
	}

	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("got %s, wanted invalid_argument: %v", connect.CodeOf(err), err)
	}

	if !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("the error should say what is wrong with the path: %v", err)
	}
}

// TestPublishingSendsNothing is decision Q in one test: marking a project
// published is a state, and the approver learns of it by asking.
func TestPublishingSendsNothing(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	dir := t.TempDir()
	writeDoc(t, dir, "README.md", "# Ladulås\n")
	writeDoc(t, dir, "docs/deployment.md", "# Deploying\n")

	waitForLink(t, headless, desktop.identity.Fingerprint())

	publication := publish(t, headless, dir, "ladulas")

	if publication.GetName() != "ladulas" {
		t.Errorf("the publication is called %q", publication.GetName())
	}

	// Nothing arrived. Under the old model the approver would be holding a
	// snapshot by now; under this one it holds what it has read, which is
	// nothing at all.
	held, err := desktop.projects.List()
	if err != nil {
		t.Fatalf("list what the desktop holds: %v", err)
	}

	if len(held) != 0 {
		t.Fatalf("publishing delivered %d projects", len(held))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// And the approver finds it by asking.
	listed := listProjects(ctx, t, desktop, headless.identity.Fingerprint())

	if len(listed) != 1 || listed[0].GetName() != "ladulas" {
		t.Fatalf("the approver was told about %+v", listed)
	}
}

// TestAnApproverBrowsesWhatItAsksFor walks the three calls a browser makes.
func TestAnApproverBrowsesWhatItAsksFor(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	dir := t.TempDir()
	writeDoc(t, dir, "README.md", "# Ladulås\n")
	writeDoc(t, dir, "docs/deployment.md", "# Deploying\n")
	writeDoc(t, dir, "docs/architecture.md", "# Shape\n")
	writeDoc(t, dir, "main.go", "package main\n")

	waitForLink(t, headless, desktop.identity.Fingerprint())

	publication := publish(t, headless, dir, "ladulas")
	id := publication.GetProjectId()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	record, ok := desktop.store.Peer(headless.identity.Fingerprint())
	if !ok {
		t.Fatal("the desktop has no record of the headless box")
	}

	var (
		listing *ladulasv1.ListDirectoryResponse
		found   *ladulasv1.SearchProjectFilesResponse
		file    *ladulasv1.FetchProjectFileResponse
	)

	err := desktop.node.call(ctx, record, func(
		ctx context.Context, client *http.Client, baseURL string,
	) error {
		projects := ladulasv1connect.NewProjectServiceClient(client, baseURL)

		dirs, err := projects.ListDirectory(ctx, connect.NewRequest(
			&ladulasv1.ListDirectoryRequest{Project: id}))
		if err != nil {
			return err
		}

		listing = dirs.Msg

		hits, err := projects.SearchProjectFiles(ctx, connect.NewRequest(
			&ladulasv1.SearchProjectFilesRequest{Project: id, Query: "deploy"}))
		if err != nil {
			return err
		}

		found = hits.Msg

		body, err := projects.FetchProjectFile(ctx, connect.NewRequest(
			&ladulasv1.FetchProjectFileRequest{
				ProjectId: id, Path: "docs/deployment.md",
			}))
		if err != nil {
			return err
		}

		file = body.Msg

		return nil
	})
	if err != nil {
		t.Fatalf("browse: %v", err)
	}

	// The root: the directory first, then the files — including the one this
	// instance will not hand over, because a listing that hid it would be
	// lying about the project.
	var names []string
	for _, entry := range listing.GetEntries() {
		names = append(names, entry.GetName())
	}

	if strings.Join(names, ",") != "docs,README.md,main.go" {
		t.Errorf("the root listed %v", names)
	}

	if listing.GetTotal() != 3 {
		t.Errorf("the root says it holds %d entries", listing.GetTotal())
	}

	if len(found.GetEntries()) != 1 ||
		found.GetEntries()[0].GetPath() != "docs/deployment.md" {
		t.Errorf("the search found %+v", found.GetEntries())
	}

	if !strings.Contains(string(file.GetContent()), "Deploying") {
		t.Errorf("the file came back as %q", file.GetContent())
	}
}

// A file the publisher does not offer is not served, however directly it is
// asked for: the listing says so, and the fetch says so again.
func TestBrowsingServesOnlyWhatIsOffered(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	dir := t.TempDir()
	writeDoc(t, dir, "README.md", "# Ladulås\n")
	writeDoc(t, dir, "main.go", "package main\n")
	writeDoc(t, dir, ".env", "SECRET=hunter2\n")

	waitForLink(t, headless, desktop.identity.Fingerprint())

	id := publish(t, headless, dir, "ladulas").GetProjectId()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	record, ok := desktop.store.Peer(headless.identity.Fingerprint())
	if !ok {
		t.Fatal("the desktop has no record of the headless box")
	}

	for _, path := range []string{
		"main.go", ".env", "../../etc/passwd", "/etc/passwd", "docs/../..",
	} {
		err := desktop.node.call(ctx, record, func(
			ctx context.Context, client *http.Client, baseURL string,
		) error {
			projects := ladulasv1connect.NewProjectServiceClient(client, baseURL)

			_, err := projects.FetchProjectFile(ctx, connect.NewRequest(
				&ladulasv1.FetchProjectFileRequest{ProjectId: id, Path: path}))

			return err
		})
		if err == nil {
			t.Errorf("%q was served", path)
		}
	}
}

// listProjects asks a peer what it publishes, the way a browser opening on a
// peer does.
func listProjects(
	ctx context.Context, t *testing.T, approver *instance, fingerprint string,
) []*ladulasv1.Publication {
	t.Helper()

	record, ok := approver.store.Peer(fingerprint)
	if !ok {
		t.Fatal("no record of the peer")
	}

	var out []*ladulasv1.Publication

	err := approver.node.call(ctx, record, func(
		ctx context.Context, client *http.Client, baseURL string,
	) error {
		projects := ladulasv1connect.NewProjectServiceClient(client, baseURL)

		resp, err := projects.ListProjects(ctx,
			connect.NewRequest(&ladulasv1.ListProjectsRequest{}))
		if err != nil {
			return err
		}

		out = resp.Msg.GetProjects()

		return nil
	})
	if err != nil {
		t.Fatalf("list projects: %v", err)
	}

	return out
}

func TestOnlyAnApproverMayBrowse(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	dir := t.TempDir()
	writeDoc(t, dir, "README.md", "# Ladulås\n")

	waitForLink(t, headless, desktop.identity.Fingerprint())
	publish(t, headless, dir, "ladulas")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// The desktop approves for the headless box, so it may list and fetch.
	record, ok := desktop.store.Peer(headless.identity.Fingerprint())
	if !ok {
		t.Fatal("the desktop has no record of the headless box")
	}

	if err := browse(ctx, desktop, record.GetFingerprint()); err != nil {
		t.Fatalf("an approver could not browse: %v", err)
	}

	// Take the approval direction away on the requester's side, and browsing
	// stops: the requester enforces the half it declared.
	if _, err := headless.store.SetPeerDirections(
		desktop.identity.Fingerprint(), directionsAsking()); err != nil {
		t.Fatalf("change directions: %v", err)
	}

	if err := browse(ctx, desktop, record.GetFingerprint()); err == nil {
		t.Fatal("a peer that no longer approves for us still read our documentation")
	}
}

// browse asks a peer to list what it publishes, the way the viewer's refresh
// does.
func browse(ctx context.Context, approver *instance, fingerprint string) error {
	record, ok := approver.store.Peer(fingerprint)
	if !ok {
		return errNoSuchPublication
	}

	return approver.node.call(ctx, record, func(
		ctx context.Context, client *http.Client, baseURL string,
	) error {
		projects := ladulasv1connect.NewProjectServiceClient(client, baseURL)

		_, err := projects.ListProjects(ctx,
			connect.NewRequest(&ladulasv1.ListProjectsRequest{}))

		return err
	})
}

// Withdrawing stops the browsing. There is no copy to take back (decision Q):
// an approver that asks next is told there is no such project.
func TestUnpublishingStopsTheBrowsing(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	dir := t.TempDir()
	writeDoc(t, dir, "README.md", "# Ladulås\n")

	waitForLink(t, headless, desktop.identity.Fingerprint())

	id := publish(t, headless, dir, "ladulas").GetProjectId()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if _, err := headless.node.UnpublishProject(ctx, connect.NewRequest(
		&ladulasv1.UnpublishProjectRequest{Project: id},
	)); err != nil {
		t.Fatalf("unpublish: %v", err)
	}

	if listed := listProjects(
		ctx, t, desktop, headless.identity.Fingerprint(),
	); len(listed) != 0 {
		t.Errorf("a withdrawn project is still published: %+v", listed)
	}

	record, ok := desktop.store.Peer(headless.identity.Fingerprint())
	if !ok {
		t.Fatal("the desktop has no record of the headless box")
	}

	err := desktop.node.call(ctx, record, func(
		ctx context.Context, client *http.Client, baseURL string,
	) error {
		projects := ladulasv1connect.NewProjectServiceClient(client, baseURL)

		_, err := projects.ListDirectory(ctx, connect.NewRequest(
			&ladulasv1.ListDirectoryRequest{Project: id}))

		return err
	})
	if err == nil {
		t.Error("a withdrawn project could still be browsed")
	}
}

// directionsAsking is what a peer that only asks for approvals is granted.
func directionsAsking() trust.Directions {
	return trust.Directions{MayRequest: true}
}

// TestAnApproverKeepsWhatItOpens is the approver's half over the real channel:
// the browser dials the publisher, reads a page, and still has that page when
// the publisher is not there (decision Q).
func TestAnApproverKeepsWhatItOpens(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	dir := t.TempDir()
	writeDoc(t, dir, "README.md", "# Ladulås\n")
	writeDoc(t, dir, "docs/deployment.md", "# Deploying\n")

	waitForLink(t, headless, desktop.identity.Fingerprint())

	id := publish(t, headless, dir, "ladulas").GetProjectId()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	browser := project.NewBrowser(desktop.projects, desktop.node)

	listed, err := browser.List(ctx, "")
	if err != nil {
		t.Fatalf("list projects: %v", err)
	}

	if len(listed) != 1 || !listed[0].Live || listed[0].Kept != 0 {
		t.Fatalf("the browser listed %+v", listed)
	}

	page, err := browser.File(
		ctx, headless.identity.Fingerprint(), id, "docs/deployment.md")
	if err != nil {
		t.Fatalf("read a page: %v", err)
	}

	if !strings.Contains(string(page.Content), "Deploying") {
		t.Errorf("the page came back as %q", page.Content)
	}

	// Take the publisher away. What was read is still readable, and the browser
	// says where it came from rather than pretending it is current.
	if err := headless.node.Close(); err != nil {
		t.Fatalf("close the publisher: %v", err)
	}

	kept, err := browser.File(
		ctx, headless.identity.Fingerprint(), id, "docs/deployment.md")
	if err != nil {
		t.Fatalf("read the kept page: %v", err)
	}

	if kept.Live {
		t.Error("a page read from a machine that is gone says it is live")
	}

	if !strings.Contains(string(kept.Content), "Deploying") {
		t.Errorf("the kept page came back as %q", kept.Content)
	}
}

// TestAskingForASignaturePublishesTheProject is the default decision Q gives
// publishing: the moment an approver most wants a project's documentation is
// while it is being asked to sign something in it.
func TestAskingForASignaturePublishesTheProject(t *testing.T) {
	desktop := newInstance(t, "desktop")
	headless := newInstance(t, "headless")

	pair(t, desktop, headless)
	headless.drop()

	desktop.human.set(approveAnswer("approved at the desktop"), nil)

	dir := t.TempDir()
	writeDoc(t, dir, "README.md", "# Ladulås\n")

	waitForLink(t, headless, desktop.identity.Fingerprint())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	msg := gitRequest()
	msg.GetSshsig().GitContext = &ladulasv1.GitContext{
		RepositoryPath: dir,
		ProjectId:      project.ID("", dir),
	}

	if _, err := headless.engine.Submit(ctx, msg); err != nil {
		t.Fatalf("submit: %v", err)
	}

	listed := listProjects(ctx, t, desktop, headless.identity.Fingerprint())

	if len(listed) != 1 || listed[0].GetPath() != dir {
		t.Fatalf("asking for a signature published %+v", listed)
	}

	// And a machine that would rather not name its repositories can say so.
	if _, err := headless.node.SetAutoPublish(ctx, connect.NewRequest(
		&ladulasv1.SetAutoPublishRequest{Enabled: false},
	)); err != nil {
		t.Fatalf("switch it off: %v", err)
	}

	other := t.TempDir()
	writeDoc(t, other, "README.md", "# private\n")

	msg = gitRequest()
	msg.GetSshsig().GitContext = &ladulasv1.GitContext{
		RepositoryPath: other,
		ProjectId:      project.ID("", other),
	}

	if _, err := headless.engine.Submit(ctx, msg); err != nil {
		t.Fatalf("submit: %v", err)
	}

	if listed := listProjects(
		ctx, t, desktop, headless.identity.Fingerprint(),
	); len(listed) != 1 {
		t.Errorf("a project was published with the default off: %+v", listed)
	}
}
