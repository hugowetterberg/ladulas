package bridge_test

import (
	"context"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/bridge"
	"github.com/hugowetterberg/ladulas/pkg/gitctx"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
)

// demoAddrEnv turns TestViewerDemo into a server rather than a test.
const demoAddrEnv = "LADULAS_VIEWER_DEMO"

// TestViewerDemo serves the bridge with a fixture request so the viewer can be
// looked at, which is the only way to review a change to it:
//
//	LADULAS_VIEWER_DEMO=127.0.0.1:8791 go test ./pkg/bridge/ \
//	    -run TestViewerDemo -v -timeout 0
//
// then open http://127.0.0.1:8791/?request=demo-1 for the prompt popup and
// http://127.0.0.1:8791/ for the desktop shell — the sidebar and its screens,
// which read the same instance JSON the fixtures below serve (decision AA).
//
// It is a test rather than a command under cmd/ so that it is compiled by
// `go test ./...` and cannot quietly rot while nobody is looking at the viewer.
func TestViewerDemo(t *testing.T) {
	addr := os.Getenv(demoAddrEnv)
	if addr == "" {
		t.Skipf("set %s to an address to serve the viewer", demoAddrEnv)
	}

	session := bridge.NewSession(bridge.Options{
		Name:        "workstation",
		Fingerprint: "SHA256:2Uf4gZ0kQ9nJmO1pXcVbN7yLtRwEaSdFgHjKlZxCvBn",
		Locations: []bridge.Location{
			{Label: "Agent socket", Path: "/run/user/1000/ladulas/agent.sock"},
			{Label: "Signing socket", Path: "/run/user/1000/ladulas/control.sock"},
			{Label: "Policy", Path: "/home/hugo/.config/ladulas/policy.json"},
			{Label: "Audit log", Path: "/home/hugo/.local/share/ladulas/audit.jsonl"},
		},
		Keys: func() []*ladulasv1.KeyInfo {
			return []*ladulasv1.KeyInfo{{
				Label:       "work",
				Algorithm:   "ssh-ed25519",
				Fingerprint: "SHA256:H9ysZRf1QUuqvtaOZHn2C9rgtUhPDq/BbDSi4SQgGGM",
				Comment:     "hugo@workstation",
			}}
		},
		Grants: func() ([]*ladulasv1.Grant, error) {
			return nil, nil
		},
		Presenter: &presenter{},
	})

	go func() {
		_, _ = session.Decide(context.Background(), demoRequest(t))
	}()

	server := &http.Server{
		Addr:              addr,
		Handler:           session.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	t.Logf("serving the viewer on http://%s/?request=demo-1", addr)

	if err := server.ListenAndServe(); err != nil {
		log.Print(err)
	}
}

func demoRequest(t *testing.T) *approval.Request {
	t.Helper()

	object := "tree e95bc8444bcd06692c882451e807e45dfe27b5ba\n" +
		"parent 937fa9137d03e1ca64111b86264e78dc907127e7\n" +
		"author Hugo Wetterberg <hugo@example.test> 1786209283 +0200\n" +
		"committer Hugo Wetterberg <hugo@example.test> 1786209283 +0200\n" +
		"\n" +
		"tighten the agent socket permissions\n" +
		"\n" +
		"The socket was created 0644, which meant every process on the box\n" +
		"could open it and ask for a signature. It is 0600 now, and the\n" +
		"directory it lives in is 0700.\n"

	digest, err := sshsig.Hash(sshsig.HashSHA512, []byte(object))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	msg := &ladulasv1.ApprovalRequest{
		RequestId: "demo-1",
		Kind:      ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
		Key: &ladulasv1.KeyRef{
			Label:       "work",
			Algorithm:   "ssh-ed25519",
			Fingerprint: "SHA256:H9ysZRf1QUuqvtaOZHn2C9rgtUhPDq/BbDSi4SQgGGM",
			Comment:     "hugo@workstation",
		},
		Requester: &ladulasv1.RequesterInfo{
			Name:  "workstation",
			Local: true,
			Process: &ladulasv1.ClientProcess{
				Pid: 4812, Executable: "/usr/local/bin/ladulas-sign",
			},
		},
		Operation: &ladulasv1.ApprovalRequest_Sshsig{
			Sshsig: &ladulasv1.SshsigRequest{
				Namespace:     "git",
				HashAlgorithm: sshsig.HashSHA512,
				MessageDigest: digest,
				GitContext: &ladulasv1.GitContext{
					RepositoryPath: "/home/hugo/Projects/ladulas",
					OriginUrl:      "git@github.com:hugowetterberg/ladulas.git",
					Branch:         "main",
					Operation:      "commit",
					Object:         []byte(object),
					Diff:           demoDiff(),
				},
			},
		},
	}

	if problem := gitctx.VerifyRequest(msg); problem != "" {
		t.Fatalf("the demo fixture does not verify: %s", problem)
	}

	return &approval.Request{
		Msg:       msg,
		Prompt:    approval.RenderPrompt(msg),
		GrantTTLs: []time.Duration{15 * time.Minute, time.Hour, 3 * time.Hour},
	}
}

func demoDiff() *ladulasv1.GitDiff {
	const (
		context = ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_CONTEXT
		added   = ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_ADDED
		removed = ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_REMOVED
	)

	line := func(kind ladulasv1.GitDiffLineKind, text string) *ladulasv1.GitDiffLine {
		return &ladulasv1.GitDiffLine{Kind: kind, Text: text}
	}

	return &ladulasv1.GitDiff{
		FilesChanged: 2,
		Insertions:   9,
		Deletions:    3,
		Range:        "937fa9137d..e95bc8444b",
		Files: []*ladulasv1.GitDiffFile{
			{
				OldPath:    "pkg/agent/server.go",
				NewPath:    "pkg/agent/server.go",
				Status:     "modified",
				Insertions: 6,
				Deletions:  3,
				Hunks: []*ladulasv1.GitDiffHunk{{
					Header: "@@ -145,9 +145,12 @@ func (s *Server) Listen() error {",
					Lines: []*ladulasv1.GitDiffLine{
						line(context, "\tdir := filepath.Dir(s.socketPath)"),
						line(context, ""),
						line(removed, "\tif err := os.MkdirAll(dir, 0o755); err != nil {"),
						line(added, "\tif err := os.MkdirAll(dir, 0o700); err != nil {"),
						line(context, "\t\treturn fmt.Errorf(\"create socket directory: %w\", err)"),
						line(context, "\t}"),
						line(context, ""),
						line(removed, "\tlistener, err := net.Listen(\"unix\", s.socketPath)"),
						line(removed, "\tif err != nil {"),
						line(added, "\tlistener, err := net.Listen(\"unix\", s.socketPath)"),
						line(added, "\tif err != nil {"),
						line(added, "\t\treturn fmt.Errorf(\"listen on %s: %w\", s.socketPath, err)"),
						line(added, "\t}"),
						line(added, ""),
						line(added, "\tif err := os.Chmod(s.socketPath, 0o600); err != nil {"),
						line(context, "\t\t_ = listener.Close()"),
					},
				}},
			},
			{
				NewPath:    "pkg/agent/permissions_test.go",
				Status:     "added",
				Insertions: 3,
				Hunks: []*ladulasv1.GitDiffHunk{{
					Header: "@@ -0,0 +1,3 @@",
					Lines: []*ladulasv1.GitDiffLine{
						line(added, "package agent"),
						line(added, ""),
						line(added, "// The socket has to be unreadable by anyone else."),
					},
				}},
			},
		},
	}
}
