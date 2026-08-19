package approval_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
)

const testCommit = "tree e95bc8444bcd06692c882451e807e45dfe27b5ba\n" +
	"parent 937fa9137d03e1ca64111b86264e78dc907127e7\n" +
	"author A U Thor <author@example.test> 1786209283 +0200\n" +
	"committer A U Thor <author@example.test> 1786209283 +0200\n" +
	"\n" +
	"tighten the socket permissions\n" +
	"\n" +
	"The agent socket was 0644.\n"

// gitSignWithContext builds the request ladulas-sign produces: the raw object,
// the asserted environment, and the digest the SSHSIG payload commits to.
func gitSignWithContext(object []byte, git *ladulasv1.GitContext) *ladulasv1.ApprovalRequest {
	digest, err := sshsig.Hash(sshsig.HashSHA512, object)
	if err != nil {
		panic(err)
	}

	if git == nil {
		git = &ladulasv1.GitContext{}
	}

	git.Object = object

	return &ladulasv1.ApprovalRequest{
		Kind: ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
		Key: &ladulasv1.KeyRef{
			Fingerprint: "SHA256:workkey",
			Label:       "work",
		},
		Requester: &ladulasv1.RequesterInfo{InstanceId: "SHA256:instance", Local: true},
		Operation: &ladulasv1.ApprovalRequest_Sshsig{
			Sshsig: &ladulasv1.SshsigRequest{
				Namespace:     "git",
				HashAlgorithm: sshsig.HashSHA512,
				MessageDigest: digest,
				GitContext:    git,
			},
		},
	}
}

func TestGitPromptShowsTheCommit(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	handler := &stubHandler{id: "gui", answer: approveAnswer()}
	f.engine.Register(handler)

	req := gitSignWithContext([]byte(testCommit), &ladulasv1.GitContext{
		RepositoryPath: "/home/hugo/Projects/ladulas",
		Branch:         "main",
		Diff: &ladulasv1.GitDiff{
			FilesChanged: 2,
			Insertions:   14,
			Deletions:    1,
		},
	})

	if _, err := f.engine.Submit(context.Background(), req); err != nil {
		t.Fatalf("submit: %v", err)
	}

	if handler.promptCount() != 1 {
		t.Fatalf("got %d prompts, want 1", handler.promptCount())
	}

	prompt := handler.prompts[0]

	if prompt.Subject != "tighten the socket permissions" {
		t.Errorf("subject is %q", prompt.Subject)
	}

	text := prompt.Text()

	for _, want := range []string{
		"A U Thor <author@example.test>",
		"/home/hugo/Projects/ladulas",
		"main",
		"2 files changed, 14 insertions, 1 deletion",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the prompt does not mention %q:\n%s", want, text)
		}
	}

	// The repository is asserted and the author is not, and the prompt has to
	// say which is which (§5).
	for _, detail := range prompt.Details {
		switch detail.Label {
		case "Repository", "Branch", "Changes":
			if !detail.Asserted {
				t.Errorf("%s is not labelled as requester-asserted", detail.Label)
			}
		case "Author":
			if detail.Asserted {
				t.Errorf("the author is labelled as asserted even though it was verified")
			}
		}
	}

	if len(prompt.Warnings) != 0 {
		t.Errorf("a verified request carries warnings: %v", prompt.Warnings)
	}
}

// A commit that is not the commit being signed is the compromised-requester
// attack, and it is denied before anyone is asked (§15).
func TestGitContextMismatchIsAHardDenial(t *testing.T) {
	f := newEngine(t, approval.NewPolicy(&ladulasv1.PolicyDocument{
		Rules: []*ladulasv1.Rule{
			{Name: "approve everything", Action: ladulasv1.Action_ACTION_APPROVE},
		},
	}))

	handler := &stubHandler{id: "gui", answer: approveAnswer()}
	f.engine.Register(handler)

	req := gitSignWithContext([]byte(testCommit), nil)

	// The requester swaps the object for a friendlier one after the digest was
	// computed over the real commit.
	req.GetSshsig().GetGitContext().Object = []byte(
		"tree aaaa\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\n" +
			"fix a typo in the README\n")

	resp, err := f.engine.Submit(context.Background(), req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_HARD_RULE {
			t.Errorf("source is %v, want a hard rule", resp.GetSource())
		}
	} else {
		t.Fatal("a request whose context lies about the commit was approved")
	}

	if !strings.Contains(resp.GetReason(), "not the one") {
		t.Errorf("the denial reason is %q", resp.GetReason())
	}

	if handler.promptCount() != 0 {
		t.Error("a mismatched request was still shown to an approver")
	}

	git := req.GetSshsig().GetGitContext()

	if git.GetVerifiedAgainstPayload() {
		t.Error("the context was marked as verified")
	}

	if git.GetVerificationError() == "" {
		t.Error("the context carries no explanation of the mismatch")
	}
}

// A payload that is not a git object at all must not be presented as one
// either, even when the digest matches.
func TestGitContextThatIsNotAGitObject(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	handler := &stubHandler{id: "gui", answer: approveAnswer()}
	f.engine.Register(handler)

	resp, err := f.engine.Submit(context.Background(),
		gitSignWithContext([]byte("this is not a commit"), nil))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Fatal("a payload that does not parse as a git object was approved")
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_HARD_RULE {
		t.Errorf("source is %v, want a hard rule", resp.GetSource())
	}

	if handler.promptCount() != 0 {
		t.Error("the request was still shown to an approver")
	}
}

// The requester's own parse is display metadata and gets thrown away; what the
// prompt shows is parsed from the signed bytes.
func TestGitContextParseIsRecomputed(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	handler := &stubHandler{id: "gui", answer: approveAnswer()}
	f.engine.Register(handler)

	req := gitSignWithContext([]byte(testCommit), &ladulasv1.GitContext{
		ObjectType: "tag",
		Parsed: &ladulasv1.GitObject{
			Type:    "tag",
			Subject: "a completely different subject",
			Author: &ladulasv1.GitIdentity{
				Name: "Somebody Else", Email: "else@example.test",
			},
		},
	})

	if _, err := f.engine.Submit(context.Background(), req); err != nil {
		t.Fatalf("submit: %v", err)
	}

	git := req.GetSshsig().GetGitContext()

	if git.GetParsed().GetSubject() != "tighten the socket permissions" {
		t.Errorf("subject is %q, want the one from the payload",
			git.GetParsed().GetSubject())
	}

	if git.GetObjectType() != "commit" {
		t.Errorf("object type is %q, want commit", git.GetObjectType())
	}

	if !git.GetVerifiedAgainstPayload() {
		t.Error("the context was not marked as verified")
	}
}

// The agent path has no object, only a digest. That is a poorer prompt, not a
// denial, and it must keep working (§5 fallback).
func TestPlainAgentGitRequestStillPrompts(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	handler := &stubHandler{id: "gui", answer: approveAnswer()}
	f.engine.Register(handler)

	req := &ladulasv1.ApprovalRequest{
		Kind: ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
		Key:  &ladulasv1.KeyRef{Fingerprint: "SHA256:workkey", Label: "work"},
		Operation: &ladulasv1.ApprovalRequest_Sshsig{
			Sshsig: &ladulasv1.SshsigRequest{
				Namespace:     "git",
				HashAlgorithm: "sha512",
				MessageDigest: []byte("0123456789abcdef"),
			},
		},
	}

	resp, err := f.engine.Submit(context.Background(), req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("decision %v: %s", resp.GetDecision(), resp.GetReason())
	}

	if handler.promptCount() != 1 {
		t.Fatalf("got %d prompts, want 1", handler.promptCount())
	}

	if !strings.Contains(handler.prompts[0].Text(), "Digest") {
		t.Errorf("the digest-only prompt does not show a digest:\n%s",
			handler.prompts[0].Text())
	}
}

func TestGitTagPromptTitle(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	handler := &stubHandler{id: "gui", answer: approveAnswer()}
	f.engine.Register(handler)

	tag := "object 937fa9137d03e1ca64111b86264e78dc907127e7\n" +
		"type commit\ntag v1.0\n" +
		"tagger A U Thor <author@example.test> 1786209283 +0200\n\n" +
		"the first release\n"

	if _, err := f.engine.Submit(context.Background(),
		gitSignWithContext([]byte(tag), nil)); err != nil {
		t.Fatalf("submit: %v", err)
	}

	prompt := handler.prompts[0]

	if prompt.Title != "Git tag signature" {
		t.Errorf("title is %q", prompt.Title)
	}

	if !strings.Contains(prompt.Text(), "v1.0") {
		t.Errorf("the prompt does not name the tag:\n%s", prompt.Text())
	}
}

func TestDiffSummary(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		diff *ladulasv1.GitDiff
		want string
	}{
		"nothing": {
			diff: &ladulasv1.GitDiff{},
			want: "no files changed",
		},
		"one of each": {
			diff: &ladulasv1.GitDiff{
				FilesChanged: 1, Insertions: 1, Deletions: 1,
			},
			want: "1 file changed, 1 insertion, 1 deletion",
		},
		"truncated": {
			diff: &ladulasv1.GitDiff{
				FilesChanged: 9, Insertions: 900, Deletions: 0, Truncated: true,
			},
			want: "9 files changed, 900 insertions, 0 deletions (truncated)",
		},
		"failed": {
			diff: &ladulasv1.GitDiff{Error: "git is not on the path"},
			want: "not available: git is not on the path",
		},
	} {
		if got := approval.DiffSummary(tc.diff); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}
