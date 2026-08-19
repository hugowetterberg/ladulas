package gitctx_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hugowetterberg/ladulas/internal/testutil"
	"github.com/hugowetterberg/ladulas/pkg/gitctx"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
)

func TestParseCommitObject(t *testing.T) {
	t.Parallel()

	payload := []byte(
		"tree e95bc8444bcd06692c882451e807e45dfe27b5ba\n" +
			"parent 937fa9137d03e1ca64111b86264e78dc907127e7\n" +
			"parent aaaa9137d03e1ca64111b86264e78dc907127e70\n" +
			"author A U Thor <author@example.test> 1786209283 +0200\n" +
			"committer C O Mitter <committer@example.test> 1786209290 -0500\n" +
			"encoding ISO-8859-1\n" +
			"\n" +
			"the subject line\n" +
			"\n" +
			"and a body\n")

	object, err := gitctx.ParseObject(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if object.GetType() != gitctx.TypeCommit {
		t.Errorf("type is %q, want commit", object.GetType())
	}

	if object.GetTree() != "e95bc8444bcd06692c882451e807e45dfe27b5ba" {
		t.Errorf("tree is %q", object.GetTree())
	}

	if got := len(object.GetParents()); got != 2 {
		t.Errorf("got %d parents, want 2", got)
	}

	if object.GetSubject() != "the subject line" {
		t.Errorf("subject is %q", object.GetSubject())
	}

	if object.GetMessage() != "the subject line\n\nand a body\n" {
		t.Errorf("message is %q", object.GetMessage())
	}

	author := object.GetAuthor()

	if author.GetName() != "A U Thor" || author.GetEmail() != "author@example.test" {
		t.Errorf("author is %+v", author)
	}

	if got := author.GetTime().AsTime().Unix(); got != 1786209283 {
		t.Errorf("author time is %d", got)
	}

	if author.GetTimezone() != "+0200" {
		t.Errorf("author timezone is %q", author.GetTimezone())
	}

	if object.GetCommitter().GetTimezone() != "-0500" {
		t.Errorf("committer timezone is %q", object.GetCommitter().GetTimezone())
	}

	extra := object.GetExtraHeaders()

	if len(extra) != 1 || extra[0].GetName() != "encoding" {
		t.Errorf("extra headers are %+v, want the encoding header kept", extra)
	}
}

func TestParseTagObject(t *testing.T) {
	t.Parallel()

	payload := []byte(
		"object 937fa9137d03e1ca64111b86264e78dc907127e7\n" +
			"type commit\n" +
			"tag v1.0\n" +
			"tagger A U Thor <author@example.test> 1786209283 +0200\n" +
			"\n" +
			"the release\n")

	object, err := gitctx.ParseObject(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if object.GetType() != gitctx.TypeTag {
		t.Errorf("type is %q, want tag", object.GetType())
	}

	if object.GetTag() != "v1.0" {
		t.Errorf("tag is %q", object.GetTag())
	}

	if object.GetTaggedType() != "commit" {
		t.Errorf("tagged type is %q", object.GetTaggedType())
	}

	if object.GetTagger().GetName() != "A U Thor" {
		t.Errorf("tagger is %+v", object.GetTagger())
	}
}

func TestParseObjectContinuationLines(t *testing.T) {
	t.Parallel()

	// mergetag is the header that really does arrive folded, and dropping it
	// silently would mean an approver never sees that a merge carries a signed
	// tag it did not check.
	payload := []byte(
		"tree e95bc8444bcd06692c882451e807e45dfe27b5ba\n" +
			"author A U Thor <author@example.test> 1786209283 +0200\n" +
			"committer A U Thor <author@example.test> 1786209283 +0200\n" +
			"mergetag object 1234\n" +
			" type commit\n" +
			" tag v1.0\n" +
			"\n" +
			"merge\n")

	object, err := gitctx.ParseObject(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	extra := object.GetExtraHeaders()
	if len(extra) != 1 {
		t.Fatalf("got %d extra headers, want 1: %+v", len(extra), extra)
	}

	want := "object 1234\ntype commit\ntag v1.0"
	if extra[0].GetValue() != want {
		t.Errorf("mergetag value is %q, want %q", extra[0].GetValue(), want)
	}
}

func TestParseObjectRejectsRubbish(t *testing.T) {
	t.Parallel()

	for name, payload := range map[string]string{
		"empty":         "",
		"no blank line": "tree abc\nauthor A <a@b> 1 +0000\n",
		"no headers":    "\n\njust a message\n",
		"neither kind":  "greeting hello\n\nbody\n",
		"bad timestamp": "tree abc\nauthor A <a@b> notanumber +0000\n\nx\n",
		"no email":      "tree abc\nauthor A U Thor 1 +0000\n\nx\n",
	} {
		if _, err := gitctx.ParseObject([]byte(payload)); err == nil {
			t.Errorf("%s: parsed without complaint", name)
		} else if !errors.Is(err, gitctx.ErrNotAGitObject) {
			t.Errorf("%s: error is %v, want ErrNotAGitObject", name, err)
		}
	}
}

func TestParseIdentityWithBracketsInTheName(t *testing.T) {
	t.Parallel()

	id, err := gitctx.ParseIdentity("A <not an email> Thor <real@example.test> 100 +0000")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if id.GetEmail() != "real@example.test" {
		t.Errorf("email is %q, want the last bracketed one", id.GetEmail())
	}

	if id.GetName() != "A <not an email> Thor" {
		t.Errorf("name is %q", id.GetName())
	}
}

func TestVerifyAgainstPayload(t *testing.T) {
	t.Parallel()

	payload := []byte(
		"tree e95bc8444bcd06692c882451e807e45dfe27b5ba\n" +
			"author A U Thor <author@example.test> 1786209283 +0200\n" +
			"committer A U Thor <author@example.test> 1786209283 +0200\n" +
			"\n" +
			"the real commit\n")

	digest, err := sshsig.Hash(sshsig.HashSHA512, payload)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	git := &ladulasv1.GitContext{
		Object: payload,
		// A lying requester: a parse of something else entirely, which Verify
		// must throw away and replace.
		Parsed: &ladulasv1.GitObject{Subject: "something harmless"},
	}

	if err := gitctx.Verify(git, sshsig.HashSHA512, digest); err != nil {
		t.Fatalf("verify: %v", err)
	}

	if !git.GetVerifiedAgainstPayload() {
		t.Error("the context was not marked as verified")
	}

	if got := git.GetParsed().GetSubject(); got != "the real commit" {
		t.Errorf("subject is %q, want the one from the payload", got)
	}
}

func TestVerifyCatchesAMismatch(t *testing.T) {
	t.Parallel()

	shown := []byte(
		"tree aaaa\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\n" +
			"a tidy little documentation fix\n")

	signed := []byte(
		"tree bbbb\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\n" +
			"add a backdoor\n")

	digest, err := sshsig.Hash(sshsig.HashSHA512, signed)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	git := &ladulasv1.GitContext{Object: shown}

	err = gitctx.Verify(git, sshsig.HashSHA512, digest)
	if !errors.Is(err, gitctx.ErrContextMismatch) {
		t.Fatalf("error is %v, want ErrContextMismatch", err)
	}

	if git.GetVerifiedAgainstPayload() {
		t.Error("a mismatched context was marked as verified")
	}

	if git.GetVerificationError() == "" {
		t.Error("a mismatched context carries no explanation")
	}
}

func TestVerifyRequestOnARequestWithNoContext(t *testing.T) {
	t.Parallel()

	// A plain agent request has a digest and nothing else. That is not a
	// mismatch, it is just a poorer prompt.
	req := &ladulasv1.ApprovalRequest{
		Kind: ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
		Operation: &ladulasv1.ApprovalRequest_Sshsig{
			Sshsig: &ladulasv1.SshsigRequest{
				Namespace:     "git",
				HashAlgorithm: "sha512",
				MessageDigest: []byte("digest"),
			},
		},
	}

	if problem := gitctx.VerifyRequest(req); problem != "" {
		t.Errorf("a contextless request reported %q", problem)
	}
}

func TestDiffTruncation(t *testing.T) {
	t.Parallel()

	var b strings.Builder

	b.WriteString("diff --git a/big.txt b/big.txt\n")
	b.WriteString("--- a/big.txt\n+++ b/big.txt\n")
	b.WriteString("@@ -0,0 +1,100 @@\n")

	for i := range 100 {
		b.WriteString("+line ")
		b.WriteString(strings.Repeat("x", i%5))
		b.WriteString("\n")
	}

	diff := gitctx.ParseDiff([]byte(b.String()), gitctx.Limits{
		LinesPerFile: 10,
		TotalLines:   10,
	})

	if len(diff.GetFiles()) != 1 {
		t.Fatalf("got %d files, want 1", len(diff.GetFiles()))
	}

	file := diff.GetFiles()[0]

	kept := 0
	for _, hunk := range file.GetHunks() {
		kept += len(hunk.GetLines())
	}

	if kept != 10 {
		t.Errorf("kept %d lines, want the cap of 10", kept)
	}

	if !file.GetTruncated() {
		t.Error("the file was not marked as truncated")
	}

	if !diff.GetTruncated() {
		t.Error("the diff was not marked as truncated")
	}

	if !strings.Contains(diff.GetTruncationNote(), "90 lines") {
		t.Errorf("truncation note is %q", diff.GetTruncationNote())
	}
}

func TestDiffFileCapAndLongLines(t *testing.T) {
	t.Parallel()

	var b strings.Builder

	for i := range 5 {
		name := string(rune('a'+i)) + ".txt"
		b.WriteString("diff --git a/" + name + " b/" + name + "\n")
		b.WriteString("new file mode 100644\n")
		b.WriteString("@@ -0,0 +1 @@\n")
		b.WriteString("+" + strings.Repeat("é", 50) + "\n")
	}

	diff := gitctx.ParseDiff([]byte(b.String()), gitctx.Limits{
		Files:      2,
		LineLength: 11,
	})

	if len(diff.GetFiles()) != 2 {
		t.Fatalf("got %d files, want the cap of 2", len(diff.GetFiles()))
	}

	if !strings.Contains(diff.GetTruncationNote(), "3 more files") {
		t.Errorf("truncation note is %q", diff.GetTruncationNote())
	}

	text := diff.GetFiles()[0].GetHunks()[0].GetLines()[0].GetText()

	if !strings.HasSuffix(text, "…") {
		t.Errorf("a long line was not cut: %q", text)
	}

	// Cutting at a byte offset inside a two-byte rune would leave a broken
	// character behind.
	if strings.ContainsRune(text, '�') {
		t.Errorf("a line was cut in the middle of a character: %q", text)
	}

	if diff.GetFiles()[0].GetStatus() != "added" {
		t.Errorf("status is %q, want added", diff.GetFiles()[0].GetStatus())
	}
}

// TestCollectFromARealRepository drives the collector the way ladulas-sign
// does: inside a repository, with the payload git would have handed over.
func TestCollectFromARealRepository(t *testing.T) {
	t.Parallel()

	git := testutil.RequireTool(t, "git")
	dir := t.TempDir()

	testutil.Run(t, dir, git, "init", "-q", "-b", "main", ".")
	testutil.Run(t, dir, git, "remote", "add", "origin",
		"git@github.com:example/project.git")

	write(t, dir, "README.md", "first\n")
	testutil.Run(t, dir, git, "add", "README.md")
	testutil.Run(t, dir, git, "commit", "-q", "-m", "the first commit")

	write(t, dir, "README.md", "first\nsecond\n")
	write(t, dir, "added.txt", "brand new\n")
	testutil.Run(t, dir, git, "add", ".")
	testutil.Run(t, dir, git, "commit", "-q", "-m", "the second commit\n\nwith a body")

	payload := commitPayload(t, dir, git, "HEAD")

	collected := gitctx.Collect(context.Background(), payload, gitctx.Options{
		Dir:       dir,
		Git:       git,
		Operation: "commit",
		Env:       testutil.Env(),
	})

	if collected.GetBranch() != "main" {
		t.Errorf("branch is %q, want main", collected.GetBranch())
	}

	if collected.GetOriginUrl() != "git@github.com:example/project.git" {
		t.Errorf("origin is %q", collected.GetOriginUrl())
	}

	// macOS resolves the temporary directory through a symlink, so compare the
	// base name rather than the whole path.
	if filepath.Base(collected.GetRepositoryPath()) != filepath.Base(dir) {
		t.Errorf("repository path is %q, want something ending in %q",
			collected.GetRepositoryPath(), filepath.Base(dir))
	}

	diff := collected.GetDiff()

	if diff.GetError() != "" {
		t.Fatalf("diff error: %s", diff.GetError())
	}

	if diff.GetFilesChanged() != 2 {
		t.Errorf("files changed is %d, want 2", diff.GetFilesChanged())
	}

	if diff.GetInsertions() != 2 {
		t.Errorf("insertions is %d, want 2", diff.GetInsertions())
	}

	byPath := map[string]*ladulasv1.GitDiffFile{}
	for _, file := range diff.GetFiles() {
		byPath[file.GetNewPath()] = file
	}

	added, ok := byPath["added.txt"]
	if !ok {
		t.Fatalf("added.txt is not in the diff: %+v", byPath)
	}

	if added.GetStatus() != "added" {
		t.Errorf("added.txt has status %q", added.GetStatus())
	}

	if len(added.GetHunks()) != 1 {
		t.Fatalf("added.txt has %d hunks", len(added.GetHunks()))
	}

	line := added.GetHunks()[0].GetLines()[0]

	if line.GetKind() != ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_ADDED {
		t.Errorf("the first line of added.txt is %s", line.GetKind())
	}

	if line.GetText() != "brand new" {
		t.Errorf("the first line of added.txt is %q", line.GetText())
	}

	// And the object itself parses to the commit git wrote.
	if err := gitctx.Describe(collected); err != nil {
		t.Fatalf("describe: %v", err)
	}

	if collected.GetParsed().GetSubject() != "the second commit" {
		t.Errorf("subject is %q", collected.GetParsed().GetSubject())
	}

	if collected.GetParsed().GetAuthor().GetEmail() != "author@example.test" {
		t.Errorf("author is %+v", collected.GetParsed().GetAuthor())
	}
}

func TestCollectRootCommitDiffsAgainstTheEmptyTree(t *testing.T) {
	t.Parallel()

	git := testutil.RequireTool(t, "git")
	dir := t.TempDir()

	testutil.Run(t, dir, git, "init", "-q", "-b", "main", ".")
	write(t, dir, "a.txt", "one\ntwo\n")
	testutil.Run(t, dir, git, "add", ".")
	testutil.Run(t, dir, git, "commit", "-q", "-m", "root")

	payload := commitPayload(t, dir, git, "HEAD")

	collected := gitctx.Collect(context.Background(), payload, gitctx.Options{
		Dir: dir, Git: git, Env: testutil.Env(),
	})

	diff := collected.GetDiff()

	if diff.GetError() != "" {
		t.Fatalf("diff error: %s", diff.GetError())
	}

	if diff.GetFilesChanged() != 1 || diff.GetInsertions() != 2 {
		t.Errorf("diff is %d files and %d insertions, want 1 and 2",
			diff.GetFilesChanged(), diff.GetInsertions())
	}
}

func TestCollectOutsideARepository(t *testing.T) {
	t.Parallel()

	git := testutil.RequireTool(t, "git")
	dir := t.TempDir()

	payload := []byte("tree abc\nauthor A <a@b> 1 +0000\n" +
		"committer A <a@b> 1 +0000\n\nnot in a repo\n")

	collected := gitctx.Collect(context.Background(), payload, gitctx.Options{
		Dir: dir, Git: git, Env: testutil.Env(),
	})

	// Nothing about this should fail; the context is simply empty, and the
	// object still travels so that the approver has something to check.
	if collected.GetRepositoryPath() != "" {
		t.Errorf("repository path is %q, want empty", collected.GetRepositoryPath())
	}

	if len(collected.GetObject()) == 0 {
		t.Error("the object was dropped")
	}
}

func TestCollectTagContext(t *testing.T) {
	t.Parallel()

	git := testutil.RequireTool(t, "git")
	dir := t.TempDir()

	testutil.Run(t, dir, git, "init", "-q", "-b", "main", ".")
	write(t, dir, "a.txt", "one\n")
	testutil.Run(t, dir, git, "add", ".")
	testutil.Run(t, dir, git, "commit", "-q", "-m", "root")

	write(t, dir, "a.txt", "one\ntwo\n")
	testutil.Run(t, dir, git, "add", ".")
	testutil.Run(t, dir, git, "commit", "-q", "-m", "second")

	head := strings.TrimSpace(testutil.Run(t, dir, git, "rev-parse", "HEAD"))

	payload := []byte(
		"object " + head + "\ntype commit\ntag v1.0\n" +
			"tagger A U Thor <author@example.test> 1786209283 +0200\n\nthe release\n")

	collected := gitctx.Collect(context.Background(), payload, gitctx.Options{
		Dir: dir, Git: git, Operation: "tag", Env: testutil.Env(),
	})

	diff := collected.GetDiff()

	if diff.GetError() != "" {
		t.Fatalf("diff error: %s", diff.GetError())
	}

	if diff.GetFilesChanged() != 1 || diff.GetInsertions() != 1 {
		t.Errorf("tag diff is %d files and %d insertions, want 1 and 1",
			diff.GetFilesChanged(), diff.GetInsertions())
	}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// commitPayload rebuilds what git would hand a signing program for a commit
// that already exists: the object with any signature header removed.
func commitPayload(t *testing.T, dir, git, rev string) []byte {
	t.Helper()

	return []byte(testutil.Run(t, dir, git, "cat-file", "commit", rev))
}
