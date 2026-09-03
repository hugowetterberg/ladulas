package project_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/project"
)

// compared parses two documents and diffs them, which is how every caller will.
func compared(before, after string) project.Document {
	return project.Compare(
		project.ParseMarkdown(before, "README.md"),
		project.ParseMarkdown(after, "README.md"),
	)
}

// summary is the shape of a diffed document, as one line per block: the change
// mark, the kind, and the text. It makes a failing test say what it got rather
// than dumping a struct.
func summary(doc project.Document) []string {
	out := make([]string, 0, len(doc.Blocks))

	for _, block := range doc.Blocks {
		mark := "="

		switch block.Change {
		case project.ChangeAdded:
			mark = "+"
		case project.ChangeRemoved:
			mark = "-"
		case project.ChangeNone:
			mark = "="
		}

		out = append(out, mark+" "+block.Kind+" "+blockText(block))
	}

	return out
}

func blockText(block project.Block) string {
	if block.Text != "" {
		return block.Text
	}

	var parts []string

	for _, span := range block.Spans {
		// A block that is itself marked marks its spans too, so that a renderer
		// never has to work out whether nested content inherited a mark.
		// Repeating that here would say the same thing twice.
		if block.Change != project.ChangeNone {
			parts = append(parts, span.Text)

			continue
		}

		prefix := ""

		switch span.Change {
		case project.ChangeAdded:
			prefix = "+"
		case project.ChangeRemoved:
			prefix = "-"
		case project.ChangeNone:
		}

		parts = append(parts, prefix+span.Text)
	}

	return strings.Join(parts, "|")
}

func TestAnUnchangedDocumentIsMarkedNowhere(t *testing.T) {
	source := "# One\n\nA paragraph.\n\n## Two\n\nAnother.\n"

	doc := compared(source, source)

	for _, block := range doc.Blocks {
		if block.Change != project.ChangeNone {
			t.Errorf("%s was marked %q in an unchanged document",
				block.Kind, block.Change)
		}

		for _, span := range block.Spans {
			if span.Change != project.ChangeNone {
				t.Errorf("a span was marked %q in an unchanged document",
					span.Change)
			}
		}
	}
}

func TestAnAddedParagraphIsMarkedAdded(t *testing.T) {
	doc := compared(
		"# One\n\nA paragraph.\n",
		"# One\n\nA paragraph.\n\nAnd another.\n",
	)

	got := summary(doc)
	want := []string{"= heading One", "= paragraph A paragraph.", "+ paragraph And another."}

	assertSummary(t, got, want)
}

func TestARemovedParagraphIsPutBackWhereItWas(t *testing.T) {
	doc := compared(
		"# One\n\nFirst.\n\nSecond.\n\nThird.\n",
		"# One\n\nFirst.\n\nThird.\n",
	)

	got := summary(doc)
	want := []string{
		"= heading One", "= paragraph First.",
		"- paragraph Second.", "= paragraph Third.",
	}

	assertSummary(t, got, want)
}

// The case a block-only differ gets uselessly wrong: one word changed should
// not black out the paragraph.
func TestAnEditedSentenceIsMarkedWordByWord(t *testing.T) {
	doc := compared(
		"A paragraph about the socket.\n",
		"A paragraph about the listener.\n",
	)

	if len(doc.Blocks) != 1 {
		t.Fatalf("got %v, want one refined paragraph", summary(doc))
	}

	block := doc.Blocks[0]

	if block.Change != project.ChangeNone {
		t.Errorf("the paragraph itself was marked %q, want unmarked — only its "+
			"words changed", block.Change)
	}

	var added, removed int

	for _, span := range block.Spans {
		switch span.Change {
		case project.ChangeAdded:
			added++
		case project.ChangeRemoved:
			removed++
		case project.ChangeNone:
		}
	}

	if added == 0 || removed == 0 {
		t.Errorf("got %v, want both an added and a removed span",
			summary(doc))
	}
}

// Two paragraphs with nothing in common read better as one removed and one
// added than as a paragraph where every word changed.
func TestTwoUnrelatedParagraphsAreNotRefined(t *testing.T) {
	doc := compared(
		"The socket lives in the runtime directory.\n",
		"Approvals expire after an hour.\n",
	)

	got := summary(doc)
	want := []string{
		"- paragraph The socket lives in the runtime directory.",
		"+ paragraph Approvals expire after an hour.",
	}

	assertSummary(t, got, want)
}

// The heading strategy, first case: a heading whose text changed comes back as
// its own removal and addition, adjacent and at the same level, which is what
// lets the navigator show them as one renamed heading.
func TestAHeadingWhoseTextChangedAppearsAsRemovedThenAdded(t *testing.T) {
	doc := compared(
		"## The socket\n\nA paragraph.\n",
		"## The listener\n\nA paragraph.\n",
	)

	got := summary(doc)

	// The heading is refined rather than replaced when the two share words,
	// which "The socket" and "The listener" do.
	if len(got) != 2 {
		t.Fatalf("got %v, want a heading and its paragraph", got)
	}

	if !strings.HasPrefix(got[0], "= heading") {
		t.Errorf("got %q, want the heading refined in place", got[0])
	}

	if !strings.Contains(got[0], "-The socket") &&
		!strings.Contains(got[0], "-socket") {
		t.Errorf("got %q, want the old heading text marked removed", got[0])
	}

	if got[1] != "= paragraph A paragraph." {
		t.Errorf("got %q, want the paragraph untouched", got[1])
	}
}

// Second case: a heading with nothing in common with any other is a section
// that went, and its content goes with it.
func TestADeletedSectionIsMarkedWholesale(t *testing.T) {
	doc := compared(
		"# One\n\n## Deployment\n\nHow to deploy.\n\n## Two\n\nText.\n",
		"# One\n\n## Two\n\nText.\n",
	)

	got := summary(doc)
	want := []string{
		"= heading One",
		"- heading Deployment",
		"- paragraph How to deploy.",
		"= heading Two",
		"= paragraph Text.",
	}

	assertSummary(t, got, want)
}

// Third case: a heading that is new.
func TestAnAddedSectionIsMarkedWholesale(t *testing.T) {
	doc := compared(
		"# One\n\n## Two\n\nText.\n",
		"# One\n\n## Observability\n\nMetrics.\n\n## Two\n\nText.\n",
	)

	got := summary(doc)
	want := []string{
		"= heading One",
		"+ heading Observability",
		"+ paragraph Metrics.",
		"= heading Two",
		"= paragraph Text.",
	}

	assertSummary(t, got, want)
}

// The guard on refinement. A paragraph inserted in front of an unchanged one
// must not be paired with it and reported as half-edited: the inserted
// paragraph is an addition and the one below it did not change.
func TestAnInsertionInFrontOfAParagraphIsNotReadAsAnEdit(t *testing.T) {
	doc := compared(
		"The socket lives in the runtime directory.\n",
		"A new paragraph about the socket.\n\nThe socket lives in the runtime directory.\n",
	)

	got := summary(doc)
	want := []string{
		"+ paragraph A new paragraph about the socket.",
		"= paragraph The socket lives in the runtime directory.",
	}

	assertSummary(t, got, want)
}

// Structure a span-level mark would misrepresent is reported at the block
// level, which is the honest answer.
func TestACodeBlockThatChangedIsMarkedWholesale(t *testing.T) {
	doc := compared(
		"```sh\nladulas status\n```\n",
		"```sh\nladulas listen\n```\n",
	)

	got := summary(doc)

	if len(got) != 2 {
		t.Fatalf("got %v, want the old code removed and the new added", got)
	}

	if !strings.HasPrefix(got[0], "- code") || !strings.HasPrefix(got[1], "+ code") {
		t.Errorf("got %v, want a removed then an added code block", got)
	}
}

// A document that changed more than the cap is reported as replaced. It is a
// rewrite, "all of it" is true, and it costs a fraction of aligning it.
func TestAWholesaleRewriteIsReportedAsReplaced(t *testing.T) {
	var before, after strings.Builder

	for i := range project.MaxDiffBlocks + 20 {
		before.WriteString("Old paragraph number " + strconv.Itoa(i) + ".\n\n")
		after.WriteString("New sentence number " + strconv.Itoa(i) + ".\n\n")
	}

	doc := compared(before.String(), after.String())

	var added, removed int

	for _, block := range doc.Blocks {
		switch block.Change {
		case project.ChangeAdded:
			added++
		case project.ChangeRemoved:
			removed++
		case project.ChangeNone:
			t.Error("a block was unmarked in a wholesale rewrite")
		}
	}

	if added == 0 || removed == 0 {
		t.Errorf("got %d added and %d removed, want both", added, removed)
	}
}

// Nested content carries the mark, so that a renderer never has to work out
// whether a block inside a removed quote inherited one.
func TestNestedContentCarriesTheMark(t *testing.T) {
	doc := compared(
		"Text.\n\n> A quoted warning.\n",
		"Text.\n",
	)

	var found bool

	for _, block := range doc.Blocks {
		if block.Kind != "quote" {
			continue
		}

		found = true

		if block.Change != project.ChangeRemoved {
			t.Errorf("the quote is marked %q, want removed", block.Change)
		}

		for _, inner := range block.Blocks {
			if inner.Change != project.ChangeRemoved {
				t.Errorf("a block inside the removed quote is marked %q",
					inner.Change)
			}
		}
	}

	if !found {
		t.Fatalf("the removed quote is missing: %v", summary(doc))
	}
}

// Comparing an empty document against a real one is a first read, and every
// caller will do it: it must be the whole document added rather than a panic.
func TestComparingAgainstNothingAddsEverything(t *testing.T) {
	doc := compared("", "# One\n\nText.\n")

	if len(doc.Blocks) == 0 {
		t.Fatal("nothing came back")
	}

	for _, block := range doc.Blocks {
		if block.Change != project.ChangeAdded {
			t.Errorf("%s is marked %q, want added", block.Kind, block.Change)
		}
	}
}

func TestComparingAgainstNothingInTheOtherDirectionRemovesEverything(t *testing.T) {
	doc := compared("# One\n\nText.\n", "")

	if len(doc.Blocks) == 0 {
		t.Fatal("nothing came back")
	}

	for _, block := range doc.Blocks {
		if block.Change != project.ChangeRemoved {
			t.Errorf("%s is marked %q, want removed", block.Kind, block.Change)
		}
	}
}

func assertSummary(t *testing.T, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("got %d blocks:\n  %s\nwant %d:\n  %s",
			len(got), strings.Join(got, "\n  "),
			len(want), strings.Join(want, "\n  "))
	}

	for i := range want {
		if got[i] != want[i] {
			t.Errorf("block %d = %q, want %q", i, got[i], want[i])
		}
	}
}
