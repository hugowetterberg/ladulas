package project_test

import (
	"strings"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/project"
)

// The markdown renderer is the one part of the doc browser that reads content a
// distrusted machine wrote, so these are mostly tests about what it refuses to
// do rather than about what it renders.

func parse(t *testing.T, source string) project.Document {
	t.Helper()

	return project.ParseMarkdown(source, "docs/design.md")
}

func TestBlocksAreParsedInGo(t *testing.T) {
	doc := parse(t, strings.TrimLeft(`
# Ladulås

Magnus Ladulås put a **lock** on the barn, and `+"`ladulas-sign`"+` is how it
signs commits.

## Running it

    ladulas init

- one
- two

1. first
2. second

> Approvals travel to the phone.

`+"```go"+`
func main() {}
`+"```"+`

---
`, "\n"))

	if doc.Title != "Ladulås" {
		t.Errorf("the title came back as %q", doc.Title)
	}

	kinds := make([]string, 0, len(doc.Blocks))
	for _, block := range doc.Blocks {
		kinds = append(kinds, block.Kind)
	}

	want := "heading,paragraph,heading,code,list,list,quote,code,rule"
	if got := strings.Join(kinds, ","); got != want {
		t.Errorf("the blocks came back as %s, want %s", got, want)
	}

	paragraph := doc.Blocks[1]

	var strong, code bool

	for _, span := range paragraph.Spans {
		switch span.Kind {
		case project.SpanStrong:
			strong = span.Text == "lock"
		case project.SpanCode:
			code = span.Text == "ladulas-sign"
		}
	}

	if !strong {
		t.Error("the emphasis in the paragraph was not picked up")
	}

	if !code {
		t.Error("the code span in the paragraph was not picked up")
	}

	if doc.Blocks[3].Text != "ladulas init" {
		t.Errorf("the indented code block reads %q", doc.Blocks[3].Text)
	}

	if len(doc.Blocks[4].Items) != 2 || doc.Blocks[4].Ordered {
		t.Errorf("the bullet list came back with %d items, ordered=%v",
			len(doc.Blocks[4].Items), doc.Blocks[4].Ordered)
	}

	if !doc.Blocks[5].Ordered {
		t.Error("the numbered list did not come back ordered")
	}

	fenced := doc.Blocks[7]

	if fenced.Language != "go" || !strings.Contains(fenced.Text, "func main") {
		t.Errorf("the fenced block came back as %q in %q",
			fenced.Text, fenced.Language)
	}
}

// TestOnlyProjectLinksAreLinks: a published document must never be able to send
// an approver's webview anywhere (§6, §12).
func TestOnlyProjectLinksAreLinks(t *testing.T) {
	doc := parse(t, strings.TrimLeft(`
See [the design](../DESIGN.md), [a section](#pairing), [the site](https://example.com/x),
[a script](javascript:alert(1)), [the root](/etc/passwd) and [escape](../../outside.md).

![a diagram](diagram.png)
`, "\n"))

	var links []project.Span

	for _, block := range doc.Blocks {
		for _, span := range block.Spans {
			if span.Kind == project.SpanLink {
				links = append(links, span)
			}
		}
	}

	if len(links) != 1 {
		t.Fatalf("%d links survived: %v", len(links), links)
	}

	if links[0].Target != "DESIGN.md" {
		t.Errorf("the surviving link points at %q", links[0].Target)
	}

	// Everything else is text, with the destination spelled out rather than
	// followed.
	text := documentText(doc)

	for _, forbidden := range []string{"javascript:", "https://example.com/x"} {
		if !strings.Contains(text, forbidden) {
			t.Errorf("the reader is not shown where %q would have gone", forbidden)
		}
	}

	for _, span := range spansOf(doc) {
		if span.Kind == project.SpanLink && strings.Contains(span.Target, ":") {
			t.Errorf("a link with a scheme survived: %q", span.Target)
		}
	}

	if !strings.Contains(text, "[image: a diagram]") {
		t.Errorf("the image was not described: %q", text)
	}
}

// A table is what the documents this exists for are full of, and a reader shown
// the pipes is being asked to parse it themselves.
func TestTablesAreParsed(t *testing.T) {
	doc := parse(t, strings.TrimLeft(`
| Flag | Default | What it does |
|------|:-------:|-------------:|
| `+"`--unlock`"+` | auto | how the passphrase is asked for |
| --console | auto | whether to approve at the terminal | dropped |
| --short |
`, "\n"))

	table := blockOfKind(t, doc, "table")

	if got := len(table.Align); got != 3 {
		t.Fatalf("%d columns, want 3: %v", got, table.Align)
	}

	if table.Align[0] != "" || table.Align[1] != "center" ||
		table.Align[2] != "right" {
		t.Errorf("the alignments came back as %v", table.Align)
	}

	if table.Header == nil || len(table.Header.Cells) != 3 {
		t.Fatalf("the header is %v", table.Header)
	}

	if got := spansText(table.Header.Cells[2]); got != "What it does" {
		t.Errorf("the third heading is %q", got)
	}

	if len(table.Rows) != 3 {
		t.Fatalf("%d rows, want 3", len(table.Rows))
	}

	// The first cell of the first row is a code span, which is a cell being
	// inline content rather than a string.
	first := table.Rows[0].Cells[0]
	if len(first) != 1 || first[0].Kind != project.SpanCode ||
		first[0].Text != "--unlock" {
		t.Errorf("the first cell came back as %v", first)
	}

	// Every row is the header's width, whichever way it was wrong: a long row
	// loses the extras and a short one is padded, so a renderer never has to
	// decide what a ragged row means.
	for i, row := range table.Rows {
		if len(row.Cells) != 3 {
			t.Errorf("row %d has %d cells, want 3", i, len(row.Cells))
		}
	}

	if got := spansText(table.Rows[2].Cells[1]); got != "" {
		t.Errorf("the padded cell is %q, want empty", got)
	}

	if strings.Contains(documentText(doc), "dropped") {
		t.Error("a cell past the header's width survived")
	}
}

// A pipe is a common character in a document about a command line, and the
// delimiter row is what tells a table from a paragraph with a pipeline in it.
func TestAPipeIsNotATable(t *testing.T) {
	doc := parse(t, strings.TrimLeft(`
Run `+"`journalctl --user -u ladulas.service | grep sealed`"+` to read it,
or pipe it | somewhere else.

| Still | not one |
| because there is no delimiter row |
`, "\n"))

	for _, block := range doc.Blocks {
		if block.Kind == "table" {
			t.Fatalf("a paragraph was read as a table: %v", block)
		}
	}
}

// Escaped pipes are content, not separators.
func TestAnEscapedPipeStaysInTheCell(t *testing.T) {
	doc := parse(t, strings.TrimLeft(`
| Pattern | Means |
|---|---|
| a \| b | either one |
`, "\n"))

	table := blockOfKind(t, doc, "table")

	if got := spansText(table.Rows[0].Cells[0]); got != "a | b" {
		t.Errorf("the escaped pipe came back as %q", got)
	}
}

// Headings carry the anchor a fragment link lands on, and it is computed in Go
// so that every host agrees on the spelling.
func TestHeadingsCarryAnchors(t *testing.T) {
	doc := parse(t, strings.TrimLeft(`
# What to watch, in order

## Configuration

## Configuration
`, "\n"))

	var anchors []string

	for _, block := range doc.Blocks {
		if block.Kind == "heading" {
			anchors = append(anchors, block.Anchor)
		}
	}

	want := []string{"what-to-watch-in-order", "configuration", "configuration-1"}

	if len(anchors) != len(want) {
		t.Fatalf("anchors are %v", anchors)
	}

	for i := range want {
		if anchors[i] != want[i] {
			t.Errorf("anchor %d is %q, want %q", i, anchors[i], want[i])
		}
	}
}

// A link to a place in this document is the one link that navigates nothing,
// and a link to a place that is not there is not a link at all.
func TestFragmentLinks(t *testing.T) {
	doc := parse(t, strings.TrimLeft(`
# Ops

See [the watch list](#what-to-watch), [the renamed section](#gone-away) and
[the other document](../ops.md#failure-modes).

## What to watch
`, "\n"))

	links := map[string]project.Span{}

	for _, span := range spansOf(doc) {
		if span.Kind == project.SpanLink {
			links[span.Text] = span
		}
	}

	if len(links) != 2 {
		t.Fatalf("%d links survived: %v", len(links), links)
	}

	within := links["the watch list"]
	if within.Target != "" || within.Fragment != "what-to-watch" {
		t.Errorf("the in-document link is %+v", within)
	}

	// A fragment naming no heading here is demoted rather than drawn as a
	// button that does nothing.
	if _, found := links["the renamed section"]; found {
		t.Error("a fragment that names no heading survived as a link")
	}

	// One naming another document travels with it: this document cannot see
	// that one's headings, and the document being opened is what checks.
	across := links["the other document"]
	if across.Target != "ops.md" || across.Fragment != "failure-modes" {
		t.Errorf("the cross-document link is %+v", across)
	}
}

// The fragment is slugified on both sides, so a link written against a rendered
// page — where somebody read the heading and typed what they saw — lands.
func TestFragmentsAreMatchedAsSlugs(t *testing.T) {
	doc := parse(t, strings.TrimLeft(`
# Ladulås

[what it settles](#What%20it%20settles) and [the ports](#Endpoints-and-ports).

## What it settles

## Endpoints and ports
`, "\n"))

	var fragments []string

	for _, span := range spansOf(doc) {
		if span.Kind == project.SpanLink {
			fragments = append(fragments, span.Fragment)
		}
	}

	// The percent-encoded one is not decoded — a fragment is compared as the
	// characters it was written with — so only the second lands.
	if len(fragments) != 1 || fragments[0] != "endpoints-and-ports" {
		t.Errorf("the fragments that landed are %v", fragments)
	}
}

func blockOfKind(t *testing.T, doc project.Document, kind string) project.Block {
	t.Helper()

	for _, block := range doc.Blocks {
		if block.Kind == kind {
			return block
		}
	}

	t.Fatalf("no %s block in %v", kind, doc.Blocks)

	return project.Block{}
}

func spansText(spans []project.Span) string {
	var b strings.Builder

	for _, span := range spans {
		b.WriteString(span.Text)
	}

	return b.String()
}

// TestRawHTMLIsNotInterpreted: the viewer builds every node itself and a
// document that contains markup gets to be a document that contains markup.
func TestRawHTMLIsNotInterpreted(t *testing.T) {
	doc := parse(t, "<img src=x onerror=alert(1)>\n\n<script>alert(2)</script>\n")

	text := documentText(doc)

	if !strings.Contains(text, "<script>") {
		t.Errorf("the markup was interpreted rather than shown: %q", text)
	}

	for _, span := range spansOf(doc) {
		if span.Kind != project.SpanText && span.Kind != project.SpanCode {
			t.Errorf("markup produced a %s span", span.Kind)
		}
	}
}

// TestAnEmptyDocumentIsADocument: the renderer is fed whatever is in a
// repository, including nothing.
func TestAnEmptyDocumentIsADocument(t *testing.T) {
	for _, source := range []string{"", "\n\n\n", "   ", "```\nunclosed\n"} {
		doc := project.ParseMarkdown(source, "README.md")

		for _, block := range doc.Blocks {
			if block.Kind == "" {
				t.Errorf("%q produced a block with no kind", source)
			}
		}
	}
}

func spansOf(doc project.Document) []project.Span {
	var out []project.Span

	var walk func(blocks []project.Block)

	walk = func(blocks []project.Block) {
		for _, block := range blocks {
			out = append(out, block.Spans...)
			walk(block.Blocks)

			for _, item := range block.Items {
				walk(item)
			}

			rows := block.Rows
			if block.Header != nil {
				rows = append([]project.TableRow{*block.Header}, rows...)
			}

			for _, row := range rows {
				for _, cell := range row.Cells {
					out = append(out, cell...)
				}
			}
		}
	}

	walk(doc.Blocks)

	return out
}

func documentText(doc project.Document) string {
	var b strings.Builder

	for _, span := range spansOf(doc) {
		b.WriteString(span.Text)
		b.WriteString(" ")
	}

	return b.String()
}

// A cell is inline content like any other, so the fragment rules reach into one
// — which is worth asserting because a cell is reached through two slices and a
// pass that copied either would leave the link exactly as it was.
func TestFragmentsInsideTablesAreSettled(t *testing.T) {
	doc := parse(t, strings.TrimLeft(`
# Ops

| Symptom | Where |
|---|---|
| sealed | [the watch list](#what-to-watch) |
| slow | [nowhere](#gone) |

## What to watch
`, "\n"))

	var kinds []string

	for _, span := range spansOf(doc) {
		if span.Text == "the watch list" || span.Text == "nowhere" {
			kinds = append(kinds, span.Kind+":"+span.Fragment)
		}
	}

	want := []string{"link:what-to-watch", "text:"}

	if len(kinds) != len(want) || kinds[0] != want[0] || kinds[1] != want[1] {
		t.Errorf("the cells came back as %v, want %v", kinds, want)
	}
}

// An underscore inside a word is not an emphasis delimiter. It is the one place
// CommonMark treats `_` and `*` differently, and it matters here because these
// documents are largely made of the names it protects.
func TestSnakeCaseSurvives(t *testing.T) {
	doc := parse(t,
		"Set SSH_AUTH_SOCK and XDG_RUNTIME_DIR before the agent starts.\n")

	paragraph := blockOfKind(t, doc, "paragraph")

	const want = "Set SSH_AUTH_SOCK and XDG_RUNTIME_DIR before the agent starts."

	if got := spansText(paragraph.Spans); got != want {
		t.Errorf("the identifiers came back as %q", got)
	}

	for _, span := range paragraph.Spans {
		if span.Kind == "emphasis" {
			t.Errorf("an underscore inside a word opened emphasis: %q", span.Text)
		}
	}
}

// The rule is about the delimiter's neighbours and nothing else, so emphasis
// between words still works and asterisks are untouched.
func TestUnderscoreEmphasisBetweenWords(t *testing.T) {
	doc := parse(t, "A _stressed_ word, and an *asterisked* one.\n")

	paragraph := blockOfKind(t, doc, "paragraph")

	var emphasised []string

	for _, span := range paragraph.Spans {
		if span.Kind == "emphasis" {
			emphasised = append(emphasised, span.Text)
		}
	}

	if len(emphasised) != 2 ||
		emphasised[0] != "stressed" || emphasised[1] != "asterisked" {
		t.Errorf("the emphasised runs came back as %v", emphasised)
	}
}
