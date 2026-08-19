package project

import (
	"strconv"
	"strings"
	"unicode"
)

// Markdown is parsed here rather than in the viewer, for the reason the diff is
// (§12): a published document is content somebody else chose, and a dumb
// renderer over typed data has a far smaller surface than a parser written in
// JavaScript and shipped to every platform's webview.
//
// It is a deliberately small markdown. Headings, paragraphs, fenced and
// indented code, block quotes, lists, pipe tables, thematic breaks, and inline
// emphasis, code spans and links. Footnotes, reference links and raw HTML are
// not interpreted — they arrive as the text they are, which is the correct
// failure mode for a document viewer that must not become a rendering engine.
//
// Tables are here because the documents this is for are full of them. A README
// says what a flag does in a table, an ops document says what breaks without a
// dependency in a table, and a reader shown the pipes instead is being asked to
// parse it themselves — which is the one thing a document viewer exists to
// spare them. The parsing is GitHub's shape and none of its extensions: a
// header row, a delimiter row that fixes the column count and the alignment,
// and rows until the paragraph ends. A row with too many cells loses the
// extras and one with too few is padded, because the alternative is a renderer
// deciding what to do about a ragged row.
//
// Links are the one place where being conservative shows. A link to a file
// inside the project becomes something the viewer can navigate with; anything
// else becomes text, because a published document must never be able to send an
// approver's webview somewhere, and a bundle that cannot navigate cannot be
// made to.
//
// A heading carries an anchor derived from its own text, which is what a
// fragment link lands on. Both halves are computed here rather than in the
// viewer, so that "#the-store-passphrase" is decided against the same slug on
// every host, and a fragment that names no heading in this document is demoted
// to text before it is ever drawn — a link that does nothing when it is tapped
// is worse than a sentence that was never a link.

// Block kinds. They are strings rather than an enum because they cross to the
// viewer as JSON and are its switch labels.
const (
	BlockParagraph = "paragraph"
	BlockHeading   = "heading"
	BlockCode      = "code"
	BlockQuote     = "quote"
	BlockList      = "list"
	BlockRule      = "rule"
	BlockTable     = "table"
)

// Column alignments, as the delimiter row spelled them.
const (
	AlignDefault = ""
	AlignLeft    = "left"
	AlignCenter  = "center"
	AlignRight   = "right"
)

// Span kinds.
const (
	SpanText     = "text"
	SpanCode     = "code"
	SpanStrong   = "strong"
	SpanEmphasis = "emphasis"
	SpanLink     = "link"
)

// Block is one piece of a rendered document.
type Block struct {
	Kind string `json:"kind"`
	// Level is the heading level, 1 to 6.
	Level int `json:"level,omitempty"`
	// Anchor is a heading's identifier, derived from its text and unique within
	// the document. It is what a fragment link lands on, and it is computed
	// here so that every host agrees on the spelling.
	Anchor string `json:"anchor,omitempty"`
	// Text is the literal content of a code block.
	Text string `json:"text,omitempty"`
	// Language is the fence's info string, for a code block.
	Language string `json:"language,omitempty"`
	// Spans is the inline content of a paragraph or a heading.
	Spans []Span `json:"spans,omitempty"`
	// Blocks is the content of a quote.
	Blocks []Block `json:"blocks,omitempty"`
	// Items is the content of a list, one block list per item.
	Items   [][]Block `json:"items,omitempty"`
	Ordered bool      `json:"ordered,omitempty"`
	// Header is a table's heading row, and Rows the body. Every row has as many
	// cells as the header does, so a renderer never has to decide what a short
	// row means.
	Header *TableRow  `json:"header,omitempty"`
	Rows   []TableRow `json:"rows,omitempty"`
	// Align is one entry per column, from the delimiter row.
	Align []string `json:"align,omitempty"`
}

// TableRow is one row of a table: inline content per cell.
type TableRow struct {
	Cells [][]Span `json:"cells"`
}

// Span is a run of inline content.
//
// Spans do not nest. Emphasis inside a link, or code inside emphasis, collapses
// to the outer kind — which loses a little typography and removes a whole class
// of renderer bugs from the one part of the system that displays what a
// distrusted machine wrote.
type Span struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
	// Target is set on a link, and only ever names a document inside the same
	// project. A link to anywhere else is not a link here at all.
	Target string `json:"target,omitempty"`
	// Fragment is the heading anchor a link asks for, with no leading #. A link
	// with a fragment and no target is a place in this document, and is the one
	// kind of link that navigates nothing — the viewer scrolls.
	Fragment string `json:"fragment,omitempty"`
}

// Document is a parsed markdown file.
type Document struct {
	// Title is the first heading, when the document starts with one, so a file
	// tree can show something better than a file name.
	Title  string  `json:"title,omitempty"`
	Blocks []Block `json:"blocks"`
}

// ParseMarkdown renders a published document into blocks.
//
// The path is the document's own location in the project, so that a relative
// link in it can be resolved to another published file.
func ParseMarkdown(source, docPath string) Document {
	p := &markdownParser{
		lines:   strings.Split(strings.ReplaceAll(source, "\r\n", "\n"), "\n"),
		base:    docPath,
		anchors: map[string]int{},
	}

	doc := Document{Blocks: p.blocks(0)}

	// A fragment may point forwards, so what a document's headings are is only
	// known once all of it has been read. This is the pass that decides which
	// of the fragment links have somewhere to land.
	settleFragments(doc.Blocks)

	for _, block := range doc.Blocks {
		if block.Kind == BlockHeading {
			doc.Title = spansText(block.Spans)

			break
		}
	}

	return doc
}

type markdownParser struct {
	lines []string
	at    int
	base  string
	// anchors counts the headings each slug has been claimed by, so that a
	// document with two "Configuration" headings has two anchors. It is shared
	// with the parsers a quote or a list item spawns, because a heading inside
	// one is still a heading in this document.
	anchors map[string]int
}

// nested is a parser for lines that belong to this document but are read on
// their own — a quote's contents, a list item's.
func (p *markdownParser) nested(lines []string) *markdownParser {
	return &markdownParser{lines: lines, base: p.base, anchors: p.anchors}
}

// blocks reads block-level structure until the lines run out or the indentation
// drops below the level a quote or a list item established.
func (p *markdownParser) blocks(indent int) []Block {
	var out []Block

	for p.at < len(p.lines) {
		line := p.lines[p.at]

		if strings.TrimSpace(line) == "" {
			p.at++

			continue
		}

		if indent > 0 && leadingSpaces(line) < indent && !strings.HasPrefix(line, ">") {
			return out
		}

		switch {
		case isFence(line):
			out = append(out, p.fence())
		case isRule(line):
			p.at++

			out = append(out, Block{Kind: BlockRule})
		case headingLevel(line) > 0:
			out = append(out, p.heading())
		case strings.HasPrefix(strings.TrimLeft(line, " "), ">"):
			out = append(out, p.quote())
		case bulletMarker(line) != "" || orderedMarker(line) != "":
			out = append(out, p.list())
		case leadingSpaces(line) >= indent+4:
			out = append(out, p.indentedCode(indent))
		case p.atTable():
			out = append(out, p.table())
		default:
			out = append(out, p.paragraph())
		}
	}

	return out
}

func (p *markdownParser) heading() Block {
	line := strings.TrimLeft(p.lines[p.at], " ")
	p.at++

	level := headingLevel(line)
	text := strings.TrimSpace(strings.TrimLeft(line[level:], " "))
	text = strings.TrimRight(text, "# ")

	spans := p.inline(text)

	return Block{
		Kind:   BlockHeading,
		Level:  level,
		Anchor: p.anchor(spansText(spans)),
		Spans:  spans,
	}
}

// anchor turns a heading's text into an identifier, and keeps the ones already
// taken apart the way GitHub does: the second "Configuration" is
// configuration-1, so a link written against a rendered page lands where its
// author expected.
func (p *markdownParser) anchor(text string) string {
	slug := slugify(text)
	if slug == "" {
		return ""
	}

	taken := p.anchors[slug]
	p.anchors[slug]++

	if taken == 0 {
		return slug
	}

	return slug + "-" + strconv.Itoa(taken)
}

func (p *markdownParser) paragraph() Block {
	var parts []string

	for p.at < len(p.lines) {
		line := p.lines[p.at]

		if strings.TrimSpace(line) == "" || isFence(line) || isRule(line) ||
			headingLevel(strings.TrimLeft(line, " ")) > 0 ||
			strings.HasPrefix(strings.TrimLeft(line, " "), ">") ||
			bulletMarker(line) != "" || orderedMarker(line) != "" {
			break
		}

		parts = append(parts, strings.TrimSpace(line))
		p.at++
	}

	return Block{
		Kind:  BlockParagraph,
		Spans: p.inline(strings.Join(parts, " ")),
	}
}

func (p *markdownParser) fence() Block {
	opening := strings.TrimLeft(p.lines[p.at], " ")
	marker := opening[:3]
	language := strings.TrimSpace(strings.TrimLeft(opening[3:], marker[:1]))
	p.at++

	var body []string

	for p.at < len(p.lines) {
		line := p.lines[p.at]

		if strings.HasPrefix(strings.TrimLeft(line, " "), marker) {
			p.at++

			break
		}

		body = append(body, line)
		p.at++
	}

	return Block{
		Kind:     BlockCode,
		Language: language,
		Text:     strings.Join(body, "\n"),
	}
}

func (p *markdownParser) indentedCode(indent int) Block {
	var body []string

	for p.at < len(p.lines) {
		line := p.lines[p.at]

		if strings.TrimSpace(line) == "" {
			body = append(body, "")
			p.at++

			continue
		}

		if leadingSpaces(line) < indent+4 {
			break
		}

		body = append(body, line[indent+4:])
		p.at++
	}

	return Block{
		Kind: BlockCode,
		Text: strings.TrimRight(strings.Join(body, "\n"), "\n"),
	}
}

func (p *markdownParser) quote() Block {
	var inner []string

	for p.at < len(p.lines) {
		line := strings.TrimLeft(p.lines[p.at], " ")

		if !strings.HasPrefix(line, ">") {
			break
		}

		inner = append(inner, strings.TrimPrefix(strings.TrimPrefix(line, ">"), " "))
		p.at++
	}

	return Block{Kind: BlockQuote, Blocks: p.nested(inner).blocks(0)}
}

// list reads a run of items at one indentation, each item parsed as its own
// little document so that a paragraph or a code block inside one works.
func (p *markdownParser) list() Block {
	ordered := orderedMarker(p.lines[p.at]) != ""
	block := Block{Kind: BlockList, Ordered: ordered}

	for p.at < len(p.lines) {
		line := p.lines[p.at]

		marker := bulletMarker(line)
		if ordered {
			marker = orderedMarker(line)
		}

		if marker == "" {
			if strings.TrimSpace(line) == "" {
				// A blank line inside a list is only the end of it when the next
				// content is not another item.
				if next := p.peekContent(); next == "" ||
					(ordered && orderedMarker(next) == "") ||
					(!ordered && bulletMarker(next) == "") {
					break
				}

				p.at++

				continue
			}

			break
		}

		indent := leadingSpaces(line)
		body := []string{strings.TrimLeft(line, " ")[len(marker):]}
		p.at++

		// Continuation lines are the ones indented past the marker.
		for p.at < len(p.lines) {
			follow := p.lines[p.at]

			if strings.TrimSpace(follow) == "" {
				break
			}

			if leadingSpaces(follow) <= indent {
				break
			}

			body = append(body, strings.TrimLeft(follow, " "))
			p.at++
		}

		block.Items = append(block.Items, p.nested(body).blocks(0))
	}

	return block
}

// atTable reports whether a table starts here: a row of cells, and under it a
// delimiter row with the same number of them.
//
// The delimiter row is what makes a table a table. Without that test any
// paragraph with a pipe in it — a shell pipeline, a regular expression — would
// be read as a one-column table, which is a worse rendering of it than the
// paragraph it is.
func (p *markdownParser) atTable() bool {
	if p.at+1 >= len(p.lines) || !isTableRow(p.lines[p.at]) {
		return false
	}

	align := tableAlignments(p.lines[p.at+1])

	return len(align) > 0 && len(align) == len(splitRow(p.lines[p.at]))
}

func (p *markdownParser) table() Block {
	header := p.cells(splitRow(p.lines[p.at]))
	align := tableAlignments(p.lines[p.at+1])
	p.at += 2

	block := Block{
		Kind:   BlockTable,
		Align:  align,
		Header: &TableRow{Cells: header},
	}

	for p.at < len(p.lines) {
		line := p.lines[p.at]

		if strings.TrimSpace(line) == "" || !isTableRow(line) {
			break
		}

		// Every row is the header's width: the extras of a long row are dropped
		// and a short one is padded, which is what GitHub does and, more to the
		// point, leaves the renderer with nothing to decide.
		block.Rows = append(block.Rows, TableRow{
			Cells: p.cells(fit(splitRow(line), len(header))),
		})
		p.at++
	}

	return block
}

// cells parses the inline content of one row.
func (p *markdownParser) cells(texts []string) [][]Span {
	out := make([][]Span, 0, len(texts))
	for _, text := range texts {
		out = append(out, p.inline(text))
	}

	return out
}

// isTableRow reports whether a line has a cell separator in it at all.
func isTableRow(line string) bool {
	trimmed := strings.TrimLeft(line, " ")

	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] == '\\' {
			i++

			continue
		}

		if trimmed[i] == '|' {
			return true
		}
	}

	return false
}

// splitRow cuts a row into cells on unescaped pipes, dropping the optional
// leading and trailing ones.
func splitRow(line string) []string {
	trimmed := strings.TrimSpace(line)
	trimmed = strings.TrimPrefix(trimmed, "|")
	trimmed = strings.TrimSuffix(trimmed, "|")

	var (
		out  []string
		cell strings.Builder
	)

	for i := 0; i < len(trimmed); i++ {
		switch {
		case trimmed[i] == '\\' && i+1 < len(trimmed) && trimmed[i+1] == '|':
			// An escaped pipe is a pipe in the text, and the one place this
			// parser has to look at a backslash before the inline pass does.
			cell.WriteByte('|')
			i++
		case trimmed[i] == '|':
			out = append(out, strings.TrimSpace(cell.String()))
			cell.Reset()
		default:
			cell.WriteByte(trimmed[i])
		}
	}

	return append(out, strings.TrimSpace(cell.String()))
}

// tableAlignments reads the delimiter row, and returns nothing at all when the
// line is not one.
func tableAlignments(line string) []string {
	if !isTableRow(line) {
		return nil
	}

	cells := splitRow(line)
	out := make([]string, 0, len(cells))

	for _, cell := range cells {
		left := strings.HasPrefix(cell, ":")
		right := strings.HasSuffix(cell, ":")
		dashes := strings.Trim(cell, ":")

		if dashes == "" || strings.Trim(dashes, "-") != "" {
			return nil
		}

		switch {
		case left && right:
			out = append(out, AlignCenter)
		case left:
			out = append(out, AlignLeft)
		case right:
			out = append(out, AlignRight)
		default:
			out = append(out, AlignDefault)
		}
	}

	return out
}

// fit makes a row exactly width cells long.
func fit(cells []string, width int) []string {
	for len(cells) < width {
		cells = append(cells, "")
	}

	return cells[:width]
}

// peekContent is the next non-blank line, without consuming anything.
func (p *markdownParser) peekContent() string {
	for i := p.at; i < len(p.lines); i++ {
		if strings.TrimSpace(p.lines[i]) != "" {
			return p.lines[i]
		}
	}

	return ""
}

// inline splits a run of text into spans.
func (p *markdownParser) inline(text string) []Span {
	var (
		out  []Span
		flat strings.Builder
	)

	flush := func() {
		if flat.Len() > 0 {
			out = append(out, Span{Kind: SpanText, Text: flat.String()})
			flat.Reset()
		}
	}

	for i := 0; i < len(text); {
		switch {
		case text[i] == '\\' && i+1 < len(text):
			flat.WriteByte(text[i+1])
			i += 2
		case text[i] == '`':
			if body, width, ok := delimited(text[i:], "`"); ok {
				flush()

				out = append(out, Span{Kind: SpanCode, Text: body})
				i += width

				continue
			}

			flat.WriteByte(text[i])
			i++
		case strings.HasPrefix(text[i:], "**"):
			if body, width, ok := delimited(text[i:], "**"); ok {
				flush()

				out = append(out, Span{Kind: SpanStrong, Text: stripMarks(body)})
				i += width

				continue
			}

			flat.WriteByte(text[i])
			i++
		case text[i] == '*' || text[i] == '_':
			mark := string(text[i])

			if body, width, ok := delimited(text[i:], mark); ok && body != "" {
				flush()

				out = append(out, Span{Kind: SpanEmphasis, Text: stripMarks(body)})
				i += width

				continue
			}

			flat.WriteByte(text[i])
			i++
		case text[i] == '!' && i+1 < len(text) && text[i+1] == '[':
			// An image is described rather than shown: the bundle may load no
			// remote resource, and a project's own images are not published.
			if label, target, width, ok := link(text[i+1:]); ok {
				flush()

				out = append(out, Span{
					Kind: SpanText,
					Text: imageNote(label, target),
				})
				i += width + 1

				continue
			}

			flat.WriteByte(text[i])
			i++
		case text[i] == '[':
			if label, target, width, ok := link(text[i:]); ok {
				flush()

				out = append(out, p.linkSpan(label, target))
				i += width

				continue
			}

			flat.WriteByte(text[i])
			i++
		default:
			flat.WriteByte(text[i])
			i++
		}
	}

	flush()

	return out
}

// linkSpan decides whether a link is one the viewer may follow.
//
// Only two things are: a place in the document being read, and a relative path
// to another file in the same project — with or without a place in that one.
// Everything else — a scheme, a protocol-relative host, an absolute path —
// becomes text with the destination spelled out beside it, so that a reader can
// see where it would have gone without anything being able to take them there.
func (p *markdownParser) linkSpan(label, target string) Span {
	label = stripMarks(label)

	// A fragment on its own is a place in this document. It navigates nothing,
	// which is why it is allowed at all: there is no destination to be careful
	// about, only a scroll. Whether it lands anywhere is settled once the whole
	// document has been read.
	if strings.HasPrefix(target, "#") {
		return Span{
			Kind:     SpanLink,
			Text:     label,
			Fragment: slugify(target[1:]),
		}
	}

	if !navigable(target) {
		return Span{Kind: SpanText, Text: linkNote(label, target)}
	}

	resolved := resolveRelative(p.base, target)
	if resolved == "" {
		return Span{Kind: SpanText, Text: linkNote(label, target)}
	}

	span := Span{Kind: SpanLink, Text: label, Target: resolved}

	// A fragment of another document travels with the link and is checked by
	// whoever opens that document, because this one cannot see its headings.
	if _, fragment, found := strings.Cut(target, "#"); found {
		span.Fragment = slugify(fragment)
	}

	return span
}

// settleFragments demotes the fragment links that name no heading in this
// document, and is why a link to "#the-part-that-was-renamed" reads as text
// rather than as a button that does nothing.
//
// It only judges links to this document. A fragment travelling with a path to
// another file is that document's business, and is left alone here.
func settleFragments(blocks []Block) {
	anchors := map[string]bool{}

	walkBlocks(blocks, func(block *Block) {
		if block.Anchor != "" {
			anchors[block.Anchor] = true
		}
	})

	walkBlocks(blocks, func(block *Block) {
		walkSpans(block, func(span *Span) {
			if span.Kind != SpanLink || span.Target != "" ||
				anchors[span.Fragment] {
				return
			}

			span.Kind = SpanText
			span.Fragment = ""
		})
	})
}

// walkBlocks visits every block in a document, including the ones inside
// quotes, list items and table cells.
func walkBlocks(blocks []Block, visit func(*Block)) {
	for i := range blocks {
		block := &blocks[i]

		visit(block)
		walkBlocks(block.Blocks, visit)

		for _, item := range block.Items {
			walkBlocks(item, visit)
		}
	}
}

// walkSpans visits the inline content a block holds directly, cells included.
func walkSpans(block *Block, visit func(*Span)) {
	for i := range block.Spans {
		visit(&block.Spans[i])
	}

	rows := block.Rows
	if block.Header != nil {
		rows = append([]TableRow{*block.Header}, rows...)
	}

	for _, row := range rows {
		for _, cell := range row.Cells {
			for i := range cell {
				visit(&cell[i])
			}
		}
	}
}

// slugify turns a heading's text into an anchor, and a fragment into the same
// shape so the two can be compared: lowercased, everything that is not a
// letter, a digit, a hyphen or an underscore dropped, and the spaces joined up.
//
// It is GitHub's rule because that is the rule the documents were written
// against — a link to "#what-to-watch-in-order" is somebody reading a heading
// on a rendered page and typing what they saw.
func slugify(text string) string {
	var b strings.Builder

	for _, r := range strings.ToLower(strings.TrimSpace(text)) {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}

	return b.String()
}

// navigable reports whether a link target is a plain relative path.
func navigable(target string) bool {
	if target == "" || strings.HasPrefix(target, "/") ||
		strings.HasPrefix(target, "//") {
		return false
	}

	// Anything with a scheme is out, and so is anything that merely looks like
	// it might have one: a colon before the first slash is enough to be
	// suspicious about, and a document link never needs one.
	if index := strings.IndexAny(target, ":?#"); index >= 0 {
		if target[index] != '#' || strings.ContainsAny(target[:index], ":?") {
			return false
		}
	}

	return IsMarkdown(strings.SplitN(target, "#", 2)[0])
}

// resolveRelative turns a link into a project-relative path, or an empty string
// when it climbs out.
func resolveRelative(base, target string) string {
	name := strings.SplitN(target, "#", 2)[0]

	dir := ""
	if index := strings.LastIndex(base, "/"); index >= 0 {
		dir = base[:index+1]
	}

	joined := cleanSlashPath(dir + name)
	if joined == "" || strings.HasPrefix(joined, "../") || joined == ".." {
		return ""
	}

	return joined
}

// cleanSlashPath is path.Clean over a slash-separated document path, kept here
// so that the parser does not depend on the shape of the host's filesystem.
func cleanSlashPath(name string) string {
	var out []string

	for _, part := range strings.Split(name, "/") {
		switch part {
		case "", ".":
		case "..":
			if len(out) == 0 {
				return ".."
			}

			out = out[:len(out)-1]
		default:
			out = append(out, part)
		}
	}

	return strings.Join(out, "/")
}

func linkNote(label, target string) string {
	if label == "" {
		return target
	}

	return label + " (" + target + ")"
}

func imageNote(label, target string) string {
	if label == "" {
		return "[image: " + target + "]"
	}

	return "[image: " + label + "]"
}

// delimited reads a run bounded by the same marker at both ends.
func delimited(text, marker string) (string, int, bool) {
	rest := text[len(marker):]

	end := strings.Index(rest, marker)
	if end < 0 {
		return "", 0, false
	}

	return rest[:end], len(marker)*2 + end, true
}

// link reads [label](target).
func link(text string) (string, string, int, bool) {
	if !strings.HasPrefix(text, "[") {
		return "", "", 0, false
	}

	close := strings.Index(text, "]")
	if close < 0 || close+1 >= len(text) || text[close+1] != '(' {
		return "", "", 0, false
	}

	end := strings.Index(text[close:], ")")
	if end < 0 {
		return "", "", 0, false
	}

	target := strings.TrimSpace(text[close+2 : close+end])

	// A title after the target — [x](y "z") — is dropped; there is nowhere in
	// the rendering for it to go.
	if space := strings.IndexFunc(target, unicode.IsSpace); space >= 0 {
		target = target[:space]
	}

	return text[1:close], target, close + end + 1, true
}

// stripMarks removes the inline markers from text that has already been decided
// to be one span, since spans do not nest.
func stripMarks(text string) string {
	replacer := strings.NewReplacer("**", "", "`", "", "*", "", "_", "")

	return replacer.Replace(text)
}

func spansText(spans []Span) string {
	var b strings.Builder

	for _, span := range spans {
		b.WriteString(span.Text)
	}

	return b.String()
}

func headingLevel(line string) int {
	level := 0

	for level < len(line) && line[level] == '#' {
		level++
	}

	if level == 0 || level > 6 {
		return 0
	}

	if level < len(line) && line[level] != ' ' {
		return 0
	}

	return level
}

func isFence(line string) bool {
	trimmed := strings.TrimLeft(line, " ")

	return strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~")
}

func isRule(line string) bool {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) < 3 {
		return false
	}

	for _, mark := range []byte{'-', '*', '_'} {
		if strings.Trim(trimmed, string(mark)) == "" {
			return true
		}
	}

	return false
}

func bulletMarker(line string) string {
	trimmed := strings.TrimLeft(line, " ")

	for _, mark := range []string{"- ", "* ", "+ "} {
		if strings.HasPrefix(trimmed, mark) {
			return mark
		}
	}

	return ""
}

func orderedMarker(line string) string {
	trimmed := strings.TrimLeft(line, " ")

	digits := 0
	for digits < len(trimmed) && trimmed[digits] >= '0' && trimmed[digits] <= '9' {
		digits++
	}

	if digits == 0 || digits+1 >= len(trimmed) {
		return ""
	}

	if (trimmed[digits] == '.' || trimmed[digits] == ')') &&
		trimmed[digits+1] == ' ' {
		return trimmed[:digits+2]
	}

	return ""
}

func leadingSpaces(line string) int {
	count := 0

	for count < len(line) && line[count] == ' ' {
		count++
	}

	return count
}
