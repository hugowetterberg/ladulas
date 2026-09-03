package project

import (
	"encoding/json"
	"strings"
)

// Showing a reader what changed in a document since they last read it
// (decision AP).
//
// It is computed here rather than in the viewer, for the reason the diff and
// the markdown parsing are (§12, §16): a published document is the most
// attacker-influenced content in the app, and a renderer over typed data has a
// far smaller surface than a differ written in JavaScript and shipped to every
// platform's webview. What crosses to the bundle is the same Document it
// already draws, with a mark on the blocks and spans that moved.
//
// **Two levels, because a reader asks two questions.** "What changed in this
// document" is answered by blocks: a paragraph that appeared, a section that
// went. "What changed in this sentence" is answered by spans, inside a
// paragraph that is otherwise the same one. A differ with only the first is
// useless on a typo fix — it marks the whole paragraph — and one with only the
// second has nothing to say about a heading that was deleted.
//
// **The work is bounded by trimming first.** The common prefix and suffix come
// off before anything quadratic runs, which for the ordinary case — somebody
// edited one paragraph of a long document — leaves a middle of two or three
// blocks. What remains is capped, and a document that changed more than the cap
// is reported as wholly replaced rather than diffed: it is a rewrite, the
// answer "all of it" is true, and it is better than spending a second of
// somebody's phone on saying so at length.

// MaxDiffBlocks bounds the quadratic part. Past it a document is reported as
// replaced rather than diffed.
//
// It is generous on purpose: it applies to what is left *after* the common
// prefix and suffix are trimmed, so reaching it means a couple of hundred
// consecutive blocks all differ, which is a rewrite and not an edit.
const MaxDiffBlocks = 250

// Change says what happened to a block or a span.
//
// The zero value is "nothing", so a document nobody has diffed carries no marks
// and the field costs nothing on the wire.
type Change string

const (
	// ChangeNone is unchanged, and the zero value.
	ChangeNone Change = ""
	// ChangeAdded is content that is in the new document and not the old. The
	// viewer draws it as though somebody went over it with a highlighter.
	ChangeAdded Change = "added"
	// ChangeRemoved is content that was in the old document and is not in the
	// new one. The viewer draws it struck through.
	ChangeRemoved Change = "removed"
)

// Compare produces one document that shows what changed between two.
//
// The result is in the new document's order, with the removed content put back
// where it used to be, so that a reader sees the document they know with the
// edits marked in it rather than two documents side by side. That is the
// difference between reading a change and comparing two files, and on a phone
// it is the only one of those that works.
func Compare(before, after Document) Document {
	out := Document{Title: after.Title}
	out.Blocks = compareBlocks(before.Blocks, after.Blocks)

	return out
}

// compareBlocks aligns two block lists and marks the difference.
func compareBlocks(before, after []Block) []Block {
	// The common ends come off first. This is what makes the ordinary edit
	// cheap: one paragraph changed in a fifty-block document leaves a middle of
	// one block on each side.
	var head []Block

	for len(before) > 0 && len(after) > 0 &&
		signature(before[0]) == signature(after[0]) {
		head = append(head, after[0])
		before = before[1:]
		after = after[1:]
	}

	var tail []Block

	for len(before) > 0 && len(after) > 0 &&
		signature(before[len(before)-1]) == signature(after[len(after)-1]) {
		tail = append([]Block{after[len(after)-1]}, tail...)
		before = before[:len(before)-1]
		after = after[:len(after)-1]
	}

	middle := alignMiddle(before, after)

	out := make([]Block, 0, len(head)+len(middle)+len(tail))
	out = append(out, head...)
	out = append(out, middle...)
	out = append(out, tail...)

	return out
}

// alignMiddle diffs the part that is left once the common ends are gone.
func alignMiddle(before, after []Block) []Block {
	switch {
	case len(before) == 0 && len(after) == 0:
		return nil

	case len(before) == 0:
		return marked(after, ChangeAdded)

	case len(after) == 0:
		return marked(before, ChangeRemoved)

	case len(before) > MaxDiffBlocks || len(after) > MaxDiffBlocks:
		// A rewrite. Saying so is true and cheap; aligning it would cost more
		// than the answer is worth.
		out := marked(before, ChangeRemoved)

		return append(out, marked(after, ChangeAdded)...)
	}

	return walkLCS(before, after, longestCommon(before, after))
}

// longestCommon is the LCS table over two block lists.
//
// A plain table rather than anything cleverer, because the trimming above has
// already taken the size down to what an edit actually touches, and the cap
// keeps the worst case bounded. Cleverness here would be paid for on every
// document to be repaid on almost none.
func longestCommon(before, after []Block) [][]int {
	table := make([][]int, len(before)+1)

	for i := range table {
		table[i] = make([]int, len(after)+1)
	}

	for i := len(before) - 1; i >= 0; i-- {
		for j := len(after) - 1; j >= 0; j-- {
			if signature(before[i]) == signature(after[j]) {
				table[i][j] = table[i+1][j+1] + 1

				continue
			}

			table[i][j] = max(table[i+1][j], table[i][j+1])
		}
	}

	return table
}

// walkLCS turns the table into a marked block list.
//
// Removed content is emitted before added content at the same position, so that
// a paragraph that was replaced reads old-then-new — which is the order
// somebody reading a change expects, and the order the strikethrough makes
// sense in.
func walkLCS(before, after []Block, table [][]int) []Block {
	var (
		out  []Block
		i, j int
	)

	for i < len(before) && j < len(after) {
		if signature(before[i]) == signature(after[j]) {
			out = append(out, after[j])
			i++
			j++

			continue
		}

		// A block that matched neither may still be the same block edited,
		// which is the case a reader most wants marked precisely: one word
		// changed in a paragraph should not black out the paragraph.
		//
		// **Only when the table says neither block matches anything later.**
		// Consuming both costs table[i+1][j+1]; dropping one costs
		// table[i+1][j] or table[i][j+1], and since the signatures differ the
		// larger of those two *is* table[i][j]. So the three are equal exactly
		// when this old block and this new block each match nothing further on
		// — which is what makes them a replaced pair rather than an insertion
		// standing in front of an edit. Refining without this check pairs a
		// paragraph somebody inserted with the one below it and reports both as
		// half-edited.
		if table[i+1][j+1] >= table[i][j] {
			if refined, ok := refine(before[i], after[j]); ok {
				out = append(out, refined)
				i++
				j++

				continue
			}
		}

		if table[i+1][j] >= table[i][j+1] {
			out = append(out, mark(before[i], ChangeRemoved))
			i++

			continue
		}

		out = append(out, mark(after[j], ChangeAdded))
		j++
	}

	out = append(out, marked(before[i:], ChangeRemoved)...)
	out = append(out, marked(after[j:], ChangeAdded)...)

	return out
}

// refine marks the difference inside one block, when the two are the same block
// edited rather than two different blocks.
//
// The test for that is deliberately narrow: the same kind, the same heading
// level, and inline content that is not wholly different. A paragraph and a
// heading are never the same block, and neither are two paragraphs with nothing
// in common — those read better as one removed and one added.
func refine(before, after Block) (Block, bool) {
	if before.Kind != after.Kind || before.Level != after.Level {
		return Block{}, false
	}

	// Only inline content is refined. A code block, a table or a list has
	// structure that a span-level mark would misrepresent, and the honest
	// answer for those is that the block changed.
	if len(before.Spans) == 0 || len(after.Spans) == 0 {
		return Block{}, false
	}

	spans, shared := compareSpans(before.Spans, after.Spans)
	if !shared {
		return Block{}, false
	}

	out := after
	out.Spans = spans

	return out, true
}

// compareSpans marks the difference between two runs of inline content, word by
// word, and reports whether the two had anything in common at all.
func compareSpans(before, after []Span) ([]Span, bool) {
	oldWords := words(before)
	newWords := words(after)

	if len(oldWords) == 0 || len(newWords) == 0 {
		return nil, false
	}

	common := commonWords(oldWords, newWords)

	// Nothing in common is two different sentences, not one edited. Marking
	// every word of both would be technically true and unreadable.
	if common == 0 {
		return nil, false
	}

	return wordDiff(before, after, oldWords, newWords), true
}

// words is the whitespace-separated words of a run of spans, for matching. The
// span kinds are deliberately ignored: emphasis added around a word that did
// not otherwise change is not a change worth marking a sentence for.
func words(spans []Span) []string {
	var out []string

	for _, span := range spans {
		out = append(out, strings.Fields(span.Text)...)
	}

	return out
}

// commonWords is how many words the two runs share, counted with multiplicity.
func commonWords(before, after []string) int {
	counts := make(map[string]int, len(before))

	for _, word := range before {
		counts[word]++
	}

	var shared int

	for _, word := range after {
		if counts[word] > 0 {
			counts[word]--
			shared++
		}
	}

	return shared
}

// wordDiff produces the marked spans for one edited paragraph.
//
// The unit is a span rather than a word, because a Span is what the viewer
// draws and spans do not nest (see markdown.go): a marked word inside an
// unmarked span would need the renderer to split one, which is the sort of
// thing that goes wrong in the one place it must not. So a span whose words all
// survived is unmarked, and one whose words changed is emitted as its removed
// and added halves.
func wordDiff(before, after []Span, oldWords, newWords []string) []Span {
	surviving := make(map[string]int, len(oldWords))

	for _, word := range oldWords {
		surviving[word]++
	}

	var out []Span

	// The old content first, marked where its words are not in the new one.
	newCounts := make(map[string]int, len(newWords))

	for _, word := range newWords {
		newCounts[word]++
	}

	for _, span := range before {
		if spanSurvives(span, newCounts) {
			continue
		}

		out = append(out, markSpan(span, ChangeRemoved))
	}

	for _, span := range after {
		if spanSurvives(span, surviving) {
			out = append(out, span)

			continue
		}

		out = append(out, markSpan(span, ChangeAdded))
	}

	return out
}

// spanSurvives reports whether every word of a span is present in the other
// side's word bag.
func spanSurvives(span Span, bag map[string]int) bool {
	fields := strings.Fields(span.Text)
	if len(fields) == 0 {
		// Punctuation or whitespace on its own is carried rather than marked:
		// it is not a word anybody changed.
		return true
	}

	for _, word := range fields {
		if bag[word] == 0 {
			return false
		}
	}

	return true
}

func marked(blocks []Block, change Change) []Block {
	out := make([]Block, 0, len(blocks))

	for _, block := range blocks {
		out = append(out, mark(block, change))
	}

	return out
}

// mark sets a change on a block and on everything inside it, so that a renderer
// never has to work out whether a nested block inherited one.
func mark(block Block, change Change) Block {
	block.Change = change

	for i := range block.Spans {
		block.Spans[i].Change = change
	}

	for i := range block.Blocks {
		block.Blocks[i] = mark(block.Blocks[i], change)
	}

	for i := range block.Items {
		for j := range block.Items[i] {
			block.Items[i][j] = mark(block.Items[i][j], change)
		}
	}

	return block
}

func markSpan(span Span, change Change) Span {
	span.Change = change

	return span
}

// signature is what makes two blocks the same block.
//
// It is the block's own JSON, which is exactly what the viewer draws — so two
// blocks with the same signature render identically, and that is the only sense
// of "the same" a reader can check. Building a shorter key by hand would be
// faster and would drift from what is drawn the first time a field is added to
// Block.
func signature(block Block) string {
	// The change mark is not part of identity: a block being compared has none
	// yet, and one that did would make a second comparison disagree with the
	// first.
	block.Change = ChangeNone

	body, err := json.Marshal(block)
	if err != nil {
		// A block that cannot be serialized cannot be drawn either, so it
		// matches nothing and is reported as changed. There is no such block —
		// every field is a string, an int or a slice of them — and returning an
		// impossible signature is cheaper than an error nobody can act on.
		return "\x00unserializable"
	}

	return string(body)
}
