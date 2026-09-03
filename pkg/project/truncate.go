package project

import (
	"bytes"
	"unicode/utf8"
)

// Serving a file that is larger than the per-file cap, rather than refusing it.
//
// The cap used to mean "not offered": a file over it was listed as unreadable
// with a reason, and the sync neither sent it nor took it away. That is the
// right answer for a kind nobody can render, and the wrong one for the case it
// actually kept hitting — a long document. The core's own architecture.md was
// three hundred kilobytes against a two hundred and fifty-six kilobyte cap, so
// the one document every other document tells the reader to go and read was the
// one document they could not open, and it did not even appear in the picker to
// say so.
//
// **The cap is about what this instance will send, not about what a reader is
// allowed to see.** So a file over it is served up to the cap and marked as cut
// short. The reader gets the beginning of a long document, which is worth
// having, instead of nothing at all with an explanation.
//
// It is cut at a line ending, because the alternative is a last line broken
// mid-word, or mid-fence, and a markdown parser handed half a code fence
// produces a document that is wrong rather than short. A line ending is where
// the file's own structure says one thing has finished.

// MaxTruncateLookback is how far back the cut searches for a line ending.
//
// Some files have impressively long lines — minified anything, a table with a
// column of prose, a document written without hard wrapping — and searching the
// whole file for a newline that is not there would mean serving nothing to
// protect the reader from a ragged last line. Past this the cut is taken where
// the cap falls and the last line is ragged, which is the lesser fault.
const MaxTruncateLookback = 64 << 10

// ServeBytes is what to hand over for a file, and whether it is a prefix.
//
// The bytes are cut at a line ending where there is one within the lookback,
// and always at a rune boundary: a document ending in half a character is not
// text, and would be refused by the check below on a file that is perfectly
// good text right up to where it was cut.
func ServeBytes(body []byte, limit int64) ([]byte, bool) {
	if int64(len(body)) <= limit {
		return body, false
	}

	cut := body[:limit]

	from := len(cut) - MaxTruncateLookback
	if from < 0 {
		from = 0
	}

	if at := bytes.LastIndexAny(cut[from:], "\n\r"); at >= 0 {
		return cut[:from+at+1], true
	}

	return trimPartialRune(cut), true
}

// trimPartialRune drops a multi-byte character the cut landed inside.
func trimPartialRune(body []byte) []byte {
	for len(body) > 0 {
		r, width := utf8.DecodeLastRune(body)
		if r != utf8.RuneError || width > 1 {
			return body
		}

		body = body[:len(body)-1]
	}

	return body
}

// IsText reports whether these bytes are something the viewer can render.
//
// Truncating is only sensible for text: half of a PNG is not a shorter PNG. The
// served kinds are all text today and the policy is what decides which they
// are, so this is the belt rather than the braces — but it is what stops a kind
// somebody adds later from being cut in half and called a document.
func IsText(body []byte) bool {
	return !bytes.ContainsRune(body, 0) && utf8.Valid(body)
}
