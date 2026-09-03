package project_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/project"
)

// A file that fits comes back whole and unmarked, which is every document there
// is apart from the ones this file exists for.
func TestAFileThatFitsIsNotCut(t *testing.T) {
	body := []byte("one\ntwo\nthree\n")

	served, cut := project.ServeBytes(body, 1024)

	if cut {
		t.Error("a file under the cap was reported as cut short")
	}

	if !bytes.Equal(served, body) {
		t.Errorf("the contents came back as %q", served)
	}
}

// The cut lands on a line ending, so the last line the reader gets is a whole
// one. A markdown parser handed half a line produces a document that is wrong
// rather than short.
func TestTheCutLandsOnALineEnding(t *testing.T) {
	body := []byte(strings.Repeat("a line of text\n", 100))

	served, cut := project.ServeBytes(body, 100)

	if !cut {
		t.Fatal("a file over the cap was not reported as cut short")
	}

	if len(served) > 100 {
		t.Errorf("the cut returned %d bytes, over the cap of 100", len(served))
	}

	if !bytes.HasSuffix(served, []byte("\n")) {
		t.Errorf("the cut did not land on a line ending: %q", served)
	}
}

// A file whose lines are longer than the lookback is cut where the cap falls.
// Serving nothing to avoid a ragged last line would be the worse answer.
func TestALineLongerThanTheLookbackIsCutMidLine(t *testing.T) {
	limit := int64(project.MaxTruncateLookback + 4096)
	body := []byte(strings.Repeat("x", int(limit)*2))

	served, cut := project.ServeBytes(body, limit)

	if !cut {
		t.Fatal("a file over the cap was not reported as cut short")
	}

	if int64(len(served)) != limit {
		t.Errorf("the cut returned %d bytes, want the cap of %d",
			len(served), limit)
	}
}

// The cut never lands inside a character, because a document ending in half of
// one is not text and would be refused by the check that follows it.
func TestTheCutDoesNotSplitACharacter(t *testing.T) {
	// Three bytes each, so a cap that is not a multiple of three falls inside
	// one of them.
	body := []byte(strings.Repeat("åäö", 4096))

	served, cut := project.ServeBytes(body, 1000)

	if !cut {
		t.Fatal("a file over the cap was not reported as cut short")
	}

	if !project.IsText(served) {
		t.Error("the cut left the contents invalid as text")
	}
}

// Binary content is recognised, which is what stops a kind somebody adds later
// from being cut in half and served as a document.
func TestBinaryContentIsNotText(t *testing.T) {
	if project.IsText([]byte("a document\x00with a NUL")) {
		t.Error("content with a NUL byte was taken for text")
	}

	if project.IsText([]byte{0xff, 0xfe, 0xfd}) {
		t.Error("content that is not UTF-8 was taken for text")
	}
}
