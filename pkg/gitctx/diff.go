package gitctx

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Limits bound how much of a diff travels with a signing request.
//
// A diff is attacker-influenced text that ends up in an approval prompt on
// somebody's phone, and an unbounded one is both a denial of service and an
// invitation to bury the interesting change under ten thousand generated lines.
// The caps are generous enough that an ordinary commit arrives whole and small
// enough that a vendored dependency update does not.
type Limits struct {
	// Bytes caps the raw output read from git diff.
	Bytes int
	// Files caps how many files keep their hunks.
	Files int
	// LinesPerFile caps the hunk lines kept for one file.
	LinesPerFile int
	// TotalLines caps the hunk lines kept across all files.
	TotalLines int
	// LineLength caps one line of a hunk; longer lines are cut with an ellipsis.
	LineLength int
}

// DefaultLimits are what ladulas-sign uses unless told otherwise.
var DefaultLimits = Limits{
	Bytes:        1 << 20,
	Files:        200,
	LinesPerFile: 2000,
	TotalLines:   20000,
	LineLength:   2000,
}

func (l Limits) withDefaults() Limits {
	if l.Bytes <= 0 {
		l.Bytes = DefaultLimits.Bytes
	}

	if l.Files <= 0 {
		l.Files = DefaultLimits.Files
	}

	if l.LinesPerFile <= 0 {
		l.LinesPerFile = DefaultLimits.LinesPerFile
	}

	if l.TotalLines <= 0 {
		l.TotalLines = DefaultLimits.TotalLines
	}

	if l.LineLength <= 0 {
		l.LineLength = DefaultLimits.LineLength
	}

	return l
}

// ParseDiff turns `git diff` output into the structured form the viewer
// renders (§12).
//
// The parse happens here rather than in JavaScript on purpose: the approval UI
// is showing content an attacker chose, and a dumb renderer over typed data has
// a much smaller surface than a parser written in the browser.
func ParseDiff(raw []byte, limits Limits) *ladulasv1.GitDiff {
	limits = limits.withDefaults()

	p := &diffParser{limits: limits, diff: &ladulasv1.GitDiff{}}
	p.run(string(raw))
	p.finish()

	return p.diff
}

type diffParser struct {
	limits Limits
	diff   *ladulasv1.GitDiff

	file *ladulasv1.GitDiffFile
	hunk *ladulasv1.GitDiffHunk

	fileLines  int
	totalLines int

	droppedFiles  int
	droppedLines  int
	lineTruncated bool
}

func (p *diffParser) run(raw string) {
	for line := range strings.SplitSeq(strings.TrimSuffix(raw, "\n"), "\n") {
		p.line(line)
	}
}

func (p *diffParser) line(line string) {
	switch {
	case strings.HasPrefix(line, "diff --git "):
		p.startFile(line)
	case p.file == nil:
		// Anything before the first file header is git chatter we have no use
		// for; the numstat pass is where the counts come from.
	case strings.HasPrefix(line, "@@"):
		p.startHunk(line)
	case p.hunk != nil:
		p.hunkLine(line)
	default:
		p.fileHeaderLine(line)
	}
}

func (p *diffParser) startFile(line string) {
	p.closeFile()

	if len(p.diff.GetFiles()) >= p.limits.Files {
		p.droppedFiles++
		p.file = nil

		return
	}

	old, current := splitDiffHeader(line)

	p.file = &ladulasv1.GitDiffFile{
		OldPath: old,
		NewPath: current,
		Status:  "modified",
	}
	p.hunk = nil
	p.fileLines = 0
}

// splitDiffHeader reads the paths out of `diff --git a/old b/new`.
//
// The header is ambiguous for paths containing " b/", and git resolves that by
// quoting such paths; the ambiguous remainder is rare enough that falling back
// to the whole string is better than guessing wrong.
func splitDiffHeader(line string) (string, string) {
	rest := strings.TrimPrefix(line, "diff --git ")

	if index := strings.Index(rest, " b/"); index >= 0 {
		return strings.TrimPrefix(rest[:index], "a/"),
			strings.TrimPrefix(rest[index+1:], "b/")
	}

	return rest, rest
}

func (p *diffParser) fileHeaderLine(line string) {
	switch {
	case strings.HasPrefix(line, "new file mode "):
		p.file.Status = "added"
	case strings.HasPrefix(line, "deleted file mode "):
		p.file.Status = "removed"
	case strings.HasPrefix(line, "rename to "):
		p.file.Status = "renamed"
		p.file.NewPath = strings.TrimPrefix(line, "rename to ")
	case strings.HasPrefix(line, "rename from "):
		p.file.Status = "renamed"
		p.file.OldPath = strings.TrimPrefix(line, "rename from ")
	case strings.HasPrefix(line, "copy to "):
		p.file.Status = "copied"
		p.file.NewPath = strings.TrimPrefix(line, "copy to ")
	case strings.HasPrefix(line, "copy from "):
		p.file.Status = "copied"
		p.file.OldPath = strings.TrimPrefix(line, "copy from ")
	case strings.HasPrefix(line, "old mode "):
		p.file.ModeChange = strings.TrimPrefix(line, "old mode ")
	case strings.HasPrefix(line, "new mode "):
		p.file.ModeChange = strings.TrimSpace(
			p.file.GetModeChange() + " → " + strings.TrimPrefix(line, "new mode "))
	case strings.HasPrefix(line, "Binary files ") ||
		strings.HasPrefix(line, "GIT binary patch"):
		p.file.Binary = true
	}
}

func (p *diffParser) startHunk(line string) {
	if p.fileLines >= p.limits.LinesPerFile || p.totalLines >= p.limits.TotalLines {
		p.file.Truncated = true
		p.hunk = nil

		return
	}

	p.hunk = &ladulasv1.GitDiffHunk{Header: p.clip(line)}
	p.file.Hunks = append(p.file.GetHunks(), p.hunk)
}

func (p *diffParser) hunkLine(line string) {
	if p.fileLines >= p.limits.LinesPerFile || p.totalLines >= p.limits.TotalLines {
		p.file.Truncated = true
		p.droppedLines++

		return
	}

	var (
		kind ladulasv1.GitDiffLineKind
		text string
	)

	switch {
	case strings.HasPrefix(line, "+"):
		kind = ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_ADDED
		text = line[1:]
	case strings.HasPrefix(line, "-"):
		kind = ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_REMOVED
		text = line[1:]
	case strings.HasPrefix(line, " "):
		kind = ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_CONTEXT
		text = line[1:]
	case strings.HasPrefix(line, "\\"):
		// "\ No newline at end of file".
		kind = ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_NOTE
		text = strings.TrimSpace(line[1:])
	default:
		// A line that belongs to no hunk ends it; git puts the next file's
		// header or a trailing marker here.
		p.hunk = nil

		return
	}

	p.hunk.Lines = append(p.hunk.GetLines(), &ladulasv1.GitDiffLine{
		Kind: kind,
		Text: p.clip(text),
	})

	p.fileLines++
	p.totalLines++
}

// clip cuts a single very long line, which is what a minified bundle or a
// base64 blob looks like to a diff.
func (p *diffParser) clip(text string) string {
	if len(text) <= p.limits.LineLength {
		return text
	}

	p.lineTruncated = true

	// Cut on a rune boundary; a diff is bytes and half a character in an
	// approval prompt looks like a bug in Ladulås rather than a long line.
	cut := p.limits.LineLength
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}

	return text[:cut] + "…"
}

func (p *diffParser) closeFile() {
	if p.file == nil {
		return
	}

	p.diff.Files = append(p.diff.GetFiles(), p.file)
	p.file = nil
	p.hunk = nil
}

func (p *diffParser) finish() {
	p.closeFile()

	var notes []string

	if p.droppedFiles > 0 {
		p.diff.Truncated = true
		notes = append(notes, fmt.Sprintf(
			"%d more files are not shown", p.droppedFiles))
	}

	if p.droppedLines > 0 {
		p.diff.Truncated = true
		notes = append(notes, fmt.Sprintf(
			"%d lines were left out to keep the diff a readable size", p.droppedLines))
	}

	if p.lineTruncated {
		p.diff.Truncated = true

		notes = append(notes, "some very long lines were cut")
	}

	p.diff.TruncationNote = strings.Join(notes, "; ")
}

// applyNumstat fills in the per-file and total insertion and deletion counts
// from `git diff --numstat -z`.
//
// They are collected separately from the patch so that the numbers stay right
// when the patch itself was capped: a prompt that says "3 files changed" and
// shows one of them is honest, one that says "1 file changed" is not.
func applyNumstat(diff *ladulasv1.GitDiff, raw []byte) {
	byPath := map[string]*ladulasv1.GitDiffFile{}

	for _, file := range diff.GetFiles() {
		byPath[file.GetNewPath()] = file
	}

	for _, entry := range parseNumstat(raw) {
		diff.FilesChanged++
		diff.Insertions += entry.insertions
		diff.Deletions += entry.deletions

		file, ok := byPath[entry.path]
		if !ok {
			continue
		}

		file.Insertions = entry.insertions
		file.Deletions = entry.deletions
		file.Binary = file.GetBinary() || entry.binary
	}
}

type numstatEntry struct {
	insertions int32
	deletions  int32
	binary     bool
	path       string
}

// parseNumstat reads the NUL-separated numstat form. Renames are three records
// rather than one — the counts and an empty path, then the old and new names —
// which is exactly why the NUL form is worth using over the quoted one.
func parseNumstat(raw []byte) []numstatEntry {
	fields := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")

	var entries []numstatEntry

	for i := 0; i < len(fields); i++ {
		if fields[i] == "" {
			continue
		}

		parts := strings.SplitN(fields[i], "\t", 3)
		if len(parts) != 3 {
			continue
		}

		entry := numstatEntry{
			insertions: countOr(parts[0]),
			deletions:  countOr(parts[1]),
			binary:     parts[0] == "-" && parts[1] == "-",
			path:       parts[2],
		}

		if entry.path == "" && i+2 < len(fields) {
			// A rename: the old name, then the new one.
			entry.path = fields[i+2]
			i += 2
		}

		entries = append(entries, entry)
	}

	return entries
}

func countOr(field string) int32 {
	n, err := strconv.ParseInt(field, 10, 32)
	if err != nil {
		// A binary file has "-" where the counts would be.
		return 0
	}

	return int32(n)
}
