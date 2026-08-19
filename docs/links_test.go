// Package docs holds the documentation set, and this test is what keeps it
// navigable.
//
// The four documents are held together by links between them — each one opens
// with a table of the other three, and every failure mode in ops.md names a
// metric defined in observability.md. A renamed heading breaks those silently:
// nothing fails to build, nothing fails to render, and the reader who followed
// the link lands at the top of a long document and gives up. So the links are
// checked mechanically, the same way the viewer bundle's self-containment is.
package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// documents are the files that link to each other, relative to this directory.
//
// CLAUDE.md is in the list without being one of the four: it is an index into
// them, so it is the file most made of links, and a stale one there sends an
// agent to the wrong place with no reader to notice.
var documents = []string{
	"../README.md",
	"../CLAUDE.md",
	"architecture.md",
	"ops.md",
	"observability.md",
}

// link matches an inline markdown link's target. Reference-style links are not
// used here and would need a second pass if they ever were.
var link = regexp.MustCompile(`\[[^\]]*\]\(([^)]+)\)`)

// heading matches an ATX heading, which is the only kind used in the set.
var heading = regexp.MustCompile(`(?m)^(#{1,6})\s+(.*?)\s*$`)

func TestLinksResolve(t *testing.T) {
	t.Parallel()

	// Keyed on the absolute path, because the same document is reached under
	// two names — `ops.md` from inside docs/ and `docs/ops.md` from the README
	// — and keying on what was written would leave half the anchors unchecked
	// while looking like it had checked them.
	anchors := map[string]map[string]bool{}

	for _, doc := range documents {
		anchors[abs(t, doc)] = anchorsOf(t, doc)
	}

	for _, doc := range documents {
		body := read(t, doc)
		dir := filepath.Dir(doc)

		for _, match := range link.FindAllStringSubmatch(body, -1) {
			target := strings.TrimSpace(match[1])

			// A link to somewhere else on the internet is not this test's to
			// check, and a bare fragment points into the document it is in.
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}

			path, fragment, _ := strings.Cut(target, "#")

			resolved := filepath.Clean(doc)
			if path != "" {
				resolved = filepath.Clean(filepath.Join(dir, path))
			}

			if _, err := os.Stat(resolved); err != nil {
				t.Errorf("%s links to %s, which does not exist", doc, target)

				continue
			}

			if fragment == "" {
				continue
			}

			known, checked := anchors[abs(t, resolved)]
			if !checked {
				// A fragment into a file outside the set — a source file, say —
				// is not something this test can resolve, and saying so is
				// better than passing on it quietly.
				t.Logf("%s links into %s, whose headings are not checked",
					doc, resolved)

				continue
			}

			if !known[fragment] {
				t.Errorf("%s links to %s, and no heading in %s produces #%s",
					doc, target, resolved, fragment)
			}
		}
	}
}

// anchorsOf returns every fragment the document's headings produce.
func anchorsOf(t *testing.T, doc string) map[string]bool {
	t.Helper()

	found := map[string]bool{}
	seen := map[string]int{}

	for _, match := range heading.FindAllStringSubmatch(read(t, doc), -1) {
		slug := slugify(match[2])
		if slug == "" {
			continue
		}

		// GitHub disambiguates a repeated heading by appending a counter, and
		// the set has repeated headings — every document carries the same
		// table of the others.
		if n := seen[slug]; n > 0 {
			found[slug+"-"+itoa(n)] = true
		} else {
			found[slug] = true
		}

		seen[slug]++
	}

	return found
}

// slugify is GitHub's heading-to-anchor rule: lowercase, drop everything that
// is not a letter, a digit, a space, a hyphen or an underscore, and turn the
// spaces into hyphens.
func slugify(text string) string {
	var b strings.Builder

	for _, r := range strings.ToLower(text) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		case r > 127:
			// Letters outside ASCII survive, which is what keeps a heading
			// with a Swedish å in it linkable.
			b.WriteRune(r)
		}
	}

	return b.String()
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}

	return itoa(n/10) + itoa(n%10)
}

func abs(t *testing.T, path string) string {
	t.Helper()

	full, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}

	return full
}

func read(t *testing.T, path string) string {
	t.Helper()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(body)
}
