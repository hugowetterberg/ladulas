package avatar_test

import (
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/avatar"
)

var (
	identifier = regexp.MustCompile(`\bid="([^"]*)"`)
	reference  = regexp.MustCompile(`(?:url\(#|href="#)([^)"]*)`)
)

// seeds are shaped like the fingerprints these are drawn from.
var seeds = []string{
	"SHA256:2m9Kx7pQrLd8vTzYb1cWnHjE4sUaFgRiOoPl3XkNvBw",
	"SHA256:aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefgh",
	"SHA256:Zq1Wr2Et3Yu4Io5Pa6Sd7Fg8Hj9Kl0ZxCvBnMqWeRtY",
	"SHA256:9f8e7d6c5b4a3210FEDCBA9876543210zyxwvutsrqpo",
	"SHA256:LadulasGuppyDesktopKeyFingerprintExample0012",
	"SHA256:PhoneIdentityKeyFingerprintExampleTwo002xyzA",
}

func TestSVGIsWellFormed(t *testing.T) {
	for _, seed := range seeds {
		drawn, err := avatar.SVG(seed)
		if err != nil {
			t.Fatalf("draw %q: %v", seed, err)
		}

		decoder := xml.NewDecoder(strings.NewReader(drawn))

		for {
			_, err := decoder.Token()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}

				t.Fatalf("the drawing for %q is not well-formed XML: %v",
					seed, err)
			}
		}
	}
}

// The seed decides the picture and nothing else does. The cache on the phone is
// keyed on the fingerprint and never invalidated, so a drawing that varied
// between calls would be a face that changed when the cache was cleared — the
// one thing the picture is there to make people notice.
func TestSVGIsDeterministic(t *testing.T) {
	first, err := avatar.SVG(seeds[0])
	if err != nil {
		t.Fatalf("draw: %v", err)
	}

	second, err := avatar.SVG(seeds[0])
	if err != nil {
		t.Fatalf("draw again: %v", err)
	}

	if first != second {
		t.Fatal("the same seed drew two different pictures")
	}

	other, err := avatar.SVG(seeds[1])
	if err != nil {
		t.Fatalf("draw another: %v", err)
	}

	if first == other {
		t.Fatal("two seeds drew the same picture")
	}
}

// Both layers have to be in there, and the character has to be in front. A
// composition that silently lost one would still be a valid SVG of a pattern.
func TestSVGHasBothLayers(t *testing.T) {
	drawn, err := avatar.SVG(seeds[0])
	if err != nil {
		t.Fatalf("draw: %v", err)
	}

	backdrop := strings.Index(drawn, "<dc:title>Loops</dc:title>")
	character := strings.Index(drawn, "<dc:title>Lorelei</dc:title>")

	if backdrop < 0 {
		t.Fatal("the backdrop is not in the drawing")
	}

	if character < 0 {
		t.Fatal("the character is not in the drawing")
	}

	if backdrop > character {
		t.Fatal("the backdrop is drawn over the character")
	}
}

// Every identifier belongs to exactly one layer. Two documents composed into
// one share an identifier space, and a clip path that resolved to the other
// layer's would be a drawing that is wrong rather than a build that fails.
func TestSVGIdentifiersAreNamespaced(t *testing.T) {
	drawn, err := avatar.SVG(seeds[0])
	if err != nil {
		t.Fatalf("draw: %v", err)
	}

	seen := map[string]bool{}

	for _, match := range identifier.FindAllStringSubmatch(drawn, -1) {
		id := match[1]

		if seen[id] {
			t.Fatalf("identifier %q is declared twice", id)
		}

		seen[id] = true

		if !strings.HasPrefix(id, "bg-") && !strings.HasPrefix(id, "fg-") {
			t.Fatalf("identifier %q belongs to no layer", id)
		}
	}

	if len(seen) == 0 {
		t.Fatal("the drawing declares no identifiers at all")
	}

	// Every reference has to resolve, or the rewrite renamed a declaration and
	// left the thing pointing at it behind.
	for _, match := range reference.FindAllStringSubmatch(drawn, -1) {
		if !seen[match[1]] {
			t.Fatalf("nothing in the drawing declares %q", match[1])
		}
	}
}

// A drawing carries its licences. Both styles are CC0 and both ask to be
// credited, and the credit travels inside the SVG rather than beside it.
func TestSVGKeepsItsAttribution(t *testing.T) {
	drawn, err := avatar.SVG(seeds[0])
	if err != nil {
		t.Fatalf("draw: %v", err)
	}

	for _, want := range []string{"Lisa Wischofsky", "DiceBear", "CC0 1.0"} {
		if !strings.Contains(drawn, want) {
			t.Errorf("the drawing does not credit %q", want)
		}
	}
}

// demoDirEnv turns TestAvatarDemo into a way of looking at these.
const demoDirEnv = "LADULAS_AVATAR_DEMO"

// TestAvatarDemo writes the sample drawings somewhere they can be looked at,
// which is the only way to review a change to how they are composed:
//
//	LADULAS_AVATAR_DEMO=/tmp/avatars go test ./pkg/avatar/ \
//	    -run TestAvatarDemo -v
//
// then rasterise them — rsvg-convert, or any browser — and see whether a face
// forty-four points across is still a face.
func TestAvatarDemo(t *testing.T) {
	dir := os.Getenv(demoDirEnv)
	if dir == "" {
		t.Skipf("set %s to a directory to write the drawings to", demoDirEnv)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("make the directory: %v", err)
	}

	for i, seed := range seeds {
		drawn, err := avatar.SVG(seed)
		if err != nil {
			t.Fatalf("draw %q: %v", seed, err)
		}

		name := filepath.Join(dir, "avatar-"+string(rune('a'+i))+".svg")

		if err := os.WriteFile(name, []byte(drawn), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}

		t.Log(name)
	}
}
