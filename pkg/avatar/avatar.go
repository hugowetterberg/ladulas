// Package avatar draws a picture of a peer from its fingerprint.
//
// A fingerprint is the thing a person is asked to compare, and forty-odd
// base64 characters are exactly what a person does not compare. The picture is
// a second channel for noticing that one changed: two instances with different
// keys look nothing alike, and a row whose face is suddenly a stranger is worth
// a second look at the characters underneath it.
//
// It is decoration, not security. Nothing here is a check, nothing here is
// signed, and two fingerprints that draw the same face are a collision in a
// 32-bit hash rather than a collision in an identity key. The characters stay
// on screen beside the picture for that reason.
//
// The drawing is DiceBear (https://www.dicebear.com): a Loops pattern behind a
// Lorelei character, both seeded from the same string, composed here into one
// SVG. Both styles are CC0 and their definitions are vendored under styles/,
// rather than taken from github.com/dicebear/styles, because that module's own
// documentation is explicit that Go embeds every style it ships into the
// consuming binary — four megabytes of JSON in a phone app, for two of them.
package avatar

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
	"sync"

	dicebear "github.com/dicebear/dicebear-go/v10"
)

//go:embed styles/lorelei.json
var loreleiDefinition []byte

//go:embed styles/loops.json
var loopsDefinition []byte

// The character is drawn full width and pushed down far enough that the bottom
// of the bust runs off the bottom of the tile, which is what makes it read as
// somebody in front of the backdrop rather than as two pictures stacked.
// Everything is in the composed document's own hundred-unit coordinate system,
// and the numbers were chosen by looking at the result — see TestAvatarDemo.
const (
	canvas        = 100.0
	characterX    = 0.0
	characterY    = 14.0
	characterSize = 100.0
)

// SVG draws the seed, as a square SVG document with a viewBox of a hundred
// units and no fixed pixel size — the caller decides how big it is drawn.
//
// The same seed always draws the same picture, on every platform DiceBear has
// an implementation for. That is a property of the library rather than of this
// function, but it is the property the cache on the phone depends on.
func SVG(seed string) (string, error) {
	styles, err := loadStyles()
	if err != nil {
		return "", err
	}

	backdrop, err := layer(styles.loops, seed, "bg", nil)
	if err != nil {
		return "", fmt.Errorf("draw the backdrop: %w", err)
	}

	// Neither layer is given a background colour. Lorelei's default is no
	// background at all, which is what lets the scene show through it; asking
	// for one explicitly is not possible anyway, since the option takes a hex
	// colour and there is no hex for "leave it alone".
	character, err := layer(styles.lorelei, seed, "fg", nil)
	if err != nil {
		return "", fmt.Errorf("draw the character: %w", err)
	}

	var out strings.Builder

	fmt.Fprintf(&out,
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %g %g" `+
			`fill="none" shape-rendering="auto">`, canvas, canvas)

	// Placed rather than scaled through the style's own scale option: a nested
	// svg keeps each layer's own coordinate system, so neither drawing has to
	// know anything about the other or about the tile they end up in.
	out.WriteString(place(backdrop, 0, 0, canvas, canvas, "xMidYMid slice"))
	out.WriteString(place(character,
		characterX, characterY, characterSize, characterSize, "xMidYMid meet"))

	out.WriteString(`</svg>`)

	return out.String(), nil
}

type styleSet struct {
	lorelei *dicebear.Style
	loops   *dicebear.Style
}

// loadStyles parses the two definitions once. Parsing is the expensive half of
// drawing one of these and the definitions never change, so a list of peers
// pays for it on its first row and not again.
var loadStyles = sync.OnceValues(func() (*styleSet, error) {
	lorelei, err := dicebear.NewStyle(loreleiDefinition)
	if err != nil {
		return nil, fmt.Errorf("read the lorelei style: %w", err)
	}

	loops, err := dicebear.NewStyle(loopsDefinition)
	if err != nil {
		return nil, fmt.Errorf("read the loops style: %w", err)
	}

	return &styleSet{lorelei: lorelei, loops: loops}, nil
})

// drawing is one rendered style, taken apart far enough to be nested in another
// document: the root element's attributes, and everything between the root tags.
type drawing struct {
	attributes []attribute
	body       string
}

// layer renders one style and namespaces every identifier in it.
//
// DiceBear already suffixes its identifiers with a hash of the style and the
// seed, so today the two layers do not collide. Composing two documents into
// one is not the place to depend on that: a clip path that quietly resolved to
// the other layer's would be a drawing that is wrong rather than a build that
// fails.
func layer(
	style *dicebear.Style, seed, prefix string, options map[string]any,
) (drawing, error) {
	opts := map[string]any{"seed": seed}

	for key, value := range options {
		opts[key] = value
	}

	rendered, err := dicebear.NewAvatar(style, opts)
	if err != nil {
		return drawing{}, err
	}

	attributes, body, err := splitRoot(rendered.SVG())
	if err != nil {
		return drawing{}, err
	}

	return drawing{
		attributes: attributes,
		body:       namespaceIDs(body, prefix),
	}, nil
}

// place nests a drawing at a position in the composed document.
func place(
	d drawing, x, y, width, height float64, aspect string,
) string {
	var out strings.Builder

	out.WriteString(`<svg`)

	for _, attr := range d.attributes {
		// The position and the size are this document's business, and a layer
		// that brought its own would be a duplicate attribute, which is not
		// valid XML rather than merely ignored.
		switch attr.name {
		case "x", "y", "width", "height", "preserveAspectRatio":
			continue
		}

		fmt.Fprintf(&out, ` %s="%s"`, attr.name, attr.value)
	}

	fmt.Fprintf(&out, ` x="%g" y="%g" width="%g" height="%g"`+
		` preserveAspectRatio="%s">`, x, y, width, height, aspect)

	out.WriteString(d.body)
	out.WriteString(`</svg>`)

	return out.String()
}

type attribute struct {
	name  string
	value string
}

// splitRoot takes a rendered document apart at its root element.
//
// It scans for the end of the start tag rather than parsing the document,
// because the alternative is decoding and re-encoding it: Go's XML encoder
// rewrites namespace declarations, and a drawing is not something to hand
// through a round trip that is allowed to change it.
func splitRoot(svg string) ([]attribute, string, error) {
	open := strings.Index(svg, "<svg")
	if open < 0 {
		return nil, "", fmt.Errorf("no root element in the drawing")
	}

	attributes, end, err := parseAttributes(svg[open+len("<svg"):])
	if err != nil {
		return nil, "", err
	}

	body := svg[open+len("<svg")+end:]

	closing := strings.LastIndex(body, "</svg>")
	if closing < 0 {
		return nil, "", fmt.Errorf("the root element of the drawing never ends")
	}

	return attributes, body[:closing], nil
}

// parseAttributes reads a start tag's attributes and returns how far it got,
// which is one past the tag's closing angle bracket. It exists so that an
// angle bracket inside an attribute value — a license text is free-form, and
// these carry one — does not look like the end of the tag.
func parseAttributes(s string) ([]attribute, int, error) {
	var attributes []attribute

	i := 0

	for i < len(s) {
		for i < len(s) && isSpace(s[i]) {
			i++
		}

		if i < len(s) && s[i] == '>' {
			return attributes, i + 1, nil
		}

		name := i

		for i < len(s) && s[i] != '=' && !isSpace(s[i]) && s[i] != '>' {
			i++
		}

		if i >= len(s) || s[i] != '=' {
			return nil, 0, fmt.Errorf(
				"attribute %q in the drawing has no value", s[name:i])
		}

		i++

		if i >= len(s) || (s[i] != '"' && s[i] != '\'') {
			return nil, 0, fmt.Errorf(
				"attribute %q in the drawing is not quoted", s[name:i])
		}

		quote := s[i]
		i++
		value := i

		for i < len(s) && s[i] != quote {
			i++
		}

		if i >= len(s) {
			return nil, 0, fmt.Errorf(
				"attribute %q in the drawing is never closed", s[name:value])
		}

		attributes = append(attributes, attribute{
			name:  s[name : value-2],
			value: s[value:i],
		})

		i++
	}

	return nil, 0, fmt.Errorf("the root element of the drawing never opens")
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

var (
	idPattern   = regexp.MustCompile(`\bid="([^"]*)"`)
	urlPattern  = regexp.MustCompile(`url\(#([^)"]*)\)`)
	hrefPattern = regexp.MustCompile(`\b(xlink:href|href)="#([^"]*)"`)
	metadata    = regexp.MustCompile(`(?s)<metadata\b.*?</metadata>`)
)

// namespaceIDs prefixes every identifier in a layer and every reference to one.
//
// The metadata block is left alone. It is prose — a licence, a title, the URL
// somebody's original is at — and prose that happens to contain the letters
// id= is prose rather than a reference to anything.
func namespaceIDs(body, prefix string) string {
	spans := metadata.FindAllStringIndex(body, -1)

	var (
		out  strings.Builder
		last int
	)

	for _, span := range spans {
		out.WriteString(rewriteIDs(body[last:span[0]], prefix))
		out.WriteString(body[span[0]:span[1]])

		last = span[1]
	}

	out.WriteString(rewriteIDs(body[last:], prefix))

	return out.String()
}

func rewriteIDs(s, prefix string) string {
	s = idPattern.ReplaceAllString(s, `id="`+prefix+`-$1"`)
	s = urlPattern.ReplaceAllString(s, `url(#`+prefix+`-$1)`)
	s = hrefPattern.ReplaceAllString(s, `$1="#`+prefix+`-$2"`)

	return s
}
