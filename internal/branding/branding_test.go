package branding_test

import (
	"bytes"
	"image"
	_ "image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/hugowetterberg/ladulas/internal/branding"
)

// masterIcon is the drawing everything else is derived from, and the thing the
// embedded copy is a downscale of.
const masterIcon = "icon-1024.png"

func TestTrayIconIsAPNG(t *testing.T) {
	t.Parallel()

	icon := branding.TrayIcon()

	if len(icon) == 0 {
		t.Fatal("there is no tray icon embedded")
	}

	if !bytes.HasPrefix(icon, []byte("\x89PNG\r\n\x1a\n")) {
		t.Error("the tray icon is not a PNG, and the bar decodes it as one")
	}

	config, format, err := image.DecodeConfig(bytes.NewReader(icon))
	if err != nil {
		t.Fatalf("decode the tray icon: %v", err)
	}

	if format != "png" {
		t.Errorf("the tray icon decodes as %s", format)
	}

	if config.Width != config.Height {
		t.Errorf("the tray icon is %dx%d; a tray draws it square",
			config.Width, config.Height)
	}
}

// The embedded icon is a downscale of the master, and a copy is a thing that
// goes stale. This is what makes it safe to keep one: replace the app icon
// without running `make icons` and this says so, in the words of what to do
// about it.
//
// It compares what survives scaling rather than bytes — a downscale is not
// reproducible across ImageMagick versions — which is enough to catch the
// failure that matters: a new drawing in one size and the old one in another.
//
// What it cannot catch is a copy of the master kept outside this repository:
// nothing here compares those, and going stale silently is what they do.
func TestTrayIconIsTheAppIcon(t *testing.T) {
	t.Parallel()

	master, err := os.ReadFile(filepath.Clean(masterIcon))
	if err != nil {
		t.Fatalf("the master icon is not beside the package that embeds it: %v", err)
	}

	want := blocks(t, master)
	got := blocks(t, branding.TrayIcon())

	for i := range want {
		for channel := range want[i] {
			if diff(want[i][channel], got[i][channel]) > tolerance {
				t.Fatalf(
					"the embedded tray icon is not a copy of %s any more "+
						"(block %d differs): run `make icons` to regenerate it",
					masterIcon, i)
			}
		}
	}
}

// tolerance is how far one block's average channel may drift. Scaling and
// PNG-writing move these by a few levels; a different picture moves them by
// dozens.
const tolerance = 12

// blocks is the average colour of each cell of a 4×4 grid over the image, which
// is a fingerprint of the composition: coarse enough to survive being scaled from
// 1024 to 128, specific enough that another drawing does not match it.
func blocks(t *testing.T, encoded []byte) [16][3]int {
	t.Helper()

	img, _, err := image.Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode an icon: %v", err)
	}

	bounds := img.Bounds()
	cellX := bounds.Dx() / 4
	cellY := bounds.Dy() / 4

	if cellX == 0 || cellY == 0 {
		t.Fatalf("an icon is %dx%d, which is too small to compare",
			bounds.Dx(), bounds.Dy())
	}

	var out [16][3]int

	for cell := range out {
		var sums [3]int64
		var count int64

		startX := bounds.Min.X + (cell%4)*cellX
		startY := bounds.Min.Y + (cell/4)*cellY

		for y := startY; y < startY+cellY; y++ {
			for x := startX; x < startX+cellX; x++ {
				r, g, b, _ := img.At(x, y).RGBA()

				sums[0] += int64(r >> 8)
				sums[1] += int64(g >> 8)
				sums[2] += int64(b >> 8)
				count++
			}
		}

		for channel := range out[cell] {
			out[cell][channel] = int(sums[channel] / count)
		}
	}

	return out
}

func diff(a, b int) int {
	if a > b {
		return a - b
	}

	return b - a
}
