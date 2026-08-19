package bridge

import (
	"fmt"
	"net/http"
	"strings"

	"rsc.io/qr"
)

// The pairing QR, and why it is drawn here.
//
// The code a QR carries has been specified since M3 and the phone has read one
// since M6 (§7): the secret, the displaying instance's identity key and its
// addresses, so a camera is the integrity root and there is nothing left for
// anybody to compare character by character. Nothing rendered one. A headless
// box printed the string and the `qrencode` command line to turn it into a
// picture, which is a reasonable thing to ask of somebody with a terminal open
// and an absurd thing to ask of somebody looking at a window.
//
// The open question (§19, decision AE) was where the drawing comes from, and
// the answer is a Go dependency rather than a viewer one. The bundle stays
// dependency-free, which is a property its tests assert; the picture is drawn
// where the code already is, by the same shape of route the avatar uses; and
// the phone gets it for nothing, being the other host of this same handler.
//
// rsc.io/qr encodes at a fixed mask rather than choosing the one with the
// lowest penalty. That is a legal QR either way — the mask is in the format
// bits, and readers read whichever is there — so it costs contrast in the worst
// case and nothing else.

// qrQuietZone is the four modules of blank the standard requires around a
// symbol. Drawn as part of the picture rather than left to the page, because a
// QR flush against a dark background is one a camera will not find.
const qrQuietZone = 4

// qrSVG draws a QR for text, at one unit per module.
//
// It is a vector rather than a bitmap so that a window can scale it to whatever
// space it has: a pairing code is read by a phone camera held at arm's length,
// and a picture that is 65 pixels across is not one.
func qrSVG(text string) (string, error) {
	if text == "" {
		return "", fmt.Errorf("bridge: nothing to draw")
	}

	// Level M — the middle of the four, and the one a code this long fits at.
	// A pairing code is read once, at arm's length, off a lit screen, so the
	// stronger levels would buy resilience nothing here needs and spend it on a
	// bigger symbol.
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", fmt.Errorf("bridge: draw the pairing code: %w", err)
	}

	side := code.Size + 2*qrQuietZone

	var path strings.Builder

	for y := range code.Size {
		for x := range code.Size {
			if !code.Black(x, y) {
				continue
			}

			fmt.Fprintf(&path, "M%d %dh1v1h-1z", x+qrQuietZone, y+qrQuietZone)
		}
	}

	var svg strings.Builder

	fmt.Fprintf(&svg,
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" `+
			`shape-rendering="crispEdges" role="img" `+
			`aria-label="Pairing code">`, side, side)
	fmt.Fprintf(&svg, `<rect width="%d" height="%d" fill="#ffffff"/>`, side, side)
	fmt.Fprintf(&svg, `<path fill="#000000" d="%s"/>`, path.String())
	svg.WriteString(`</svg>`)

	return svg.String(), nil
}

// handlePairingQR draws a pairing code for a camera.
//
// Unlike the avatar route beside it, this one is emphatically not cacheable.
// The string it draws is a secret with five minutes to live, single use and
// attempt capped (§7) — a copy of it sitting in a cache after the window has
// closed is the one thing a picture of it must not leave behind.
func (s *Session) handlePairingQR(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	drawn, err := qrSVG(code)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())

		return
	}

	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	_, _ = w.Write([]byte(drawn))
}
