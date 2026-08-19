// Package viewer is the shared approval viewer: one HTML/JS bundle that every
// Ladulås front end hosts in a webview (docs/architecture.md §12).
//
// The desktop serves it in Wails' webview; iOS will serve it from a WKWebView
// URL scheme handler and Android from a WebView asset loader. What makes that
// possible is that the bundle asks for nothing but its own origin: no
// framework, no CDN, no fetch to anywhere but the bridge, and a Content
// Security Policy that says so.
//
// There is no build step and nothing vendored. The bundle is the files in
// assets/ as they are written, which means `make viewer` has nothing to compile
// and the thing that ships is the thing that was reviewed. A dependency would
// have to earn its way in past that.
package viewer

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed assets
var assets embed.FS

// ContentSecurityPolicy is what the bundle is served under.
//
// Everything is denied by default and then only what the viewer genuinely uses
// is allowed back. The important part is that there is no 'unsafe-inline' for
// scripts and no host but 'self' anywhere: a diff, a commit message, or a
// published README (M4) is attacker-influenced text, and the policy is the
// backstop for the rendering code getting it wrong.
const ContentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"base-uri 'none'; " +
	"form-action 'none'; " +
	"frame-ancestors 'none'"

// bundle is the embedded directory rooted so that index.html is at the top.
// It is resolved once: the tree is fixed at build time and every request would
// otherwise walk it again.
var bundle = func() fs.FS {
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		// The directory is embedded at build time; its absence is not a runtime
		// condition.
		panic("viewer: the bundle is missing: " + err.Error())
	}

	return sub
}()

// FS is the bundle.
func FS() fs.FS {
	return bundle
}

// Handler serves the bundle.
//
// Every path that is not a file in the bundle serves index.html, because the
// viewer is one page that reads what to show from its address — a host opens
// /?request=<id> for one request in a popup, /?diff=<id> for a pane a phone
// pushed, and / for the desktop's application window, which takes its screen
// from the fragment (decision AA).
func Handler() http.Handler {
	files := http.FileServer(http.FS(FS()))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")

		if name != "" && !exists(name) {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}

		w.Header().Set("Content-Security-Policy", ContentSecurityPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")

		files.ServeHTTP(w, r)
	})
}

func exists(name string) bool {
	file, err := FS().Open(name)
	if err != nil {
		return false
	}

	_ = file.Close()

	return true
}
