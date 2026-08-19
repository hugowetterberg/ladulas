package viewer_test

import (
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"

	"github.com/hugowetterberg/ladulas/viewer"
)

// The bundle is local content only (§12), and these are the properties that
// keep it that way. They are worth asserting rather than reviewing, because
// pasting a CDN link into an HTML file is exactly the kind of thing that gets
// done in a hurry and noticed a year later.
func TestBundleIsSelfContained(t *testing.T) {
	t.Parallel()

	remote := regexp.MustCompile(`(?i)(https?:)?//[a-z0-9.-]+\.[a-z]{2,}`)

	forEachFile(t, func(name, body string) {
		if match := remote.FindString(withoutSVGNamespace(body)); match != "" {
			t.Errorf("%s refers to a remote resource: %q", name, match)
		}

		for _, forbidden := range []string{
			"innerHTML",
			"outerHTML",
			"insertAdjacentHTML",
			"document.write",
			"eval(",
			"new Function(",
		} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s uses %s; the viewer renders untrusted text and "+
					"builds every node with textContent", name, forbidden)
			}
		}
	})
}

// No inline script or style, because the Content Security Policy has no
// 'unsafe-inline' and the page would simply not work.
func TestHTMLHasNoInlineCode(t *testing.T) {
	t.Parallel()

	body := read(t, "index.html")

	if strings.Contains(body, "<script>") {
		t.Error("index.html has an inline script")
	}

	if strings.Contains(body, "<style") {
		t.Error("index.html has an inline stylesheet")
	}

	if !strings.Contains(body, `src="/app.js"`) {
		t.Error("index.html does not load the bundle")
	}

	for _, attribute := range []string{"onclick=", "onload=", "onerror="} {
		if strings.Contains(body, attribute) {
			t.Errorf("index.html has an inline %s handler", attribute)
		}
	}
}

// Every module the bundle imports has to be in the bundle. A typo here is a
// blank window with a console error nobody sees.
func TestEveryImportResolves(t *testing.T) {
	t.Parallel()

	// Anchored to the start of a line, because "from" is an ordinary English
	// word and the bundle has sentences in it.
	imports := regexp.MustCompile(`(?m)^\s*(?:import|export)\b[^"\n]*\bfrom\s+"([^"]+)"`)

	forEachFile(t, func(name, body string) {
		if !strings.HasSuffix(name, ".js") {
			return
		}

		for _, match := range imports.FindAllStringSubmatch(body, -1) {
			target := match[1]

			if !strings.HasPrefix(target, "./") && !strings.HasPrefix(target, "/") {
				t.Errorf("%s imports %q, which is not a path in the bundle",
					name, target)

				continue
			}

			resolved := path.Join(path.Dir(name), strings.TrimPrefix(target, "./"))

			if _, err := fs.Stat(viewer.FS(), resolved); err != nil {
				t.Errorf("%s imports %q, which is not there", name, target)
			}
		}
	})
}

func TestPolicyDeniesByDefault(t *testing.T) {
	t.Parallel()

	if !strings.HasPrefix(viewer.ContentSecurityPolicy, "default-src 'none'") {
		t.Errorf("the policy does not start by denying everything: %q",
			viewer.ContentSecurityPolicy)
	}

	if strings.Contains(viewer.ContentSecurityPolicy, "unsafe-inline") ||
		strings.Contains(viewer.ContentSecurityPolicy, "unsafe-eval") {
		t.Errorf("the policy allows unsafe sources: %q", viewer.ContentSecurityPolicy)
	}
}

// svgNamespace is the one URL-shaped string in the bundle that is not a
// resource. `document.createElementNS` takes it as the name of a namespace and
// nothing ever fetches it — there is no request to make and no host to reach —
// but it is spelled like a link, so the check above would read the icons in
// ui.js as a CDN. It is taken out by exact match, with its quotes, so that any
// other URL in any other place still fails: the property being asserted is that
// the bundle asks nothing of the network, and an XML namespace does not.
const svgNamespace = `"http://www.w3.org/2000/svg"`

func withoutSVGNamespace(body string) string {
	return strings.ReplaceAll(body, svgNamespace, `"svg"`)
}

func forEachFile(t *testing.T, check func(name, body string)) {
	t.Helper()

	err := fs.WalkDir(viewer.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if entry.IsDir() {
			return nil
		}

		check(name, read(t, name))

		return nil
	})
	if err != nil {
		t.Fatalf("walk the bundle: %v", err)
	}
}

func read(t *testing.T, name string) string {
	t.Helper()

	body, err := fs.ReadFile(viewer.FS(), name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	return string(body)
}
