package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/hugowetterberg/ladulas/pkg/bridge"
)

// The card, drawn as lines.
//
// It is the same card the desktop draws, from the same JSON: `renderCard` here
// and `renderCard` in viewer/assets/cards.js are two renderings of one
// RequestView, and neither of them parses anything. That is the rule §5 sets
// and the reason the parsing is in Go — a second surface answering signing
// requests is a second chance to disagree about what a commit says, and the
// only way not to take it is to have nothing here that could decide differently.
//
// Where it parts from the window is the diff. The window draws every file as a
// disclosure the reader opens in place; here the card lists the files and
// nothing else, and one file's hunks are a screen of their own (decision AN).
// Two things follow and both are the reason. The card is the same length
// whatever the change is, so the facts a decision rests on cannot be pushed off
// the screen by a commit that touched thirty files. And reading a file is
// somewhere you go, which is what lets `enter` mean "approve" on the card
// without meaning it while somebody is scrolling through the change.

// builder collects lines at a width.
type builder struct {
	lines []string
	width int
	st    *styles
}

func (b *builder) push(text string) {
	b.lines = append(b.lines, text)
}

func (b *builder) blank() {
	if len(b.lines) == 0 {
		return
	}

	// One blank line between blocks and never two, so that a card with several
	// empty sections does not open with a screen of nothing.
	if strings.TrimSpace(b.lines[len(b.lines)-1]) == "" {
		return
	}

	b.push("")
}

// wrap adds prose, broken at the width and never through a word.
func (b *builder) wrap(style lipgloss.Style, text string) {
	if text == "" {
		return
	}

	for _, line := range strings.Split(
		ansi.Wordwrap(text, max(b.width, 20), " -"), "\n") {
		b.push(style.Render(line))
	}
}

// cut adds one line that is truncated rather than wrapped, which is what a diff
// line and a path want: a wrapped diff stops looking like a diff.
func (b *builder) cut(style lipgloss.Style, text string) {
	b.push(style.Render(ansi.Truncate(text, max(b.width, 20), "…")))
}

// factWidth is the label column. Wide enough for "Fingerprint" and "Requested
// by", which are the longest labels any card uses.
const factWidth = 13

// fact is one labelled line, wrapped under a hanging indent so that a long
// value stays in its column.
func (b *builder) fact(label, value string, asserted bool) {
	if value == "" {
		return
	}

	if asserted {
		value += " " + b.st.asserted.Render("(the requester's word)")
	}

	head := b.st.label.Render(fmt.Sprintf("%-*s", factWidth, label))
	indent := strings.Repeat(" ", factWidth)
	body := ansi.Wordwrap(value, max(b.width-factWidth, 20), " -/")

	for i, line := range strings.Split(body, "\n") {
		if i == 0 {
			b.push(head + line)

			continue
		}

		b.push(indent + line)
	}
}

func (b *builder) heading(text string) {
	b.blank()
	b.push(b.st.heading.Render(text))
}

// renderCard draws the whole card: what is being asked, on what, by whom, with
// which key, and which files the change touches.
func renderCard(st *styles, view bridge.RequestView, width int) []string {
	b := &builder{width: width, st: st}

	b.wrap(st.title, view.Title)
	b.wrap(st.subject, view.Subject)

	for _, warning := range view.Warnings {
		b.blank()

		style := st.warning
		if view.Danger {
			style = st.danger
		}

		b.wrap(style, "! "+warning)
	}

	switch view.Kind {
	case "git-sign":
		renderGit(b, view)
	case "ssh-auth":
		renderSSHAuth(b, view)
	case "sshsig":
		renderSshsig(b, view)
	case "opaque-sign":
		renderOpaque(b, view)
	case "pairing":
		renderPairing(b, view)
	default:
		renderGeneric(b, view)
	}

	renderCommon(b, view)
	renderTrust(b, view)

	if diff := diffOf(view); diff != nil {
		renderChanges(b, diff)
	}

	return b.lines
}

// renderCommon is the key and who is asking, which every card carries and which
// the window draws in the same place for the same reason: they are the two
// facts that do not depend on what kind of request this is (decision W).
func renderCommon(b *builder, view bridge.RequestView) {
	if view.Key == nil && view.Requester == nil {
		return
	}

	b.blank()

	if key := view.Key; key != nil {
		label := key.Label

		if key.Comment != "" {
			label = fmt.Sprintf("%s (%s)", label, key.Comment)
		}

		if label == "" {
			label = key.Fingerprint
		}

		b.fact("Key", label, false)
		b.fact("Fingerprint", key.Fingerprint, false)
		b.fact("Algorithm", key.Algorithm, false)
	}

	who := view.Requester
	if who == nil {
		return
	}

	b.fact("Program", who.Program, false)
	b.fact("Asked by", who.Asker, false)
	b.fact("Started by", who.Chain, false)

	if !who.Local {
		b.fact("Requested by", who.Name, false)
		b.fact("Connected from", who.Address, false)
	}
}

// renderTrust is the note a timed promise carries when its scope would rest on
// something the requesting machine only asserted (decision X).
//
// It is in the card rather than beside the length, which is where the window
// puts it and for the same reason: it is prose to be read before deciding to
// make a promise, not a label on the control that makes one.
func renderTrust(b *builder, view bridge.RequestView) {
	if view.Grant == nil || view.Grant.Trust == nil {
		return
	}

	trust := view.Grant.Trust

	b.heading("Before you promise anything")

	for _, fact := range trust.Facts {
		b.fact(fact.Label, fact.Value, fact.Asserted)
	}

	b.wrap(b.st.warning, trust.Note)
	b.wrap(b.st.note, trust.Detail)
}

func renderGit(b *builder, view bridge.RequestView) {
	git := view.Git
	if git == nil {
		// The plain agent socket only ever saw a digest, which is the whole
		// reason ladulas-sign exists (§5).
		b.blank()

		if sig := view.Sshsig; sig != nil {
			b.fact("Digest", sig.Digest, false)
			b.fact("Namespace", sig.Namespace, false)
		}

		return
	}

	b.blank()

	if !git.Verified {
		problem := git.VerificationError
		if problem == "" {
			problem = "The commit shown here was not checked against the " +
				"payload being signed."
		}

		b.wrap(b.st.danger, "! "+problem)
	} else {
		what := "commit"
		if git.ObjectType == "tag" {
			what = "tag"
		}

		b.wrap(b.st.verified, "The "+what+" below was checked against the bytes "+
			"being signed: the message, author and timestamps are what the "+
			"signature covers. The repository, branch and diff are the "+
			"requesting machine's account of itself and are marked as such.")
	}

	b.blank()
	b.fact("Operation", git.Operation, false)
	b.fact("Repository", git.Repository, true)
	b.fact("Remote", git.OriginURL, true)
	b.fact("Branch", git.Branch, true)
	b.fact("Author", identity(git.Author), false)
	b.fact("Committer", differentCommitter(git), false)
	b.fact("Tagger", identity(git.Tagger), false)
	b.fact("Tag", git.Tag, false)
	b.fact("Tagged object", git.TaggedObject, false)
	b.fact("Tree", git.Tree, false)
	b.fact("Parents", strings.Join(git.Parents, ", "), false)

	for _, header := range git.ExtraHeaders {
		b.fact("Header", header.Name+": "+header.Value, false)
	}

	if git.Message != "" {
		b.blank()

		for _, line := range strings.Split(git.Message, "\n") {
			b.wrap(b.st.message, line)
		}
	}

	if project := view.Project; project != nil && project.ProjectID != "" {
		b.blank()
		b.wrap(b.st.note, project.Note)
	}
}

func renderSSHAuth(b *builder, view bridge.RequestView) {
	auth := view.SSHAuth
	if auth == nil {
		return
	}

	b.blank()
	b.fact("Destination", auth.Destination, false)
	b.fact("Host key", auth.HostKey, false)
	b.fact("Known hosts", auth.KnownHosts, false)
	b.fact("User name", auth.Username, false)
	b.fact("Path", strings.Join(auth.Path, " → "), false)
}

func renderSshsig(b *builder, view bridge.RequestView) {
	sig := view.Sshsig
	if sig == nil {
		return
	}

	b.blank()
	b.fact("Namespace", sig.Namespace, false)
	b.fact("Hash", sig.HashAlgorithm, false)
	b.fact("Digest", sig.Digest, false)
}

func renderOpaque(b *builder, view bridge.RequestView) {
	opaque := view.Opaque
	if opaque == nil {
		return
	}

	b.blank()
	b.fact("Reason", opaque.Reason, false)

	if opaque.Length > 0 {
		b.fact("Length", fmt.Sprintf("%d bytes", opaque.Length), false)
	}

	b.fact("Digest", opaque.Digest, false)
}

// renderPairing shows both fingerprints, because that is the whole of what
// makes trust on first use trustworthy: the two machines display the same pair
// and the people in front of them agree that they match (§7).
func renderPairing(b *builder, view bridge.RequestView) {
	pairing := view.Pairing
	if pairing == nil {
		return
	}

	b.blank()

	if pairing.InitiatedLocally {
		b.wrap(b.st.note, "You started this pairing. Both machines should now "+
			"be showing the same two fingerprints.")
	} else {
		b.wrap(b.st.note, "This machine was asked to pair. Both machines "+
			"should be showing the same two fingerprints.")
	}

	b.blank()
	b.fact("This instance", pairing.LocalName, false)
	b.fact("Fingerprint", pairing.LocalFingerprint, false)
	b.fact("The other", pairing.Name, false)
	b.fact("Fingerprint", pairing.Fingerprint, false)
	b.fact("Connected from", pairing.Address, false)
	b.fact("Reachable at", strings.Join(pairing.Addresses, ", "), false)
	b.fact("This pairing", pairing.Direction, false)

	if pairing.KeyFromCode {
		b.blank()
		b.wrap(b.st.note, "The pairing code carried the other instance's "+
			"identity, so its fingerprint has already been checked against "+
			"the code.")
	}
}

func renderGeneric(b *builder, view bridge.RequestView) {
	if len(view.Details) == 0 {
		return
	}

	b.blank()

	for _, detail := range view.Details {
		b.fact(detail.Label, detail.Value, detail.Asserted)
	}
}

// renderChanges is the diffstat and the list of files, which is what an
// approver reads first and often all they read.
//
// The hunks are not here. They are a screen of their own, reached from the file
// list (decision AN), which is what keeps the length of this card independent
// of the size of the change.
func renderChanges(b *builder, diff *bridge.DiffView) {
	b.heading("Changes")

	if diff.Error != "" {
		b.wrap(b.st.warning, "The diff was not available: "+diff.Error)

		return
	}

	summary := fmt.Sprintf("%s  %s  %s",
		plural(diff.FilesChanged, "file", "files")+" changed",
		b.st.plus.Render(fmt.Sprintf("+%d", diff.Insertions)),
		b.st.minus.Render(fmt.Sprintf("-%d", diff.Deletions)))

	if diff.Range != "" {
		summary += "  " + b.st.asserted.Render(diff.Range)
	}

	b.push(summary)

	if diff.TruncationNote != "" {
		b.wrap(b.st.note, diff.TruncationNote)
	}

	// The window puts a button here, and this is the same offer: the cap is
	// about what travels with a request somebody is waiting on, and was never a
	// statement about what an approver may see (§5).
	if diff.Truncated {
		b.wrap(b.st.note,
			"The diff was cut short. Press r to ask the requesting machine "+
				"for the whole of it.")
	}

	if len(diff.Files) == 0 {
		b.wrap(b.st.note, "No files changed.")

		return
	}

	b.blank()

	for _, file := range diff.Files {
		b.cut(b.st.value, fileRow(b.st, file))
	}

	b.blank()
	b.wrap(b.st.note, "Press f to read one of them.")
}

// fileRow is one file as a line: what it is called, what it did, and how much
// of it changed. It is the same row the file list draws, so that picking a file
// and reading the card are looking at one description of it.
func fileRow(st *styles, file bridge.DiffFileView) string {
	row := fmt.Sprintf("%s  %s %s",
		pathOf(file),
		st.plus.Render(fmt.Sprintf("+%d", file.Insertions)),
		st.minus.Render(fmt.Sprintf("-%d", file.Deletions)))

	if file.Status != "" {
		row += "  " + st.dim.Render(file.Status)
	}

	if file.ModeChange != "" {
		row += "  " + st.asserted.Render(file.ModeChange)
	}

	if file.Binary {
		row += "  " + st.dim.Render("binary")
	}

	return row
}

// renderFileDiff is one file's change, which is the screen the file list opens.
func renderFileDiff(st *styles, file bridge.DiffFileView, width int) []string {
	b := &builder{width: width, st: st}

	b.cut(st.title, pathOf(file))
	b.push(fileRow(st, file))
	b.blank()

	if file.Binary {
		b.wrap(st.note, "Binary file; no diff to show.")
	}

	for _, hunk := range file.Hunks {
		b.cut(st.hunk, hunk.Header)

		for _, line := range hunk.Lines {
			b.cut(lineStyle(st, line.Kind), gutter(line.Kind)+line.Text)
		}

		b.blank()
	}

	if file.Truncated {
		b.wrap(st.note,
			"This file's diff was cut short to keep the request a readable "+
				"size. Press r to ask for the whole of it.")
	}

	if !file.Binary && len(file.Hunks) == 0 && !file.Truncated {
		b.wrap(st.note, "No textual change.")
	}

	return b.lines
}

func gutter(kind string) string {
	switch kind {
	case "added":
		return "+"
	case "removed":
		return "-"
	case "note":
		return `\`
	default:
		return " "
	}
}

func lineStyle(st *styles, kind string) lipgloss.Style {
	switch kind {
	case "added":
		return st.added
	case "removed":
		return st.removed
	case "note":
		return st.note
	default:
		return st.context
	}
}

func pathOf(file bridge.DiffFileView) string {
	if file.OldPath != "" && file.NewPath != "" && file.OldPath != file.NewPath {
		return file.OldPath + " → " + file.NewPath
	}

	if file.NewPath != "" {
		return file.NewPath
	}

	if file.OldPath != "" {
		return file.OldPath
	}

	return "(unnamed)"
}

func identity(who *bridge.IdentityView) string {
	if who == nil {
		return ""
	}

	var parts []string

	switch {
	case who.Name != "" && who.Email != "":
		parts = append(parts, fmt.Sprintf("%s <%s>", who.Name, who.Email))
	case who.Name != "" || who.Email != "":
		parts = append(parts, who.Name+who.Email)
	}

	if who.Time != "" {
		when := who.Time

		if who.Timezone != "" {
			when += " " + who.Timezone
		}

		parts = append(parts, when)
	}

	return strings.Join(parts, ", ")
}

// differentCommitter only reports the committer when it is not the author: on
// an ordinary commit the same line twice is noise, and on a rebased or applied
// patch the difference is the interesting part.
func differentCommitter(git *bridge.GitView) string {
	committer := identity(git.Committer)
	if committer == identity(git.Author) {
		return ""
	}

	return committer
}

func plural(n int32, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}

	return fmt.Sprintf("%d %s", n, many)
}
