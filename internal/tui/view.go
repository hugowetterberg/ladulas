package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/bridge"
)

// The screen: a header, what is waiting, the card, and what the keys do.
//
// The answer keys are at the bottom and are always drawn, whatever is scrolled
// where. The window learned this the hard way and wrote it down: on any commit
// worth reading, buttons underneath the diff meant scrolling past the whole
// change before you could refuse it, and the one thing a signing prompt must
// never be is hard to say no to.

func (m *model) View() string {
	var b strings.Builder

	b.WriteString(m.header())
	b.WriteString("\n")
	b.WriteString(m.rule())
	b.WriteString("\n")

	if len(m.queue) > 1 {
		b.WriteString(m.strip())
		b.WriteString(m.rule())
		b.WriteString("\n")
	}

	b.WriteString(m.body())
	b.WriteString(m.rule())
	b.WriteString("\n")
	b.WriteString(m.footer())

	return b.String()
}

func (m *model) rule() string {
	return m.st.rule.Render(strings.Repeat("─", max(m.width, 1)))
}

// headerHeight, stripHeight and footerHeight are what the card does not get.
func (m *model) stripHeight() int {
	if len(m.queue) < 2 {
		return 0
	}

	// One line per waiting request, and a rule under them.
	return len(m.queue) + 1
}

func (m *model) footerHeight() int {
	switch m.mode {
	case modeGrant:
		return 4
	case modeHelp:
		return 1
	case modeUnlock:
		return 3
	case modeFiles, modeDiff, modeCard:
		return 2
	}

	return 2
}

func (m *model) bodyHeight() int {
	// Header, its rule, the strip, the rule above the footer, the footer.
	return max(m.height-2-m.stripHeight()-1-m.footerHeight(), 1)
}

func (m *model) header() string {
	left := m.st.title.Render("Ladulås") + m.st.dim.Render(" · terminal approver")

	state := m.st.err.Render("not attached")
	if m.attached {
		state = m.st.ok.Render("attached")
	}

	right := state

	if n := len(m.queue); n > 0 {
		right += m.st.dim.Render(" · ") +
			m.st.selected.Render(plural(int32(n), "request", "requests")+" waiting")
	}

	return m.spread(left, right)
}

// spread puts one string at each end of the line, and drops the right one
// rather than wrapping when there is no room for both.
func (m *model) spread(left, right string) string {
	lw := ansi.StringWidth(left)
	rw := ansi.StringWidth(right)

	if lw+rw+1 > m.width {
		return truncate(left, m.width)
	}

	return left + strings.Repeat(" ", m.width-lw-rw) + right
}

// strip is what is waiting, when more than one thing is. With one request there
// is nothing to choose between and the card is the whole screen.
func (m *model) strip() string {
	var b strings.Builder

	for i, item := range m.queue {
		marker := m.st.dim.Render(fmt.Sprintf("%d ", i+1))
		style := m.st.dim

		if i == m.sel {
			marker = m.st.key.Render(fmt.Sprintf("%d▸", i+1))
			style = m.st.selected
		}

		title := item.view.Title
		if item.view.Subject != "" {
			title += " — " + item.view.Subject
		}

		waited := m.st.dim.Render("waiting " + since(m.now, item.since))

		b.WriteString(m.spread(
			marker+style.Render(truncate(title, max(m.width-24, 10))), waited))
		b.WriteString("\n")
	}

	return b.String()
}

func (m *model) body() string {
	height := m.bodyHeight()

	if m.mode == modeHelp {
		return window(m.helpRows(), m.helpScroll, height)
	}

	item := m.current()
	if item == nil {
		return pad(m.idle(), height)
	}

	if m.mode == modeFiles {
		return m.fileList(height)
	}

	if m.mode == modeDiff {
		lines := m.diffLines(item)
		item.diffScroll = clamp(item.diffScroll, len(lines), height)

		return window(margin(lines), item.diffScroll, height)
	}

	m.rebuild(item)

	item.scroll = clamp(item.scroll, len(item.lines), height)

	return window(margin(item.lines), item.scroll, height)
}

// margin is the one column of space every drawn line gets, so that nothing
// starts hard against the edge of the terminal.
func margin(lines []string) []string {
	out := make([]string, len(lines))

	for i, line := range lines {
		out[i] = " " + line
	}

	return out
}

// fileList is the picker: the files this change touches, narrowed by whatever
// has been typed, over the card rather than in it.
func (m *model) fileList(height int) string {
	item := m.current()
	if item == nil {
		return pad("", height)
	}

	shown := m.shownFiles(item)

	lines := []string{"", " " + m.st.heading.Render("Files in this change"), ""}

	if len(shown) == 0 {
		lines = append(lines, " "+m.st.note.Render(
			"Nothing matches what you have typed."))

		return window(lines, 0, height)
	}

	for i, entry := range shown {
		row := fmt.Sprintf("%s  %s %s",
			pathOf(entry.file),
			m.st.plus.Render(fmt.Sprintf("+%d", entry.file.Insertions)),
			m.st.minus.Render(fmt.Sprintf("-%d", entry.file.Deletions)))

		// The file behind this list, so that opening it again to change files
		// says which one you came from. It is a nicety rather than a fact a
		// decision rests on, which is why it is allowed to be only a weight.
		if entry.index == item.reading {
			row = m.st.selected.Render(row)
		}

		if i == item.picker.at {
			lines = append(lines, m.st.focused.Render("› ")+row)

			continue
		}

		lines = append(lines, "  "+row)
	}

	// The cursor is kept on screen by scrolling the list under it, which is the
	// one thing a list has to do that the card does not.
	item.picker.scroll = keepInView(
		item.picker.scroll, item.picker.at+3, len(lines), height)

	return window(lines, item.picker.scroll, height)
}

// keepInView moves a scroll offset the least it can to bring a row inside the
// window.
func keepInView(scroll, at, rows, height int) int {
	if at < scroll {
		scroll = at
	}

	if at >= scroll+height {
		scroll = at - height + 1
	}

	return clamp(scroll, rows, height)
}

// idle is the screen with nothing on it, which is where this program spends
// almost all of its life. It says what it is attached to and what will happen
// when something arrives, because a terminal that says nothing at all is
// indistinguishable from one that has stopped working.
//
// "Nothing is waiting" is not the whole truth on a sealed instance, where
// nothing *can* wait: the agent offers no keys, so a signature fails before it
// is a request and this screen would sit empty and reassuring while every
// commit on the machine was refused. So the lock state is on it, in the words
// every other surface uses, with the way out of it — which is the same thing
// the window does by drawing the passphrase panel in place of its screens
// (§10).
func (m *model) idle() string {
	var lines []string

	lines = append(lines, "")

	if !m.attached {
		lines = append(lines, " "+m.st.warning.Render(
			"Not attached to a daemon. This keeps trying."))
		lines = append(lines, " "+m.st.dim.Render(" "+m.socket))

		return strings.Join(lines, "\n") + "\n"
	}

	switch state := m.lockWord(); state {
	case "", bridge.StateUnlocked:
		lines = append(lines, " "+m.st.value.Render(
			"Nothing is waiting. Requests raised on this machine, and the ones"))
		lines = append(lines, " "+m.st.value.Render(
			"paired machines send here, come up on this screen."))
	case bridge.StateSealed, bridge.StateNoStore:
		lines = append(lines, " "+m.st.warning.Render(
			"The store is "+state+", so nothing here can sign and nothing"))
		lines = append(lines, " "+m.st.warning.Render(
			"will be asked of this terminal."))
		lines = append(lines, "")
		lines = append(lines, " "+m.st.dim.Render(
			"`ladulas unlock` opens it. A paired approver cannot help with"))
		lines = append(lines, " "+m.st.dim.Render(
			"this one: the key is what is missing, not the answer."))
	case bridge.StateLocked:
		lines = append(lines, " "+m.st.warning.Render(
			"Approving here is suspended: the store is locked."))
		lines = append(lines, " "+m.st.dim.Render(
			"Paired approvers still answer for this machine, and the keys are"))
		lines = append(lines, " "+m.st.dim.Render(
			"still here. `ladulas unlock` lifts it."))
	default:
		// A word this build has no branch for, and the state a front end
		// reports when it could not ask. Neither is a state to describe
		// confidently: saying nothing is waiting would be a claim about a
		// daemon that has not answered.
		lines = append(lines, " "+m.st.warning.Render(
			"The daemon did not say what state its store is in — "+state+"."))
		lines = append(lines, " "+m.st.dim.Render(
			"`ladulas status` is the one that answers it."))
	}

	if reason := m.lockReason(); reason != "" {
		lines = append(lines, " "+m.st.dim.Render(reason+"."))
	}

	if m.settings != nil {
		lines = append(lines, "")
		lines = append(lines, " "+m.st.dim.Render(
			"A signing request waits up to "+
				approval.HumanDuration(
					time.Duration(m.settings.SignTimeoutSeconds)*time.Second)+
				" for an answer."))
	}

	return strings.Join(lines, "\n") + "\n"
}

// window is exactly `height` lines of a list, starting at an offset. Exactly,
// because the pane between the two rules is a fixed size and a screen that
// grows by a line pushes the answer keys off the bottom.
func window(lines []string, scroll, height int) string {
	scroll = clamp(scroll, len(lines), height)

	var b strings.Builder

	for i := scroll; i < scroll+height; i++ {
		if i < len(lines) {
			b.WriteString(lines[i])
		}

		b.WriteString("\n")
	}

	return b.String()
}

func pad(text string, height int) string {
	return window(strings.Split(strings.TrimSuffix(text, "\n"), "\n"), 0, height)
}

func (m *model) footer() string {
	switch m.mode {
	case modeHelp:
		return m.help()
	case modeGrant:
		return m.grant()
	case modeUnlock:
		return m.passphrase()
	case modeFiles:
		return m.fileKeys()
	case modeDiff:
		return m.diffKeys()
	case modeCard:
		return m.keys()
	}

	return m.keys()
}

// fileKeys is the file list's own line. `esc` is the only way out because every
// printable key narrows the list.
func (m *model) fileKeys() string {
	line := " " + strings.Join([]string{
		m.st.key.Render("enter") + " read it",
		m.st.key.Render("↑ ↓") + " choose",
		m.st.key.Render("esc") + " back",
	}, m.st.dim.Render(" · "))

	item := m.current()
	if item == nil {
		return m.status0(line)
	}

	shown := len(m.shownFiles(item))

	typed := m.st.dim.Render("type to narrow the list")
	if len(item.picker.filter) > 0 {
		typed = m.st.dim.Render("matching ") +
			m.st.fieldOn.Render(string(item.picker.filter)) +
			m.st.dim.Render(fmt.Sprintf(" — %s",
				plural(int32(shown), "file", "files")))
	}

	return m.spread(line, typed+" ") + "\n" + " " + m.st.dim.Render("")
}

// diffKeys is one file's change: the way back, the way on, and the answers.
//
// `enter` is the way back and not an answer, which is the whole of why reading a
// change is a screen of its own (decision AN). The letters still answer,
// because they are deliberate.
func (m *model) diffKeys() string {
	item := m.current()
	if item == nil {
		return m.keys()
	}

	parts := []string{
		m.st.key.Render("enter") + " close",
		m.st.key.Render("n p") + " next file",
		m.st.key.Render("f") + " the list",
		m.st.key.Render("a") + " approve",
		m.st.key.Render("d") + " deny",
	}

	position := ""

	if count := m.files(item); count > 0 && item.reading >= 0 {
		position = m.st.dim.Render(
			fmt.Sprintf("file %d of %d", item.reading+1, count))
	}

	return m.spread(" "+strings.Join(parts, m.st.dim.Render(" · ")),
		position+" ") + "\n" + " " + m.st.dim.Render("")
}

// passphrase is the unlock field: one thing to type, and two ways out of it.
//
// What is typed is drawn as dots and is never anywhere else — not in the log,
// which this program does not write to the screen anyway, and not in the status
// line. The length shows, which is what every passphrase field does and is a
// deliberate trade against typing blind into a terminal.
func (m *model) passphrase() string {
	prompt := " " + m.st.label.Render("Passphrase  ") +
		m.st.fieldOn.Render(strings.Repeat("•", len(m.typed)))

	if m.unlocking {
		prompt = " " + m.st.dim.Render("Opening the store…")
	}

	hint := m.st.dim.Render("enter opens it · esc goes back")

	if m.lock != nil && m.lock.KeyringEnrolled && len(m.typed) == 0 {
		hint = m.st.dim.Render(
			"enter with nothing typed uses the keychain · esc goes back")
	}

	note := m.status
	style := m.st.dim

	if m.statusErr {
		style = m.st.err
	}

	return prompt + "\n" + " " + hint + "\n" +
		" " + style.Render(truncate(note, max(m.width-2, 10)))
}

// keys is the answer line and the status line under it. The answer line does
// not change with the scroll: whatever is on screen, the way to refuse is in
// the same place.
func (m *model) keys() string {
	item := m.current()

	if item == nil {
		hints := []string{}

		if m.canUnlock() {
			hints = append(hints, m.st.key.Render("u")+" unlock the store")
		}

		hints = append(hints,
			m.st.key.Render("?")+" keys",
			m.st.key.Render("q")+" quit")

		return m.status0(" " + strings.Join(hints, m.st.dim.Render(" · ")))
	}

	// A grant request has no "approve once" in it: there is no payload behind it,
	// so a yes with no length attached grants nothing and the daemon refuses one
	// (decision AO). Offering the key would offer a keystroke that only ever
	// produces an error.
	var parts []string

	if !item.view.GrantOnly {
		parts = append(parts, m.st.key.Render("a")+" approve once")
	}

	if item.view.Grant != nil {
		parts = append(parts, m.st.key.Render("w")+" approve for a while")
	}

	parts = append(parts, m.st.key.Render("d")+" deny")

	// The way into the change, with how much of one there is: "enter open a
	// file" was the whole of what this used to say, which left the reader to
	// work out which file and how to choose another.
	if count := m.files(item); count > 0 {
		parts = append(parts, m.st.key.Render("f")+
			fmt.Sprintf(" read %s", plural(int32(count), "file", "files")))
	}

	if len(m.queue) > 1 {
		parts = append(parts, m.st.key.Render("[ ]")+" next request")
	}

	parts = append(parts, m.st.key.Render("?")+" keys")

	line := " " + strings.Join(parts, m.st.dim.Render(" · "))

	if item.answering {
		line = " " + m.st.dim.Render("waiting for the instance…")
	}

	return m.status0(line)
}

// status0 draws the key line with the status under it, which is where anything
// that went wrong ends up: an answer that lost its race, a diff that could not
// be fetched, a request that was settled elsewhere.
func (m *model) status0(keys string) string {
	right := ""

	if at, of := m.position(); of > m.bodyHeight() {
		right = m.st.dim.Render(fmt.Sprintf("%d/%d", at, of))
	}

	note := m.status
	style := m.st.dim

	if m.statusErr {
		style = m.st.err
	}

	if item := m.current(); item != nil && item.note != "" {
		note = item.note
		style = m.st.dim

		if item.noteErr {
			style = m.st.err
		}
	}

	return m.spread(keys, right) + "\n" + " " + style.Render(truncate(note, max(m.width-2, 10)))
}

// position is how far down whichever screen is scrolling somebody has read.
func (m *model) position() (int, int) {
	item := m.current()
	if item == nil {
		return 0, 0
	}

	if m.mode == modeDiff {
		lines := m.diffLines(item)

		return min(item.diffScroll+m.bodyHeight(), len(lines)), len(lines)
	}

	return min(item.scroll+m.bodyHeight(), len(item.lines)), len(item.lines)
}

// grant is the promise being made, as the two questions decision V asks: who it
// is made to, and how long it runs.
func (m *model) grant() string {
	item := m.current()
	if item == nil || item.view.Grant == nil {
		return m.keys()
	}

	offer := item.view.Grant
	form := item.grant

	reach := "any session on " + offer.Machine
	if !form.machine && offer.Session != "" {
		reach = offer.Session
	}

	reachStyle := m.st.fieldOff
	lengthStyle := m.st.fieldOff

	if form.field == 0 {
		reachStyle = m.st.fieldOn
	} else {
		lengthStyle = m.st.fieldOn
	}

	choose := m.st.dim.Render("  ← →")

	if offer.Session == "" && form.field == 0 {
		choose = m.st.dim.Render("  (this request names no session)")
	}

	lines := []string{
		" " + m.st.label.Render("Promise to  ") + reachStyle.Render(reach) +
			pick(form.field == 0, choose, ""),
		" " + m.st.label.Render("For         ") +
			lengthStyle.Render(approval.HumanDuration(time.Duration(form.seconds)*time.Second)) +
			pick(form.field == 1, m.st.dim.Render("  ← → 15m · H L 1h"+
				suggestionHint(m.st, offer)), ""),
		" " + m.st.dim.Render("tab switches · ") +
			m.st.key.Render("enter") + m.st.dim.Render(" approve · ") +
			m.st.key.Render("esc") + m.st.dim.Render(" back"),
	}

	note := ""

	if trust := offer.Trust; trust != nil {
		note = " " + m.st.warning.Render(truncate(trust.Note, max(m.width-2, 10)))
	}

	return strings.Join(lines, "\n") + "\n" + note
}

func suggestionHint(st *styles, offer *bridge.GrantOffer) string {
	if len(offer.Suggestions) == 0 {
		return ""
	}

	var parts []string

	for i, seconds := range offer.Suggestions {
		if i >= 9 {
			break
		}

		parts = append(parts, fmt.Sprintf("%d %s",
			i+1, approval.HumanDuration(time.Duration(seconds)*time.Second)))
	}

	return st.dim.Render(" · " + strings.Join(parts, " · "))
}

func pick(when bool, yes, no string) string {
	if when {
		return yes
	}

	return no
}

// help is the whole key table, on top of the card rather than beside it: this
// is a program somebody uses a few times a week, and the keys they do not use
// every day are the ones worth being able to look up.
//
// It scrolls, because on a short terminal the rows that fall off the bottom
// would be the ones about leaving.
func (m *model) help() string {
	return " " + m.st.dim.Render("↑ ↓ scrolls · any other key closes this")
}

// helpRows is the table itself, drawn in the body while the help is up.
func (m *model) helpRows() []string {
	rows := [][2]string{
		{"enter, a", "approve this request, once — on the card, not while"},
		{"", "reading a change, where enter closes the change"},
		{"w", "approve for a while: a promise with a reach and a length"},
		{"d", "deny it"},
		{"", ""},
		{"j / k, ↑ / ↓", "scroll the card"},
		{"space / b", "a page at a time"},
		{"g / G", "the top and the bottom"},
		{"", ""},
		{"f", "the list of files this change touches"},
		{"n / p", "straight to the next or previous file's change"},
		{"r", "ask the requesting machine for the rest of a truncated diff"},
		{"", ""},
		{"u", "unlock the store, when it is sealed or locked"},
		{"", ""},
		{"[ / ]", "the previous and next waiting request"},
		{"1 - 9", "the request at that place in the list above"},
		{"q", "leave; anything waiting is left to the other approvers"},
		{"ctrl+c", "the same, without the confirmation"},
	}

	out := []string{"", " " + m.st.heading.Render("Keys"), ""}

	for _, entry := range rows {
		if entry[0] == "" {
			out = append(out, "")

			continue
		}

		out = append(out, fmt.Sprintf(" %s  %s",
			m.st.key.Render(fmt.Sprintf("%-14s", entry[0])),
			m.st.value.Render(entry[1])))
	}

	return out
}

// since is how long something has been waiting, at the resolution somebody
// reads it: seconds while that is the interesting number, minutes after.
func since(now, then time.Time) string {
	d := now.Sub(then)

	if d < 0 {
		d = 0
	}

	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}

	return approval.HumanDuration(d.Round(time.Minute))
}
