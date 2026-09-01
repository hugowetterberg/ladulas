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
	case modeCard:
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
		marker := "  "
		style := m.st.dim

		if i == m.sel {
			marker = m.st.key.Render("▸ ")
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

	m.rebuild(item)

	item.scroll = clamp(item.scroll, len(item.rows), height)

	var b strings.Builder

	heads := fileHeads(item.rows)
	focused := -1

	if item.focus >= 0 && item.focus < len(heads) {
		focused = heads[item.focus]
	}

	for i := item.scroll; i < item.scroll+height; i++ {
		if i >= len(item.rows) {
			b.WriteString("\n")

			continue
		}

		line := item.rows[i].text

		if i == focused {
			line = m.st.focused.Render("▶") + line
		} else {
			line = " " + line
		}

		b.WriteString(line)
		b.WriteString("\n")
	}

	return b.String()
}

// idle is the screen with nothing on it, which is where this program spends
// almost all of its life. It says what it is attached to and what will happen
// when something arrives, because a terminal that says nothing at all is
// indistinguishable from one that has stopped working.
func (m *model) idle() string {
	var lines []string

	lines = append(lines, "")

	if m.attached {
		lines = append(lines, " "+m.st.value.Render(
			"Nothing is waiting. Requests raised on this machine, and the ones "))
		lines = append(lines, " "+m.st.value.Render(
			"paired machines send here, come up on this screen."))
	} else {
		lines = append(lines, " "+m.st.warning.Render(
			"Not attached to a daemon. This keeps trying."))
		lines = append(lines, " "+m.st.dim.Render(" "+m.socket))
	}

	if m.settings != nil {
		lines = append(lines, "")
		lines = append(lines, " "+m.st.dim.Render(
			"A signing request waits up to "+
				approval.HumanDuration(time.Duration(m.settings.SignTimeoutSeconds)*time.Second)+
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
	case modeCard:
		return m.keys()
	}

	return m.keys()
}

// keys is the answer line and the status line under it. The answer line does
// not change with the scroll: whatever is on screen, the way to refuse is in
// the same place.
func (m *model) keys() string {
	item := m.current()

	if item == nil {
		return m.status0(m.st.dim.Render(" ? keys · q quit"))
	}

	parts := []string{
		m.st.key.Render("a") + " approve once",
	}

	if item.view.Grant != nil {
		parts = append(parts, m.st.key.Render("w")+" approve for a while")
	}

	parts = append(parts,
		m.st.key.Render("d")+" deny",
		m.st.key.Render("enter")+" open a file",
		m.st.key.Render("?")+" keys")

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

	if item := m.current(); item != nil && len(item.rows) > m.bodyHeight() {
		right = m.st.dim.Render(fmt.Sprintf("%d/%d",
			min(item.scroll+m.bodyHeight(), len(item.rows)), len(item.rows)))
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
		{"a", "approve this request, once"},
		{"w", "approve for a while: a promise with a reach and a length"},
		{"d", "deny it"},
		{"", ""},
		{"j / k, ↑ / ↓", "scroll the card"},
		{"space / b", "a page at a time"},
		{"g / G", "the top and the bottom"},
		{"", ""},
		{"n / p", "the next and previous file in the diff"},
		{"enter", "open or close the file under the cursor"},
		{"e / c", "open or close every file"},
		{"f", "ask the requesting machine for the rest of a truncated diff"},
		{"", ""},
		{"tab", "the next waiting request, when more than one is"},
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
