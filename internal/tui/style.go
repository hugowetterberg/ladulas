package tui

import "github.com/charmbracelet/lipgloss"

// The palette is the sixteen ANSI colours and nothing else.
//
// A terminal's colours are the user's, set once for every program they run, and
// a prompt that picks its own hex values is a prompt that is unreadable on
// somebody's light theme and garish on somebody's dark one. Numbered colours
// are the terminal's own answer to "what is red here", which is the answer that
// matches the diff they read everywhere else.
//
// What is not decorative: added and removed lines, the provenance line, and a
// warning. Those carry meaning that the words alone also carry — every coloured
// line here is readable with the colour stripped, because a signing prompt that
// only works in colour is one that stops working over a pipe or for somebody
// who cannot tell green from red.
type styles struct {
	title     lipgloss.Style
	subject   lipgloss.Style
	heading   lipgloss.Style
	label     lipgloss.Style
	value     lipgloss.Style
	mono      lipgloss.Style
	asserted  lipgloss.Style
	note      lipgloss.Style
	warning   lipgloss.Style
	danger    lipgloss.Style
	verified  lipgloss.Style
	message   lipgloss.Style
	added     lipgloss.Style
	removed   lipgloss.Style
	context   lipgloss.Style
	hunk      lipgloss.Style
	file      lipgloss.Style
	focused   lipgloss.Style
	plus      lipgloss.Style
	minus     lipgloss.Style
	rule      lipgloss.Style
	bar       lipgloss.Style
	selected  lipgloss.Style
	key       lipgloss.Style
	dim       lipgloss.Style
	err       lipgloss.Style
	ok        lipgloss.Style
	fieldOn   lipgloss.Style
	fieldOff  lipgloss.Style
	promptBox lipgloss.Style
}

func newStyles() *styles {
	var (
		red     = lipgloss.Color("1")
		green   = lipgloss.Color("2")
		yellow  = lipgloss.Color("3")
		blue    = lipgloss.Color("4")
		magenta = lipgloss.Color("5")
		cyan    = lipgloss.Color("6")
		bright  = lipgloss.Color("7")
		grey    = lipgloss.Color("8")
	)

	plain := lipgloss.NewStyle()

	return &styles{
		title:     plain.Bold(true),
		subject:   plain.Foreground(bright),
		heading:   plain.Bold(true).Foreground(blue),
		label:     plain.Foreground(grey),
		value:     plain,
		mono:      plain.Foreground(bright),
		asserted:  plain.Foreground(magenta),
		note:      plain.Foreground(grey),
		warning:   plain.Foreground(yellow),
		danger:    plain.Foreground(red).Bold(true),
		verified:  plain.Foreground(green),
		message:   plain,
		added:     plain.Foreground(green),
		removed:   plain.Foreground(red),
		context:   plain,
		hunk:      plain.Foreground(cyan),
		file:      plain.Bold(true),
		focused:   plain.Bold(true).Foreground(cyan),
		plus:      plain.Foreground(green),
		minus:     plain.Foreground(red),
		rule:      plain.Foreground(grey),
		bar:       plain.Foreground(grey),
		selected:  plain.Bold(true),
		key:       plain.Foreground(cyan),
		dim:       plain.Foreground(grey),
		err:       plain.Foreground(red),
		ok:        plain.Foreground(green),
		fieldOn:   plain.Bold(true).Foreground(cyan),
		fieldOff:  plain.Foreground(grey),
		promptBox: plain.Foreground(yellow),
	}
}
