package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/hugowetterberg/ladulas/pkg/bridge"
)

// The messages the host sends in. Everything that happens to this program
// happens on the one goroutine bubbletea runs Update on, which is what lets the
// presenter be called from whichever goroutine is deciding a request.
type (
	presentMsg struct {
		id    string
		since time.Time
		view  bridge.RequestView
	}
	dismissMsg  struct{ id string }
	attachedMsg bool
	answeredMsg struct {
		id       string
		approved bool
		err      error
	}
	diffMsg struct {
		id   string
		diff bridge.DiffView
		err  error
	}
	stateMsg struct {
		settings *bridge.SettingsView
		lock     *bridge.LockView
	}
	unlockedMsg struct {
		lock bridge.LockView
		err  error
	}
	troubleMsg  struct{ text string }
	announceMsg struct{ activity bridge.ActivityView }
	tickMsg     time.Time
)

// mode is what the bottom of the screen is asking.
type mode int

const (
	modeCard mode = iota
	modeGrant
	modeHelp
	modeUnlock
	modeFiles
	modeDiff
)

// card is one request in front of somebody, and how far they have read.
//
// The rows are rebuilt rather than scrolled over, because the two things that
// change them — the width and which files are open — change what a line *is*.
// A cached render with a width beside it is the whole of the bookkeeping that
// needs.
type card struct {
	id    string
	since time.Time
	view  bridge.RequestView

	scroll int
	// reading is the file whose diff is on screen, or -1 when the card is. It
	// is what makes `enter` safe to use for approving: the key means approve on
	// the card and "close this" while somebody is reading a change, and the two
	// are different screens rather than two meanings of one.
	reading int
	// diffScroll is how far into that file somebody has read, kept per card so
	// that leaving a file and coming back does not start again.
	diffScroll int

	lines []string
	width int

	answering bool
	note      string
	noteErr   bool

	grant  grantForm
	picker filePicker
}

// filePicker is the list of files, open over the card.
//
// It is a dialog rather than a cursor living in the card, and that is the whole
// design: the card is a thing you scroll, and one set of keys that sometimes
// scrolls and sometimes moves between files is two programs sharing a keyboard.
// It shipped as the cursor, briefly, and the cursor could only be moved with
// keys nobody found.
type filePicker struct {
	at     int
	scroll int
	// filter narrows the list by substring, because the change this is for is a
	// commit touching thirty files and the answer to "where is the one I care
	// about" should be typing part of its name.
	filter []rune
}

// grantForm is "approve for a while" as two questions (decision V): who the
// promise is made to, and how long it runs.
type grantForm struct {
	// field is 0 for the reach and 1 for the length.
	field   int
	machine bool
	seconds int64
}

type model struct {
	api    *api
	socket string
	st     *styles

	width  int
	height int

	attached bool
	queue    []*card
	sel      int

	settings *bridge.SettingsView
	lock     *bridge.LockView

	mode       mode
	helpScroll int
	// typed is the passphrase being entered, held as runes so that a backspace
	// takes off a character rather than a byte. It is cleared the moment it has
	// been sent, and never goes near the log.
	typed       []rune
	unlocking   bool
	status      string
	statusErr   bool
	quitConfirm bool

	// answered remembers the requests this terminal settled, so that the
	// dismissal that follows is not reported as somebody else having answered.
	answered map[string]bool

	now   time.Time
	ticks int
}

func newModel(api *api, socket string) *model {
	return &model{
		api:      api,
		socket:   socket,
		st:       newStyles(),
		width:    80,
		height:   24,
		answered: map[string]bool{},
		now:      time.Now(),
	}
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), m.stateCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(tick, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// stateCmd asks the daemon the two things this screen says about it when there
// is nothing on it: how long a request will wait, and whether one could be
// answered at all.
//
// Both are allowed to fail without a word. A daemon that is not up yet has
// neither to give, which is an ordinary state here — the header already says
// "not attached" — and a line about it would be a line about something the
// screen has said better.
func (m *model) stateCmd() tea.Cmd {
	return func() tea.Msg {
		var msg stateMsg

		if view, err := m.api.settings(); err == nil {
			msg.settings = &view
		}

		if view, err := m.api.lock(); err == nil {
			msg.lock = &view
		}

		return msg
	}
}

// statePoll is how many ticks apart the two are re-read. The lock state is the
// one that changes under this screen — somebody unlocks the store in another
// window — and four seconds is what the desktop's own pane settles for.
const statePoll = 4

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		return m, nil

	case tickMsg:
		m.now = time.Time(msg)
		m.ticks++

		if m.ticks%statePoll == 0 {
			return m, tea.Batch(tickCmd(), m.stateCmd())
		}

		return m, tickCmd()

	case attachedMsg:
		m.attached = bool(msg)

		if m.attached {
			// Both are the daemon's, so they are worth asking for again once
			// there is a daemon to ask.
			return m, m.stateCmd()
		}

		return m, nil

	case stateMsg:
		if msg.settings != nil {
			m.settings = msg.settings
		}

		if msg.lock != nil {
			m.lock = msg.lock
		}

		return m, nil

	case presentMsg:
		m.present(msg)

		return m, nil

	case dismissMsg:
		m.dismiss(msg.id)

		return m, nil

	case answeredMsg:
		return m, m.settled(msg)

	case diffMsg:
		m.replaceDiff(msg)

		return m, nil

	case troubleMsg:
		m.complain(msg.text)

		return m, nil

	case announceMsg:
		m.say(fmt.Sprintf("%s — %s",
			msg.activity.Outcome, msg.activity.Title))

		return m, nil

	case unlockedMsg:
		m.unlocked(msg)

		return m, nil

	case tea.KeyMsg:
		return m.key(msg)
	}

	return m, nil
}

// present puts a request on the pile. A request already here is redrawn rather
// than duplicated: the daemon re-raising one is a stream that reconnected, not
// a second question.
func (m *model) present(msg presentMsg) {
	for _, existing := range m.queue {
		if existing.id != msg.id {
			continue
		}

		existing.view = msg.view
		existing.width = 0

		return
	}

	m.queue = append(m.queue, &card{
		id:      msg.id,
		since:   waitingSince(msg),
		view:    msg.view,
		reading: -1,
		grant:   grantForm{seconds: 3600},
	})

	// A new card does not steal the screen from one somebody is reading. It
	// goes on the end and the header says how many are waiting, which is what
	// the window does with its popup queue (decision AA).
	if len(m.queue) == 1 {
		m.sel = 0
	}
}

// waitingSince is when the request started waiting, and not when this screen
// first saw it.
//
// The two used to be the same thing and are not since a terminal can join a
// request that was raised before it started (decision AL): a card that had been
// on somebody's desktop for forty minutes would say "waiting 0s" here, which is
// the one number on the header that somebody uses to decide whether to hurry.
// The request's own timestamp is what the daemon put on it; the fall-back is
// when it reached this screen, for a host that sent none.
func waitingSince(msg presentMsg) time.Time {
	if msg.view.CreatedAt == "" {
		return msg.since
	}

	created, err := time.Parse(time.RFC3339, msg.view.CreatedAt)
	if err != nil {
		return msg.since
	}

	return created
}

// dismiss takes a card away because the daemon said so, whatever the reason:
// this terminal answered it, another approver did, the requester gave up, or
// the budget ran out.
func (m *model) dismiss(id string) {
	for i, existing := range m.queue {
		if existing.id != id {
			continue
		}

		if !m.answered[id] {
			m.say(existing.view.Title + " was settled without this terminal.")
		}

		delete(m.answered, id)

		m.queue = append(m.queue[:i], m.queue[i+1:]...)

		if m.sel >= len(m.queue) {
			m.sel = max(0, len(m.queue)-1)
		}

		if m.mode != modeCard && m.mode != modeHelp {
			m.mode = modeCard
		}

		return
	}
}

// settled reports what happened to an answer this terminal sent.
//
// A failure leaves the card exactly where it was, because the request is still
// waiting: the usual reason is that somebody else answered first, and the
// second-usual is that the daemon went away, and neither is a reason to stop
// showing a question that has not been settled.
func (m *model) settled(msg answeredMsg) tea.Cmd {
	item := m.card(msg.id)

	if msg.err == nil {
		// The dismissal is what takes the card off, and it is on its way.
		return nil
	}

	delete(m.answered, msg.id)

	if item == nil {
		return nil
	}

	item.answering = false
	item.note = "The answer did not go through: " + msg.err.Error()
	item.noteErr = true

	return nil
}

func (m *model) replaceDiff(msg diffMsg) {
	item := m.card(msg.id)
	if item == nil {
		return
	}

	item.answering = false

	if msg.err != nil {
		item.note = "The rest of the diff could not be fetched: " + msg.err.Error()
		item.noteErr = true

		return
	}

	if item.view.Git == nil {
		return
	}

	diff := msg.diff
	item.view.Git.Diff = &diff
	item.width = 0
	item.note = ""

	// The file being read may not be the same file, or may not exist, in a diff
	// that arrived whole.
	if item.reading >= len(diff.Files) {
		item.reading = -1
		m.mode = modeCard
	}

	if diff.Truncated {
		item.note = "Even the whole diff was too large to send in one piece."
		item.noteErr = false
	}
}

// diffOf is the change a request carries, or nothing, without every caller
// having to walk two pointers to find out which.
func diffOf(view bridge.RequestView) *bridge.DiffView {
	if view.Git == nil {
		return nil
	}

	return view.Git.Diff
}

func (m *model) card(id string) *card {
	for _, item := range m.queue {
		if item.id == id {
			return item
		}
	}

	return nil
}

// lockWord and lockReason are the store's state as this screen needs it: the
// word every surface uses, or nothing at all when the daemon has not been
// asked yet. Not-asked is not the same as "unknown" and must not draw as a
// fault.
func (m *model) lockWord() string {
	if m.lock == nil {
		return ""
	}

	return m.lock.State
}

func (m *model) lockReason() string {
	if m.lock == nil {
		return ""
	}

	return m.lock.Reason
}

func (m *model) current() *card {
	if m.sel < 0 || m.sel >= len(m.queue) {
		return nil
	}

	return m.queue[m.sel]
}

func (m *model) say(text string) {
	m.status = text
	m.statusErr = false
}

func (m *model) complain(text string) {
	m.status = text
	m.statusErr = true
}

// key is every keystroke this program understands, and the three modes are the
// three questions it can be asking.
func (m *model) key(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Ctrl-C leaves whatever is on screen, always. A prompt that could trap
	// somebody in it would be a prompt they answer to get out of, and an answer
	// given to escape a program is not an answer.
	if key == "ctrl+c" {
		return m, tea.Quit
	}

	if m.mode == modeHelp {
		switch key {
		case "up", "k":
			m.helpScroll--
		case "down", "j":
			m.helpScroll++
		case "pgup", "b":
			m.helpScroll -= m.bodyHeight()
		case "pgdown", " ":
			m.helpScroll += m.bodyHeight()
		default:
			m.mode = modeCard
		}

		return m, nil
	}

	if m.mode == modeUnlock {
		return m.unlockKey(msg, key)
	}

	if m.mode == modeFiles {
		return m.filesKey(msg, key)
	}

	if m.mode == modeDiff {
		return m.diffKey(key)
	}

	if m.mode == modeGrant {
		return m.grantKey(key)
	}

	return m.cardKey(key)
}

// canUnlock reports whether there is a store here to open. "Not created yet" is
// not one of them: there is nothing to unlock, and `ladulas init` is the answer
// rather than a passphrase field (§14).
func (m *model) canUnlock() bool {
	switch m.lockWord() {
	case bridge.StateSealed, bridge.StateLocked:
		return m.attached
	default:
		return false
	}
}

// unlockKey is the passphrase field. It is a field and not a form: there is one
// thing to type and two ways out of it.
func (m *model) unlockKey(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	if m.unlocking {
		// The daemon is checking it. Ignoring keys here is deliberate: the one
		// worth catching is a second enter, which would send the passphrase
		// twice and spend two of whatever attempts the store allows.
		return m, nil
	}

	switch key {
	case "esc":
		m.clearTyped()
		m.mode = modeCard

		return m, nil

	case "enter":
		return m, m.submitPassphrase()

	case "backspace":
		if len(m.typed) > 0 {
			m.typed[len(m.typed)-1] = 0
			m.typed = m.typed[:len(m.typed)-1]
		}

		return m, nil

	case "ctrl+u":
		m.clearTyped()

		return m, nil
	}

	// Everything else that is a character somebody typed. A key with a name —
	// "up", "f2" — is not one, and typing one into a passphrase would put its
	// name in the passphrase.
	if msg.Type == tea.KeyRunes {
		m.typed = append(m.typed, msg.Runes...)
	}

	if msg.Type == tea.KeySpace {
		m.typed = append(m.typed, ' ')
	}

	return m, nil
}

// clearTyped zeroes what was typed rather than dropping the slice, so the
// characters do not sit in a heap this process may still dump (§16).
func (m *model) clearTyped() {
	for i := range m.typed {
		m.typed[i] = 0
	}

	m.typed = m.typed[:0]
}

// submitPassphrase sends what was typed and clears it here.
//
// An empty passphrase is not refused: on an instance that enrolled "unlock at
// login" it is the whole of the answer, and the daemon is the one that knows
// whether it is (decision I).
func (m *model) submitPassphrase() tea.Cmd {
	passphrase := []byte(string(m.typed))

	m.clearTyped()
	m.unlocking = true
	m.status = ""

	return func() tea.Msg {
		view, err := m.api.unlock(passphrase)

		wipe(passphrase)

		return unlockedMsg{lock: view, err: err}
	}
}

// unlocked is what the daemon said about the passphrase.
func (m *model) unlocked(msg unlockedMsg) {
	m.unlocking = false

	if msg.err != nil {
		// The daemon's own sentence, which distinguishes a wrong passphrase
		// from a store that could not be opened at all.
		m.complain(msg.err.Error())

		return
	}

	view := msg.lock
	m.lock = &view
	m.mode = modeCard

	m.say("The store is open. Requests raised here come to this terminal.")
}

//nolint:cyclop // a key table is a list of cases; splitting it hides the table.
func (m *model) cardKey(key string) (tea.Model, tea.Cmd) {
	if key != "q" {
		m.quitConfirm = false
	}

	item := m.current()

	switch key {
	case "q":
		// Leaving with something waiting takes this approver away, and the
		// request goes on waiting for whoever else can answer it. That is
		// ordinary and is not a denial — but it is worth one keystroke of
		// confirmation, because the person who quits is often the one the
		// request was waiting for.
		if len(m.queue) > 0 && !m.quitConfirm {
			m.quitConfirm = true
			m.complain(fmt.Sprintf(
				"%s still waiting. Press q again to leave %s to the other approvers.",
				plural(int32(len(m.queue)), "request is", "requests are"),
				pronoun(len(m.queue))))

			return m, nil
		}

		return m, tea.Quit

	case "?":
		m.mode = modeHelp
		m.helpScroll = 0

		return m, nil

	case "u":
		// Unlocking is only offered where there is something to unlock, and
		// only from the empty screen: a sealed store raises no cards, so there
		// is never one under this.
		if m.canUnlock() && item == nil {
			m.mode = modeUnlock
			m.clearTyped()
			m.status = ""
		}

		return m, nil

	// Moving between waiting requests is `[` and `]`, and a number picks one
	// straight off the strip. It had the arrow keys and tab, which are the keys
	// somebody reaches for to move around the diff in front of them — so on
	// the ordinary card, with one request waiting, every arrow key appeared to
	// do nothing at all. Choosing between requests is the rarer need and gets
	// the rarer keys.
	case "]":
		if len(m.queue) > 1 {
			m.sel = (m.sel + 1) % len(m.queue)
		}

		return m, nil

	case "[":
		if len(m.queue) > 1 {
			m.sel = (m.sel - 1 + len(m.queue)) % len(m.queue)
		}

		return m, nil
	}

	if index := strings.IndexByte("123456789", key[0]); len(key) == 1 &&
		index >= 0 && index < len(m.queue) {
		m.sel = index

		return m, nil
	}

	if item == nil {
		return m, nil
	}

	return m.itemKey(item, key)
}

// itemKey is the card: the facts, and the answers.
//
// Nothing here moves a cursor. Every key either scrolls the card, opens
// something, or answers — which is what makes `enter` usable for the answer
// somebody gives most often. Reading a file is a screen of its own, and `enter`
// there closes it (decision AN).
//
//nolint:cyclop // a key table is a list of cases; splitting it hides the table.
func (m *model) itemKey(item *card, key string) (tea.Model, tea.Cmd) {
	// Drawn before it is moved, because `G` means "the end" and the end is not
	// known until the card has been laid out at this width. Pressed before the
	// first paint it used to scroll to line zero of nothing.
	m.rebuild(item)

	switch key {
	case "up", "k":
		item.scroll--
	case "down", "j":
		item.scroll++
	case "pgup", "b":
		item.scroll -= m.bodyHeight()
	case "pgdown", " ":
		item.scroll += m.bodyHeight()
	case "home", "g":
		item.scroll = 0
	case "end", "G":
		item.scroll = len(item.lines)
	case "f":
		m.openFiles(item)
	case "n":
		m.stepFile(item, 1)
	case "p":
		m.stepFile(item, -1)
	case "r":
		return m, m.fetchDiff(item)
	// Enter is approve, the way it is the default action in a dialog: the
	// answer given most often should be the key under the reader's hand. It
	// means this only here — on the screen whose whole content is the four facts
	// a decision rests on. In the change itself it closes the change.
	case "enter", "a":
		return m, m.answer(item, answerBody{Decision: "approve"})
	case "d":
		return m, m.answer(item, answerBody{Decision: "deny"})
	case "w":
		m.openGrant(item)
	}

	return m, nil
}

// diffKey is one file's change on screen: somewhere to read, and one key to
// leave by.
//
// The answering letters still work, because they are deliberate and having to
// come back to say no to something you have just read would be its own small
// insult. `enter` does not: it is the key a reader presses without deciding to,
// and a signature is not something to approve by reflex.
func (m *model) diffKey(key string) (tea.Model, tea.Cmd) {
	item := m.current()
	if item == nil {
		m.mode = modeCard

		return m, nil
	}

	switch key {
	case "enter", "esc", "q":
		item.reading = -1
		m.mode = modeCard

		return m, nil

	case "up", "k":
		item.diffScroll--
	case "down", "j":
		item.diffScroll++
	case "pgup", "b":
		item.diffScroll -= m.bodyHeight()
	case "pgdown", " ":
		item.diffScroll += m.bodyHeight()
	case "home", "g":
		item.diffScroll = 0
	case "end", "G":
		item.diffScroll = len(m.diffLines(item))
	case "f":
		m.openFiles(item)
	case "n":
		m.stepFile(item, 1)
	case "p":
		m.stepFile(item, -1)
	case "r":
		return m, m.fetchDiff(item)
	case "a":
		return m, m.answer(item, answerBody{Decision: "approve"})
	case "d":
		return m, m.answer(item, answerBody{Decision: "deny"})
	case "w":
		m.openGrant(item)
	case "?":
		m.mode = modeHelp
		m.helpScroll = 0
	}

	return m, nil
}

// openFiles puts the file list up, starting on the file somebody was last
// taken to.
func (m *model) openFiles(item *card) {
	if m.files(item) == 0 {
		item.note = "This request carries no diff to pick a file from."
		item.noteErr = false

		return
	}

	item.picker = filePicker{at: max(item.reading, 0)}
	m.mode = modeFiles
}

// filesKey drives the file list: a cursor, a filter, and one way in and out.
//
// Typing narrows rather than jumping to a letter, because the change this is for
// is a commit touching thirty files. That makes every printable key a filter
// key, which is why `esc` is the only way out: a `q` would otherwise be
// ambiguous between quitting and looking for `queue.go`.
func (m *model) filesKey(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	item := m.current()
	if item == nil {
		m.mode = modeCard

		return m, nil
	}

	shown := m.shownFiles(item)
	picker := &item.picker

	switch key {
	case "esc":
		m.mode = modeCard

		return m, nil

	case "enter":
		m.mode = modeCard

		if picker.at < len(shown) {
			m.showFile(item, shown[picker.at].index)
		}

		return m, nil

	case "up", "k":
		picker.at--
	case "down", "j":
		picker.at++
	case "pgup":
		picker.at -= m.bodyHeight()
	case "pgdown":
		picker.at += m.bodyHeight()
	case "home":
		picker.at = 0
	case "end":
		picker.at = len(shown) - 1

	case "backspace":
		if len(picker.filter) > 0 {
			picker.filter = picker.filter[:len(picker.filter)-1]
			picker.at = 0
		}
	case "ctrl+u":
		picker.filter = picker.filter[:0]
		picker.at = 0

	default:
		if msg.Type == tea.KeyRunes {
			picker.filter = append(picker.filter, msg.Runes...)
			picker.at = 0
		}

		if msg.Type == tea.KeySpace {
			picker.filter = append(picker.filter, ' ')
			picker.at = 0
		}
	}

	picker.at = min(max(picker.at, 0), max(len(m.shownFiles(item))-1, 0))

	return m, nil
}

// pickedFile is one row of the list: the file, and where it is in the diff so
// that choosing it can open the right one however the list was narrowed.
type pickedFile struct {
	index int
	file  bridge.DiffFileView
}

// shownFiles is the list as the filter leaves it. A filter matching nothing
// shows nothing, which is the honest answer and says itself.
func (m *model) shownFiles(item *card) []pickedFile {
	diff := diffOf(item.view)
	if diff == nil {
		return nil
	}

	needle := strings.ToLower(string(item.picker.filter))

	out := make([]pickedFile, 0, len(diff.Files))

	for index, file := range diff.Files {
		if needle != "" &&
			!strings.Contains(strings.ToLower(pathOf(file)), needle) {
			continue
		}

		out = append(out, pickedFile{index: index, file: file})
	}

	return out
}

// showFile puts one file's change on screen.
func (m *model) showFile(item *card, index int) {
	if index < 0 || index >= m.files(item) {
		return
	}

	if item.reading != index {
		item.diffScroll = 0
	}

	item.reading = index
	m.mode = modeDiff
}

// stepFile is the quick way through a change: the next file, straight to its
// diff, without the list in between. Reading a commit file by file is a motion
// rather than a choice, and it wraps, so `n` from the last file is the first.
func (m *model) stepFile(item *card, by int) {
	count := m.files(item)
	if count == 0 {
		item.note = "This request carries no diff to read."
		item.noteErr = false

		return
	}

	next := item.reading + by

	switch {
	case item.reading < 0 && by > 0:
		next = 0
	case item.reading < 0:
		next = count - 1
	case next < 0:
		next = count - 1
	case next >= count:
		next = 0
	}

	m.showFile(item, next)
}

// diffLines is the file being read, drawn. Like the card it is cached against
// the width it was drawn at, since that is the only thing that changes it.
func (m *model) diffLines(item *card) []string {
	diff := diffOf(item.view)
	if diff == nil || item.reading < 0 || item.reading >= len(diff.Files) {
		return nil
	}

	return renderFileDiff(m.st, diff.Files[item.reading], m.cardWidth())
}

// openGrant starts the "approve for a while" form, unless this request may not
// be promised for at all — a pairing, and a key listing, are answered once and
// there is nothing to make a promise about (§9).
func (m *model) openGrant(item *card) {
	offer := item.view.Grant
	if offer == nil {
		item.note = "This request cannot be approved for a while."
		item.noteErr = false

		return
	}

	item.grant = grantForm{
		field:   0,
		machine: offer.Session == "",
		seconds: min(3600, offer.MaxSeconds),
	}

	m.mode = modeGrant
}

//nolint:cyclop // as above: this is the table for the grant form.
func (m *model) grantKey(key string) (tea.Model, tea.Cmd) {
	item := m.current()
	if item == nil {
		m.mode = modeCard

		return m, nil
	}

	offer := item.view.Grant
	if offer == nil {
		m.mode = modeCard

		return m, nil
	}

	form := &item.grant

	switch key {
	case "esc", "q", "w":
		m.mode = modeCard

		return m, nil

	case "tab", "up", "down":
		form.field = 1 - form.field

		return m, nil

	case "enter":
		m.mode = modeCard

		scope := "session"
		if form.machine {
			scope = "machine"
		}

		return m, m.answer(item, answerBody{
			Decision:     "approve",
			GrantSeconds: form.seconds,
			GrantScope:   scope,
		})
	}

	if form.field == 0 {
		// With no session to name there is only one reach on offer, and the
		// form says so rather than letting the arrow keys pretend otherwise.
		if offer.Session != "" && (key == "left" || key == "right" ||
			key == "h" || key == "l") {
			form.machine = !form.machine
		}

		return m, nil
	}

	m.adjust(form, offer, key)

	return m, nil
}

// adjust moves the length. Quarter-hours on the arrows and hours on the shifted
// ones, because a promise is a round number somebody chose and not a value to
// be dialled in a minute at a time.
func (m *model) adjust(form *grantForm, offer *bridge.GrantOffer, key string) {
	const (
		quarter = int64(15 * 60)
		hour    = int64(60 * 60)
	)

	switch key {
	case "left", "h":
		form.seconds -= quarter
	case "right", "l":
		form.seconds += quarter
	case "H":
		form.seconds -= hour
	case "L":
		form.seconds += hour
	default:
		index := strings.IndexByte("123456789", key[0])
		if len(key) != 1 || index < 0 || index >= len(offer.Suggestions) {
			return
		}

		form.seconds = offer.Suggestions[index]
	}

	form.seconds = min(max(form.seconds, minGrantSeconds), offer.MaxSeconds)
}

// minGrantSeconds is the shortest promise the bridge will make, and is here so
// that the form refuses to dial below it rather than offering a length that is
// then rejected.
const minGrantSeconds = 60

// answer sends a decision. The card stays where it is until the daemon takes it
// away, which is what makes an answer that lost a race visible.
func (m *model) answer(item *card, body answerBody) tea.Cmd {
	if item.answering {
		return nil
	}

	item.answering = true
	item.note = ""
	m.answered[item.id] = true

	id := item.id

	return func() tea.Msg {
		err := m.api.answer(id, body)

		return answeredMsg{
			id:       id,
			approved: body.Decision == "approve",
			err:      err,
		}
	}
}

// fetchDiff asks the machine that wants the signature for the rest of a diff
// the caps cut short (§5).
func (m *model) fetchDiff(item *card) tea.Cmd {
	diff := diffOf(item.view)
	if diff == nil || !diff.Truncated {
		item.note = "The whole diff is already here."
		item.noteErr = false

		return nil
	}

	if item.answering {
		return nil
	}

	item.answering = true
	item.note = "Asking for the rest of the diff…"
	item.noteErr = false

	id := item.id

	return func() tea.Msg {
		view, err := m.api.diff(id)

		return diffMsg{id: id, diff: view, err: err}
	}
}

// files is how many files the change touches, for the footer that offers to
// list them. Zero when there is no diff, which is when there is nothing to
// pick from.
func (m *model) files(item *card) int {
	if diff := diffOf(item.view); diff != nil {
		return len(diff.Files)
	}

	return 0
}

// rebuild redraws the card when the width has changed, which is the only thing
// that changes it now that the diff is not folded into it.
func (m *model) rebuild(item *card) {
	width := m.cardWidth()

	if item.width == width && item.lines != nil {
		return
	}

	item.lines = renderCard(m.st, item.view, width)
	item.width = width
}

func (m *model) cardWidth() int {
	return max(m.width-2, 20)
}

func pronoun(n int) string {
	if n == 1 {
		return "it"
	}

	return "them"
}

// clamp keeps the scroll inside the card, and is applied at draw time rather
// than at every keystroke so that a page down at the bottom is not an error.
func clamp(scroll, rows, height int) int {
	if rows <= height {
		return 0
	}

	return min(max(scroll, 0), rows-height)
}

// truncate cuts a line to the width, for the header and the queue strip where
// what is cut is a name rather than a fact somebody is deciding on.
func truncate(text string, width int) string {
	if width <= 0 {
		return ""
	}

	return ansi.Truncate(text, width, "…")
}
