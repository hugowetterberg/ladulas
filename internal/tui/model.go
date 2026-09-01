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

	expanded map[int]bool
	scroll   int
	// focus is the diff file the file keys act on, or -1 before anything has
	// been focused.
	focus int

	rows  []row
	width int

	answering bool
	note      string
	noteErr   bool

	grant grantForm
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
		id:       msg.id,
		since:    waitingSince(msg),
		view:     msg.view,
		expanded: map[int]bool{},
		focus:    -1,
		grant:    grantForm{seconds: 3600},
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

		if m.mode == modeGrant {
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

	case "tab", "right":
		if len(m.queue) > 1 {
			m.sel = (m.sel + 1) % len(m.queue)
		}

		return m, nil

	case "shift+tab", "left":
		if len(m.queue) > 1 {
			m.sel = (m.sel - 1 + len(m.queue)) % len(m.queue)
		}

		return m, nil
	}

	if item == nil {
		return m, nil
	}

	return m.itemKey(item, key)
}

//nolint:cyclop // as above: this is the table for a card.
func (m *model) itemKey(item *card, key string) (tea.Model, tea.Cmd) {
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
		item.scroll = len(item.rows)
	case "n":
		m.focusFile(item, 1)
	case "p":
		m.focusFile(item, -1)
	case "enter":
		m.toggleFile(item)
	case "e":
		m.setAllFiles(item, true)
	case "c":
		m.setAllFiles(item, false)
	case "f":
		return m, m.fetchDiff(item)
	case "a":
		return m, m.answer(item, answerBody{Decision: "approve"})
	case "d":
		return m, m.answer(item, answerBody{Decision: "deny"})
	case "w":
		m.openGrant(item)
	}

	return m, nil
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

// The diff's focus ring. `n` and `p` walk the file headers and enter opens the
// one under the cursor, which is how a diff is read on a screen with no pointer
// on it.
func (m *model) focusFile(item *card, by int) {
	m.rebuild(item)

	heads := fileHeads(item.rows)
	if len(heads) == 0 {
		return
	}

	next := item.focus + by

	switch {
	case item.focus < 0 && by > 0:
		next = 0
	case item.focus < 0:
		next = len(heads) - 1
	case next < 0:
		next = len(heads) - 1
	case next >= len(heads):
		next = 0
	}

	item.focus = next
	item.scroll = max(0, heads[next]-2)
}

func (m *model) toggleFile(item *card) {
	if item.focus < 0 {
		m.focusFile(item, 1)

		return
	}

	item.expanded[item.focus] = !item.expanded[item.focus]
	item.width = 0

	m.rebuild(item)

	if heads := fileHeads(item.rows); item.focus < len(heads) {
		item.scroll = max(0, heads[item.focus]-2)
	}
}

func (m *model) setAllFiles(item *card, open bool) {
	diff := diffOf(item.view)
	if diff == nil {
		return
	}

	for index := range diff.Files {
		item.expanded[index] = open
	}

	item.width = 0
	m.rebuild(item)
}

// fileHeads is the row index of each file's summary line, which is what the
// focus ring walks.
func fileHeads(rows []row) []int {
	var heads []int

	for index, line := range rows {
		if line.head {
			heads = append(heads, index)
		}
	}

	return heads
}

// rebuild redraws the card when the width or the open files have changed.
func (m *model) rebuild(item *card) {
	width := m.cardWidth()

	if item.width == width && item.rows != nil {
		return
	}

	item.rows = renderCard(m.st, item.view, width, item.expanded)
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
