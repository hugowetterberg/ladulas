package peer

// PairingAnnouncer puts a pairing window on the local network while its PIN is
// on screen, so that a joining desktop or headless box can list it by name
// rather than having somebody type an address (decision AW).
//
// It is an interface here and DNS-SD in internal/discovery because a phone
// never announces: phones are always joiners, pair by scanning the QR, and
// accept no peer connections at all (§3). The multicast responder and its
// dependencies stay out of the gomobile build by never being imported by it,
// and a node with no announcer — every phone, and every test — pairs exactly
// as it did before, by address and by full code.
//
// The signatures are strings and an error, which is all `gomobile` needs to
// see of it (§21).
type PairingAnnouncer interface {
	// AnnouncePairing starts announcing a window under the instance's name,
	// replacing anything announced before. It returns one sentence for the
	// screen showing the PIN — where the window is announced, or why it is
	// not — and an error when it is not. Not being announced is never a
	// reason not to show the PIN: the full code and an address both still
	// work.
	AnnouncePairing(name string) (string, error)
	// WithdrawPairing withdraws the announcement with goodbye packets. It is
	// safe to call when nothing is announced.
	WithdrawPairing()
}

// AnnouncePairingWith gives the node its announcer. It is set once, after
// New, by whatever built the node — the announcer needs to ask the node what
// its listener bound, so the two cannot be built in one expression.
func (n *Node) AnnouncePairingWith(announcer PairingAnnouncer) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.announcer = announcer
}

// announce puts a window on the network, if this node has an announcer, and
// returns what the screen should say about it. Empty means there is nothing
// to say: a node without an announcer is one that never announces, and a
// sentence about that on every phone's screen would be noise.
//
// windowAnnounceMu is held across the check and the call, here and in
// withdrawWindow. Holding mu only for the bookkeeping and calling the
// announcer after releasing it let a screen going away check that its
// window was still the announced one, lose the processor to a second
// screen's announce, and then withdraw the second screen's announcement: a
// PIN on screen saying "Announced" with nothing on the network.
func (n *Node) announce(window *pairingWindow) string {
	n.windowAnnounceMu.Lock()
	defer n.windowAnnounceMu.Unlock()

	n.mu.Lock()
	announcer := n.announcer
	closed := n.pairingClosed

	if !closed {
		n.announcedWindow = window
	}
	n.mu.Unlock()

	if announcer == nil || closed {
		return ""
	}

	// The error is the announcer's to log, and it does; here it changes
	// nothing, because the PIN goes on screen either way and the sentence
	// already says why the window is not in anybody's list.
	note, _ := announcer.AnnouncePairing(n.identity.Name())

	return note
}

// withdrawWindow takes a window off the network, if it is still the one announced.
//
// The check is what lets a screen that is going away call this without
// knowing whether another screen has since opened a window of its own: one
// window at a time means a second BeginPairing closes the first, and the
// first's deferred withdraw must not take the second's announcement with it.
func (n *Node) withdrawWindow(window *pairingWindow) {
	n.windowAnnounceMu.Lock()
	defer n.windowAnnounceMu.Unlock()

	n.withdrawLocked(window)
}

// withdrawLocked is withdrawWindow with windowAnnounceMu held.
func (n *Node) withdrawLocked(window *pairingWindow) {
	n.mu.Lock()
	announcer := n.announcer
	current := n.announcedWindow == window && window != nil

	if current {
		n.announcedWindow = nil
	}
	n.mu.Unlock()

	if current && announcer != nil {
		announcer.WithdrawPairing()
	}
}

// withdrawAny takes whatever is announced off the network, and keeps anything
// from being announced again. It is what closing the node does: a sealed
// instance announces nothing (§3), including a window whose BeginPairing was
// still on its way to announce when the node closed.
func (n *Node) withdrawAny() {
	n.windowAnnounceMu.Lock()
	defer n.windowAnnounceMu.Unlock()

	n.mu.Lock()
	window := n.announcedWindow
	n.pairingClosed = true
	n.mu.Unlock()

	n.withdrawLocked(window)
}
