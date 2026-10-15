package peer

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/internal/cpace"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// How the PIN exchange binds CPace to a pairing (decision AV, and the comment
// above PairStartRequest in service.proto, which is the wire's description of
// the same thing).
//
// The listener is CPace's initiator and the joiner its responder, and that is
// the whole of why the order is safe. The listener's first message is a share,
// which reveals nothing about the PIN to anybody. The joiner then has the key
// and sends its share and its tag together, so it has committed — spent its one
// guess, if it is guessing — before it has received anything derived from the
// key. The listener verifies that tag before it sends its own and before it
// reads anything else the joiner said. An attacking joiner therefore learns
// nothing it can check until it has paid for it, and an impostor listener gets
// one guess: the joiner's tag.
//
// The party identities go into CI, the channel identifier, as the draft
// prefers (§10.1): both identity keys as the TLS handshake presented them, so a
// relay that got either side to connect to it computes over its own key and
// arrives at a different key altogether. They are in a fixed order, joiner
// then listener. The draft recommends initiator first; what it requires is
// that the encoding ties each identity to its role, which a fixed order does,
// and the order was settled before the roles were (the feasibility study that
// preceded decision AV), so it is kept rather than flipped to match a
// recommendation.
const (
	// pakeVersion is the protocol the associated data carries, so that it is
	// part of what both sides must agree on and cannot be negotiated down.
	pakeVersion = "ladulas-pairing-v2"

	// adListener and adJoiner are the two sides' associated data: the version,
	// and the direction. The draft's own tags are already over different
	// messages; the direction labels make that true of the associated data as
	// well, the way the older proof's two prefixes did.
	adListener = pakeVersion + "/listener"
	adJoiner   = pakeVersion + "/joiner"

	// pakeSessionIDSize is the length of the CPace session id the listener
	// mints for each run.
	pakeSessionIDSize = 16

	// pinExchangeTimeout is how long a started exchange may wait for its
	// second round. It has been charged an attempt since it started; this is
	// only when it is written down as abandoned, so the displaying screen can
	// say so and the window can find out that its attempts are spent.
	pinExchangeTimeout = 30 * time.Second
)

// Errors the joining side reports in so many words (§7). They are sentences a
// person reads on the screen they typed the PIN into, so they say what to do.
var (
	// ErrCodeSpent is the code already used by somebody else. The other
	// machine now has a pending pairing with whoever that was, and the person
	// at it is about to be asked to confirm it.
	ErrCodeSpent = errors.New(
		"another machine used this code — reject the pairing on the other screen")

	// ErrPINRefused is the listener refusing the PIN, which is either a typo
	// or the wrong machine: a wrong address typed, or a wrong entry picked
	// from the list (decision AW), which can be a stranger's announcement
	// under the right name.
	ErrPINRefused = errors.New(
		"that machine refused the PIN — if you typed it correctly, " +
			"you may have picked the wrong machine or address")

	// ErrPossibleImpostor is a machine that answered at the address but does
	// not behave like one displaying this PIN: one that does not speak the PIN
	// exchange at all, or one whose confirmation does not verify.
	ErrPossibleImpostor = errors.New(
		"the machine that answered may be an impostor")

	// ErrAttemptsSpent is a window that has had all the attempts it allows.
	ErrAttemptsSpent = errors.New(
		"that machine has refused too many attempts at this code; " +
			"ask for a new one")
)

// pinInputs is the CPace input both sides compute, each from the keys its own
// TLS handshake saw.
func pinInputs(pin trust.PIN, joiner, listener ssh.PublicKey, sid []byte) cpace.Inputs {
	return cpace.Inputs{
		PRS: []byte(pin),
		CI:  cpace.LVCat(joiner.Marshal(), listener.Marshal()),
		SID: sid,
	}
}

// newPAKESessionID mints the listener's session id for one run.
func newPAKESessionID() ([]byte, error) {
	sid := make([]byte, pakeSessionIDSize)

	if _, err := rand.Read(sid); err != nil {
		return nil, fmt.Errorf("peer: no randomness for a pairing exchange: %w", err)
	}

	return sid, nil
}
