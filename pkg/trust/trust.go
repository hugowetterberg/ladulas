// Package trust is the paired-peer side of Ladulås: the records, the approval
// directions, and the pairing code that establishes them (docs/architecture.md
// §7).
//
// A trust record is the identity key of a peer plus what this instance has
// decided that peer may do. The directions are declared independently by each
// side and never negotiated: what the peer says it wrote down about us is shown
// on the pairing prompt and then forgotten. That is also why revocation is
// unilateral — nothing in a record needs the other end's agreement, so nothing
// in forgetting one does either.
package trust

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// ErrNoSuchPeer is returned when a name or fingerprint matches no record.
var ErrNoSuchPeer = errors.New("trust: no such peer")

// Store holds trust records. keystore.Vault implements it, which is what keeps
// them inside the encrypted store where §10 puts them.
//
// **A record that has been handed out is never written to again.** That is the
// whole of what makes the rest of the system safe without a lock in sight: a
// link holds the record for its peer for the lifetime of a connection, and
// every request that arrives is authorized by reading fields off a record while
// the store carries on serving. None of those readers takes a lock, and none of
// them should have to.
//
// So an implementation returns records the caller owns — a copy, or a message
// it will never touch again — and a change to a peer's permissions builds the
// replacement and swaps it in rather than reaching into the record that is out
// there being read. Applied and Renamed are how that is spelled; there is no
// in-place mutator, deliberately.
//
// The failure this rules out is not merely a torn field. `ladulas peers allow`
// sets a direction and a key list at once, and a reader part way through would
// authorize against the old direction and the new keys, or the reverse — a
// permission decision made from a state neither user ever asked for.
type Store interface {
	// Peers returns every record. The records belong to the caller.
	Peers() []*storepb.TrustRecord
	// Peer finds a record by fingerprint or by name. The record belongs to the
	// caller.
	Peer(ref string) (*storepb.TrustRecord, bool)
	// PutPeer writes a record, replacing any with the same fingerprint.
	PutPeer(record *storepb.TrustRecord) error
	// RemovePeer forgets a peer and returns the fingerprint it forgot.
	RemovePeer(ref string) (string, error)
}

// PublicKey parses the identity key out of a record.
func PublicKey(record *storepb.TrustRecord) (ssh.PublicKey, error) {
	pub, err := ssh.ParsePublicKey(record.GetIdentityPublicKey())
	if err != nil {
		return nil, fmt.Errorf("trust: unusable identity key for %q: %w",
			record.GetName(), err)
	}

	// The fingerprint is display, and the key is the record — but a record
	// whose two halves disagree has been tampered with or has been written by
	// something with a bug, and neither is a thing to authorize against.
	if got := ssh.FingerprintSHA256(pub); got != record.GetFingerprint() {
		return nil, fmt.Errorf(
			"trust: record for %q claims %s but holds %s",
			record.GetName(), record.GetFingerprint(), got)
	}

	return pub, nil
}

// NewRecord builds a trust record from what a pairing exchange established.
func NewRecord(
	name string, pub ssh.PublicKey, addresses []string,
	mayApprove, mayRequest, weInitiated bool,
) *storepb.TrustRecord {
	return &storepb.TrustRecord{
		Fingerprint:       ssh.FingerprintSHA256(pub),
		Name:              name,
		IdentityPublicKey: pub.Marshal(),
		Addresses:         addresses,
		MayApprove:        mayApprove,
		MayRequest:        mayRequest,
		PairedAt:          timestamppb.Now(),
		WeInitiated:       weInitiated,
	}
}

// Directions is everything one side has decided a peer may do. It is passed
// around whole rather than as three arguments because it is one decision: the
// caller says what the record should say afterwards, and anything it leaves out
// is a permission it is taking away.
type Directions struct {
	// MayApprove lets the peer answer this instance's requests, and MayRequest
	// lets it put requests to this instance.
	MayApprove bool
	MayRequest bool
	// AllowedKeys are the keys the peer may ask this instance to sign with, as
	// fingerprints. Resolving a label to a fingerprint happens where the keys
	// are; a record only ever holds fingerprints.
	AllowedKeys []string
	// AllKeys covers every key the instance holds, now and later (§7).
	AllKeys bool
}

// Intent is what a pairing is for, as the side displaying the code declares it
// — decision AD.
//
// It is the same two flags Directions holds, asked as one question instead of
// two. That is the whole of the change and it is not cosmetic: the two sides
// used to declare a half each, independently, with nothing making the halves
// agree, so "this machine may approve for me" was routinely written down about
// an instance whose own user had never said it would answer anything. Pairing
// one of those does not add a second way to get an answer, it takes the first
// one away (decision AC).
//
// The names are from the point of view of the screen the code is on: the peer
// is the machine about to join. Changing what a pairing is for means removing
// the peer and pairing again, which is a deliberate limit — a direction that
// can be widened later is a direction nobody has to think about now, and this
// is the one question a pairing exists to ask.
type Intent int

const (
	// IntentUnspecified is not an intent. It is what an unset field reads as,
	// and it is refused rather than defaulted: guessing here is what decision
	// AD exists to stop.
	IntentUnspecified Intent = iota
	// IntentPeerApproves: the machine that joins answers for this one. What
	// somebody at a headless box wants when they pair a phone.
	IntentPeerApproves
	// IntentPeerRequests: this machine answers for the one that joins. The
	// same pairing from the other end, and what somebody at a desktop wants
	// when they display a code for a build box.
	IntentPeerRequests
	// IntentMutual: both directions.
	IntentMutual
)

// ParseIntent reads the word somebody typed or clicked.
func ParseIntent(text string) (Intent, error) {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "approver":
		return IntentPeerApproves, nil
	case "requester":
		return IntentPeerRequests, nil
	case "mutual", "both":
		return IntentMutual, nil
	default:
		return IntentUnspecified, fmt.Errorf(
			"trust: %q is not what a pairing can be for; "+
				"use approver, requester or mutual", text)
	}
}

// IntentOf reads an intent back out of the two flags a record holds.
func IntentOf(mayApprove, mayRequest bool) Intent {
	switch {
	case mayApprove && mayRequest:
		return IntentMutual
	case mayApprove:
		return IntentPeerApproves
	case mayRequest:
		return IntentPeerRequests
	default:
		return IntentUnspecified
	}
}

// PeerMayApprove and PeerMayRequest are the intent as the declaring side writes
// it down.
func (i Intent) PeerMayApprove() bool {
	return i == IntentPeerApproves || i == IntentMutual
}

// PeerMayRequest reports whether the peer may put requests to the declaring
// side.
func (i Intent) PeerMayRequest() bool {
	return i == IntentPeerRequests || i == IntentMutual
}

// Mirror is the same pairing as the other side records it.
//
// A peer that may ask us to approve is a peer we approve for, so the mirror is
// the two flags swapped — which is why one declaration settles both records and
// the joining side has nothing to declare. A mutual pairing mirrors to itself.
func (i Intent) Mirror() Intent {
	switch i {
	case IntentPeerApproves:
		return IntentPeerRequests
	case IntentPeerRequests:
		return IntentPeerApproves
	case IntentMutual, IntentUnspecified:
		return i
	}

	return IntentUnspecified
}

// String is the word the command line and the API use.
func (i Intent) String() string {
	switch i {
	case IntentPeerApproves:
		return "approver"
	case IntentPeerRequests:
		return "requester"
	case IntentMutual:
		return "mutual"
	case IntentUnspecified:
	}

	return "none"
}

// Describe says what the intent means in the words a prompt should use, which
// are Describe's: an intent is two directions asked as one question, and the
// sentence a person reads has to be the same either way.
func (i Intent) Describe() string {
	return Describe(i.PeerMayApprove(), i.PeerMayRequest())
}

// IntentFromWire and IntentToWire convert to the control API's enum.
//
// They live here rather than beside either caller for the reason DescribeState
// does: there is one vocabulary for what a pairing is for, and a second mapping
// of it somewhere else is a second thing to keep in step.
func IntentFromWire(intent ladulasv1.PairingIntent) Intent {
	switch intent {
	case ladulasv1.PairingIntent_PAIRING_INTENT_PEER_APPROVES:
		return IntentPeerApproves
	case ladulasv1.PairingIntent_PAIRING_INTENT_PEER_REQUESTS:
		return IntentPeerRequests
	case ladulasv1.PairingIntent_PAIRING_INTENT_MUTUAL:
		return IntentMutual
	case ladulasv1.PairingIntent_PAIRING_INTENT_UNSPECIFIED:
	}

	return IntentUnspecified
}

// IntentToWire is the other direction.
func IntentToWire(intent Intent) ladulasv1.PairingIntent {
	switch intent {
	case IntentPeerApproves:
		return ladulasv1.PairingIntent_PAIRING_INTENT_PEER_APPROVES
	case IntentPeerRequests:
		return ladulasv1.PairingIntent_PAIRING_INTENT_PEER_REQUESTS
	case IntentMutual:
		return ladulasv1.PairingIntent_PAIRING_INTENT_MUTUAL
	case IntentUnspecified:
	}

	return ladulasv1.PairingIntent_PAIRING_INTENT_UNSPECIFIED
}

// DirectionsOf reads the decisions back out of a record.
func DirectionsOf(record *storepb.TrustRecord) Directions {
	return Directions{
		MayApprove:  record.GetMayApprove(),
		MayRequest:  record.GetMayRequest(),
		AllowedKeys: record.GetAllowedKeyFingerprints(),
		AllKeys:     record.GetMayUseAllKeys(),
	}
}

// Applied returns the record as it should read once the decisions are made.
//
// It builds a new record rather than changing the one it was given, and that is
// the rule Store states rather than a preference: the record it is given may be
// one an authorization is being decided against right now, on another goroutine
// and without a lock. A store applies this by swapping the result into the
// place the old one occupied.
func (d Directions) Applied(record *storepb.TrustRecord) *storepb.TrustRecord {
	revised := proto.CloneOf(record)

	revised.MayApprove = d.MayApprove
	revised.MayRequest = d.MayRequest
	revised.AllowedKeyFingerprints = append([]string(nil), d.AllowedKeys...)
	revised.MayUseAllKeys = d.AllKeys

	return revised
}

// Renamed returns the record under a different name, and returns a new one for
// the same reason Applied does.
func Renamed(record *storepb.TrustRecord, name string) *storepb.TrustRecord {
	revised := proto.CloneOf(record)

	revised.Name = name

	return revised
}

// MayUseKey reports whether a peer is allowed to ask for a signature with a
// key.
//
// Holding a key for a peer is a permission of its own, separate from either
// approval direction: a peer that may ask this instance to approve is not
// thereby allowed to borrow its keys, and a peer that approves for us has no
// business signing with ours either. Nothing here falls back to a direction
// flag, so the only way to end up with key access is to have been given it.
func MayUseKey(record *storepb.TrustRecord, fingerprint string) bool {
	if record.GetMayUseAllKeys() {
		return true
	}

	for _, allowed := range record.GetAllowedKeyFingerprints() {
		if allowed == fingerprint {
			return true
		}
	}

	return false
}

// DescribeKeys renders a peer's key access the way a listing should read.
func DescribeKeys(record *storepb.TrustRecord) string {
	switch {
	case record.GetMayUseAllKeys():
		return "all"
	case len(record.GetAllowedKeyFingerprints()) == 0:
		return "none"
	default:
		return fmt.Sprintf("%d", len(record.GetAllowedKeyFingerprints()))
	}
}

// Describe renders what a pairing means, in the words a prompt should use.
//
// The two directions are separate sentences on purpose: "this machine may
// approve for me" and "this machine may ask me to approve" are different
// decisions with different blast radii, and a prompt that collapsed them into
// "trust this peer" would be hiding the one that matters.
func Describe(mayApprove, mayRequest bool) string {
	switch {
	case mayApprove && mayRequest:
		return "may approve signing requests for this instance, " +
			"and may ask this instance to approve its own"
	case mayApprove:
		return "may approve signing requests for this instance"
	case mayRequest:
		return "may ask this instance to approve its signing requests"
	default:
		return "may do nothing until a direction is granted"
	}
}

// DescribeShort says the same thing as Describe in the words a list row has
// space for.
//
// It is here rather than in whatever is drawing the row because both wordings
// are describing the same pair of permissions and they have to agree: a row
// that says one thing and the card behind it another is worse than a row that
// says nothing. The two directions stay distinguishable, which is the part of
// Describe's reasoning that survives being shortened.
func DescribeShort(mayApprove, mayRequest bool) string {
	switch {
	case mayApprove && mayRequest:
		return "Approves and asks"
	case mayApprove:
		return "Approves for this instance"
	case mayRequest:
		return "Asks this instance to approve"
	default:
		return "No direction yet"
	}
}

// DescribeState says how a peer is reachable right now, in the words every
// surface shows: the pill on a card, the STATE column of `ladulas peers list`,
// and the badge on the phone.
//
// It lives here for the reason DescribeShort does — two surfaces describing the
// same fact have to agree — and it existed twice before that, once in
// internal/command and once in internal/frontend, which is exactly the drift
// this package is for.
//
// **Not being connected is not the same as not being available**, and the
// difference is which side does the dialling. A machine that listens is
// something this instance dials, so a link that is not up is a machine that is
// not there: "connecting" while it tries, "offline" once a dial has failed. A
// phone listens to nothing. It reaches *us* — when somebody opens the app, when
// a push wakes it, when it polls — so a phone with no link is the ordinary state
// of a phone in a pocket, and calling that "offline" says its keys are gone when
// they are one notification away (§11, decision T). What it gets instead is when
// it was last here, which is the question somebody actually has: a phone seen a
// minute ago and a phone seen in March want different things done.
//
// The lack of an address is what tells the two apart, because it is the same
// thing the dialling is decided on: a peer whose record carries no address is
// one nothing can dial.
func DescribeState(
	online bool, addresses []string, mayApprove bool,
	lastError string, lastSeen time.Time, now time.Time,
) string {
	if online {
		return "connected"
	}

	// A peer that only asks this instance for approvals is never dialled from
	// here, so there is no reachability to report about it at all.
	if !mayApprove {
		return "listening"
	}

	if len(addresses) == 0 {
		if !known(lastSeen) {
			// Not "never": this instance forgets when a peer was last here every
			// time it restarts (peer.Node.seen), so the honest statement is about
			// what it is doing rather than about the peer's history.
			return "waiting to hear from it"
		}

		return "last seen " + DescribeAge(now.Sub(lastSeen))
	}

	if lastError != "" {
		return "offline"
	}

	return "connecting"
}

// known reports whether a timestamp is a time rather than an absence.
//
// Both spellings of "no time" have to be caught. A Go zero `time.Time` is the
// year 1, and a nil protobuf timestamp becomes `time.Unix(0, 0)` — the epoch,
// which is emphatically not `IsZero()`. Missing that turned a phone nothing had
// heard from into one "last seen 20683 days ago", which is 1970 counted in days
// and the sort of thing a reader has to decode rather than read.
func known(at time.Time) bool {
	return !at.IsZero() && at.Unix() > 0
}

// DescribeAge is how long ago something was, in the two or three characters a
// pill has room for. It rounds down and stops at days, because "last seen 4d
// ago" and "last seen 4d 7h ago" lead to the same decision.
func DescribeAge(since time.Duration) string {
	switch {
	case since < time.Minute:
		return "just now"
	case since < time.Hour:
		return fmt.Sprintf("%dm ago", int(since.Minutes()))
	case since < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(since.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(since.Hours()/24))
	}
}

// MatchesRef reports whether a record answers to a name or fingerprint.
func MatchesRef(record *storepb.TrustRecord, ref string) bool {
	return record.GetFingerprint() == ref ||
		strings.EqualFold(record.GetName(), ref)
}
