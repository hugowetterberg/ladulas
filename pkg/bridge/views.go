package bridge

import (
	"fmt"
	"strings"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The view types are the bridge contract. They are hand-written rather than
// protojson of the wire types because they are a different thing: the wire
// schema is what peers agree on, and this is what a viewer needs in order to
// draw a card. Keeping them apart means a field can be added to either without
// the other having to change, and it keeps the raw signed object — which the
// viewer has no use for — off the wire to the webview.

// RequestView is one approval request, ready to render.
type RequestView struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	CreatedAt string `json:"createdAt,omitempty"`
	Title     string `json:"title"`
	Subject   string `json:"subject,omitempty"`
	// Danger marks warnings that should be shown in red rather than amber.
	Danger   bool         `json:"danger,omitempty"`
	Warnings []string     `json:"warnings,omitempty"`
	Details  []DetailView `json:"details,omitempty"`
	Grant    *GrantOffer  `json:"grant,omitempty"`

	Key       *KeyView       `json:"key,omitempty"`
	Requester *RequesterView `json:"requester,omitempty"`

	// Project is the published documentation this change belongs to, and how
	// current it is (§6).
	Project *RequestProjectView `json:"project,omitempty"`

	Git     *GitView     `json:"git,omitempty"`
	SSHAuth *SSHAuthView `json:"sshAuth,omitempty"`
	Sshsig  *SshsigView  `json:"sshsig,omitempty"`
	Opaque  *OpaqueView  `json:"opaque,omitempty"`
	Pairing *PairingView `json:"pairing,omitempty"`
}

// DetailView is a labelled line for the kinds that have no card of their own.
type DetailView struct {
	Label    string `json:"label"`
	Value    string `json:"value"`
	Asserted bool   `json:"asserted,omitempty"`
}

// GrantOffer is what "approve for a while" may be on this request: how far the
// promise can reach, how long it may run, and the lengths worth one tap
// (decision V).
//
// It replaced a list of four ready-made buttons, and the reason is what those
// buttons could not say. A length was a label — "approve this kitty window for
// 3 hours" — so the promise's reach was written into the same word as its
// length, four times over, and the wider promise was not on offer at all. Here
// the two are asked separately: who it is made to, and then how long, on a
// clock.
type GrantOffer struct {
	// Session is who a session-wide promise would be made to, worded for a
	// button: "this kitty window" (decision U). Empty when the request named no
	// session, and then there is only the machine to promise anything to.
	Session string `json:"session,omitempty"`
	// Machine is the machine that asked, for the wider promise.
	Machine string `json:"machine"`
	// MaxSeconds is as long as this instance will promise anything for. A
	// surface offers nothing past it and the bridge refuses anything past it.
	MaxSeconds int64 `json:"maxSeconds"`
	// Suggestions are the lengths a policy considers worth one tap. Nothing
	// says a promise has to be one of them.
	Suggestions []int64 `json:"suggestions,omitempty"`
	// Trust is set when the promise would rest on something the requesting
	// machine only asserted (decision X), and says what it is before it is made.
	Trust *GrantTrust `json:"trust,omitempty"`
}

// GrantTrust is the note a grant offer carries when the promise would lean on
// requester-asserted context (decision X): the facts it would take on the
// requester's word, a line saying so, and the fuller explanation a surface puts
// behind a disclosure. It is set only for a request from another machine — when
// the requester is this machine the asserted context is this machine's own word
// — and only when a grant's scope would pin something unverified, so an ordinary
// local commit does not carry it.
type GrantTrust struct {
	// Facts are the asserted scope fields the promise would pin, labelled the
	// way every asserted line on the card is.
	Facts []DetailView `json:"facts,omitempty"`
	// Note is the one line shown beside the length.
	Note string `json:"note"`
	// Detail is the fuller explanation of what the promise trusts the remote to
	// keep telling the truth about, meant for a disclosure.
	Detail string `json:"detail"`
}

// KeyView is the key a request wants to use.
type KeyView struct {
	Label       string `json:"label"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

// RequesterView says who is asking.
type RequesterView struct {
	Name     string `json:"name,omitempty"`
	Local    bool   `json:"local"`
	Headless bool   `json:"headless,omitempty"`
	Program  string `json:"program,omitempty"`
	Address  string `json:"address,omitempty"`
	// App is the name of what asked — `kitty`, `emacs` — and Asker is the same
	// name with the session that says so (decision U). Both are the thing a
	// card leads with: the helper at the socket is `ssh` whoever ran it, and
	// the session is what tells one window from another. Chain is the walk from
	// the helper up to it, so the name can be checked rather than believed, and
	// belongs with the rest of the detail behind an (i).
	App   string `json:"app,omitempty"`
	Asker string `json:"asker,omitempty"`
	Chain string `json:"chain,omitempty"`
}

// IdentityView is a git author, committer or tagger.
type IdentityView struct {
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	Time     string `json:"time,omitempty"`
	Timezone string `json:"timezone,omitempty"`
}

// HeaderView is an object header the schema has no field for.
type HeaderView struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// GitView is the rich commit card.
//
// Verified is the field the whole card hangs off: it says whether the object
// below was checked against the bytes being signed, and the viewer renders a
// different provenance line depending on it (§5).
type GitView struct {
	Verified          bool   `json:"verified"`
	VerificationError string `json:"verificationError,omitempty"`
	ObjectType        string `json:"objectType,omitempty"`
	Operation         string `json:"operation,omitempty"`

	// Requester-asserted.
	Repository string `json:"repository,omitempty"`
	OriginURL  string `json:"originUrl,omitempty"`
	Branch     string `json:"branch,omitempty"`

	// Derived from the signed bytes.
	Subject string `json:"subject,omitempty"`
	Message string `json:"message,omitempty"`
	// Body is the message with its subject line taken off, for a surface that
	// has already shown the subject somewhere else — which on a phone is the
	// summary card at the top of the screen (decision W). Sending both is not a
	// convenience: splitting the message where the first newline is would be a
	// renderer working out what "the subject" means, and the whole of §5 is
	// that what is shown beside a signature is parsed once, on this side.
	Body         string        `json:"body,omitempty"`
	Author       *IdentityView `json:"author,omitempty"`
	Committer    *IdentityView `json:"committer,omitempty"`
	Tagger       *IdentityView `json:"tagger,omitempty"`
	Tag          string        `json:"tag,omitempty"`
	TaggedObject string        `json:"taggedObject,omitempty"`
	TaggedType   string        `json:"taggedType,omitempty"`
	Tree         string        `json:"tree,omitempty"`
	Parents      []string      `json:"parents,omitempty"`
	ExtraHeaders []HeaderView  `json:"extraHeaders,omitempty"`

	Diff *DiffView `json:"diff,omitempty"`
}

// DiffView is the change, already parsed.
type DiffView struct {
	FilesChanged   int32          `json:"filesChanged"`
	Insertions     int32          `json:"insertions"`
	Deletions      int32          `json:"deletions"`
	Range          string         `json:"range,omitempty"`
	Truncated      bool           `json:"truncated,omitempty"`
	TruncationNote string         `json:"truncationNote,omitempty"`
	Error          string         `json:"error,omitempty"`
	Files          []DiffFileView `json:"files,omitempty"`
}

// DiffFileView is one file's diff.
type DiffFileView struct {
	OldPath    string         `json:"oldPath,omitempty"`
	NewPath    string         `json:"newPath,omitempty"`
	Status     string         `json:"status,omitempty"`
	Insertions int32          `json:"insertions"`
	Deletions  int32          `json:"deletions"`
	Binary     bool           `json:"binary,omitempty"`
	ModeChange string         `json:"modeChange,omitempty"`
	Truncated  bool           `json:"truncated,omitempty"`
	Hunks      []DiffHunkView `json:"hunks,omitempty"`
}

// DiffHunkView is one @@ section.
type DiffHunkView struct {
	Header string         `json:"header"`
	Lines  []DiffLineView `json:"lines,omitempty"`
}

// DiffLineView is one line, with its +/- already resolved to a kind so the
// viewer never has to look at the first character of anything.
type DiffLineView struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// SSHAuthView is the login card.
type SSHAuthView struct {
	Destination string `json:"destination,omitempty"`
	HostKey     string `json:"hostKey,omitempty"`
	// KnownHosts is the verdict as a sentence and Known is the same verdict as
	// a fact. Both are here because a card that leads with "a known host" and
	// hides the fingerprint behind an (i) needs the verdict without reading the
	// sentence back: a surface that decided by matching on the words would be
	// working out here what was already worked out in Go.
	KnownHosts string   `json:"knownHosts,omitempty"`
	Known      bool     `json:"known,omitempty"`
	Username   string   `json:"username,omitempty"`
	Forwarded  bool     `json:"forwarded,omitempty"`
	Bound      bool     `json:"bound"`
	Path       []string `json:"path,omitempty"`
}

// SshsigView is a signature that is not a commit, and a commit signature that
// arrived through the plain agent with nothing but a digest.
type SshsigView struct {
	Namespace     string `json:"namespace,omitempty"`
	HashAlgorithm string `json:"hashAlgorithm,omitempty"`
	Digest        string `json:"digest,omitempty"`
}

// OpaqueView is a payload that classified as nothing.
type OpaqueView struct {
	Reason string `json:"reason,omitempty"`
	Length uint32 `json:"length,omitempty"`
	Digest string `json:"digest,omitempty"`
}

// PairingView is a trust change.
//
// Both fingerprints are here because both have to be on screen. The integrity
// of a trust-on-first-use pairing is that the two machines show the same pair
// of fingerprints and their users agree they match; a card showing only the
// other side's would leave nothing to compare it against (§7).
type PairingView struct {
	Name             string `json:"name,omitempty"`
	Fingerprint      string `json:"fingerprint,omitempty"`
	Address          string `json:"address,omitempty"`
	MayApprove       bool   `json:"mayApprove,omitempty"`
	MayRequest       bool   `json:"mayRequest,omitempty"`
	LocalName        string `json:"localName,omitempty"`
	LocalFingerprint string `json:"localFingerprint,omitempty"`
	InitiatedLocally bool   `json:"initiatedLocally,omitempty"`
	// KeyFromCode says the peer's identity arrived in the pairing code itself,
	// which makes the visual channel the integrity root and leaves the user
	// nothing to compare by hand.
	KeyFromCode bool     `json:"keyFromCode,omitempty"`
	Addresses   []string `json:"addresses,omitempty"`
}

// PeerView is a paired instance in the status pane.
//
// Direction and Summary are the same fact at two lengths: the sentence a card
// has room for, and the few words a list row does. Both are rendered in Go
// (trust.Describe and trust.DescribeShort) so that a surface which shows one
// and a surface which shows the other cannot drift apart.
type PeerView struct {
	Name        string   `json:"name"`
	Fingerprint string   `json:"fingerprint"`
	Direction   string   `json:"direction"`
	Summary     string   `json:"summary,omitempty"`
	State       string   `json:"state"`
	Addresses   []string `json:"addresses,omitempty"`
	// MayUseKeys says this peer may ask for signatures with the keys this
	// instance holds (decision T). It is a permission somebody has to be able to
	// give from the device holding the key, which on a phone is this field and a
	// switch beside it.
	MayUseKeys bool `json:"mayUseKeys"`
	// KeyAccess is the same thing in the words a listing uses: all, none, or how
	// many.
	KeyAccess string `json:"keyAccess,omitempty"`
	// Dialable says this instance can reach out to the peer, which is true of a
	// machine that listens and false of a phone. It is the difference between a
	// peer that is missing when there is no link and one that is simply not
	// holding one open (trust.DescribeState), and a surface needs it to know
	// which sentence to put beside the state.
	Dialable bool `json:"dialable"`
	// LastSeen is when there was last a link, for the rows that have not got one
	// now. It is the absolute time rather than "4m ago" because a screen that
	// wants a countdown has State for that, and a screen that wants to know
	// whether a phone has been near this machine today wants the clock.
	LastSeen string `json:"lastSeen,omitempty"`
}

// PairingSummaryView is a pairing under way, in the status pane.
//
// It is beside the waiting requests rather than inside them because it is a
// different question. A card asks "do these two fingerprints match"; this list
// says which pairings exist at all, including the ones this side has already
// answered and which are only waiting for somebody at the other machine. Those
// have no card and never will, and without a row here there would be no way to
// see one, let alone call it off (§7).
type PairingSummaryView struct {
	Session          string `json:"session"`
	Name             string `json:"name"`
	Fingerprint      string `json:"fingerprint"`
	LocalFingerprint string `json:"localFingerprint,omitempty"`
	Direction        string `json:"direction,omitempty"`
	State            string `json:"state"`
	// URL is the card to answer it on, when this side has still to answer.
	URL string `json:"url,omitempty"`
}

// BorrowedKeyView is a key that lives on a paired instance (§10, decision N).
//
// It is a section of its own rather than a flag on KeyView because the two
// answer different questions. The keys list says what this machine holds; this
// says what it can reach for, where each of those lives, and — the field the
// whole thing exists for — whether reaching for it would get anywhere right
// now. A phone is unreachable most of the time by construction, so "not
// available" is an ordinary state and is shown as one rather than by leaving
// the row out.
type BorrowedKeyView struct {
	Label       string `json:"label"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm,omitempty"`
	Comment     string `json:"comment,omitempty"`
	// Peer is the name this instance gave the machine that holds the key.
	Peer string `json:"peer"`
	// Available is whether the holder is there and still offering it.
	Available bool `json:"available"`
	// LastSeen is when the holder last said so, for the rows that are not.
	LastSeen string `json:"lastSeen,omitempty"`
	// HeldHere says the same key is in this instance's own store, which is what
	// the row means when it means "this also lives on that machine" rather than
	// "this can be reached for": the copy here signs, awake or not (§10).
	HeldHere bool `json:"heldHere,omitempty"`
}

// InstanceView is the status pane.
type InstanceView struct {
	Name        string             `json:"name"`
	Fingerprint string             `json:"fingerprint"`
	Locations   []LocationView     `json:"locations,omitempty"`
	Keys        []KeyView          `json:"keys,omitempty"`
	Borrowed    []BorrowedKeyView  `json:"borrowed,omitempty"`
	Grants      []GrantSummaryView `json:"grants,omitempty"`
	// Delegations are the promises somebody else made about this instance,
	// which it keeps for itself (decision P). The other side of Grants, and a
	// separate list because they are answered from here and revoked elsewhere.
	Delegations []DelegationSummaryView `json:"delegations,omitempty"`
	Peers       []PeerView              `json:"peers,omitempty"`
	Recent      []ActivityView          `json:"recent,omitempty"`
	Pending     []PendingView           `json:"pending,omitempty"`
	Pairings    []PairingSummaryView    `json:"pairings,omitempty"`
	// Lock is the store's state, when the host manages one (§10).
	Lock  *LockView `json:"lock,omitempty"`
	Error string    `json:"error,omitempty"`
}

// LocationView is one "this file lives here" row.
type LocationView struct {
	Label string `json:"label"`
	Path  string `json:"path"`
}

// GrantSummaryView is a live TTL grant.
//
// It says when it runs out twice. Expires is the sentence a table cell wants;
// ExpiresAt is the timestamp a shell counting down to it needs, and a host that
// wants the countdown should not have to parse the sentence to get it.
type GrantSummaryView struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Expires     string `json:"expires"`
	ExpiresAt   string `json:"expiresAt,omitempty"`

	// Delegated says the promise was handed to the requester rather than kept
	// here (decision P), and Delegate names who has it. Worth saying on the
	// row, because it changes what revoking means: a grant kept here stops
	// answering at once, and a delegated one stops when its holder is next
	// reached — or when it expires, whichever comes first.
	Delegated bool   `json:"delegated,omitempty"`
	Delegate  string `json:"delegate,omitempty"`

	// RevokePending says somebody has revoked this and the machine holding it
	// could not be told, so it is still being honoured over there. It is the
	// one grant state a list must show rather than tidy away: dropping the row
	// would say the signing had stopped, and showing it unmarked would say it
	// was still wanted.
	RevokePending bool `json:"revokePending,omitempty"`

	// UseCount is everything done under it and Uses is the tail. A grant used
	// two hundred times is one row that says two hundred, and the individual
	// signatures belong behind it (decision P).
	UseCount int            `json:"useCount"`
	Uses     []GrantUseView `json:"uses,omitempty"`
}

// DelegationSummaryView is a standing permission this instance was given.
//
// It reads like a grant on purpose — the same identifier, the same expiry in
// both shapes, the same count of what has been done under it — because it is
// the same promise seen from the other end. What differs is what a reader can
// do about it: nothing here, except let it run out. Revoking is the approver's,
// which is why there is no button and why the row names who made it.
type DelegationSummaryView struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Expires     string `json:"expires"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
	// Approver is the instance that made the promise, by name when it sent one
	// and by fingerprint when it did not.
	Approver string `json:"approver"`
	Received string `json:"received,omitempty"`
	// UseCount is everything self-approved under it; Unreported is how much of
	// that the approver has not been told about yet, which is a machine that
	// has been out of touch rather than a fault.
	UseCount   int `json:"useCount"`
	Unreported int `json:"unreported,omitempty"`
}

// GrantUseView is one signature a delegated grant covered.
//
// It is an account received rather than a decision made: this instance never
// saw the request and holds no signed artifact for it, and the surfaces say so
// rather than letting it sit in the activity list looking like something that
// was decided here (§18).
type GrantUseView struct {
	RequestID string `json:"requestId"`
	When      string `json:"when"`
	WhenAt    string `json:"whenAt,omitempty"`
	Kind      string `json:"kind"`
	Subject   string `json:"subject,omitempty"`
}

// ActivityView is a line of the "what has been happening" list.
type ActivityView struct {
	// When is the wall clock this instance rendered, and WhenAt is the instant
	// it rendered it from. A host that knows the user's time zone and clock
	// preference — a phone does; a Go runtime inside an app sandbox does not —
	// should draw WhenAt and ignore When.
	When   string `json:"when"`
	WhenAt string `json:"whenAt,omitempty"`
	// ID names the audit entry this row came from, and is what opens it again.
	// It is empty on a row the log has not been told about yet — the moment
	// between a decision and its line being written — and on a host that keeps
	// no log, where there is nothing to open.
	ID      string `json:"id,omitempty"`
	Title   string `json:"title"`
	Outcome string `json:"outcome"`
}

// ActivityDetailView is a decision opened again: the card as it stood, and what
// was done about it (§18).
type ActivityDetailView struct {
	ActivityView

	// Request is the card, rendered from the request the log kept. It carries no
	// grant options: the offer was made once.
	Request RequestView `json:"request"`
	// Decided says who answered and on what footing.
	Decided string `json:"decided,omitempty"`
	// Reason is the approver's own words for the decision.
	Reason string `json:"reason,omitempty"`
	// Prompt is the plain text the log recorded as having been shown, which is
	// the audit record itself rather than a rendering of it. It is worth having
	// beside the card for the same reason the log has it: it is what this
	// instance committed to having put in front of somebody (§9).
	Prompt string `json:"prompt,omitempty"`
}

// PendingView is a request still waiting for an answer.
//
// URL is where to go to answer it. It is here rather than left for the reader
// to build because the reader is sometimes a shell rather than the bundle: a
// phone coming back to the foreground asks what is still waiting and has to be
// able to point its webview at one without knowing how the viewer spells its
// own routes.
type PendingView struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Title   string `json:"title"`
	Subject string `json:"subject,omitempty"`
	Since   string `json:"since,omitempty"`
	URL     string `json:"url"`
}

// borrowedKeyView renders one key that lives on a paired instance.
//
// The last-seen line is only put on the rows that need it. A key whose holder
// is there right now is described by "available" and nothing else; one whose
// holder is not needs to say how long ago it was, because a phone last seen a
// minute ago and a phone last seen in March want different things done.
func borrowedKeyView(key *ladulasv1.BorrowedKeyStatus) BorrowedKeyView {
	view := BorrowedKeyView{
		Label:       key.GetKey().GetLabel(),
		Fingerprint: key.GetKey().GetFingerprint(),
		Algorithm:   key.GetKey().GetAlgorithm(),
		Comment:     key.GetKey().GetComment(),
		Peer:        key.GetPeer(),
		Available:   key.GetAvailable(),
		HeldHere:    key.GetHeldHere(),
	}

	if seen := key.GetLastSeenAt(); seen != nil && !view.Available {
		view.LastSeen = seen.AsTime().Local().Format(time.RFC1123)
	}

	return view
}

// PairingSummaries renders the pairings under way for the status pane.
//
// It is here rather than in each host because both hosts have the same list to
// show and the same two things to say about a row: which of the two people it
// is waiting for, and where to answer it if that person is here.
func PairingSummaries(
	pairings []*ladulasv1.PendingPairingStatus,
) []PairingSummaryView {
	out := make([]PairingSummaryView, 0, len(pairings))

	for _, pairing := range pairings {
		view := PairingSummaryView{
			Session:          pairing.GetSessionId(),
			Name:             pairing.GetName(),
			Fingerprint:      pairing.GetFingerprint(),
			LocalFingerprint: pairing.GetLocalFingerprint(),
			Direction: describeDirections(
				pairing.GetMayApprove(), pairing.GetMayRequest()),
			State: "waiting for the other side",
		}

		if pairing.GetOurAnswer() ==
			ladulasv1.PairingAnswer_PAIRING_ANSWER_UNSPECIFIED {
			view.State = "waiting for you"

			if id := pairing.GetConfirmationRequestId(); id != "" {
				view.URL = "/?request=" + id
			}
		}

		out = append(out, view)
	}

	return out
}

// describeDirections says what a pairing would grant, in the words a listing
// should use. It is deliberately the short form: the card says it properly.
func describeDirections(mayApprove, mayRequest bool) string {
	switch {
	case mayApprove && mayRequest:
		return "approves for us, and asks us"
	case mayApprove:
		return "approves for us"
	case mayRequest:
		return "asks us"
	default:
		return "nothing yet"
	}
}

// kindName is the name a request kind has in the bridge JSON. They are the
// viewer's switch labels, so they are stable strings rather than the enum's
// own spelling.
func kindName(kind ladulasv1.RequestKind) string {
	switch kind {
	case ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH:
		return "ssh-auth"
	case ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN:
		return "git-sign"
	case ladulasv1.RequestKind_REQUEST_KIND_SSHSIG:
		return "sshsig"
	case ladulasv1.RequestKind_REQUEST_KIND_OPAQUE_SIGN:
		return "opaque-sign"
	case ladulasv1.RequestKind_REQUEST_KIND_KEY_LIST:
		return "key-list"
	case ladulasv1.RequestKind_REQUEST_KIND_PAIRING:
		return "pairing"
	case ladulasv1.RequestKind_REQUEST_KIND_UNSPECIFIED:
		return "unknown"
	default:
		return "unknown"
	}
}

func lineKindName(kind ladulasv1.GitDiffLineKind) string {
	switch kind {
	case ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_ADDED:
		return "added"
	case ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_REMOVED:
		return "removed"
	case ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_NOTE:
		return "note"
	case ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_CONTEXT:
		return "context"
	case ladulasv1.GitDiffLineKind_GIT_DIFF_LINE_KIND_UNSPECIFIED:
		return "context"
	default:
		return "context"
	}
}

// grantTrust is the note a grant offer carries when the promise it would make
// rests on something the requesting machine merely asserted (decision X). A
// grant is scoped on the repository a commit says it belongs to, and that is the
// peer's word: approving once, a person weighs it; a timed promise weighs it now
// and reuses that judgement until it expires, signing a later request that names
// the same repository without asking. The note says so before the promise is
// made rather than leaving it to be reconstructed from the asserted markers
// scattered down the card. It returns nil when nothing in the scope is asserted.
func grantTrust(msg *ladulasv1.ApprovalRequest) *GrantTrust {
	asserted := approval.AssertedScope(msg)
	if len(asserted) == 0 {
		return nil
	}

	who := msg.GetRequester().GetName()
	if who == "" {
		who = "the requester"
	}

	trust := &GrantTrust{
		Note: who + " reports this, and nothing here checks it. A one-off " +
			"approval weighs that word; a timed promise takes it on trust until " +
			"it expires.",
		Detail: "The key, the kind of request and who is asking are settled by " +
			"this machine. The repository a commit says it belongs to is " + who +
			"'s word — the card marks it “reported by the requester”. Approving " +
			"once, you weigh that word yourself. A timed promise weighs it now and " +
			"reuses your judgement: a later request from " + who + " that names the " +
			"same repository is signed without asking, whether or not it is really " +
			"that repository. Keep the promise as short as the work needs, and make " +
			"it only to a peer you would trust with this key whatever it claims.",
	}

	for _, fact := range asserted {
		trust.Facts = append(trust.Facts, DetailView{
			Label:    fact.Label,
			Value:    fact.Value,
			Asserted: fact.Asserted,
		})
	}

	return trust
}

// requestView renders a pending request for the viewer.
func requestView(req *approval.Request) RequestView {
	msg := req.Msg

	view := RequestView{
		ID:       msg.GetRequestId(),
		Kind:     kindName(msg.GetKind()),
		Title:    req.Prompt.Title,
		Subject:  req.Prompt.Subject,
		Warnings: req.Prompt.Warnings,
	}

	if created := msg.GetCreatedAt(); created != nil {
		view.CreatedAt = created.AsTime().Format(time.RFC3339)
	}

	for _, detail := range req.Prompt.Details {
		view.Details = append(view.Details, DetailView{
			Label:    detail.Label,
			Value:    detail.Value,
			Asserted: detail.Asserted,
		})
	}

	// The offer names who a promise would be made to rather than describing it,
	// because that is what it is scoped to (decisions U and V) and because the
	// surface has to word two of them: the session, and the machine.
	if req.GrantMaxTTL > 0 {
		offer := GrantOffer{
			Session:    req.GrantSubject,
			Machine:    req.GrantMachine,
			MaxSeconds: int64(req.GrantMaxTTL / time.Second),
		}

		for _, ttl := range req.GrantTTLs {
			if ttl <= 0 || ttl > req.GrantMaxTTL {
				continue
			}

			offer.Suggestions = append(
				offer.Suggestions, int64(ttl/time.Second))
		}

		// A promise made to answer a peer's requests reuses a judgement about
		// the peer's word, so the surface says what that word is first (§9,
		// decision X). Only for a request from another machine: locally the
		// asserted context is this machine's own.
		if !msg.GetRequester().GetLocal() {
			offer.Trust = grantTrust(msg)
		}

		view.Grant = &offer
	}

	if key := msg.GetKey(); key != nil {
		view.Key = &KeyView{
			Label:       key.GetLabel(),
			Fingerprint: key.GetFingerprint(),
			Algorithm:   key.GetAlgorithm(),
			Comment:     key.GetComment(),
		}
	}

	if requester := msg.GetRequester(); requester != nil {
		view.Requester = &RequesterView{
			Name:     requester.GetName(),
			Local:    requester.GetLocal(),
			Headless: requester.GetHeadless(),
			Address:  requester.GetRemoteAddress(),
			Program:  programName(requester.GetProcess()),
			App:      approval.AskerName(requester.GetProcess()),
			Asker:    approval.AskerDetail(requester.GetProcess()),
			Chain:    approval.AskerChain(requester.GetProcess()),
		}
	}

	attachOperation(&view, msg)

	return view
}

func programName(process *ladulasv1.ClientProcess) string {
	if process == nil {
		return ""
	}

	if executable := process.GetExecutable(); executable != "" {
		return fmt.Sprintf("%s (pid %d)", executable, process.GetPid())
	}

	if pid := process.GetPid(); pid != 0 {
		return fmt.Sprintf("pid %d", pid)
	}

	return ""
}

func attachOperation(view *RequestView, msg *ladulasv1.ApprovalRequest) {
	switch {
	case msg.GetSshAuth() != nil:
		view.SSHAuth = sshAuthView(msg.GetSshAuth())
	case msg.GetSshsig() != nil:
		sig := msg.GetSshsig()

		view.Sshsig = &SshsigView{
			Namespace:     sig.GetNamespace(),
			HashAlgorithm: sig.GetHashAlgorithm(),
			Digest:        fmt.Sprintf("%x", sig.GetMessageDigest()),
		}

		if git := sig.GetGitContext(); git != nil {
			view.Git = gitView(git)
			view.Danger = !git.GetVerifiedAgainstPayload()
		}
	case msg.GetOpaqueSign() != nil:
		opaque := msg.GetOpaqueSign()

		view.Danger = true
		view.Opaque = &OpaqueView{
			Reason: opaque.GetReason(),
			Length: opaque.GetPayloadLength(),
			Digest: fmt.Sprintf("%x", opaque.GetPayloadSha256()),
		}
	case msg.GetPairing() != nil:
		pairing := msg.GetPairing()

		view.Pairing = &PairingView{
			Name:             pairing.GetPeerName(),
			Fingerprint:      pairing.GetPeerFingerprint(),
			Address:          pairing.GetRemoteAddress(),
			MayApprove:       pairing.GetPeerMayApprove(),
			MayRequest:       pairing.GetPeerMayRequest(),
			LocalName:        pairing.GetLocalName(),
			LocalFingerprint: pairing.GetLocalFingerprint(),
			InitiatedLocally: pairing.GetInitiatedLocally(),
			KeyFromCode:      pairing.GetKeyFromCode(),
			Addresses:        pairing.GetPeerAddresses(),
		}
	}
}

func sshAuthView(auth *ladulasv1.SshAuthRequest) *SSHAuthView {
	view := &SSHAuthView{
		Destination: auth.GetDestinationLabel(),
		Username:    auth.GetUsername(),
		Forwarded:   auth.GetForwarded(),
		Bound:       auth.GetBound(),
	}

	if host := auth.GetDestination(); host != nil {
		view.HostKey = host.GetFingerprint()
		view.Known = host.GetKnown()

		view.KnownHosts = "not found in known_hosts"
		if host.GetKnown() {
			view.KnownHosts = "matched in known_hosts"
		}
	}

	if chain := auth.GetBindingChain(); len(chain) > 1 {
		for _, binding := range chain {
			view.Path = append(view.Path, approval.DisplayHost(binding.GetHostKey()))
		}
	}

	return view
}

// messageBody is everything after the subject line, which is what a commit is
// being signed for beyond its one-line summary. Empty for a message that is
// only a subject, which is most of them.
func messageBody(message string) string {
	_, rest, found := strings.Cut(message, "\n")
	if !found {
		return ""
	}

	return strings.TrimSpace(rest)
}

func gitView(git *ladulasv1.GitContext) *GitView {
	object := git.GetParsed()

	view := &GitView{
		Verified:          git.GetVerifiedAgainstPayload(),
		VerificationError: git.GetVerificationError(),
		ObjectType:        git.GetObjectType(),
		Operation:         git.GetOperation(),
		Repository:        git.GetRepositoryPath(),
		OriginURL:         git.GetOriginUrl(),
		Branch:            git.GetBranch(),
		Subject:           object.GetSubject(),
		Message:           object.GetMessage(),
		Body:              messageBody(object.GetMessage()),
		Author:            identityView(object.GetAuthor()),
		Committer:         identityView(object.GetCommitter()),
		Tagger:            identityView(object.GetTagger()),
		Tag:               object.GetTag(),
		TaggedObject:      object.GetTaggedObject(),
		TaggedType:        object.GetTaggedType(),
		Tree:              object.GetTree(),
		Parents:           object.GetParents(),
		Diff:              diffView(git.GetDiff()),
	}

	for _, header := range object.GetExtraHeaders() {
		view.ExtraHeaders = append(view.ExtraHeaders, HeaderView{
			Name:  header.GetName(),
			Value: header.GetValue(),
		})
	}

	return view
}

func identityView(id *ladulasv1.GitIdentity) *IdentityView {
	if id == nil {
		return nil
	}

	view := &IdentityView{
		Name:     id.GetName(),
		Email:    id.GetEmail(),
		Timezone: id.GetTimezone(),
	}

	if when := id.GetTime(); when != nil {
		view.Time = when.AsTime().Format("2006-01-02 15:04:05")
	}

	return view
}

func diffView(diff *ladulasv1.GitDiff) *DiffView {
	if diff == nil {
		return nil
	}

	view := &DiffView{
		FilesChanged:   diff.GetFilesChanged(),
		Insertions:     diff.GetInsertions(),
		Deletions:      diff.GetDeletions(),
		Range:          diff.GetRange(),
		Truncated:      diff.GetTruncated(),
		TruncationNote: diff.GetTruncationNote(),
		Error:          diff.GetError(),
	}

	for _, file := range diff.GetFiles() {
		fileView := DiffFileView{
			OldPath:    file.GetOldPath(),
			NewPath:    file.GetNewPath(),
			Status:     file.GetStatus(),
			Insertions: file.GetInsertions(),
			Deletions:  file.GetDeletions(),
			Binary:     file.GetBinary(),
			ModeChange: file.GetModeChange(),
			Truncated:  file.GetTruncated(),
		}

		for _, hunk := range file.GetHunks() {
			hunkView := DiffHunkView{Header: hunk.GetHeader()}

			for _, line := range hunk.GetLines() {
				hunkView.Lines = append(hunkView.Lines, DiffLineView{
					Kind: lineKindName(line.GetKind()),
					Text: line.GetText(),
				})
			}

			fileView.Hunks = append(fileView.Hunks, hunkView)
		}

		view.Files = append(view.Files, fileView)
	}

	return view
}

// HumanDuration renders a grant TTL the way a button should read.
//
// It is the engine's own wording rather than a second one that agrees with it
// most of the time: the length in an answer's reason and the length in the
// grant's description are the same promise, and two renderers would eventually
// say it two ways.
func HumanDuration(d time.Duration) string {
	return approval.HumanDuration(d)
}

// delegationSummary renders a promise this instance holds and applies itself.
func delegationSummary(held Delegation) DelegationSummaryView {
	d := held.Delegation
	expires := d.GetExpiresAt().AsTime()

	view := DelegationSummaryView{
		ID:          d.GetDelegationId(),
		Description: d.GetDescription(),
		Expires:     expires.Local().Format(time.RFC1123),
		ExpiresAt:   expires.Format(time.RFC3339),
		Approver:    d.GetApproverName(),
		UseCount:    held.UseCount,
		Unreported:  held.Unreported,
	}

	if view.Approver == "" {
		view.Approver = d.GetApproverFingerprint()
	}

	if !held.ReceivedAt.IsZero() {
		view.Received = held.ReceivedAt.Format(time.RFC3339)
	}

	return view
}

// grantSummary renders a live grant, whichever half of decision P it is.
func grantSummary(grant *ladulasv1.Grant) GrantSummaryView {
	expires := grant.GetExpiresAt().AsTime()

	view := GrantSummaryView{
		ID:          grant.GetGrantId(),
		Description: grant.GetDescription(),
		Expires:     expires.Local().Format(time.RFC1123),
		ExpiresAt:   expires.Format(time.RFC3339),
		Delegated:   grant.GetDelegated(),
		Delegate:    grant.GetDelegateName(),
		UseCount:    int(grant.GetUseCount()),

		RevokePending: grant.GetRevokePending(),
	}

	if view.Delegated && view.Delegate == "" {
		view.Delegate = grant.GetDelegateFingerprint()
	}

	// Newest first, because a list of what a promise has covered is read from
	// the end.
	uses := grant.GetRecentUses()

	for i := len(uses) - 1; i >= 0; i-- {
		use := uses[i]
		when := use.GetUsedAt().AsTime()

		view.Uses = append(view.Uses, GrantUseView{
			RequestID: use.GetRequestId(),
			When:      when.Local().Format("15:04:05"),
			WhenAt:    when.Format(time.RFC3339),
			Kind:      kindName(use.GetKind()),
			Subject:   use.GetSubject(),
		})
	}

	return view
}
