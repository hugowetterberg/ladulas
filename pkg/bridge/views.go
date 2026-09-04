package bridge

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
	"golang.org/x/crypto/ssh"
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
	// GrantOnly says the only approval on offer is a timed one: the request
	// asked for a promise ahead of the login it is about and carries no payload,
	// so a plain yes would grant nothing and settle the card (decision AO). A
	// surface that sets this draws the lengths and no Approve button; one that
	// ignores it draws a button the daemon refuses.
	GrantOnly bool `json:"grantOnly,omitempty"`

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

// KeyView is a key: the one a request wants to use, or one the instance holds.
//
// Everything after Comment is only filled for a key the instance holds. Public
// is the authorized_keys line, which is what the public half is for — it goes
// into GitHub, an authorized_keys file, an allowed_signers file — and a screen
// that showed a key without a way to get that line out was a screen somebody
// had to leave for a terminal. AgentUse is whether the agent offers the key
// (decision T); a key a request names has already been offered, so the
// question does not arise there. Disabled is the stronger switch: a disabled
// key signs for nobody until it is turned back on. Hardware says the private
// half is in a secure element, which is what decides that the key cannot be
// handed to another machine (decision S). HandedTo and ReceivedFrom are the
// other machines that hold a copy — the list somebody needs after losing one
// of them, because those are the ends the key has to be rotated at.
type KeyView struct {
	Label        string            `json:"label"`
	Fingerprint  string            `json:"fingerprint"`
	Algorithm    string            `json:"algorithm,omitempty"`
	Comment      string            `json:"comment,omitempty"`
	Public       string            `json:"public,omitempty"`
	AgentUse     bool              `json:"agentUse,omitempty"`
	Disabled     bool              `json:"disabled,omitempty"`
	Hardware     bool              `json:"hardware,omitempty"`
	HandedTo     []KeyTransferView `json:"handedTo,omitempty"`
	ReceivedFrom *KeyTransferView  `json:"receivedFrom,omitempty"`
}

// KeyTransferView is one machine a key was copied to or from, and when.
type KeyTransferView struct {
	// Peer is the machine's name, or its fingerprint when the name is gone
	// with the pairing.
	Peer        string `json:"peer"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// At is when, rendered for the screen the way an offer's arrival is;
	// empty when the store did not record it.
	At string `json:"at,omitempty"`
}

func keyTransferView(transfer *ladulasv1.KeyTransferInfo) KeyTransferView {
	view := KeyTransferView{
		Peer:        transfer.GetPeerName(),
		Fingerprint: transfer.GetPeerFingerprint(),
	}

	if view.Peer == "" {
		view.Peer = view.Fingerprint
	}

	if at := transfer.GetAt(); at != nil {
		view.At = at.AsTime().Local().Format(time.RFC1123)
	}

	return view
}

// storedKeyView is a key the instance holds, with the public half rendered.
//
// The line is rendered here rather than by the host because every host hands
// over the same wire-format bytes and none of them should have to know what
// an authorized_keys line looks like. A public half that does not parse is
// left out rather than reported: the key still signs, and the fingerprint
// beside it is the store's, not this function's.
func storedKeyView(key *ladulasv1.KeyInfo) KeyView {
	view := KeyView{
		Label:       key.GetLabel(),
		Fingerprint: key.GetFingerprint(),
		Algorithm:   key.GetAlgorithm(),
		Comment:     key.GetComment(),
		// Unset means offered, as it does in the store (decision T).
		AgentUse: key.AgentUse == nil || key.GetAgentUse(),
		Disabled: key.GetDisabled(),
		Hardware: key.GetHardware(),
	}

	for _, transfer := range key.GetHandedTo() {
		view.HandedTo = append(view.HandedTo, keyTransferView(transfer))
	}

	if from := key.GetReceivedFrom(); from != nil {
		received := keyTransferView(from)
		view.ReceivedFrom = &received
	}

	if pub, err := ssh.ParsePublicKey(key.GetPublicKey()); err == nil {
		line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\r\n")

		// The comment is what an authorized_keys line says the key is, and
		// the label is the next best name when nobody gave it one — the same
		// choice `ladulas keys public` makes.
		comment := key.GetComment()
		if comment == "" {
			comment = key.GetLabel()
		}

		if comment != "" {
			line += " " + comment
		}

		view.Public = line
	}

	return view
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
	Name        string `json:"name,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Address     string `json:"address,omitempty"`
	MayApprove  bool   `json:"mayApprove,omitempty"`
	MayRequest  bool   `json:"mayRequest,omitempty"`
	// Direction is those two flags as the sentence every surface words them
	// with (trust.Describe), because what a pairing is for is one decision
	// somebody made on one screen and not two checkboxes to read off
	// (decision AD). It is rendered here for the reason PeerView's is: a card
	// that worded it itself would be a second wording to keep in step.
	Direction        string `json:"direction,omitempty"`
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
	// MayUseKeys says this peer may ask for signatures with every key this
	// instance holds (decision T). It is a permission somebody has to be able to
	// give from the device holding the key, which on a phone is this field and a
	// switch beside it.
	MayUseKeys bool `json:"mayUseKeys"`
	// AllowedKeys are the keys the peer may use when it is not every key, as
	// fingerprints, which is how the trust record holds them and how a form
	// matches them against the keys the instance lists.
	AllowedKeys []string `json:"allowedKeys,omitempty"`
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

// InvitationView is a pairing code as a screen shows it (§7, decision AD).
//
// The three ways in are all here because they are one invitation seen by three
// kinds of machine: a terminal somewhere types the command, a window somewhere
// else pastes the full code, and a phone points a camera at the QR. Every one
// of them carries the same secret, and which is easiest depends on what the
// person is holding rather than on anything this instance knows.
type InvitationView struct {
	// Code is what somebody types, in the two groups it is displayed in.
	Code string `json:"code"`
	// FullCode is the string behind the QR, and the one to paste into another
	// window. It carries the identity key, so a side that has it pins before
	// it connects and has nothing left to compare by hand.
	FullCode string `json:"fullCode,omitempty"`
	// QR is where to fetch the picture of FullCode. It is a URL rather than
	// markup because the bundle builds every node itself and injects none.
	QR        string   `json:"qr,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	// ExpiresAt is when the code stops working, for a countdown. The pairing it
	// opens has no clock on it at all (decision M) — this is the other half.
	ExpiresAt string `json:"expiresAt,omitempty"`
	// Intent is the word, for a surface that shows which of the three was
	// chosen, and Direction is the sentence it means.
	Intent    string `json:"intent"`
	Direction string `json:"direction"`
	// Join is the command line to run on the other machine, ready to be copied
	// — the address that is most likely to work and the code in it.
	Join string `json:"join,omitempty"`
}

func invitationView(invitation Invitation) InvitationView {
	view := InvitationView{
		Code:      invitation.Code,
		FullCode:  invitation.FullCode,
		Addresses: invitation.Addresses,
		Intent:    invitation.Intent.String(),
		Direction: invitation.Intent.Describe(),
	}

	if invitation.FullCode != "" {
		view.QR = "/api/v1/pairings/qr?code=" +
			url.QueryEscape(invitation.FullCode)
	}

	if !invitation.Expires.IsZero() {
		view.ExpiresAt = invitation.Expires.Format(time.RFC3339)
	}

	// The first address is the one the instance itself puts first, which is the
	// one it thinks is most likely to be reachable. A person with a machine
	// this does not suit has the whole list beside it.
	address := "<host:port>"
	if len(invitation.Addresses) > 0 {
		address = invitation.Addresses[0]
	}

	view.Join = fmt.Sprintf("ladulas pair %s --code %s", address, invitation.Code)

	return view
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

// KeyOfferView is a portable key a paired machine has handed this instance and
// nobody here has answered yet (decision S).
//
// It is not a KeyView with a flag on it: an offer is not a key this instance
// holds, and the whole point of the design is that it does not become one until
// somebody says so. What the surface needs is the fingerprint to compare, who
// sent it, and when it arrived — the private half never reaches a viewer, which
// is the same rule KeyView follows for the keys that were accepted.
type KeyOfferView struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Comment     string `json:"comment,omitempty"`
	Algorithm   string `json:"algorithm,omitempty"`
	Fingerprint string `json:"fingerprint"`
	// Peer is the name this instance gave the machine that sent it, and
	// PeerFingerprint what the two compared when they paired.
	Peer            string `json:"peer"`
	PeerFingerprint string `json:"peerFingerprint,omitempty"`
	// Received says when it arrived twice, for the same reason a grant says
	// when it runs out twice: the sentence is what a card wants, and the
	// timestamp is what a shell counting the minutes needs.
	Received   string `json:"received,omitempty"`
	ReceivedAt string `json:"receivedAt,omitempty"`
}

// keyOfferView renders one offer for a viewer.
func keyOfferView(offer *ladulasv1.KeyOfferInfo) KeyOfferView {
	view := KeyOfferView{
		ID:              offer.GetId(),
		Label:           offer.GetLabel(),
		Comment:         offer.GetComment(),
		Algorithm:       offer.GetAlgorithm(),
		Fingerprint:     offer.GetFingerprint(),
		Peer:            offer.GetPeerName(),
		PeerFingerprint: offer.GetPeerFingerprint(),
	}

	if at := offer.GetReceivedAt(); at != nil {
		local := at.AsTime().Local()

		view.Received = local.Format(time.RFC1123)
		view.ReceivedAt = local.Format(time.RFC3339)
	}

	return view
}

// InstanceView is the status pane.
type InstanceView struct {
	Name        string            `json:"name"`
	Fingerprint string            `json:"fingerprint"`
	Locations   []LocationView    `json:"locations,omitempty"`
	Keys        []KeyView         `json:"keys,omitempty"`
	Borrowed    []BorrowedKeyView `json:"borrowed,omitempty"`
	// Offers are the portable keys paired machines have handed this instance
	// and nobody has answered (decision S). Waiting for somebody rather than
	// held, which is why they are not in Keys.
	Offers []KeyOfferView     `json:"offers,omitempty"`
	Grants []GrantSummaryView `json:"grants,omitempty"`
	// Delegations are the promises somebody else made about this instance,
	// which it keeps for itself (decision P). The other side of Grants, and a
	// separate list because they are answered from here and revoked elsewhere.
	Delegations []DelegationSummaryView `json:"delegations,omitempty"`
	Peers       []PeerView              `json:"peers,omitempty"`
	Recent      []ActivityView          `json:"recent,omitempty"`
	Pending     []PendingView           `json:"pending,omitempty"`
	Pairings    []PairingSummaryView    `json:"pairings,omitempty"`
	// Endorsements are the promises other holders of a key have made about a
	// machine, and Retractions the ones that have been taken back (decision
	// AG). Both are listed in full, including the promises this instance only
	// carries and will never act on: what a surface must be able to answer is
	// "what is this machine signing under", and a filtered list cannot.
	Endorsements []EndorsementSummaryView `json:"endorsements,omitempty"`
	Retractions  []RetractionSummaryView  `json:"retractions,omitempty"`
	// Lock is the store's state, when the host manages one (§10).
	Lock *LockView `json:"lock,omitempty"`
	// Settings is the part of the policy a surface may show and change, when
	// the host offers one (§9).
	Settings *SettingsView `json:"settings,omitempty"`
	// Listen is where the peer channel listens, when the host can say (§8,
	// decision AH). Publishing and UnlockAtLogin are the other two per-instance
	// settings a surface may change (decisions Q and I); each is present only
	// on a host that offers it, so a screen draws the sections it has and no
	// heading over a control that would answer 501.
	Listen        *ListenView        `json:"listen,omitempty"`
	Publishing    *PublishingView    `json:"publishing,omitempty"`
	UnlockAtLogin *UnlockAtLoginView `json:"unlockAtLogin,omitempty"`
	Error         string             `json:"error,omitempty"`
}

// ListenView is where the peer channel listens, as the process that bound it
// sees things (§8): the specification in force and what decided it, what is
// bound, what a peer is told to dial, and every address the automatic policy
// passed over with the reason it did (decision AH).
//
// It is the control socket's PeerListenState with the words already chosen,
// because the words are the point of the screen — "the tailnet and the local
// network addresses" is what somebody wants to read, not `local`, and the tier
// name is the same whether the machine has both kinds or one (decision AR).
type ListenView struct {
	Spec string `json:"spec"`
	// Source is what decided the specification: "flag", "stored" or
	// "automatic". SourceNote is the same fact as a sentence.
	Source      string `json:"source"`
	SourceNote  string `json:"sourceNote"`
	AllowPublic bool   `json:"allowPublic,omitempty"`
	// StoredSpec is the stored setting when there is one, in force or not. A
	// flag overriding a stored setting is the thing worth being able to see:
	// the two together are why a change somebody made yesterday does nothing.
	StoredSpec        string `json:"storedSpec,omitempty"`
	StoredAllowPublic bool   `json:"storedAllowPublic,omitempty"`
	// Bound is what is bound right now and Advertised what a peer is told to
	// dial. They differ by design (§8), and both are drawn.
	Bound      []string `json:"bound,omitempty"`
	Advertised []string `json:"advertised,omitempty"`
	// Tier is the automatic policy's choice as the daemon names it, and Chose
	// the same choice as a sentence, with what it costs when it costs something.
	Tier    string               `json:"tier,omitempty"`
	Chose   string               `json:"chose,omitempty"`
	Skipped []SkippedAddressView `json:"skipped,omitempty"`
	// Detail is why nothing is bound, when nothing is. Empty when the listener
	// is up.
	Detail string `json:"detail,omitempty"`
}

// SkippedAddressView is one address the automatic policy did not bind.
type SkippedAddressView struct {
	Address string `json:"address"`
	// Interface is the interface it was found on, empty when the address was
	// skipped for being in a tier a better one covered.
	Interface string `json:"interface,omitempty"`
	Reason    string `json:"reason"`
}

// ListenChangeView is what changing the listener answers with: the state as
// it now is, and what happened in a sentence — including the words "the
// previous addresses are back" when the new ones could not be bound, which is
// the half a screen has to show rather than the state alone.
type ListenChangeView struct {
	Listen ListenView `json:"listen"`
	Detail string     `json:"detail"`
}

// listenView chooses the words for a PeerListenState.
func listenView(state *ladulasv1.PeerListenState) ListenView {
	view := ListenView{
		Spec:              state.GetSpec(),
		AllowPublic:       state.GetAllowPublic(),
		StoredSpec:        state.GetStoredSpec(),
		StoredAllowPublic: state.GetStoredAllowPublic(),
		Bound:             state.GetBound(),
		Advertised:        state.GetAdvertised(),
		Tier:              state.GetTier(),
		Detail:            state.GetDetail(),
	}

	switch state.GetSource() {
	case ladulasv1.ListenSource_LISTEN_SOURCE_FLAG:
		view.Source = "flag"
		view.SourceNote = "Set by --peer-listen on the daemon, which beats " +
			"anything stored here."
	case ladulasv1.ListenSource_LISTEN_SOURCE_STORED:
		view.Source = "stored"
		view.SourceNote = "Set here, and kept in the store across restarts."
	case ladulasv1.ListenSource_LISTEN_SOURCE_AUTOMATIC,
		ladulasv1.ListenSource_LISTEN_SOURCE_UNSPECIFIED:
		view.Source = "automatic"
		view.SourceNote = "Nobody has said, so the policy decides."
	}

	if tier := state.GetTier(); tier != "" {
		view.Chose = tierWord(tier, state.GetBound())
	}

	for _, one := range state.GetSkipped() {
		view.Skipped = append(view.Skipped, SkippedAddressView{
			Address:   one.GetAddress(),
			Interface: one.GetInterface(),
			Reason:    one.GetReason(),
		})
	}

	return view
}

// tierWord says what the automatic policy chose and, for the tiers that mean
// something is missing, what that costs.
//
// The local tier is one tier covering two kinds of address (decision AR), and
// which kinds this machine actually has is the thing worth reading, so the
// bound list is looked at rather than the tier name repeated. The same words
// `ladulas listen` prints.
func tierWord(tier string, bound []string) string {
	switch tier {
	case transport.TierLocal:
		return localTierWord(bound)
	case transport.TierLoopback:
		if len(bound) == 0 {
			return "loopback"
		}

		return "loopback only — no peer on another machine can reach this " +
			"instance"
	case transport.TierExplicit:
		return "the addresses given"
	case transport.TierNone:
		return "nothing"
	}

	return tier
}

func localTierWord(bound []string) string {
	var tailnet, lan bool

	for _, address := range bound {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}

		ip := net.ParseIP(host)

		switch {
		case ip == nil:
			continue
		case transport.IsTailnetIP(ip):
			tailnet = true
		default:
			lan = true
		}
	}

	switch {
	case tailnet && lan:
		return "the tailnet and the local network addresses"
	case tailnet:
		return "the tailnet addresses; there is no local network address here"
	case lan:
		return "the local network addresses; there is no tailnet here"
	}

	return "the tailnet and local network addresses"
}

// PublishingView is what this instance publishes to its approvers (decision
// Q): whether projects it asks for signatures in are published automatically,
// and what is published now, whichever way it got there.
type PublishingView struct {
	AutoPublish bool              `json:"autoPublish"`
	Published   []PublicationView `json:"published,omitempty"`
}

// PublicationView is one project this instance publishes: what approvers see
// it as, where it is on this machine, and which commit of which branch was
// current when it was last looked at. The identifier is what an unpublish
// names, because names are not unique and rows are.
type PublicationView struct {
	ProjectID string `json:"projectId"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	OriginURL string `json:"originUrl,omitempty"`
	Branch    string `json:"branch,omitempty"`
	Commit    string `json:"commit,omitempty"`
	// PublishedAt is when it was offered, rendered for the screen.
	PublishedAt string `json:"publishedAt,omitempty"`
}

// UnlockAtLoginView is whether this instance unlocks from the platform
// keychain at login, and whether the passphrase is still there behind it
// (decision I). It always should be: the keychain is enrolled beside a
// passphrase, never instead of one, and a screen that could not show the
// second fact could not honestly offer the first.
type UnlockAtLoginView struct {
	Enrolled           bool `json:"enrolled"`
	PassphraseWrapping bool `json:"passphraseWrapping"`
}

// SettingsView is the policy a settings screen draws: the signing budget in
// force, what it would go back to, and the range it may be moved within.
//
// It rides along on the instance view because a settings screen is drawn from
// one call and a second one would be a second thing to be out of date. The
// bounds come with it for the reason a grant offer carries its max_ttl
// (decision V): the surface draws the bound, the daemon owns it, and a surface
// that made its own up would offer something that is refused when it is used.
type SettingsView struct {
	SignTimeoutSeconds int64 `json:"signTimeoutSeconds"`
	// DefaultSignTimeoutSeconds is what it is when the policy says nothing, so
	// a screen can offer to put it back without knowing the number.
	DefaultSignTimeoutSeconds int64 `json:"defaultSignTimeoutSeconds"`
	MinSignTimeoutSeconds     int64 `json:"minSignTimeoutSeconds"`
	MaxSignTimeoutSeconds     int64 `json:"maxSignTimeoutSeconds"`
	// PolicyPath is the file being written, for a screen that says where the
	// setting ends up. Empty on a host that has no file to name.
	PolicyPath string `json:"policyPath,omitempty"`
	// MaxGrantSeconds is the longest promise the instance makes, so a clock
	// extending a grant stops where a clock granting one does (decision V).
	// The instance refuses anything past it whatever the screen drew.
	MaxGrantSeconds int64 `json:"maxGrantSeconds,omitempty"`
}

// EndorsementSummaryView is one promise another holder of a key has made about
// a machine, as a surface needs it (decision AG).
//
// It carries why it would not be acted on rather than being left out when it
// would not. An endorsement works whether or not this instance was told about
// it — the requester carries a copy and presents it — so a list that showed
// only the live ones would be a machine unable to say what it is honouring, and
// a promise nobody can see is a promise nobody can retract.
type EndorsementSummaryView struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Expires     string `json:"expires"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
	// Issuer is the holder that made the promise, and Requester the machine it
	// is about — both by name where there is one.
	Issuer    string `json:"issuer"`
	Requester string `json:"requester"`
	// Key is the fingerprint the promise is about, which is also the key that
	// signed it.
	Key      string `json:"key"`
	Received string `json:"received,omitempty"`
	// Published says a holder was told before the promise could be spent, as
	// opposed to it arriving on the request that spent it. The second is the
	// state publishing exists to avoid and cannot always reach.
	Published bool `json:"published,omitempty"`
	// Live says this instance would answer under it. InertBecause says why not
	// when it would not, in the store's own words.
	Live         bool   `json:"live"`
	InertBecause string `json:"inertBecause,omitempty"`

	UseCount   int `json:"useCount"`
	Unreported int `json:"unreported,omitempty"`
}

// RetractionSummaryView is one promise taken back, remembered until what it
// takes back would have expired anyway (decision AG).
type RetractionSummaryView struct {
	ID string `json:"id"`
	// Target is what it takes back, worded: one promise, or everything about
	// the key up to a moment.
	Target string `json:"target"`
	Key    string `json:"key"`
	Issuer string `json:"issuer"`
	Reason string `json:"reason,omitempty"`
	// Until is when it may be forgotten, which is not when it takes effect.
	Until   string `json:"until,omitempty"`
	UntilAt string `json:"untilAt,omitempty"`
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
		ID:        msg.GetRequestId(),
		Kind:      kindName(msg.GetKind()),
		Title:     req.Prompt.Title,
		Subject:   req.Prompt.Subject,
		Warnings:  req.Prompt.Warnings,
		GrantOnly: msg.GetGrantOnly(),
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
		view.SSHAuth = sshAuthView(msg.GetSshAuth(), msg.GetGrantOnly())
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
			Name:        pairing.GetPeerName(),
			Fingerprint: pairing.GetPeerFingerprint(),
			Address:     pairing.GetRemoteAddress(),
			MayApprove:  pairing.GetPeerMayApprove(),
			MayRequest:  pairing.GetPeerMayRequest(),
			Direction: trust.Describe(
				pairing.GetPeerMayApprove(), pairing.GetPeerMayRequest()),
			LocalName:        pairing.GetLocalName(),
			LocalFingerprint: pairing.GetLocalFingerprint(),
			InitiatedLocally: pairing.GetInitiatedLocally(),
			KeyFromCode:      pairing.GetKeyFromCode(),
			Addresses:        pairing.GetPeerAddresses(),
		}
	}
}

func sshAuthView(
	auth *ladulasv1.SshAuthRequest, grantOnly bool,
) *SSHAuthView {
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

		// On a grant request the fingerprint was read off the server a moment
		// ago rather than proven inside a signature, because nothing has been
		// signed yet (decision AO). The card has to say which of the two it is:
		// "matched in known_hosts" is true either way and, on its own, invites
		// the reader to think the host has been established the way a login
		// establishes it. It cannot be spent on the wrong host — the promise is
		// matched against the proven key when a login happens — but the person
		// agreeing should know what they are looking at.
		if grantOnly && host.GetKnown() {
			view.KnownHosts = "matched in known_hosts; read from the server " +
				"just now, and checked against the signed payload when a " +
				"login actually happens"
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

// endorsementSummary renders one promise about a key for a surface.
func endorsementSummary(held Endorsement) EndorsementSummaryView {
	e := held.Endorsement
	expires := e.GetExpiresAt().AsTime()

	view := EndorsementSummaryView{
		ID:           e.GetEndorsementId(),
		Description:  e.GetDescription(),
		Expires:      expires.Local().Format(time.RFC1123),
		ExpiresAt:    expires.Format(time.RFC3339),
		Issuer:       named(e.GetIssuerName(), e.GetIssuerFingerprint()),
		Requester:    named(e.GetRequesterName(), e.GetRequesterFingerprint()),
		Key:          e.GetKeyFingerprint(),
		Published:    held.Published,
		Live:         held.InertBecause == "",
		InertBecause: held.InertBecause,
		UseCount:     held.UseCount,
		Unreported:   held.Unreported,
	}

	if !held.ReceivedAt.IsZero() {
		view.Received = held.ReceivedAt.Format(time.RFC3339)
	}

	return view
}

// retractionSummary renders one promise taken back.
func retractionSummary(held Retraction) RetractionSummaryView {
	r := held.Retraction

	view := RetractionSummaryView{
		ID:     r.GetRetractionId(),
		Key:    r.GetKeyFingerprint(),
		Issuer: named(r.GetIssuerName(), r.GetIssuerFingerprint()),
		Reason: r.GetReason(),
		Target: r.GetEndorsementId(),
	}

	if view.Target == "" {
		view.Target = "every promise made before " +
			r.GetIssuedBefore().AsTime().Local().Format(time.RFC1123)
	}

	if until := r.GetRememberUntil(); until != nil {
		view.Until = until.AsTime().Local().Format(time.RFC1123)
		view.UntilAt = until.AsTime().Format(time.RFC3339)
	}

	return view
}

// named is a name where there is one and a fingerprint where there is not,
// which is what every one of these views does with an instance.
func named(name, fingerprint string) string {
	if name != "" {
		return name
	}

	return fingerprint
}

// PublicationViewOf renders one of the daemon's publications for a screen. It
// is exported because the hosts that read publications off the control socket
// — the desktop window and the phones — should agree on the rendering rather
// than each choosing a time format.
func PublicationViewOf(pub *ladulasv1.Publication) PublicationView {
	view := PublicationView{
		ProjectID: pub.GetProjectId(),
		Name:      pub.GetName(),
		Path:      pub.GetPath(),
		OriginURL: pub.GetOriginUrl(),
		Branch:    pub.GetBranch(),
		Commit:    pub.GetCommit(),
	}

	if at := pub.GetPublishedAt(); at != nil {
		view.PublishedAt = at.AsTime().Local().Format(time.RFC1123)
	}

	return view
}
