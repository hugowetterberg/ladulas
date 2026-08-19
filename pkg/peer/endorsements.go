package peer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// The channel's half of decision AG, and the whole of it is an asymmetry.
//
// **A promise travels with the party that benefits from it.** The requester
// gets the endorsement back with its answer and presents it to whichever holder
// it borrows from next. That is what makes the promise work at all: the
// instance that made it may be a phone in a pocket, and the holder that acts on
// it may never have been awake at the same time as either of them.
//
// **The taking back of a promise never travels that road.** The requester is
// precisely the party with no reason to stop presenting an endorsement, so a
// retraction is pushed between holders and gossiped onward by every instance
// that learns one. It is honoured from any holder of the key whatever the trust
// records say, where an endorsement is honoured only from an issuer this
// instance would have taken a live approval from — because honouring a
// retraction nobody wanted costs a prompt, and ignoring one that was meant
// costs a signature.
//
// **And a promise is published as well as carried.** Not because the publishing
// is what makes it work — it is not — but because a holder that was never told
// has a promise it will honour and cannot see, and a promise nobody can see is
// a promise nobody can retract. Which holders could not be told is written down
// beside the grant rather than being smoothed over, for the reason a
// revocation nobody could deliver is (decision P).

// publishTimeout bounds telling one holder. It is generous next to an ordinary
// call because the point is to reach a laptop that may be waking up, and short
// enough that a fan-out over a dozen unreachable addresses ends.
const publishTimeout = 10 * time.Second

// Endorsements is what the peer node needs of the store to carry decision AG.
// keystore.Vault implements it.
type Endorsements interface {
	AddEndorsement(
		signed *ladulasv1.SignedEndorsement, e *ladulasv1.Endorsement,
		published bool,
	) error
	Endorsements() ([]*storepb.HeldEndorsement, error)
	AddRetraction(
		signed *ladulasv1.SignedRetraction, r *ladulasv1.Retraction,
	) (bool, error)
	Retractions() ([]*storepb.HeldRetraction, error)
	RetractionsForKey(keyFingerprint string) []*ladulasv1.SignedRetraction
	NoteGossiped(retractionID, peerFingerprint string) error
	NoteEndorsementReach(grantID string, told, unreached []string) error
	DropEndorsementsFrom(issuerFingerprint string) (int, error)
	DropEndorsementsAbout(requesterFingerprint string) (int, error)
	// KeyHolders is every paired instance this one has reason to believe holds
	// a key. It is a question about the store rather than about the channel,
	// and it is asked here so that nothing in the peer package has to reach for
	// a signer to answer it — on a phone, loading a signer can mean a biometric
	// prompt, and "who else holds this" must never be a question that lights up
	// a screen.
	KeyHolders(keyFingerprint string) []string
}

// PublishEndorsement tells this instance that a promise has been made about a
// key it may hold.
//
// It accepts from any paired peer, and what decides whether the endorsement is
// honoured is inside the artifact rather than in who carried it: the two
// signatures, and the store's own two questions about whether it holds the key
// and takes approvals from the issuer. So a holder that learns about a promise
// second-hand learns as much as one the issuer reached directly.
func (s *peerService) PublishEndorsement(
	ctx context.Context,
	req *connect.Request[ladulasv1.PublishEndorsementRequest],
) (*connect.Response[ladulasv1.PublishEndorsementResponse], error) {
	if _, _, err := s.node.authorize(ctx); err != nil {
		return nil, err
	}

	if s.node.endorsements == nil {
		return connect.NewResponse(&ladulasv1.PublishEndorsementResponse{
			Reason: "this instance keeps no endorsements",
		}), nil
	}

	signed := req.Msg.GetEndorsement()

	e, err := identity.VerifyEndorsement(signed)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the endorsement does not verify: %w", err))
	}

	reason := s.node.keepEndorsement(signed, e, true)

	return connect.NewResponse(&ladulasv1.PublishEndorsementResponse{
		Accepted: reason == "",
		Reason:   reason,
		// What this instance already knows about the key travels back on the
		// answer rather than in a call of its own. A publisher learns at once
		// that somebody has taken this key's promises back, which is the one
		// moment both machines are certainly awake.
		Retractions: s.node.endorsements.RetractionsForKey(e.GetKeyFingerprint()),
	}), nil
}

// keepEndorsement writes one down and says why it did not, if it did not.
//
// An endorsement this instance cannot act on is still kept: the requester's own
// copy is exactly that, and dropping it would leave the machine that has to
// present the promise unable to say it holds one. What "cannot act on it" earns
// is a sentence in the listing, not a deletion.
func (n *Node) keepEndorsement(
	signed *ladulasv1.SignedEndorsement, e *ladulasv1.Endorsement,
	published bool,
) string {
	if err := n.endorsements.AddEndorsement(signed, e, published); err != nil {
		n.log.Warn("an endorsement could not be kept",
			"endorsement_id", e.GetEndorsementId(), "error", err.Error())

		return err.Error()
	}

	n.log.Info("kept an endorsement",
		"endorsement_id", e.GetEndorsementId(),
		"issuer", e.GetIssuerName(),
		"requester", e.GetRequesterName(),
		"published", published)

	return ""
}

// PublishRetraction takes a promise back, and is deliberately the least
// demanding call in the protocol.
//
// Any paired peer may make it; the artifact is honoured whatever the trust
// records say about its issuer; and a retraction for a key this instance does
// not hold, or for an endorsement it has never seen, is accepted and remembered
// rather than discarded. That last one is not laxity — an endorsement is
// carried by the requester and a retraction gossips, so the retraction very
// often arrives first, and one that was thrown away for naming nothing would let
// the endorsement land afterwards and be honoured.
func (s *peerService) PublishRetraction(
	ctx context.Context,
	req *connect.Request[ladulasv1.PublishRetractionRequest],
) (*connect.Response[ladulasv1.PublishRetractionResponse], error) {
	if _, _, err := s.node.authorize(ctx); err != nil {
		return nil, err
	}

	if s.node.endorsements == nil {
		return connect.NewResponse(&ladulasv1.PublishRetractionResponse{
			Reason: "this instance keeps no endorsements",
		}), nil
	}

	signed := req.Msg.GetRetraction()

	r, err := identity.VerifyRetraction(signed)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the retraction does not verify: %w", err))
	}

	fresh, err := s.node.endorsements.AddRetraction(signed, r)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("keep the retraction: %w", err))
	}

	if fresh {
		s.node.log.Info("a promise about a key was taken back",
			"key", r.GetKeyFingerprint(), "issuer", r.GetIssuerName(),
			"reason", r.GetReason())

		// Onward, to the holders this instance can reach and the one that sent
		// it cannot. Only what was news: an instance that passed on every
		// retraction it was told about would bounce one between two holders for
		// as long as it is remembered.
		go s.node.gossipRetraction(
			context.WithoutCancel(context.Background()), signed, r)
	}

	return connect.NewResponse(&ladulasv1.PublishRetractionResponse{
		Accepted: true,
	}), nil
}

// PublishEndorsement is the issuing side: tell every holder of the key that
// this instance can find.
//
// It is called off the answering path, because the requester waiting on its
// signature has no stake in how long a sleeping laptop takes to answer — and
// what it reached is written back onto the grant, because somebody reading that
// grant later very much does.
func (n *Node) PublishEndorsement(
	ctx context.Context, signed *ladulasv1.SignedEndorsement,
) {
	if n.endorsements == nil {
		return
	}

	e, err := identity.VerifyEndorsement(signed)
	if err != nil {
		n.log.Error("this instance produced an endorsement it cannot verify",
			"error", err.Error())

		return
	}

	told, unreached := n.tellHolders(ctx, e.GetKeyFingerprint(),
		e.GetRequesterFingerprint(),
		func(ctx context.Context, client ladulasv1connect.KeyServiceClient) error {
			resp, err := client.PublishEndorsement(ctx, connect.NewRequest(
				&ladulasv1.PublishEndorsementRequest{Endorsement: signed}))
			if err != nil {
				return err
			}

			// A holder that already knows the key's promises have been taken
			// back says so here, and this instance believes it: the artifact
			// carries its own proof and arrives from a holder of the key.
			n.keepRetractions(resp.Msg.GetRetractions())

			return nil
		})

	if err := n.endorsements.NoteEndorsementReach(
		e.GetEndorsementId(), told, unreached); err != nil {
		n.log.Warn("could not write down who was told about an endorsement",
			"endorsement_id", e.GetEndorsementId(), "error", err.Error())
	}

	n.log.Info("published an endorsement",
		"endorsement_id", e.GetEndorsementId(),
		"told", len(told), "unreached", len(unreached))
}

// Retract takes a promise about a key back and tells everyone it can.
//
// Any holder may call it, including one that did not make the promise, which is
// the point: the machine that sees an endorsement it did not expect is very
// often not the machine that made it. What stands in for authorization is
// holding the key — the retraction is signed with it, and a machine that cannot
// reach the private half cannot produce one.
//
// Naming no endorsement retracts every promise about the key issued up to now,
// which is what somebody reaches for when they think the key has leaked.
func (n *Node) Retract(
	ctx context.Context, endorsementID, keyFingerprint, reason string,
	maxTTL time.Duration,
) (told, unreached []string, dropped int, err error) {
	if n.endorsements == nil || n.keys == nil {
		return nil, nil, 0, errors.New("peer: this instance keeps no endorsements")
	}

	now := time.Now()

	r := &ladulasv1.Retraction{
		RetractionId:      identity.NewRequestID(),
		KeyFingerprint:    keyFingerprint,
		EndorsementId:     endorsementID,
		IssuedAt:          timestamppb.New(now),
		IssuerFingerprint: n.identity.Fingerprint(),
		IssuerName:        n.identity.Name(),
		Reason:            reason,
	}

	// How long it has to be remembered follows what it takes back. One naming a
	// single promise is done when that promise would have expired; one naming a
	// moment has to outlive the youngest endorsement that could have been issued
	// at that moment, which is the longest promise anybody makes. Erring short
	// is the dangerous direction — a retraction forgotten while its target is
	// still live is a promise that comes back the next time the requester
	// presents its copy.
	if endorsementID != "" {
		expires, ok := n.endorsementExpiry(endorsementID)
		if !ok {
			expires = now.Add(maxTTL)
		}

		r.RememberUntil = timestamppb.New(expires.Add(time.Hour))
	} else {
		r.IssuedBefore = timestamppb.New(now)
		r.RememberUntil = timestamppb.New(now.Add(maxTTL).Add(time.Hour))
	}

	signer, _, err := n.keys.Signer(keyFingerprint)
	if err != nil {
		return nil, nil, 0, fmt.Errorf(
			"peer: only a holder of the key can retract a promise about it: %w", err)
	}

	signed, err := n.identity.SignRetraction(r, signer)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("peer: sign the retraction: %w", err)
	}

	// Written down here first. A retraction that reached three machines and was
	// not kept on the one that issued it would come back the moment somebody
	// republished the endorsement.
	before, _ := n.endorsements.Endorsements()

	if _, err := n.endorsements.AddRetraction(signed, r); err != nil {
		return nil, nil, 0, fmt.Errorf("peer: keep the retraction: %w", err)
	}

	after, _ := n.endorsements.Endorsements()
	dropped = len(before) - len(after)

	told, unreached = n.tellHolders(ctx, keyFingerprint, "",
		func(ctx context.Context, client ladulasv1connect.KeyServiceClient) error {
			_, err := client.PublishRetraction(ctx, connect.NewRequest(
				&ladulasv1.PublishRetractionRequest{Retraction: signed}))

			return err
		})

	return told, unreached, dropped, nil
}

func (n *Node) endorsementExpiry(id string) (time.Time, bool) {
	held, err := n.endorsements.Endorsements()
	if err != nil {
		return time.Time{}, false
	}

	for _, item := range held {
		if item.GetEndorsement().GetEndorsementId() == id {
			return item.GetEndorsement().GetExpiresAt().AsTime(), true
		}
	}

	return time.Time{}, false
}

// gossipRetraction passes one on to the holders this instance can reach and has
// not already told.
func (n *Node) gossipRetraction(
	ctx context.Context,
	signed *ladulasv1.SignedRetraction, r *ladulasv1.Retraction,
) {
	told, _ := n.tellHolders(ctx, r.GetKeyFingerprint(), "",
		func(ctx context.Context, client ladulasv1connect.KeyServiceClient) error {
			_, err := client.PublishRetraction(ctx, connect.NewRequest(
				&ladulasv1.PublishRetractionRequest{Retraction: signed}))

			return err
		})

	for _, fingerprint := range told {
		if err := n.endorsements.NoteGossiped(
			r.GetRetractionId(), fingerprint); err != nil {
			n.log.Debug("could not write down a gossiped retraction",
				"error", err.Error())
		}
	}
}

// keepRetractions writes down what a peer handed back, and gossips what was
// news.
func (n *Node) keepRetractions(list []*ladulasv1.SignedRetraction) {
	for _, signed := range list {
		r, err := identity.VerifyRetraction(signed)
		if err != nil {
			n.log.Warn("a peer offered a retraction that does not verify",
				"error", err.Error())

			continue
		}

		fresh, err := n.endorsements.AddRetraction(signed, r)
		if err != nil {
			n.log.Warn("a retraction could not be kept", "error", err.Error())

			continue
		}

		if fresh {
			go n.gossipRetraction(
				context.WithoutCancel(context.Background()), signed, r)
		}
	}
}

// tellHolders calls every paired instance that holds the key, skipping one.
//
// Who holds a key is three things the store already writes down, and none of
// them is a guess: a peer that advertises the key as one it lends (decision N),
// a peer this instance handed the key to, and the peer it was received from
// (decision S). The union is the honest answer to "who else could act on a
// promise about this key", and a holder that is in none of them is one this
// instance has no way of knowing about — which is exactly why the requester
// carrying its own copy is the mechanism and this is the visibility.
func (n *Node) tellHolders(
	ctx context.Context, keyFingerprint, skip string,
	call func(context.Context, ladulasv1connect.KeyServiceClient) error,
) (told, unreached []string) {
	for _, fingerprint := range n.holdersOf(keyFingerprint) {
		if fingerprint == skip {
			continue
		}

		if err := n.callHolder(ctx, fingerprint, call); err != nil {
			n.log.Debug("a holder could not be told",
				"peer", fingerprint, "error", err.Error())

			unreached = append(unreached, fingerprint)

			continue
		}

		told = append(told, fingerprint)
	}

	return told, unreached
}

func (n *Node) callHolder(
	ctx context.Context, fingerprint string,
	call func(context.Context, ladulasv1connect.KeyServiceClient) error,
) error {
	ctx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()

	holder := n.link(fingerprint)
	if holder == nil {
		return ErrHolderUnreachable
	}

	addresses := holder.addresses()
	if len(addresses) == 0 {
		// A peer that advertises no address is a phone, which is never dialled
		// and comes to collect instead. It is not a failure to reach — it is a
		// machine that has to be waited for, and the list of unreached holders
		// says so honestly by having it in it.
		return ErrHolderUnreachable
	}

	var lastErr error

	for _, address := range addresses {
		client := ladulasv1connect.NewKeyServiceClient(
			holder.client.HTTP(), holder.client.URL(address))

		if err := call(ctx, client); err != nil {
			lastErr = err

			continue
		}

		holder.succeeded(address)

		return nil
	}

	return lastErr
}

func (n *Node) holdersOf(keyFingerprint string) []string {
	if n.endorsements == nil {
		return nil
	}

	return n.endorsements.KeyHolders(keyFingerprint)
}

// acceptEndorsement keeps a promise a holder made about this instance, which
// arrives on the answer to a borrowed signature.
//
// The signatures are checked here and nothing else is, deliberately. This
// instance holds no copy of the key — that is why it was borrowing — so it can
// neither act on the endorsement nor judge it. What it can do is carry it, and
// a copy it refused to carry because it could not use it would be a promise
// that only ever worked against the machine that made it.
func (n *Node) acceptEndorsement(signed *ladulasv1.SignedEndorsement) {
	if signed == nil || n.endorsements == nil {
		return
	}

	e, err := identity.VerifyEndorsement(signed)
	if err != nil {
		n.log.Warn("a holder sent an endorsement that does not verify",
			"error", err.Error())

		return
	}

	// One addressed to somebody else is not this instance's to carry. It would
	// match nothing anywhere it was presented, and keeping it would put another
	// machine's promise in this one's listing.
	if e.GetRequesterFingerprint() != n.identity.Fingerprint() {
		n.log.Warn("a holder sent an endorsement about another machine",
			"about", e.GetRequesterName())

		return
	}

	n.keepEndorsement(signed, e, false)
}

// acceptPresented keeps an endorsement a requester sent with a borrowed-signing
// request.
//
// The one check that belongs here rather than later is that the endorsement is
// about the machine on the other end of this connection. Everything else the
// engine and the store ask; this is the check that cannot be made anywhere else,
// because this is the only place that has both the artifact and the identity
// the channel authenticated.
func (n *Node) acceptPresented(
	peerFingerprint string, signed *ladulasv1.SignedEndorsement,
) {
	if signed == nil || n.endorsements == nil {
		return
	}

	e, err := identity.VerifyEndorsement(signed)
	if err != nil {
		n.log.Warn("a peer presented an endorsement that does not verify",
			"peer", peerFingerprint, "error", err.Error())

		return
	}

	if e.GetRequesterFingerprint() != peerFingerprint {
		n.log.Warn("a peer presented an endorsement about another machine",
			"peer", peerFingerprint, "about", e.GetRequesterName())

		return
	}

	n.keepEndorsement(signed, e, false)
}

// endorsementFor is the endorsement this instance holds for a key, to present
// when it borrows.
//
// Live and about this instance, and nothing more is asked: whether it is
// honoured is the holder's question, and a requester that decided for itself
// which of its promises were still good would be answering a question it has no
// standing to answer.
func (n *Node) endorsementFor(keyFingerprint string) *ladulasv1.SignedEndorsement {
	if n.endorsements == nil || keyFingerprint == "" {
		return nil
	}

	held, err := n.endorsements.Endorsements()
	if err != nil {
		return nil
	}

	me := n.identity.Fingerprint()
	now := time.Now()

	for _, item := range held {
		e := item.GetEndorsement()

		if e.GetKeyFingerprint() != keyFingerprint {
			continue
		}

		if e.GetRequesterFingerprint() != me {
			continue
		}

		if !e.GetExpiresAt().AsTime().After(now) {
			continue
		}

		return item.GetSigned()
	}

	return nil
}

// dropPeerEndorsements is what revoking a pairing takes with it on decision
// AG's side, and it is two lists rather than one.
//
// A promise that peer *made* stops being honoured, which UsableEndorsements
// would already refuse — this is so that the store stops holding a promise from
// somebody who is no longer anybody. And a promise made *about* that peer goes
// too: it says a machine may borrow a key unattended, and a machine that is no
// longer paired may not borrow it at all.
//
// What this cannot do is reach the other holders. They were told about the
// promise and were not told about this pairing, so they go on honouring it
// until it expires — which is a retraction's job and not a revocation's, and is
// the honest reason `ladulas endorsements retract` exists beside
// `ladulas peers revoke`.
func (n *Node) dropPeerEndorsements(record *storepb.TrustRecord) {
	if n.endorsements == nil {
		return
	}

	fingerprint := record.GetFingerprint()

	from, err := n.endorsements.DropEndorsementsFrom(fingerprint)
	if err != nil {
		n.log.Error("could not drop a revoked peer's endorsements",
			"peer", fingerprint, "error", err.Error())
	}

	about, err := n.endorsements.DropEndorsementsAbout(fingerprint)
	if err != nil {
		n.log.Error("could not drop the endorsements about a revoked peer",
			"peer", fingerprint, "error", err.Error())
	}

	if from+about > 0 {
		n.log.Info("dropped a revoked peer's endorsements",
			"peer", fingerprint, "issued", from, "about", about)
	}
}
