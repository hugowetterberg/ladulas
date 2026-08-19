package approval

import (
	"context"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The engine's half of decision AG.
//
// A grant follows the key (decision P), and there is a third case that neither
// of its two branches covers: a portable key that several instances hold. The
// requester holds no copy, so nothing can be delegated to it; and the private
// half has very much moved, so "the holder is in the loop per signature
// whatever anyone decided" is a statement about hardware keys and not about
// this one. What was left was a promise stranded on the machine that made it,
// with every borrowed signature waking that machine — which is the cost
// decision P exists to remove, in the shape decision S created.
//
// An endorsement is that promise, signed with the key it is about so that any
// other holder can check it, and honoured under two conditions that do
// different work. **Signed by the key** means the issuer could have made the
// signature itself, so the promise adds no authority to the system that was not
// already in it. **From an issuer this instance would have taken a live
// approval from** means the promise is one this instance was going to listen to
// anyway. Together they reduce the security argument to a sentence worth
// keeping in view: an endorsement can produce no outcome that a live
// conversation with the same approver could not have produced, and what it
// removes is the round trip rather than the trust decision.

// EndorsementStore holds the promises other holders of a key have made about a
// requester. keystore.Vault implements it.
type EndorsementStore interface {
	// UsableEndorsements returns the ones that may still be applied: live, over
	// a key this instance holds, from a peer it still trusts to approve for it,
	// and not retracted.
	//
	// Everything about the artifact was settled when it arrived — both
	// signatures, and that its three claims about identity agree — so what is
	// left for the engine is matching a scope and checking who is asking.
	UsableEndorsements() ([]*ladulasv1.Endorsement, error)
	// RecordEndorsementUse writes down that one answered a request, for the
	// account this instance owes the holder that promised it.
	RecordEndorsementUse(use *ladulasv1.GrantUse) error
}

// KeySigner hands the engine a signer for a key this instance holds, so that a
// promise about that key can be signed with it.
type KeySigner interface {
	// PortableSigner answers only for a key whose private half is in this
	// instance's store.
	//
	// A hardware key cannot be handed to another instance (decision S), so no
	// other instance holds one, and an endorsement about it would be a promise
	// nobody else could ever act on. Answering an error for those is what keeps
	// this from minting artifacts that mean nothing — and on a phone it also
	// keeps the enclave out of a path that is not a signature anybody asked for.
	PortableSigner(fingerprint string) (ssh.Signer, error)
}

// matchEndorsement returns the endorsement covering a borrowed-signing request,
// if any.
//
// Three things are checked here that the store could not. The requester is the
// machine the endorsement names — and it is the *channel's* idea of who is
// asking, because signForPeer replaces the requester field with the identity
// that authenticated the connection before anything is decided, so a copy of an
// endorsement presented by anybody else names somebody else and matches
// nothing. The scope covers this request, by the same strict matching a grant
// uses. And the promise runs no longer than this instance would ever promise
// anything for, which is the one bound nobody else can raise: an issuer that
// wrote itself a month is refused by a holder whose policy tops out at eight
// hours, and the request raises an ordinary prompt.
func (e *Engine) matchEndorsement(
	req *Request, policy *Policy,
) *ladulasv1.Endorsement {
	if e.endorsements == nil {
		return nil
	}

	requester := req.Msg.GetRequester().GetInstanceId()
	if requester == "" {
		return nil
	}

	held, err := e.endorsements.UsableEndorsements()
	if err != nil {
		e.log.Error("could not read endorsements", "error", err.Error())

		return nil
	}

	now := e.now()
	ceiling := now.Add(policy.MaxGrantTTL())

	for _, en := range held {
		if en.GetRequesterFingerprint() != requester {
			continue
		}

		expires := en.GetExpiresAt().AsTime()

		if !expires.After(now) || expires.After(ceiling) {
			continue
		}

		if covers(en.GetScope(), req.Msg) {
			return en
		}
	}

	return nil
}

// recordEndorsedUse writes down that another holder's promise answered a
// request here, so that the holder which made it can be told what it did.
func (e *Engine) recordEndorsedUse(
	msg *ladulasv1.ApprovalRequest, en *ladulasv1.Endorsement,
) {
	if e.endorsements == nil {
		return
	}

	use := e.grantUse(en.GetEndorsementId(), msg)

	if err := e.endorsements.RecordEndorsementUse(use); err != nil {
		e.log.Error("could not record what an endorsement covered",
			"endorsement_id", en.GetEndorsementId(), "error", err.Error())

		return
	}

	if report := e.useReporter(); report != nil {
		report(en.GetIssuerFingerprint())
	}
}

// shouldEndorse reports whether a promise just made should also be written down
// for the other holders of the key.
//
// Only for a borrowed signature: a request that arrived over the channel for a
// *decision* is one whose requester holds the key, and that promise is
// delegated instead (decision P). Only for a requester with a fingerprint to
// name, because an endorsement that names nobody is one any machine could
// present. And only where there is a key signer to reach for, which is what
// confines this to portable keys.
func (e *Engine) shouldEndorse(req *Request) bool {
	if req.Origin != OriginPeerSigning {
		return false
	}

	if e.keySigner == nil {
		return false
	}

	return req.Msg.GetRequester().GetInstanceId() != ""
}

// endorse signs the promise a grant has just made so that the other holders of
// the key can act on it.
//
// It cannot fail the answer. A key with no portable half, a signer that refuses,
// a store that will not write — every one of them leaves the grant exactly as it
// was before endorsements existed, which is a promise kept here that the
// requester comes back to this machine to spend. Failing the approval over it
// would be refusing a signature somebody agreed to because an optimization did
// not work.
func (e *Engine) endorse(
	msg *ladulasv1.ApprovalRequest, grant *ladulasv1.Grant,
) *ladulasv1.SignedEndorsement {
	if grant == nil {
		return nil
	}

	fingerprint := grant.GetScope().GetKeyFingerprint()

	signer, err := e.keySigner.PortableSigner(fingerprint)
	if err != nil {
		e.log.Debug("the promise was not endorsed",
			"grant_id", grant.GetGrantId(), "reason", err.Error())

		return nil
	}

	// The identifier is the grant's. A promise and its endorsement are two
	// halves of one thing, and sharing an identifier is what lets a use
	// reported by another holder be filed against the right one — the shape a
	// delegation already has.
	en := &ladulasv1.Endorsement{
		EndorsementId:        grant.GetGrantId(),
		Scope:                grant.GetScope(),
		CreatedAt:            grant.GetCreatedAt(),
		ExpiresAt:            grant.GetExpiresAt(),
		OriginRequestId:      grant.GetOriginRequestId(),
		Description:          grant.GetDescription(),
		IssuerFingerprint:    e.identity.Fingerprint(),
		IssuerName:           e.identity.Name(),
		RequesterFingerprint: msg.GetRequester().GetInstanceId(),
		RequesterName:        msg.GetRequester().GetName(),
		KeyFingerprint:       fingerprint,
	}

	signed, err := e.identity.SignEndorsement(en, signer)
	if err != nil {
		e.log.Warn("the promise could not be endorsed",
			"grant_id", grant.GetGrantId(), "error", err.Error())

		return nil
	}

	// The grant is amended rather than written again, and the order is the
	// invariant worth naming: **nothing is endorsed that was not first recorded
	// here.** The record is what makes a promise listable and retractable, so
	// an endorsement that existed without one would be a promise loose in the
	// world with nothing on this machine able to take it back.
	grant.Endorsed = true

	if err := e.grants.ReplaceGrant(grant); err != nil {
		e.log.Error("the grant could not be marked as endorsed",
			"grant_id", grant.GetGrantId(), "error", err.Error())
	}

	if publish := e.endorsementPublisher(); publish != nil {
		// Off the answering path. Telling the other holders means dialling
		// them, and the requester waiting on its signature has no stake in how
		// long a sleeping laptop takes to answer — but somebody reading the
		// grant later very much does, which is why the fan-out writes what it
		// reached and what it did not back onto the grant.
		go publish(context.WithoutCancel(context.Background()), signed)
	}

	return signed
}

// PublishEndorsements installs the way a promise reaches the other holders of
// the key, and is set after construction for the reason the use reporter is:
// what can reach a peer is the peer node, and the node is built around the
// engine.
//
// Without one an endorsement still works — the requester carries it and
// presents it where it borrows — and it works *silently*, which is the state
// this must not be left in. A holder that was never told has a promise it will
// honour and cannot see, and a promise nobody can see is a promise nobody can
// retract.
func (e *Engine) PublishEndorsements(
	publish func(ctx context.Context, signed *ladulasv1.SignedEndorsement),
) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.publishEndorsement = publish
}

func (e *Engine) endorsementPublisher() func(
	context.Context, *ladulasv1.SignedEndorsement,
) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.publishEndorsement
}

// RememberUntil is how long a retraction has to be kept: past the expiry of
// what it takes back, and no longer.
//
// For a retraction naming one endorsement that is the endorsement's own expiry.
// For one naming a moment it is that moment plus the longest promise this
// instance believes anybody could have made, because what it takes back is
// every endorsement issued up to then and the youngest of those could run that
// far. Getting it wrong in the short direction is the dangerous one: a
// retraction forgotten while its target is still live is a promise that comes
// back from the dead the next time the requester presents its copy.
func RememberUntil(target time.Time, maxTTL time.Duration) *timestamppb.Timestamp {
	return timestamppb.New(target.Add(maxTTL))
}
