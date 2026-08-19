package peer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// The channel's half of decision P.
//
// A delegated grant has two halves that are apart from each other by design:
// the requester holds the artifact and applies it while nobody is reachable,
// and the approver holds the record of having promised it. Reconciliation is
// how they find out about each other again — revocations one way, an account of
// what was done the other, in one call.
//
// The approver drives it. That is not a preference: a phone advertises no
// address and collects rather than listens (§8, §11), so a requester that had
// to report in would have nowhere to report to. The same asymmetry the inbox
// exists for.

// Delegations is what the peer node needs of the store to hold delegated
// grants. keystore.Vault implements it.
type Delegations interface {
	AddDelegation(*ladulasv1.SignedDelegation, *ladulasv1.Delegation) error
	Delegations() ([]*storepb.HeldDelegation, error)
	DropDelegations(ids []string) (int, error)
	DropDelegationsFrom(approverFingerprint string) (int, error)
	UnreportedUses(approverFingerprint string) []*ladulasv1.GrantUse
	AcknowledgeUses(requestIDs []string) error
	RecordGrantUses(uses []*ladulasv1.GrantUse) error
	Grants() ([]*ladulasv1.Grant, error)
	// PendingRevocations names the grants delegated to a peer whose revocation
	// could not be delivered when it was made, and RevokeGrant finishes one
	// once it has been.
	PendingRevocations(fingerprint string) []string
	RevokeGrant(id string) error
}

// acceptDelegation stores a delegation that came back with an answer.
//
// Every way it could be somebody else's promise is checked here, in the order
// that keeps parsing behind verification: the signature first, then that the
// key which signed it is the paired one, then that the delegation is addressed
// to this instance, and only then that the peer was allowed to make it.
//
// A delegation that fails any of these is dropped and the answer it arrived
// with still stands. They are separate claims: the peer approved this request,
// and the peer says it will go on approving ones like it. Refusing the second
// is not a reason to throw away the first.
func (n *Node) acceptDelegation(
	record *storepb.TrustRecord,
	key ssh.PublicKey,
	resp *ladulasv1.ApprovalResponse,
) {
	signed := resp.GetDelegation()
	if signed == nil {
		return
	}

	if n.delegations == nil {
		n.log.Warn("a peer granted a delegation and there is nowhere to keep it",
			"peer", record.GetName())

		return
	}

	name := record.GetName()

	d, pub, err := identity.VerifyDelegation(signed)
	if err != nil {
		n.log.Warn("a peer sent an unverifiable delegation",
			"peer", name, "error", err.Error())

		return
	}

	if !bytes.Equal(pub.Marshal(), key.Marshal()) {
		n.log.Warn("a delegation was signed by a key that is not the paired one",
			"peer", name, "signer", signed.GetApproverFingerprint())

		return
	}

	// Addressed to somebody else is the replay this check exists for: a
	// delegation lifted off one machine's wire and offered to another that
	// happens to hold the same key.
	if d.GetRequesterFingerprint() != n.identity.Fingerprint() {
		n.log.Warn("a delegation was addressed to another instance",
			"peer", name, "addressed_to", d.GetRequesterFingerprint())

		return
	}

	if !record.GetMayApprove() {
		n.log.Warn("a peer that may not approve for this instance sent a delegation",
			"peer", name)

		return
	}

	if err := n.delegations.AddDelegation(signed, d); err != nil {
		n.log.Error("could not keep a delegation",
			"peer", name, "error", err.Error())

		return
	}

	n.log.Info("a peer delegated a standing approval",
		"peer", name,
		"delegation_id", d.GetDelegationId(),
		"expires_at", d.GetExpiresAt().AsTime(),
		"scope", d.GetDescription())
}

// acceptRenewedDelegation keeps a promise that has been re-issued with more
// time on it.
//
// It arrives on a reconciliation rather than beside an approval, so there is no
// link key to compare the signature against — what there is instead is the
// trust record for the peer that dialled, which is where the key it was paired
// with lives. That is the same claim, checked against the same material.
func (n *Node) acceptRenewedDelegation(
	record *storepb.TrustRecord, signed *ladulasv1.SignedDelegation,
) {
	name := record.GetName()

	key, err := ssh.ParsePublicKey(record.GetIdentityPublicKey())
	if err != nil {
		n.log.Warn("a paired peer's identity key does not parse",
			"peer", name, "error", err.Error())

		return
	}

	n.acceptDelegation(record, key, &ladulasv1.ApprovalResponse{
		Delegation: signed,
	})
}

// ReportGrantUse is the approver's side of the push: a requester telling it,
// over the link it already holds, what it has just done under a delegation.
//
// It is the same account ReconcileGrants collects, arriving by the other road.
// Between two desktops it is the road that works and is immediate; an approver
// that cannot be dialled never sees one and is told there is something waiting
// instead (decision P).
func (s *peerService) ReportGrantUse(
	ctx context.Context, req *connect.Request[ladulasv1.ReportGrantUseRequest],
) (*connect.Response[ladulasv1.ReportGrantUseResponse], error) {
	// The half of the pairing that matters is the other one from the inbox's:
	// this is a peer this instance approves *for*, reporting on a promise this
	// instance made to it.
	peer := transport.PeerFrom(ctx)
	if peer == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("the connection is not authenticated"))
	}

	record, ok := s.node.trust.Peer(peer.Fingerprint)
	if !ok {
		return nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("%s is not a paired peer", peer.Fingerprint))
	}

	if s.node.delegations == nil {
		return connect.NewResponse(&ladulasv1.ReportGrantUseResponse{}), nil
	}

	recorded, err := s.node.recordReported(record, req.Msg.GetUses())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&ladulasv1.ReportGrantUseResponse{
		AcknowledgedRequestIds: recorded,
	}), nil
}

// recordReported files an account against the promises this instance actually
// made to the peer sending it, and answers with the ones it kept.
//
// A peer may report against its own delegations and nobody else's. Naming what
// was recorded rather than saying "all of it" is what lets the requester drop
// exactly those and no more — a report that crossed with a revocation leaves
// the rest of the ledger alone.
func (n *Node) recordReported(
	record *storepb.TrustRecord, uses []*ladulasv1.GrantUse,
) ([]string, error) {
	if len(uses) == 0 {
		return nil, nil
	}

	grants, err := n.delegations.Grants()
	if err != nil {
		return nil, fmt.Errorf("read the grants: %w", err)
	}

	theirs := make(map[string]bool)

	for _, grant := range grants {
		if grant.GetDelegated() &&
			grant.GetDelegateFingerprint() == record.GetFingerprint() {
			theirs[grant.GetGrantId()] = true
		}
	}

	var (
		kept         []*ladulasv1.GrantUse
		acknowledged []string
	)

	for _, use := range uses {
		if !theirs[use.GetGrantId()] {
			continue
		}

		kept = append(kept, use)
		acknowledged = append(acknowledged, use.GetRequestId())
	}

	if err := n.delegations.RecordGrantUses(kept); err != nil {
		return nil, fmt.Errorf("record what %s did: %w", record.GetName(), err)
	}

	if len(acknowledged) > 0 {
		n.log.Info("a delegate reported what it did",
			"peer", record.GetName(), "uses", len(acknowledged))
	}

	return acknowledged, nil
}

// PushGrantActivity tells one approver what this instance has done under its
// delegations, if it can be reached.
//
// It runs when a use is recorded and again when a link comes up, so the two
// desktop case is immediate and a machine that was offline catches up the
// moment it is not. Failing is ordinary: the ledger keeps what was not
// acknowledged, and an approver that collects will come for it.
func (n *Node) PushGrantActivity(approverFingerprint string) {
	if n.delegations == nil || approverFingerprint == "" {
		return
	}

	record, ok := n.trust.Peer(approverFingerprint)
	if !ok || len(record.GetAddresses()) == 0 {
		return
	}

	uses := n.delegations.UnreportedUses(approverFingerprint)
	if len(uses) == 0 {
		return
	}

	go n.pushGrantActivity(record, uses)
}

func (n *Node) pushGrantActivity(
	record *storepb.TrustRecord, uses []*ladulasv1.GrantUse,
) {
	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	var acknowledged []string

	err := n.call(ctx, record, func(
		ctx context.Context, client *http.Client, baseURL string,
	) error {
		inbox := ladulasv1connect.NewInboxServiceClient(client, baseURL,
			connect.WithReadMaxBytes(maxRequestBytes))

		resp, err := inbox.ReportGrantUse(ctx, connect.NewRequest(
			&ladulasv1.ReportGrantUseRequest{Uses: uses}))
		if err != nil {
			return err //nolint:wrapcheck // call wraps it with the address
		}

		acknowledged = resp.Msg.GetAcknowledgedRequestIds()

		return nil
	})
	if err != nil {
		// Ordinary. An approver that cannot be dialled is the case this whole
		// arrangement exists for, and the ledger is what covers it.
		n.log.Debug("could not report grant activity",
			"peer", record.GetName(), "error", err.Error())

		return
	}

	if err := n.delegations.AcknowledgeUses(acknowledged); err != nil {
		n.log.Error("could not clear reported grant activity",
			"peer", record.GetName(), "error", err.Error())

		return
	}

	if len(acknowledged) > 0 {
		n.log.Info("reported what a delegation covered",
			"peer", record.GetName(), "uses", len(acknowledged))
	}
}

// HasGrantActivityFor says whether this instance owes a peer an account. It is
// what a poll's answer carries, so that an approver which cannot be dialled
// knows to come and collect rather than asking on every round for ever.
func (n *Node) HasGrantActivityFor(approverFingerprint string) bool {
	if n.delegations == nil {
		return false
	}

	return len(n.delegations.UnreportedUses(approverFingerprint)) > 0
}

// ReconcileGrants is the requester's side of the call: it is told what has been
// taken back and what has been heard, and answers with what it has done.
func (s *peerService) ReconcileGrants(
	ctx context.Context, req *connect.Request[ladulasv1.ReconcileGrantsRequest],
) (*connect.Response[ladulasv1.ReconcileGrantsResponse], error) {
	// The same half of the pairing that authorizes the inbox, and for the same
	// reason: only a peer this instance agreed may approve for it can have
	// granted it anything to reconcile.
	_, record, err := s.node.publisherFor(ctx)
	if err != nil {
		return nil, err
	}

	if s.node.delegations == nil {
		return connect.NewResponse(&ladulasv1.ReconcileGrantsResponse{}), nil
	}

	if ids := req.Msg.GetRevokedDelegationIds(); len(ids) > 0 {
		dropped, err := s.node.dropRevoked(record, ids)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}

		if dropped > 0 {
			s.node.log.Info("an approver took delegations back",
				"peer", record.GetName(), "count", dropped)
		}
	}

	if err := s.node.delegations.AcknowledgeUses(
		req.Msg.GetAcknowledgedRequestIds()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// A re-issued promise goes through exactly the checks one that arrives with
	// an approval goes through, and is kept the same way — replacing what was
	// held under that identifier, ledger and all. Somebody extended it; nothing
	// about what it covers has changed.
	for _, signed := range req.Msg.GetRenewedDelegations() {
		s.node.acceptRenewedDelegation(record, signed)
	}

	held, err := s.node.delegations.Delegations()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	ids := make([]string, 0, len(held))

	for _, item := range held {
		if item.GetDelegation().GetApproverFingerprint() != record.GetFingerprint() {
			continue
		}

		ids = append(ids, item.GetDelegation().GetDelegationId())
	}

	return connect.NewResponse(&ladulasv1.ReconcileGrantsResponse{
		Uses:              s.node.delegations.UnreportedUses(record.GetFingerprint()),
		HeldDelegationIds: ids,
	}), nil
}

// dropRevoked forgets delegations an approver has taken back, and only the ones
// it granted: a peer may end its own promises and nobody else's.
func (n *Node) dropRevoked(
	record *storepb.TrustRecord, ids []string,
) (int, error) {
	held, err := n.delegations.Delegations()
	if err != nil {
		return 0, fmt.Errorf("read the delegations: %w", err)
	}

	mine := make(map[string]bool, len(held))

	for _, item := range held {
		d := item.GetDelegation()

		if d.GetApproverFingerprint() == record.GetFingerprint() {
			mine[d.GetDelegationId()] = true
		}
	}

	var theirs []string

	for _, id := range ids {
		if mine[id] {
			theirs = append(theirs, id)
		}
	}

	dropped, err := n.delegations.DropDelegations(theirs)
	if err != nil {
		return 0, fmt.Errorf("drop the delegations: %w", err)
	}

	return dropped, nil
}

// reconcileWith is the approver's side: tell one requester what has been taken
// back, and record what it says it has done.
//
// Nothing here is load-bearing for a delegation working. A requester that
// cannot be reached goes on honouring what it holds until it expires, which is
// the whole point of having handed it over — so a failure is logged at debug
// and tried again next time.
func (n *Node) reconcileWith(
	ctx context.Context, record *storepb.TrustRecord,
) error {
	if n.delegations == nil {
		return nil
	}

	grants, err := n.delegations.Grants()
	if err != nil {
		return fmt.Errorf("read the grants: %w", err)
	}

	live := make(map[string]bool)

	var acknowledged []string

	for _, grant := range grants {
		if !grant.GetDelegated() ||
			grant.GetDelegateFingerprint() != record.GetFingerprint() {
			continue
		}

		// A grant somebody revoked while this machine was unreachable is not
		// live, whatever the record still says. Leaving it out here is what
		// makes the next contact deliver the revocation, since what the
		// requester holds and this side does not call live is precisely what
		// gets taken back below.
		if grant.GetRevokePending() {
			continue
		}

		live[grant.GetGrantId()] = true

		for _, use := range grant.GetRecentUses() {
			acknowledged = append(acknowledged, use.GetRequestId())
		}
	}

	var resp *ladulasv1.ReconcileGrantsResponse

	err = n.call(ctx, record, func(
		ctx context.Context, client *http.Client, baseURL string,
	) error {
		inbox := ladulasv1connect.NewInboxServiceClient(client, baseURL,
			connect.WithReadMaxBytes(maxRequestBytes))

		answer, err := inbox.ReconcileGrants(ctx, connect.NewRequest(
			&ladulasv1.ReconcileGrantsRequest{
				RevokedDelegationIds:   nil,
				AcknowledgedRequestIds: acknowledged,
			}))
		if err != nil {
			return err //nolint:wrapcheck // call wraps it with the address
		}

		resp = answer.Msg

		return nil
	})
	if err != nil {
		return fmt.Errorf("reconcile with %s: %w", record.GetName(), err)
	}

	// A delegation the requester still holds and this instance has no live
	// record of is one that was revoked, or expired here first.
	var revoked []string

	for _, id := range resp.GetHeldDelegationIds() {
		if !live[id] {
			revoked = append(revoked, id)
		}
	}

	if err := n.delegations.RecordGrantUses(resp.GetUses()); err != nil {
		return fmt.Errorf("record what %s did: %w", record.GetName(), err)
	}

	var received []string

	for _, use := range resp.GetUses() {
		received = append(received, use.GetRequestId())
	}

	if len(revoked) == 0 && len(received) == 0 {
		return nil
	}

	// The second half of the round trip, made only when there is something to
	// say. It is what clears the requester's ledger: an account that was
	// collected and never acknowledged would be offered again on every poll for
	// as long as the delegation lasted.
	if err := n.tellReconciled(ctx, record, revoked, received); err != nil {
		return err
	}

	// A revocation that was made while this machine was unreachable has now
	// been delivered, so the record marked "pending" can finally go. Only once
	// the telling succeeded: a grant dropped here on the strength of a call
	// that failed would leave the holder signing under a promise nothing
	// remembers.
	n.finishPendingRevocations(record.GetFingerprint())

	return nil
}

// finishPendingRevocations removes the grants whose revocation has just been
// delivered. Failing to remove one is worth a line and nothing more: the record
// stays marked, and the next reconciliation tries again.
func (n *Node) finishPendingRevocations(fingerprint string) {
	for _, id := range n.delegations.PendingRevocations(fingerprint) {
		if err := n.delegations.RevokeGrant(id); err != nil {
			n.log.Warn("could not finish revoking a grant",
				"grant", id, "error", err.Error())

			continue
		}

		n.log.Info("a revocation that was waiting has been delivered",
			"grant", id, "peer", fingerprint)
	}
}

// tellReconciled says what was taken back and what was heard.
//
// Losing it is survivable and deliberately so: the uses stay in the requester's
// ledger, the flag on its next poll is still set, and the next round collects
// the same entries — which are recorded once, because filing is keyed on the
// request id.
func (n *Node) tellReconciled(
	ctx context.Context,
	record *storepb.TrustRecord,
	revoked, acknowledged []string,
	renewed ...*ladulasv1.SignedDelegation,
) error {
	err := n.call(ctx, record, func(
		ctx context.Context, client *http.Client, baseURL string,
	) error {
		inbox := ladulasv1connect.NewInboxServiceClient(client, baseURL,
			connect.WithReadMaxBytes(maxRequestBytes))

		_, err := inbox.ReconcileGrants(ctx, connect.NewRequest(
			&ladulasv1.ReconcileGrantsRequest{
				RevokedDelegationIds:   revoked,
				AcknowledgedRequestIds: acknowledged,
				RenewedDelegations:     renewed,
			}))

		return err //nolint:wrapcheck // call wraps it with the address
	})
	if err != nil {
		return fmt.Errorf("finish reconciling with %s: %w",
			record.GetName(), err)
	}

	if len(revoked) > 0 {
		n.log.Info("took delegations back",
			"peer", record.GetName(), "count", len(revoked))
	}

	if len(acknowledged) > 0 {
		n.log.Info("collected what a delegation covered",
			"peer", record.GetName(), "uses", len(acknowledged))
	}

	return nil
}

// RevokeDelegation takes a delegation back from the machine holding it, now,
// and reports whether there was one to take.
//
// This is the half of revoking that has to happen somewhere else. A delegation
// is a signed promise the requester holds and honours by itself (decision P) —
// it does not ask before using one, which is what handing it over was for — so
// deleting the approver's record of it stops precisely nothing. Until this call
// lands, the other machine goes on signing.
//
// It is therefore synchronous and it is allowed to fail. The caller revokes
// locally only once this has succeeded, because an approver told "revoked"
// while the machine it delegated to keeps signing has been told a lie, and a
// revocation that lies is worse than one that refuses: the second sends
// somebody to unplug something, and the first sends them to bed.
//
// A delegation that cannot be reached cannot be revoked, and saying so is the
// honest answer rather than a shortcoming — reconciliation will not help
// either, since it is the same unreachable machine at the other end of it.
func (n *Node) RevokeDelegation(
	ctx context.Context, grantID string,
) (bool, error) {
	if n.delegations == nil {
		return false, nil
	}

	grants, err := n.delegations.Grants()
	if err != nil {
		return false, fmt.Errorf("read the grants: %w", err)
	}

	var holder string

	for _, grant := range grants {
		if grant.GetGrantId() != grantID {
			continue
		}

		if !grant.GetDelegated() {
			// An approver-side grant: nobody else is holding anything, and
			// removing it here is the whole of revoking it.
			return false, nil
		}

		holder = grant.GetDelegateFingerprint()

		break
	}

	if holder == "" {
		return false, nil
	}

	for _, record := range n.trust.Peers() {
		if record.GetFingerprint() != holder {
			continue
		}

		if err := n.tellReconciled(
			ctx, record, []string{grantID}, nil,
		); err != nil {
			return false, fmt.Errorf(
				"take the delegation back from %s: %w", record.GetName(), err)
		}

		return true, nil
	}

	return false, fmt.Errorf(
		"the delegation for %s is held by a peer this instance no longer knows",
		grantID)
}

// RenewDelegation hands a re-signed promise to the machine holding it, now.
//
// It is the delivering half of extending one, and it is not optional the way
// reporting a use is: until this lands, the holder is acting on the artifact it
// already has and stops at the old expiry. So the caller is told whether it
// arrived, and stores the longer promise only if it did — an approver whose
// list said three hours while the machine acting on it stopped at one would be
// a list that lies in the safe direction, which is still a list that lies.
func (n *Node) RenewDelegation(
	ctx context.Context, holder string, signed *ladulasv1.SignedDelegation,
) error {
	for _, record := range n.trust.Peers() {
		if record.GetFingerprint() != holder {
			continue
		}

		if err := n.tellReconciled(ctx, record, nil, nil, signed); err != nil {
			return fmt.Errorf("hand the extended promise to %s: %w",
				record.GetName(), err)
		}

		n.log.Info("extended a delegation",
			"peer", record.GetName(),
			"delegation_id", signed.GetApproverFingerprint())

		return nil
	}

	return fmt.Errorf(
		"the promise is held by a peer this instance no longer knows")
}

// ReconcileDelegations brings every requester this instance has delegated to
// back into line. It runs after a collect round, so a phone that opened its app
// catches up on what its machines did while it was away.
func (n *Node) ReconcileDelegations(ctx context.Context) {
	if n.delegations == nil {
		return
	}

	for _, record := range n.requesters() {
		if err := n.reconcileWith(ctx, record); err != nil {
			n.log.Debug("could not reconcile delegated grants",
				"peer", record.GetName(), "error", err.Error())
		}
	}
}

// reconcileTimeout bounds one round. It is bookkeeping about promises already
// made, and has no business holding anything up.
const reconcileTimeout = 20 * time.Second
