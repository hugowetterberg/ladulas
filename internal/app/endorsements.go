package app

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The management surface's part of decision AG: seeing the promises other
// holders of a key have made, and taking one back.
//
// Listing is the load-bearing half. An endorsement works whether or not this
// instance was ever told about it — the requester carries a copy and presents
// it — so a machine that could not show what it is honouring would be signing
// on a promise nobody here could find, which is the definition of the silent
// background activity this must not become. Everything is listed, including the
// copies this instance is only carrying and the ones it will not act on, with
// the reason it will not.

// ListEndorsements reports what this instance holds and what it remembers being
// taken back.
func (s *controlService) ListEndorsements(
	_ context.Context, _ *connect.Request[ladulasv1.ListEndorsementsRequest],
) (*connect.Response[ladulasv1.ListEndorsementsResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	held, err := vault.Endorsements()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &ladulasv1.ListEndorsementsResponse{}

	for _, item := range held {
		e := item.GetEndorsement()
		inert := vault.InertBecause(e)

		resp.Endorsements = append(resp.Endorsements,
			&ladulasv1.HeldEndorsementInfo{
				Endorsement:  e,
				ReceivedAt:   item.GetReceivedAt(),
				Published:    item.GetPublished(),
				Actionable:   inert == "",
				InertBecause: inert,
				UseCount:     item.GetUseCount(),
				//nolint:gosec // a ledger of unsent reports is not that long
				UnreportedUses: uint32(len(item.GetUnreportedUses())),
			})
	}

	retracted, err := vault.Retractions()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	for _, item := range retracted {
		resp.Retractions = append(resp.Retractions, &ladulasv1.RetractionInfo{
			Retraction: item.GetRetraction(),
			ReceivedAt: item.GetReceivedAt(),
		})
	}

	return connect.NewResponse(resp), nil
}

// RetractEndorsement takes a promise about a key back and tells every holder
// this instance can reach.
//
// It needs no passphrase, and that is deliberate rather than an omission. What
// authorizes a retraction is holding the key, and the artifact is signed with
// it — a machine that cannot reach the private half cannot produce one. Putting
// a deliberateness gate in front of the thing that *stops* unattended signing
// would be a gate on the wrong side of the door: sending a key is the act that
// asks for a pause (decision S), and taking a promise back is the act that
// wants to be as easy as it can be made.
func (s *controlService) RetractEndorsement(
	ctx context.Context, req *connect.Request[ladulasv1.RetractEndorsementRequest],
) (*connect.Response[ladulasv1.RetractEndorsementResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	node, err := s.peerControl()
	if err != nil {
		return nil, err
	}

	key := req.Msg.GetKeyFingerprint()
	id := req.Msg.GetEndorsementId()

	// One of the two names the key directly and the other has to be looked up,
	// and both end in the same place: a retraction is about a key, because the
	// key is what signs it.
	if id != "" && key == "" {
		key, err = endorsedKey(vault, id)
		if err != nil {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
	}

	if key == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("say which endorsement, or which key"))
	}

	told, unreached, dropped, err := node.Retract(
		ctx, id, key, req.Msg.GetReason(),
		s.app.Engine().Policy().MaxGrantTTL())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	s.app.LogKeyTransfer(retractionNote(id, req.Msg.GetReason()), key)

	return connect.NewResponse(&ladulasv1.RetractEndorsementResponse{
		Told:      told,
		Unreached: unreached,
		//nolint:gosec // a count of endorsements dropped is not that large
		Dropped: uint32(dropped),
	}), nil
}

func retractionNote(id, reason string) string {
	what := "took back every promise about a key"
	if id != "" {
		what = fmt.Sprintf("took back the promise %q", id)
	}

	if reason == "" {
		return what
	}

	return what + ": " + reason
}

// endorsedKey answers which key an endorsement is about.
//
// A retraction naming an endorsement this instance has never heard of is
// refused rather than guessed at: the key is what signs the artifact, and one
// signed with the wrong key takes nothing back anywhere.
func endorsedKey(vault *keystore.Vault, id string) (string, error) {
	held, err := vault.Endorsements()
	if err != nil {
		return "", err
	}

	for _, item := range held {
		if item.GetEndorsement().GetEndorsementId() == id {
			return item.GetEndorsement().GetKeyFingerprint(), nil
		}
	}

	return "", fmt.Errorf("no endorsement %q is held here", id)
}
