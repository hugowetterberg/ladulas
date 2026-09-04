package app

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The management surface's part of decision S: giving a portable key to a peer,
// and answering one that has arrived.
//
// Sending is the only call here that asks for the store passphrase, and the
// store is already open when it does — what it gates is deliberateness (§10).
// It is checked in this process rather than by the caller, for the reason
// everything else about the store is: the daemon is the only thing that has the
// wrapping to check it against, and a client that decided for itself whether
// somebody had typed the right passphrase would be a client anybody could
// replace with one that always said yes.

// SendKey hands a portable key to a paired peer.
func (s *controlService) SendKey(
	ctx context.Context, req *connect.Request[ladulasv1.SendKeyRequest],
) (*connect.Response[ladulasv1.SendKeyResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	node, err := s.peerControl()
	if err != nil {
		return nil, err
	}

	defer keystore.Wipe(req.Msg.GetPassphrase())

	if len(req.Msg.GetPassphrase()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("sending a key needs the store passphrase"))
	}

	if err := vault.VerifyPassphrase(req.Msg.GetPassphrase()); err != nil {
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	}

	// The key first: "that key cannot be handed over" is a fact about the key
	// and stays true whatever was typed for the peer.
	key, err := vault.PortableKey(req.Msg.GetKey())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	record, ok := vault.Peer(req.Msg.GetPeer())
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("no paired peer %q", req.Msg.GetPeer()))
	}

	handover, err := node.SendKey(ctx, record, key)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&ladulasv1.SendKeyResponse{
		Fingerprint: key.GetFingerprint(),
		PeerName:    record.GetName(),
		OfferId:     handover.GetId(),
	}), nil
}

// ListKeyOffers reports the keys peers have handed over and nobody has answered.
func (s *controlService) ListKeyOffers(
	_ context.Context, _ *connect.Request[ladulasv1.ListKeyOffersRequest],
) (*connect.Response[ladulasv1.ListKeyOffersResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	resp := &ladulasv1.ListKeyOffersResponse{}

	for _, offer := range vault.PendingKeyOffers() {
		resp.Offers = append(resp.Offers, &ladulasv1.KeyOfferInfo{
			Id:              offer.GetId(),
			PeerFingerprint: offer.GetPeerFingerprint(),
			PeerName:        offer.GetPeerName(),
			Label:           offer.GetLabel(),
			Comment:         offer.GetComment(),
			Algorithm:       offer.GetAlgorithm(),
			Fingerprint:     offer.GetFingerprint(),
			PublicKey:       offer.GetPublicKey(),
			ReceivedAt:      offer.GetReceivedAt(),
		})
	}

	return connect.NewResponse(resp), nil
}

// AnswerKeyOffer takes an offered key into the store, or forgets it.
func (s *controlService) AnswerKeyOffer(
	_ context.Context, req *connect.Request[ladulasv1.AnswerKeyOfferRequest],
) (*connect.Response[ladulasv1.AnswerKeyOfferResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	if !req.Msg.GetAccept() {
		if err := vault.RefuseKeyOffer(req.Msg.GetId()); err != nil {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}

		s.app.LogKeyTransfer("refused an offered key", "")

		return connect.NewResponse(&ladulasv1.AnswerKeyOfferResponse{}), nil
	}

	key, err := vault.AcceptKeyOffer(req.Msg.GetId(), req.Msg.GetLabel())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	s.app.LogKeyTransfer(fmt.Sprintf(
		"accepted the key %q from %q", key.GetLabel(),
		key.GetReceivedFrom().GetPeerName()), key.GetFingerprint())

	return connect.NewResponse(&ladulasv1.AnswerKeyOfferResponse{
		Key: keystore.KeyInfo(key),
	}), nil
}
