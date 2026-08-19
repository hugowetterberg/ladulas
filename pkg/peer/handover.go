package peer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// Handing a portable key to a paired peer (§10, decision S).
//
// It is the only call in the protocol that carries key material, and the shape
// of it is decided by the same fact that shapes the approval path: half the
// peers in this design cannot be dialled. So a send is a queue entry, and there
// are two ways it leaves — pushed at a peer that listens, or collected by one
// that does not and was woken to come and look. Which one happens is about
// reachability and nothing else; a key that travelled either way arrives as an
// offer nobody has accepted yet.
//
// What this file will not do: deliver to somebody who is not paired, deliver
// what nobody typed a passphrase for — the queue entry is the evidence that
// somebody did — or let an arriving key become usable without an answer at this
// end.

// Handovers is what handing keys over needs from the encrypted store.
// keystore.Vault implements it.
type Handovers interface {
	// The sending side.
	QueueHandover(
		peerFingerprint, peerName string,
		key *storepb.StoredKey, at time.Time,
	) (*storepb.QueuedKeyHandover, error)
	QueuedHandovers() []*storepb.QueuedKeyHandover
	CompleteHandover(id string, at time.Time) error
	DropPeerHandovers(peerFingerprint string) error

	// The receiving side.
	AddKeyOffer(
		peerFingerprint, peerName, label, comment, handoverID string,
		keyPEM []byte, at time.Time,
	) (*storepb.PendingKeyOffer, error)
	PendingKeyOffers() []*storepb.PendingKeyOffer
	DropPeerKeyOffers(peerFingerprint string) error
}

// maxKeyBytes caps an offered private key. An OpenSSH ed25519 key is a few
// hundred bytes and a 4096-bit RSA one a few thousand; anything past this is not
// a key and is refused before it is parsed.
const maxKeyBytes = 32 << 10

// OfferKey takes a portable key a paired peer has handed over.
//
// Nothing here decides anything: the key is written down as an offer and waits
// for somebody at this end. That is the whole of the receiving side's part in
// decision S, and it is why this call is authorized by the pairing alone —
// which direction a pairing grants is about who may ask whom for a signature,
// and being given a key is neither.
func (s *peerService) OfferKey(
	ctx context.Context,
	req *connect.Request[ladulasv1.OfferKeyRequest],
) (*connect.Response[ladulasv1.OfferKeyResponse], error) {
	peer, record, err := s.node.pairedPeer(ctx)
	if err != nil {
		return nil, err
	}

	offer, err := s.node.takeOfferedKey(peer, record, &ladulasv1.OfferedKey{
		Label:      req.Msg.GetLabel(),
		Comment:    req.Msg.GetComment(),
		PrivateKey: req.Msg.GetPrivateKey(),
	})
	if err != nil {
		// Every refusal here is something the sender can do something about —
		// a key already held, a full list, something that is not a key — so it
		// travels as what it is rather than as an internal error.
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}

	return connect.NewResponse(&ladulasv1.OfferKeyResponse{
		OfferId: offer.GetId(),
	}), nil
}

// takeOfferedKey is the receiving side of both delivery paths.
func (n *Node) takeOfferedKey(
	peer *transport.PeerIdentity, record *storepb.TrustRecord,
	offered *ladulasv1.OfferedKey,
) (*storepb.PendingKeyOffer, error) {
	if n.handovers == nil {
		return nil, errors.New("this instance holds no keys and cannot be handed one")
	}

	if len(offered.GetPrivateKey()) == 0 {
		return nil, errors.New("the offer carries no key")
	}

	if len(offered.GetPrivateKey()) > maxKeyBytes {
		return nil, errors.New("that is too large to be a private key")
	}

	offer, err := n.handovers.AddKeyOffer(
		peer.Fingerprint, record.GetName(),
		offered.GetLabel(), offered.GetComment(), offered.GetHandoverId(),
		offered.GetPrivateKey(), time.Now())
	if err != nil {
		return nil, err
	}

	n.log.Info("a peer handed over a key",
		"peer", record.GetName(),
		"key", offer.GetFingerprint(),
		"label", offer.GetLabel())

	n.engine.LogKeyTransfer(fmt.Sprintf(
		"%q handed over the key %q, which is waiting to be answered",
		record.GetName(), offer.GetLabel()), offer.GetFingerprint())

	return offer, nil
}

// CollectKeyOffers hands a collecting peer what is queued for it, and releases
// what it says it already has.
//
// The order matters and is the reason a lost answer is survivable: what the
// caller acknowledges is released first, and what is still held is then read,
// so a redelivery is the worst outcome and a key silently dropped is not a
// possible one.
func (s *peerService) CollectKeyOffers(
	ctx context.Context,
	req *connect.Request[ladulasv1.CollectKeyOffersRequest],
) (*connect.Response[ladulasv1.CollectKeyOffersResponse], error) {
	peer, record, err := s.node.pairedPeer(ctx)
	if err != nil {
		return nil, err
	}

	if s.node.handovers == nil {
		return connect.NewResponse(&ladulasv1.CollectKeyOffersResponse{}), nil
	}

	queued := s.node.handovers.QueuedHandovers()

	for _, id := range req.Msg.GetReceivedIds() {
		for _, handover := range queued {
			if handover.GetId() != id ||
				handover.GetPeerFingerprint() != peer.Fingerprint {
				continue
			}

			s.node.handoverDelivered(handover, record.GetName())
		}
	}

	var offers []*ladulasv1.OfferedKey

	for _, handover := range s.node.handovers.QueuedHandovers() {
		if handover.GetPeerFingerprint() != peer.Fingerprint {
			continue
		}

		offers = append(offers, &ladulasv1.OfferedKey{
			HandoverId: handover.GetId(),
			Label:      handover.GetLabel(),
			Comment:    handover.GetComment(),
			PrivateKey: handover.GetPrivateKey(),
		})
	}

	return connect.NewResponse(&ladulasv1.CollectKeyOffersResponse{
		Offers: offers,
	}), nil
}

// pairedPeer authorizes the calls that are about a pairing rather than about a
// direction within one.
//
// Handing somebody a key is not asking them to sign and is not being asked, so
// neither half of a trust record has anything to say about it. What the pairing
// proves is that these two instances know each other, and the decisions that
// matter are at the two ends: a passphrase before a key is queued, and an answer
// before an arriving one is held.
func (n *Node) pairedPeer(
	ctx context.Context,
) (*transport.PeerIdentity, *storepb.TrustRecord, error) {
	peer := transport.PeerFrom(ctx)
	if peer == nil {
		return nil, nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("the connection is not authenticated"))
	}

	record, ok := n.trust.Peer(peer.Fingerprint)
	if !ok {
		return nil, nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("%s is not a paired peer", peer.Fingerprint))
	}

	return peer, record, nil
}

// SendKey queues a key for a peer and tries to deliver it at once.
//
// The queue is written first and always, so that "the passphrase was typed and
// the key was given away" is one durable fact rather than something that
// depends on a peer being awake. Delivery failing is not the send failing: a
// desktop that is shut gets it when it comes back, and a phone was never going
// to take it here.
func (n *Node) SendKey(
	ctx context.Context, record *storepb.TrustRecord, key *storepb.StoredKey,
) (*storepb.QueuedKeyHandover, error) {
	if n.handovers == nil {
		return nil, errors.New("peer: this instance cannot hand over keys")
	}

	handover, err := n.handovers.QueueHandover(
		record.GetFingerprint(), record.GetName(), key, time.Now())
	if err != nil {
		return nil, err
	}

	n.engine.LogKeyTransfer(fmt.Sprintf(
		"handed the key %q to %q", key.GetLabel(), record.GetName()),
		key.GetFingerprint())

	n.deliverHandover(ctx, record, handover)

	return handover, nil
}

// deliverHandover makes one attempt at one queued key.
//
// A peer with an address is pushed at. One without is a phone, which cannot be
// pushed at and is woken instead — the wake-up is a knock and nothing else, and
// the key is taken by the poll that follows it (§11). Both paths end in the
// queue entry surviving, which is what makes the next attempt free.
func (n *Node) deliverHandover(
	ctx context.Context, record *storepb.TrustRecord,
	handover *storepb.QueuedKeyHandover,
) {
	if len(record.GetAddresses()) == 0 {
		n.wakeForKey(record.GetFingerprint())

		return
	}

	// Bounded, because this runs on the loop that also reconciles pairings: a
	// peer that accepts a connection and then says nothing must not hold up
	// everything else waiting to be taken to somebody.
	ctx, cancel := context.WithTimeout(ctx, deliverTimeout)
	defer cancel()

	err := n.call(ctx, record,
		func(ctx context.Context, client *http.Client, baseURL string) error {
			keys := ladulasv1connect.NewKeyServiceClient(client, baseURL,
				connect.WithSendMaxBytes(maxRequestBytes))

			_, err := keys.OfferKey(ctx, connect.NewRequest(
				&ladulasv1.OfferKeyRequest{
					Label:      handover.GetLabel(),
					Comment:    handover.GetComment(),
					PrivateKey: handover.GetPrivateKey(),
				}))
			if err != nil {
				return fmt.Errorf("offer the key: %w", err)
			}

			return nil
		})
	if err != nil {
		n.log.Debug("could not hand a key to a peer, it stays queued",
			"peer", record.GetName(),
			"key", handover.GetFingerprint(),
			"error", err.Error())

		return
	}

	n.handoverDelivered(handover, record.GetName())
}

// deliverTimeout bounds one attempt at handing a key over. Generous enough for
// a large key over a slow link, short enough that a peer which is not really
// there costs the convergence loop a few seconds rather than a minute.
const deliverTimeout = 20 * time.Second

// handoverDelivered writes down that the key has gone.
func (n *Node) handoverDelivered(
	handover *storepb.QueuedKeyHandover, peerName string,
) {
	err := n.handovers.CompleteHandover(handover.GetId(), time.Now())
	if err != nil {
		n.log.Error("could not record that a key was handed over",
			"peer", peerName,
			"key", handover.GetFingerprint(),
			"error", err.Error())

		return
	}

	n.log.Info("handed a key to a peer",
		"peer", peerName, "key", handover.GetFingerprint())
}

// deliverQueuedKeys retries every queued handover, and runs on the loop that
// already takes a pending pairing to a peer that was not there.
//
// It is the same problem: something this side has decided, and a peer that has
// to be around to hear it. A key queued for a phone is left alone here — waking
// it once when the key was sent is a knock, and knocking every thirty seconds
// until somebody opens the app is something else.
func (n *Node) deliverQueuedKeys(ctx context.Context) {
	if n.handovers == nil {
		return
	}

	for _, handover := range n.handovers.QueuedHandovers() {
		if ctx.Err() != nil {
			return
		}

		record, ok := n.trust.Peer(handover.GetPeerFingerprint())
		if !ok {
			// The peer was revoked between the send and now. Revoking drops what
			// was queued for it, so this is a race rather than a state, and the
			// key stays where it is.
			continue
		}

		if len(record.GetAddresses()) == 0 {
			continue
		}

		n.deliverHandover(ctx, record, handover)
	}
}

// collectKeysFrom asks one peer for the keys it is holding for this instance.
//
// It runs in the poll a phone already does, because that is what a phone does at
// all: open, ask everybody what is waiting, and show it. A key offer is one more
// thing that can be waiting.
func (n *Node) collectKeysFrom(
	ctx context.Context, record *storepb.TrustRecord,
) error {
	if n.handovers == nil {
		return nil
	}

	received := n.receivedFrom(record.GetFingerprint())

	err := n.call(ctx, record,
		func(ctx context.Context, client *http.Client, baseURL string) error {
			keys := ladulasv1connect.NewKeyServiceClient(client, baseURL,
				connect.WithReadMaxBytes(maxRequestBytes))

			resp, err := keys.CollectKeyOffers(ctx, connect.NewRequest(
				&ladulasv1.CollectKeyOffersRequest{ReceivedIds: received}))
			if err != nil {
				return fmt.Errorf("collect key offers: %w", err)
			}

			for _, offered := range resp.Msg.GetOffers() {
				peer := &transport.PeerIdentity{
					Fingerprint: record.GetFingerprint(),
				}

				_, err := n.takeOfferedKey(peer, record, offered)
				if err == nil {
					continue
				}

				// One key that cannot be taken must not stop the others. What
				// happens next depends on why, and there are only two kinds of
				// why: a full offer list clears by itself and the sender should
				// keep the key for the next round, and a key this instance
				// already holds never stops being one — which is what an offer
				// accepted before its acknowledgement reached the sender looks
				// like from here. Left alone, that one would be redelivered on
				// every poll for ever, so it is acknowledged instead.
				if errors.Is(err, keystore.ErrDuplicateKey) {
					n.settleHandover(offered.GetHandoverId())
				}

				n.log.Warn("could not take a key a peer offered",
					"peer", record.GetName(), "error", err.Error())
			}

			return nil
		})
	if err != nil {
		return err
	}

	// The acknowledgement got through, so what was remembered only in order to
	// send it can be forgotten. A round that failed keeps it, and a round that
	// forgot it too early would learn it again from the next redelivery.
	n.forgetSettled(received)

	return nil
}

// forgetSettled drops what has been acknowledged, so the set that exists only
// to be sent does not outlive the sending.
func (n *Node) forgetSettled(ids []string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	for _, id := range ids {
		delete(n.settled, id)
	}
}

// receivedFrom is what this instance has already dealt with from a peer, to be
// acknowledged on the next collection: the offers it is holding, and the ones
// it has nothing left to do about.
func (n *Node) receivedFrom(fingerprint string) []string {
	var out []string

	for _, offer := range n.handovers.PendingKeyOffers() {
		if offer.GetPeerFingerprint() != fingerprint {
			continue
		}

		if id := offer.GetHandoverId(); id != "" {
			out = append(out, id)
		}
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	for id := range n.settled {
		out = append(out, id)
	}

	return out
}

// settleHandover remembers a handover to acknowledge even though nothing was
// written down for it.
//
// In memory rather than in the store, because it is worth exactly one
// redelivery: an instance that restarts before the acknowledgement goes out is
// offered the key once more, notices it holds it already, and settles it again.
func (n *Node) settleHandover(id string) {
	if id == "" {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.settled == nil {
		n.settled = map[string]bool{}
	}

	n.settled[id] = true
}

// dropPeerHandovers is the key-transfer half of revoking a pairing: what was
// queued for that peer, and what it offered and nobody answered.
//
// An accepted key stays, because accepting made it this instance's key. That is
// the difference between a key and everything else a pairing brings with it, and
// it is why the acceptance is a deliberate act.
func (n *Node) dropPeerHandovers(record *storepb.TrustRecord) {
	if n.handovers == nil {
		return
	}

	if err := n.handovers.DropPeerHandovers(record.GetFingerprint()); err != nil {
		n.log.Error("could not drop the keys queued for a revoked peer",
			"peer", record.GetName(), "error", err.Error())
	}

	if err := n.handovers.DropPeerKeyOffers(record.GetFingerprint()); err != nil {
		n.log.Error("could not drop the keys a revoked peer had offered",
			"peer", record.GetName(), "error", err.Error())
	}
}

// collectKeys asks a peer for what it holds for this instance, quietly.
//
// A peer that cannot be reached, or one running a build with no such call, is
// not a failure worth a line above debug: the poll it rides on is about
// approvals, and a key that was not collected this time is collected next time.
func (n *Node) collectKeys(ctx context.Context, record *storepb.TrustRecord) {
	if n.handovers == nil || ctx.Err() != nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, collectKeysTimeout)
	defer cancel()

	if err := n.collectKeysFrom(ctx, record); err != nil {
		n.log.Debug("could not collect keys from a peer",
			"peer", record.GetName(), "error", err.Error())
	}
}

// collectKeysTimeout bounds that call. It is short because it is bookkeeping in
// front of the poll somebody is actually waiting for.
const collectKeysTimeout = 15 * time.Second
