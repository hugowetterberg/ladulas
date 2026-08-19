package peer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// The key list, from both ends of the peer channel (decision T).
//
// M4 gave a requester one way to learn what a holder offers: ask it. That works
// between two desktops and not at all with a phone, which advertises no address
// and cannot be asked anything — so the phone says it instead, from the poll loop
// that is the one thing it reliably does, exactly as it says where it can be
// woken (§11).
//
// Nothing here is authorization. What arrives is a list of public halves, kept
// because a requester with an agent socket has to be able to answer "which
// identities are there" without waking anybody; every signature made with one is
// still asked for, decided and produced where the key is.

// AnnounceKeys tells a requester which of this instance's keys it may use.
//
// Called by the holder, served by the requester, because the holder is the side
// that can always dial. The list is what ListKeys would have answered — the
// intersection of what this store holds and what the trust record allows — so a
// peer granted one key learns about one key.
func (s *peerService) AnnounceKeys(
	ctx context.Context,
	req *connect.Request[ladulasv1.AnnounceKeysRequest],
) (*connect.Response[ladulasv1.AnnounceKeysResponse], error) {
	peer, record, err := s.node.publisherFor(ctx)
	if err != nil {
		return nil, err
	}

	keys := validKeys(req.Msg.GetKeys())

	s.node.rememberKeys(peer.Fingerprint, keys)

	s.node.log.Debug("a peer said which keys it offers",
		"peer", record.GetName(), "keys", len(keys))

	return connect.NewResponse(&ladulasv1.AnnounceKeysResponse{
		Accepted: true,
	}), nil
}

// validKeys drops what cannot be a key.
//
// A reference whose blob does not parse could never be signed with and could
// never be matched against a request, so remembering one would only put a row in
// a listing that nothing can ever use. A reference whose fingerprint disagrees
// with its blob is worse: the blob is what an agent advertises and the
// fingerprint is what a signature is later resolved by, and two names for one key
// that point at different keys is not a state to keep in a store. The blob wins,
// because it is the half that cannot lie about itself.
func validKeys(keys []*ladulasv1.KeyRef) []*ladulasv1.KeyRef {
	out := make([]*ladulasv1.KeyRef, 0, len(keys))

	for _, ref := range keys {
		pub, err := ssh.ParsePublicKey(ref.GetPublicKey())
		if err != nil {
			continue
		}

		if ref.GetFingerprint() != ssh.FingerprintSHA256(pub) {
			continue
		}

		out = append(out, ref)
	}

	return out
}

// announcedList is what was last announced to one requester.
type announcedList struct {
	at     time.Time
	digest string
}

// AnnounceKeys takes this instance's key list to the requesters that have not
// been told it, or have been told something else.
//
// It runs from the poll loop for the reason the wake-up announcement does: the
// loop starts when the app comes to the foreground, which is also when somebody
// has just granted a machine the use of a key, and a requester that is about to
// be polled is a requester that can be reached.
func (n *Node) AnnounceKeys(ctx context.Context) {
	if n.keys == nil {
		return
	}

	n.announceKeysMu.Lock()
	defer n.announceKeysMu.Unlock()

	for _, record := range n.requesters() {
		if ctx.Err() != nil {
			return
		}

		keys := n.keysFor(record)

		if !n.shouldAnnounceKeys(record.GetFingerprint(), keys) {
			continue
		}

		n.announceKeysTo(ctx, record, keys)
	}
}

// shouldAnnounceKeys paces it. The list changes when somebody grants a key, hides
// one or generates one, and otherwise never — so this is one small call per
// change, plus one every announceRefresh for the requester that was rebuilt and
// has forgotten.
func (n *Node) shouldAnnounceKeys(
	fingerprint string, keys []*ladulasv1.KeyRef,
) bool {
	digest := keyListDigest(keys)

	n.mu.Lock()
	defer n.mu.Unlock()

	last, seen := n.announcedKeys[fingerprint]

	// Nothing to say and nothing said: a phone that holds no key this requester
	// may use, which is every pairing until somebody says otherwise.
	if !seen && len(keys) == 0 {
		return false
	}

	if seen && last.digest == digest &&
		time.Since(last.at) < announceRefresh {
		return false
	}

	n.announcedKeys[fingerprint] = announcedList{
		at:     time.Now(),
		digest: digest,
	}

	return true
}

// keyListDigest is a list of keys as one comparable string, and covers the agent
// setting as well as the key: turning that off is a change the requester has to
// hear about, since the requester is where the agent is.
func keyListDigest(keys []*ladulasv1.KeyRef) string {
	sum := sha256.New()

	for _, ref := range keys {
		_, _ = sum.Write([]byte(ref.GetFingerprint()))
		_, _ = sum.Write([]byte(ref.GetLabel()))
		_, _ = sum.Write([]byte(ref.GetComment()))

		if !keystore.RefAgentUse(ref) {
			_, _ = sum.Write([]byte("\x00hidden"))
		}

		_, _ = sum.Write([]byte("\x00"))
	}

	return hex.EncodeToString(sum.Sum(nil))
}

// announceKeysTo tells one requester, and is best effort by construction: one
// that cannot be reached is one this instance is about to fail to collect from
// anyway, and the next round tries again.
func (n *Node) announceKeysTo(
	ctx context.Context, record *storepb.TrustRecord, keys []*ladulasv1.KeyRef,
) {
	ctx, cancel := context.WithTimeout(ctx, announceTimeout)
	defer cancel()

	msg := &ladulasv1.AnnounceKeysRequest{Keys: keys}

	var refused string

	err := n.call(ctx, record, func(
		ctx context.Context, client *http.Client, baseURL string,
	) error {
		service := ladulasv1connect.NewKeyServiceClient(client, baseURL)

		resp, err := service.AnnounceKeys(ctx, connect.NewRequest(msg))
		if err != nil {
			return err //nolint:wrapcheck // call wraps it with the address
		}

		if !resp.Msg.GetAccepted() {
			refused = resp.Msg.GetReason()
		}

		return nil
	})
	if err != nil {
		// Not announced means not remembered as announced, so the next round says
		// it again rather than assuming a requester that was asleep heard it.
		n.forgetKeyAnnouncement(record.GetFingerprint())

		n.log.Debug("could not announce the key list",
			"peer", record.GetName(), "error", err.Error())

		return
	}

	if refused != "" {
		n.log.Info("a requester will not remember this instance's keys",
			"peer", record.GetName(), "reason", refused)
	}
}

func (n *Node) forgetKeyAnnouncement(fingerprint string) {
	n.mu.Lock()
	delete(n.announcedKeys, fingerprint)
	n.mu.Unlock()
}
