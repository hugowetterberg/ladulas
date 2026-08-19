package peer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/agent"
	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// Remote signing is the keyless requester of §3: a machine that holds no
// private key at all lists the keys its paired holders offer, and asks one of
// them to sign.
//
// The whole of the security argument is on the holder's side of this file. It
// rebuilds the SSHSIG wrapper from the payload rather than signing bytes the
// requester handed it, it classifies the payload itself rather than believing
// the request's account of what it is, and it takes the commit object from the
// payload — so the prompt a human reads is a parse of the exact bytes about to
// be signed and not of something that merely travelled beside them (§5).
//
// The requester's side is the mirror image: the answer's signature is checked
// against the trust record, the answer is checked to be about the request that
// was sent, and the signature that comes back is checked to verify over the
// blob this side expected. A denial is an answer and is final — never retried
// elsewhere, and never fallen back on, because on a keyless box there is
// nothing to fall back to.

// KeyStore is what the key holder's half of this needs from the encrypted
// store. keystore.Vault implements it, as it does for the agent.
type KeyStore interface {
	KeyRefs() []*ladulasv1.KeyRef
	Signer(fingerprint string) (ssh.Signer, *storepb.StoredKey, error)
}

// ErrNoRemoteKey is returned when no paired holder offers a key.
var ErrNoRemoteKey = errors.New("peer: no paired instance offers that key")

// ErrHolderUnreachable is returned when the instance that holds a key is known
// and cannot be reached (decision N).
//
// It is a separate error from ErrNoRemoteKey because it is a separate
// situation, and telling them apart is most of what the cache is for: one means
// nobody here can sign with that key, and the other means the machine that can
// is asleep, in a pocket, or on another network. It is also not a denial, and
// must not be read as one — nobody was asked.
var ErrHolderUnreachable = errors.New("peer: the instance holding that key cannot be reached")

// ListKeys tells a peer which of this instance's keys it may sign with.
//
// The answer is the intersection of what the store holds and what the trust
// record allows, never a listing of everything: a peer granted one key has no
// business learning what else is here.
func (s *peerService) ListKeys(
	ctx context.Context,
	_ *connect.Request[ladulasv1.ListKeysRequest],
) (*connect.Response[ladulasv1.ListKeysResponse], error) {
	_, record, err := s.node.authorize(ctx)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&ladulasv1.ListKeysResponse{
		Keys: s.node.keysFor(record),
	}), nil
}

// keysFor is the key set a peer may use.
func (n *Node) keysFor(record *storepb.TrustRecord) []*ladulasv1.KeyRef {
	if n.keys == nil {
		return nil
	}

	var out []*ladulasv1.KeyRef

	for _, ref := range n.keys.KeyRefs() {
		if trust.MayUseKey(record, ref.GetFingerprint()) {
			out = append(out, ref)
		}
	}

	return out
}

// RemoteSign performs a signature here for a peer that has no key of its own.
func (s *peerService) RemoteSign(
	ctx context.Context,
	req *connect.Request[ladulasv1.RemoteSignRequest],
) (*connect.Response[ladulasv1.RemoteSignResponse], error) {
	peer, record, err := s.node.authorize(ctx)
	if err != nil {
		return nil, err
	}

	// The same cap RequestApproval keeps: a borrowed signature can raise a
	// prompt too, so a peer cannot pour these in past what it is already holding
	// on an approver's screen (M3).
	if !s.node.load.acquire(peer.Fingerprint) {
		return nil, connect.NewError(connect.CodeResourceExhausted,
			errors.New("too many requests are already pending from this peer"))
	}

	defer s.node.load.release(peer.Fingerprint)

	body := req.Msg.GetRequest()

	msg, err := parseSignRequest(body)
	if err != nil {
		return nil, err
	}

	requester := &ladulasv1.RequesterInfo{
		InstanceId:    peer.Fingerprint,
		Name:          record.GetName(),
		Local:         false,
		Headless:      msg.GetRequester().GetHeadless(),
		RemoteAddress: peer.RemoteAddr,
		// The process behind the request is the asking machine's word for it,
		// and it is the asking machine that is distrusted here (§5, §16).
		Process: msg.GetRequester().GetProcess(),
	}

	signed, signature, err := s.node.signForPeer(ctx, record, requester, msg,
		body, req.Msg.GetPayload(), req.Msg.GetWrapSshsig())
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&ladulasv1.RemoteSignResponse{
		Approval:  signed,
		Signature: signature,
	}), nil
}

// parseSignRequest reads the request bytes a borrowed signature travels as.
func parseSignRequest(body []byte) (*ladulasv1.ApprovalRequest, error) {
	if len(body) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request is empty"))
	}

	var msg ladulasv1.ApprovalRequest

	if err := proto.Unmarshal(body, &msg); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the request does not parse: %w", err))
	}

	return &msg, nil
}

// signForPeer is the key holder's half of a borrowed signature, and is reached
// by both roads a request can take to a holder: dialled over RemoteSign, or
// collected out of a requester's inbox by a holder that cannot be dialled
// (decision T).
//
// Everything the security argument rests on is here rather than in either
// caller, which is the reason it is one function. The key is resolved against
// what this instance holds and what the trust record permits; the bytes that
// will be signed are rebuilt from the payload rather than taken on trust; the
// request's account of what it is is replaced by this instance's own parse of
// those bytes; and only then is anybody asked.
//
// A denial comes back as an answer with no signature rather than as an error.
// The requester needs the reason to print and the artifact to log, and neither
// is something to have to infer from a status code.
func (n *Node) signForPeer(
	ctx context.Context,
	record *storepb.TrustRecord,
	requester *ladulasv1.RequesterInfo,
	msg *ladulasv1.ApprovalRequest,
	body, payload []byte,
	wrapSSHSIG bool,
) (*ladulasv1.SignedApproval, []byte, error) {
	if n.keys == nil {
		return nil, nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("this instance holds no keys to sign with"))
	}

	ref, err := n.borrowableKey(record, msg.GetKey())
	if err != nil {
		return nil, nil, err
	}

	blob, err := signingBlob(payload, wrapSSHSIG, msg)
	if err != nil {
		return nil, nil, err
	}

	if err := rebuildOperation(msg, payload, wrapSSHSIG); err != nil {
		return nil, nil, err
	}

	msg.Key = ref
	msg.Requester = requester

	// The signature is made here, so the engine is told so: a promise agreed to
	// on the way past cannot be handed to a requester that will be back for the
	// next signature anyway (decision P).
	resp, signed, err := n.engine.SubmitPeerSigning(ctx, msg, body)
	if err != nil {
		return nil, nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("decide the request: %w", err))
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		return signed, nil, nil
	}

	signer, _, err := n.keys.Signer(ref.GetFingerprint())
	if err != nil {
		return nil, nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("load key: %w", err))
	}

	signature, err := signBlob(signer, blob, msg.GetSignatureAlgorithm())
	if err != nil {
		return nil, nil, connect.NewError(connect.CodeInternal, err)
	}

	n.engine.Signed(msg, ref)

	n.log.Info("signed for a peer",
		"request_id", msg.GetRequestId(),
		"peer", record.GetName(),
		"key", ref.GetLabel())

	return signed, ssh.Marshal(signature), nil
}

// signBlob signs the bytes with the algorithm the request resolved to.
//
// The algorithm only ever means anything for RSA, where the agent protocol's
// SSH_AGENT_RSA_SHA2_* flags decide between rsa-sha2-256 and rsa-sha2-512 and
// getting it wrong produces a signature the far server rejects. Everything else
// signs with the key's own algorithm, which is what sshsig.SignBlob does.
func signBlob(
	signer ssh.Signer, blob []byte, algorithm string,
) (*ssh.Signature, error) {
	if algorithm == "" {
		return sshsig.SignBlob(signer, blob)
	}

	as, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf(
			"peer: the key cannot sign with %s", algorithm)
	}

	sig, err := as.SignWithAlgorithm(rand.Reader, blob, algorithm)
	if err != nil {
		return nil, fmt.Errorf("sign with %s: %w", algorithm, err)
	}

	return sig, nil
}

// borrowableKey resolves the key a request names against what this instance
// holds and what the record permits.
//
// The key is taken from the message because it is the one thing the channel
// cannot say — but it is only ever used to look one up here, and the permission
// is checked against the record. A peer naming a key it was never granted is
// refused before anything is decided, so no prompt appears for a signature that
// could not have been produced anyway.
func (n *Node) borrowableKey(
	record *storepb.TrustRecord, named *ladulasv1.KeyRef,
) (*ladulasv1.KeyRef, error) {
	blob := named.GetPublicKey()
	fingerprint := named.GetFingerprint()

	for _, ref := range n.keys.KeyRefs() {
		matched := (len(blob) > 0 && bytes.Equal(ref.GetPublicKey(), blob)) ||
			(len(blob) == 0 && fingerprint != "" &&
				ref.GetFingerprint() == fingerprint)
		if !matched {
			continue
		}

		if !trust.MayUseKey(record, ref.GetFingerprint()) {
			return nil, connect.NewError(connect.CodePermissionDenied,
				fmt.Errorf("%q may not sign with %s",
					record.GetName(), ref.GetLabel()))
		}

		return ref, nil
	}

	return nil, connect.NewError(connect.CodeNotFound,
		fmt.Errorf("no key %s in the store", fingerprint))
}

// signingBlob builds the bytes that will actually be signed.
//
// This is §5's design detail in its remote form: when the requester sends a raw
// message the wrapper is computed here, from the namespace and the message, so
// the digest inside it cannot disagree with the object the approver is shown. A
// request claiming a payload digest other than the one the blob produces is
// refused rather than corrected — the answer's signature covers the bytes that
// arrived, and those bytes ought to say something true.
func signingBlob(
	payload []byte, wrapSSHSIG bool, msg *ladulasv1.ApprovalRequest,
) ([]byte, error) {
	blob, err := blobFor(payload, wrapSSHSIG, msg.GetSshsig())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	digest := sha256.Sum256(blob)

	if claimed := msg.GetPayloadSha256(); len(claimed) > 0 &&
		!bytes.Equal(claimed, digest[:]) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request describes a different payload from the one sent"))
	}

	msg.PayloadSha256 = digest[:]

	return blob, nil
}

// blobFor is the one place either end works out what bytes a remote signature
// covers, so that the requester checks the answer against the same thing the
// holder signed.
func blobFor(
	payload []byte, wrapSSHSIG bool, sig *ladulasv1.SshsigRequest,
) ([]byte, error) {
	if len(payload) == 0 {
		return nil, errors.New("nothing to sign")
	}

	if !wrapSSHSIG {
		return payload, nil
	}

	namespace := sig.GetNamespace()
	if namespace == "" {
		return nil, errors.New("no SSHSIG namespace to wrap the payload in")
	}

	return sshsig.SigningBlobFor(namespace, sig.GetHashAlgorithm(), payload)
}

// rebuildOperation replaces the request's account of what is being signed with
// this instance's own parse of the bytes.
//
// Everything provable comes from the blob: what kind of request this is, the
// namespace and digest of a signature, the user name and session identifier of
// a login. Everything that cannot be derived from the bytes — the repository,
// the branch, the diff, the host a login is going to — is kept as the requester
// sent it, because it is the only source there is and the prompt already labels
// it as the requester's word (§5).
//
// The consequence that matters most: a payload parsing as neither an SSHSIG
// blob nor an authentication blob classifies as opaque here whatever the
// request called it, and the engine's hard rule denies it.
func rebuildOperation(
	msg *ladulasv1.ApprovalRequest, payload []byte, wrapSSHSIG bool,
) error {
	blob, err := blobFor(payload, wrapSSHSIG, msg.GetSshsig())
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}

	class := agent.Classify(blob)

	msg.Kind = class.Kind

	switch {
	case class.Sshsig != nil:
		rebuildSshsig(msg, class.Sshsig, payload, wrapSSHSIG)
	case class.SSHAuth != nil:
		if err := rebuildSSHAuth(msg, class.SSHAuth); err != nil {
			return err
		}
	default:
		msg.Operation = &ladulasv1.ApprovalRequest_OpaqueSign{OpaqueSign: class.Opaque}
	}

	return nil
}

// rebuildSshsig keeps the requester's git context but takes the object from the
// payload, so that the engine's check compares the bytes being signed against
// themselves rather than against a claim.
//
// When the requester wrapped nothing there is no object in the payload — the
// blob is a digest — and whatever object the requester sent is checked against
// that digest by the engine, and refused on a mismatch.
func rebuildSshsig(
	msg *ladulasv1.ApprovalRequest,
	sig *ladulasv1.SshsigRequest,
	payload []byte,
	wrapSSHSIG bool,
) {
	git := msg.GetSshsig().GetGitContext()

	if sig.GetNamespace() != sshsig.GitNamespace {
		// A signature in some other namespace has no git object behind it and
		// must not be dressed up as one.
		git = nil
	} else if wrapSSHSIG {
		if git == nil {
			git = &ladulasv1.GitContext{}
		}

		git.Object = payload
	}

	sig.GitContext = git
	msg.Operation = &ladulasv1.ApprovalRequest_Sshsig{Sshsig: sig}
}

// rebuildSSHAuth keeps the session-bind context, which cannot be derived from
// the blob, and takes everything that can from the blob itself.
//
// The host key of a hostbound login is one of the things that can, and it is the
// most valuable one here: it means an approver holding the key knows which
// server the login it is about to sign for is going to, from the bytes rather
// than from what the asking machine says about them. So a requester whose
// claimed destination is not the one in the payload is refused — the §15 attack
// in its authentication form, caught here rather than left for somebody to spot
// in a prompt that is lying to them.
//
// The label is kept as the requester sent it, and stays display metadata: it
// comes from a known_hosts file that only the requesting machine has, and it is
// only ever shown beside the fingerprint that has just been checked.
func rebuildSSHAuth(
	msg *ladulasv1.ApprovalRequest, auth *ladulasv1.SshAuthRequest,
) error {
	claimed := msg.GetSshAuth()

	if claimed != nil && len(claimed.GetSessionId()) > 0 &&
		!bytes.Equal(claimed.GetSessionId(), auth.GetSessionId()) {
		return connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request describes a different login from the one signed"))
	}

	auth.Bound = claimed.GetBound()
	auth.Forwarded = claimed.GetForwarded()
	auth.BindingChain = claimed.GetBindingChain()
	auth.ForwardedHops = claimed.GetForwardedHops()
	auth.Destination = claimed.GetDestination()
	auth.DestinationLabel = claimed.GetDestinationLabel()

	payload := auth.GetPayloadDestination()
	if payload == nil {
		msg.Operation = &ladulasv1.ApprovalRequest_SshAuth{SshAuth: auth}

		return nil
	}

	if named := claimed.GetDestination(); named != nil &&
		named.GetFingerprint() != payload.GetFingerprint() {
		return connect.NewError(connect.CodeInvalidArgument,
			errors.New(
				"the request describes a different destination from the one signed"))
	}

	// The claimed host key survives only because it is the same key: what it adds
	// is the known_hosts annotation, and what it cannot change is the
	// fingerprint.
	if auth.GetDestination() == nil {
		auth.Destination = payload
		auth.DestinationLabel = payload.GetFingerprint()
	}

	msg.Operation = &ladulasv1.ApprovalRequest_SshAuth{SshAuth: auth}

	return nil
}

// RemoteKeyRefs returns the keys paired holders offer this instance and can be
// asked to use right now.
//
// It answers from what is already known rather than asking anybody, because the
// caller is an SSH agent answering SSH_AGENTC_REQUEST_IDENTITIES and ssh will
// not wait while three sleeping desktops are dialled.
//
// A holder that cannot be reached contributes nothing here, and that is decision
// N's one deliberate exclusion: the agent socket advertises what can sign, not
// what exists. Everything that exists is in BorrowedKeys, and every surface a
// person reads shows that instead. What decision T changed is what reaching
// consists of — a phone that is polling or can be woken is reachable, since the
// signature is parked and pushed to it like an approval — so this is now
// BorrowedKeys' availability column read back rather than a second, narrower
// idea of the same thing.
// A key this instance holds itself is left out as well, and that exclusion is
// not about reachability at all: the copy here signs, so there is nothing to
// borrow (§10).
func (n *Node) RemoteKeyRefs() []*ladulasv1.KeyRef {
	var out []*ladulasv1.KeyRef

	for _, borrowed := range n.BorrowedKeys() {
		if borrowed.GetAvailable() && !borrowed.GetHeldHere() {
			out = append(out, borrowed.GetKey())
		}
	}

	return out
}

// heldHere is the fingerprints of the keys this instance can sign with itself.
//
// The same key living in two stores is something decision S does on purpose —
// a portable key handed to a phone, or accepted from one — and once a copy is
// here, the copy is what everything uses. The reason is stronger than "local is
// faster": a signature made on the holder is the holder's decision every single
// time, while one made here can be covered by a standing delegation (decision
// P), so reaching for the holder's copy would throw away the one mechanism that
// lets a phone stay in a pocket.
//
// It is the keys that can sign, which settles the two edges the same way.
// `KeyRefs` leaves out a disabled key, so a copy switched off here stops being
// the answer and the holder's is borrowed again — the useful reading of a key
// that is off on one of the two machines that have it. A sealed store holds
// nothing anybody can sign with, and answers with nothing.
func (n *Node) heldHere() map[string]bool {
	if n.keys == nil {
		return nil
	}

	refs := n.keys.KeyRefs()

	out := make(map[string]bool, len(refs))

	for _, ref := range refs {
		out[ref.GetFingerprint()] = true
	}

	return out
}

// RefreshKeys asks every linked holder what it offers, now.
//
// The cache is refreshed on its own on every heartbeat, which is fine for
// answering ssh's request for identities. It is not fine for the moment
// somebody grants a key on the holder and immediately commits on the box: the
// grant is the holder's to make and there is no way for it to say so, so the
// requester asks again the first time it is looking for a key it does not have.
func (n *Node) RefreshKeys(ctx context.Context) {
	for _, l := range n.sortedLinks() {
		addresses := l.addresses()
		if len(addresses) == 0 {
			continue
		}

		l.learnKeys(ctx, addresses[0])
	}
}

// rememberKeys writes down what a holder has just said it offers, so that the
// answer outlives the connection it arrived on (decision N).
//
// It is called only with an answer a holder actually gave. A holder that could
// not be asked leaves what is remembered alone, and a holder that answered with
// nothing empties it — which is how a key somebody stopped lending disappears
// on the next successful refresh rather than lingering for ever.
func (n *Node) rememberKeys(fingerprint string, keys []*ladulasv1.KeyRef) {
	if err := n.trust.SetBorrowedKeys(fingerprint, keys, time.Now()); err != nil {
		n.log.Error("could not remember the keys a peer offers",
			"peer", fingerprint, "error", err.Error())
	}
}

// dropPeerKeys is the other half of revoking a pairing, beside dropping its
// documentation (§7): a peer that is no longer trusted should not still be
// occupying the key list.
func (n *Node) dropPeerKeys(record *storepb.TrustRecord) {
	dropped, err := n.trust.DropBorrowedKeys(record.GetFingerprint())
	if err != nil {
		n.log.Error("could not drop a revoked peer's keys",
			"peer", record.GetFingerprint(), "error", err.Error())

		return
	}

	if dropped > 0 {
		n.log.Info("dropped a revoked peer's keys",
			"peer", record.GetFingerprint(), "keys", dropped)
	}

	n.dropPeerDelegations(record)
	n.dropPeerWakeup(record)
}

// dropPeerWakeup is the fourth: the route that peer announced for itself (§11).
//
// Nothing would go wrong if it stayed — a route is only ever used to say
// "something is waiting for you", and nothing is parked for a peer that is no
// longer an approver — but it is a capability that wakes somebody's phone, and
// keeping one for a machine that has been forgotten is keeping it for no reason.
func (n *Node) dropPeerWakeup(record *storepb.TrustRecord) {
	if n.wakeups == nil {
		return
	}

	dropped, err := n.wakeups.DropPeerWakeup(record.GetFingerprint())
	if err != nil {
		n.log.Error("could not drop a revoked peer's wake-up route",
			"peer", record.GetFingerprint(), "error", err.Error())

		return
	}

	if dropped {
		n.log.Info("dropped a revoked peer's wake-up route",
			"peer", record.GetFingerprint())
	}
}

// dropPeerDelegations is the third thing revoking a pairing has to take with
// it: the standing permissions that peer granted (decision P).
//
// Without it a peer that is no longer trusted would go on answering for this
// instance until its last delegation ran out — which is exactly the state
// somebody revoking a pairing is trying to end. UsableDelegations filters on
// trust as well, so this is belt and braces; it is here so that the store stops
// holding a promise from somebody who is no longer anybody.
func (n *Node) dropPeerDelegations(record *storepb.TrustRecord) {
	if n.delegations == nil {
		return
	}

	dropped, err := n.delegations.DropDelegationsFrom(record.GetFingerprint())
	if err != nil {
		n.log.Error("could not drop a revoked peer's delegations",
			"peer", record.GetFingerprint(), "error", err.Error())

		return
	}

	if dropped > 0 {
		n.log.Info("dropped a revoked peer's delegations",
			"peer", record.GetFingerprint(), "delegations", dropped)
	}
}

// BorrowedKeys is every key a paired peer has offered this instance, whether or
// not that peer can be reached (decision N).
//
// This is what the key listings and the viewer show, and the difference from
// RemoteKeyRefs is the whole point: a phone is unreachable most of the time by
// construction, and a listing that showed only what could be signed with this
// second would say a phone holds nothing almost always. Availability is a
// field here rather than a reason to leave a row out.
//
// Entries whose peer is no longer paired are left out even if revocation
// somehow failed to drop them, because a trust record is what makes a key
// borrowable at all.
func (n *Node) BorrowedKeys() []*ladulasv1.BorrowedKeyStatus {
	records := map[string]*storepb.TrustRecord{}

	for _, record := range n.trust.Peers() {
		records[record.GetFingerprint()] = record
	}

	live := map[string]map[string]bool{}
	seen := map[string]time.Time{}

	for _, l := range n.sortedLinks() {
		fingerprint := l.Fingerprint()
		offered := map[string]bool{}

		for _, ref := range l.offeredKeys() {
			offered[ref.GetFingerprint()] = true
		}

		live[fingerprint] = offered

		if _, _, lastSeen := l.State(); !lastSeen.IsZero() {
			seen[fingerprint] = lastSeen
		}
	}

	var out []*ladulasv1.BorrowedKeyStatus

	held := n.heldHere()

	for _, borrowed := range n.trust.BorrowedKeys() {
		record, paired := records[borrowed.GetPeerFingerprint()]
		if !paired {
			continue
		}

		holder := borrowed.GetPeerFingerprint()

		offered, dialled := live[holder]

		available := offered[borrowed.GetKey().GetFingerprint()]

		// A holder with no link is one that cannot be dialled, and for one of
		// those what "available" means is that something can tell it there is
		// something to do (decision T). It announced these keys itself, so the
		// list is as fresh as the last time it was awake; what decides is
		// whether it can be reached now.
		if !dialled {
			available = n.canCollectFor(record)
		}

		status := &ladulasv1.BorrowedKeyStatus{
			Key:             borrowed.GetKey(),
			Peer:            record.GetName(),
			PeerFingerprint: holder,
			Available:       available,
			LastSeenAt:      borrowed.GetLastSeenAt(),
			// The row stays either way. "Which machines have this key" is what a
			// listing is for, and a copy on the holder is exactly the thing
			// somebody has to know about after losing a device — it is simply not
			// a key this instance reaches for any more.
			HeldHere: held[borrowed.GetKey().GetFingerprint()],
		}

		// While the link is up, what it knows about the peer is fresher than
		// what the store was last rewritten with.
		if lastSeen, ok := seen[holder]; ok && status.GetAvailable() {
			status.LastSeenAt = timestamppb.New(lastSeen)
		}

		out = append(out, status)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].GetPeer() != out[j].GetPeer() {
			return out[i].GetPeer() < out[j].GetPeer()
		}

		return out[i].GetKey().GetLabel() < out[j].GetKey().GetLabel()
	})

	return out
}

// canCollectFor reports whether a request parked for a peer that cannot be
// dialled would actually get to it (decision T).
//
// Two questions, and the first is a permission rather than a fact about the
// network: collecting is the approver's half of a pairing, so a peer that does
// not approve for this instance has no inbox here to come and look in, whatever
// keys it lends. The second is whether anything can tell it, and there the inbox
// already had both answers — a poll this instance is holding open, which is an
// app somebody is looking at, and a wake-up route the peer announced, which is a
// push.
//
// Neither is a promise that anybody will answer; nothing here is. But the
// difference between them and nothing at all is the difference between a key an
// agent may offer and one it may not, because an ssh login has about two minutes
// before the far server hangs up.
func (n *Node) canCollectFor(record *storepb.TrustRecord) bool {
	if !record.GetMayApprove() {
		return false
	}

	fingerprint := record.GetFingerprint()

	n.mu.Lock()
	polling := len(n.waiters[fingerprint]) > 0
	n.mu.Unlock()

	if polling {
		return true
	}

	if n.wakeups == nil {
		return false
	}

	wakeup, ok := n.wakeups.PeerWakeup(fingerprint)

	return ok && wakeup.GetRoute() != nil
}

// collectingHolderOf finds the peer that holds a key, cannot be dialled, and can
// be reached — the phone in somebody's pocket that a signature has to be parked
// for.
func (n *Node) collectingHolderOf(fingerprint string) *storepb.TrustRecord {
	for _, borrowed := range n.BorrowedKeys() {
		if borrowed.GetKey().GetFingerprint() != fingerprint ||
			!borrowed.GetAvailable() {
			continue
		}

		record, ok := n.trust.Peer(borrowed.GetPeerFingerprint())
		if !ok || len(record.GetAddresses()) > 0 {
			continue
		}

		return record
	}

	return nil
}

// BorrowedKey finds what this instance remembers about a public key a peer
// offers, reachable or not.
//
// It is what turns "no key here or on a paired instance" — an answer that is
// simply wrong when the key is on a phone in somebody's pocket — into a
// signing attempt that fails naming the machine that has it.
func (n *Node) BorrowedKey(blob []byte) (*ladulasv1.KeyRef, bool) {
	for _, borrowed := range n.BorrowedKeys() {
		if bytes.Equal(borrowed.GetKey().GetPublicKey(), blob) {
			return borrowed.GetKey(), true
		}
	}

	return nil, false
}

// sortedLinks is the links in a stable order, so that two holders offering the
// same fingerprint always resolve to the same one rather than to whichever the
// map happened to yield first.
func (n *Node) sortedLinks() []*link {
	n.mu.Lock()
	links := make([]*link, 0, len(n.links))

	for _, l := range n.links {
		links = append(links, l)
	}

	n.mu.Unlock()

	sort.Slice(links, func(i, j int) bool {
		return links[i].Fingerprint() < links[j].Fingerprint()
	})

	return links
}

// holderOf finds the link to the peer that offers a key.
func (n *Node) holderOf(fingerprint string) *link {
	for _, l := range n.sortedLinks() {
		for _, ref := range l.offeredKeys() {
			if ref.GetFingerprint() == fingerprint {
				return l
			}
		}
	}

	return nil
}

// RemoteSign asks the paired holder of a key to produce a signature (§8).
//
// Which road it takes is decided the same way the approval fan-out decides
// (§3): a holder that advertised an address is dialled, and one that did not is
// a phone, which has to be knocked at and come and collect (decision T). The
// holder's half of the work is the same code either way, and so is everything
// this side checks about the answer.
func (n *Node) RemoteSign(
	ctx context.Context,
	msg *ladulasv1.ApprovalRequest,
	payload []byte,
	wrapSSHSIG bool,
) (*ladulasv1.RemoteSignResponse, error) {
	if holder := n.holderOf(msg.GetKey().GetFingerprint()); holder != nil {
		return n.signOverLink(ctx, holder, msg, payload, wrapSSHSIG)
	}

	if record := n.collectingHolderOf(msg.GetKey().GetFingerprint()); record != nil {
		return n.signThroughInbox(ctx, record, msg, payload, wrapSSHSIG)
	}

	return nil, n.noHolder(msg.GetKey())
}

// signOverLink asks a holder this instance can dial.
//
// The request travels as the bytes serialized here, so the digest in the answer
// is over material both ends had — exactly as it is for an approval, and for
// the same reason: protobuf serialization is not promised to be reproducible.
func (n *Node) signOverLink(
	ctx context.Context,
	holder *link,
	msg *ladulasv1.ApprovalRequest,
	payload []byte,
	wrapSSHSIG bool,
) (*ladulasv1.RemoteSignResponse, error) {
	// A borrowed signature is decided by the holder's engine, under the holder's
	// timeout, so this side only needs a bound on a holder that has stopped
	// answering altogether. Without one an ssh that reached a black hole would
	// wait for the kernel rather than for a person.
	ctx, cancel := context.WithTimeout(ctx, waitFor(msg))
	defer cancel()

	outgoing, body, err := n.outgoingSign(ctx, msg)
	if err != nil {
		return nil, err
	}

	addresses := holder.addresses()
	if len(addresses) == 0 {
		return nil, errors.New("peer: the key holder has no address to dial")
	}

	request := &ladulasv1.RemoteSignRequest{
		Request:    body,
		Payload:    payload,
		WrapSshsig: wrapSSHSIG,
	}

	// The holder is deciding this, so it may ask for the rest of the diff for
	// as long as it is (§5).
	defer n.track(outgoing.GetRequestId(), holder.Fingerprint(),
		outgoing.GetSshsig().GetGitContext())()

	var lastErr error

	for _, address := range addresses {
		client := ladulasv1connect.NewKeyServiceClient(
			holder.client.HTTP(), holder.client.URL(address),
			connect.WithSendMaxBytes(maxRequestBytes))

		resp, err := client.RemoteSign(ctx, connect.NewRequest(request))
		if err != nil {
			lastErr = fmt.Errorf("peer: ask %s to sign: %w", holder.Name(), err)

			if ctx.Err() != nil {
				return nil, lastErr
			}

			continue
		}

		holder.succeeded(address)

		return n.checkSignature(
			holder, outgoing, body, payload, wrapSSHSIG, resp.Msg)
	}

	holder.failed(lastErr)

	return nil, lastErr
}

// signThroughInbox asks a holder that cannot be dialled, by parking the request
// where it will come and find it (decision T).
//
// It is the inbox of §3 with the payload riding along: the entry is parked, the
// wake-up goes out because park() sends one when nobody is polling, and the
// holder posts back the decision and the signature together. What this side
// checks about the answer is not weakened by the road it came down — the
// artifact is verified against the trust record, the request identifier and the
// digest by the time it reaches here, and the signature is verified against the
// key and the bytes below.
//
// The timeout is the requester's own, and for an ssh login it is the one clock
// that matters: sshd will hang up long before a generous budget expires, so
// there is nothing to be gained by waiting longer than the login can.
func (n *Node) signThroughInbox(
	ctx context.Context,
	record *storepb.TrustRecord,
	msg *ladulasv1.ApprovalRequest,
	payload []byte,
	wrapSSHSIG bool,
) (*ladulasv1.RemoteSignResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, waitFor(msg))
	defer cancel()

	outgoing, body, err := n.outgoingSign(ctx, msg)
	if err != nil {
		return nil, err
	}

	fingerprint := record.GetFingerprint()

	entry := &parked{
		peer:       fingerprint,
		id:         outgoing.GetRequestId(),
		body:       body,
		digest:     identity.Digest(body),
		since:      time.Now(),
		deadline:   deadlineOf(ctx),
		payload:    payload,
		wrapSSHSIG: wrapSSHSIG,
		answer:     make(chan *collectedAnswer, 1),
	}

	// The holder is deciding this, so it may ask for the rest of the diff for as
	// long as it is (§5) — the same permission a dialled holder gets.
	defer n.track(entry.id, fingerprint, outgoing.GetSshsig().GetGitContext())()

	defer n.unpark(fingerprint, entry.id)

	n.park(entry)

	select {
	case answer := <-entry.answer:
		return n.acceptBorrowedSignature(record.GetName(), outgoing, payload,
			wrapSSHSIG, answer.answer, answer.decision, answer.signature)
	case <-ctx.Done():
		return nil, fmt.Errorf("peer: %s did not answer: %w",
			record.GetName(), ctx.Err())
	}
}

// noHolder says why a key cannot be used, from what this instance remembers
// rather than only from what it can reach (decision N).
//
// It is deliberately immediate. The link's state is already known here, so
// there is nothing to dial and nothing to wait for: the answer arrives before
// anything has been asked of anybody, which is what "never hang" means in
// practice. There is no new budget and no retry — the link reconnects on its
// own backoff (§8), and the next attempt finds a holder that is there.
//
// It is also not a denial and does not read like one. Nobody was asked, nothing
// was refused, and the sentence names the machine to go and wake up.
func (n *Node) noHolder(key *ladulasv1.KeyRef) error {
	for _, borrowed := range n.BorrowedKeys() {
		if borrowed.GetKey().GetFingerprint() != key.GetFingerprint() {
			continue
		}

		return fmt.Errorf("%w: %s holds %s, %s",
			ErrHolderUnreachable, borrowed.GetPeer(),
			describeKey(borrowed.GetKey()), lastSeenPhrase(borrowed))
	}

	return fmt.Errorf("%w: %s", ErrNoRemoteKey, key.GetFingerprint())
}

// describeKey names a key the way somebody reading an error would: by the label
// their own instance gave it, falling back to the fingerprint.
func describeKey(key *ladulasv1.KeyRef) string {
	if label := key.GetLabel(); label != "" {
		return label
	}

	return key.GetFingerprint()
}

// lastSeenPhrase says how long ago the holder was there, because "not reachable
// for four minutes" and "not reachable since March" want different things done
// about them.
func lastSeenPhrase(borrowed *ladulasv1.BorrowedKeyStatus) string {
	at := borrowed.GetLastSeenAt()
	if at == nil {
		return "and has not been reachable since it was paired"
	}

	return fmt.Sprintf("and was last reachable %s",
		at.AsTime().Local().Format(time.RFC1123))
}

// waitFor is how long to give a holder: what the requester asked for, or the
// same defaults the approval engine would have applied here (§9).
func waitFor(msg *ladulasv1.ApprovalRequest) time.Duration {
	if requested := msg.GetTimeout(); requested != nil &&
		requested.AsDuration() > 0 {
		return requested.AsDuration()
	}

	if msg.GetKind() == ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH {
		return approval.DefaultSSHAuthTimeout
	}

	return approval.DefaultSignTimeout
}

// outgoingSign builds the request as the holder should see it, and the bytes
// the answer will commit to.
func (n *Node) outgoingSign(
	ctx context.Context, msg *ladulasv1.ApprovalRequest,
) (*ladulasv1.ApprovalRequest, []byte, error) {
	out := proto.CloneOf(msg)

	out.Requester = &ladulasv1.RequesterInfo{
		InstanceId: n.identity.Fingerprint(),
		Name:       n.identity.Name(),
		Local:      false,
		Headless:   n.headless,
		Process:    msg.GetRequester().GetProcess(),
	}

	// The holder should stop waiting when we do; a prompt left on a screen after
	// the requester has given up is how somebody approves a commit that is no
	// longer being made.
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, nil, context.DeadlineExceeded
		}

		out.Timeout = durationpb.New(remaining)
	}

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(out)
	if err != nil {
		return nil, nil, fmt.Errorf("peer: serialize the request: %w", err)
	}

	return out, body, nil
}

// checkSignature is the requester's whole defence against a holder answering
// with something other than what it was asked for, and the point at which the
// decision reaches this instance's audit log.
func (n *Node) checkSignature(
	holder *link,
	msg *ladulasv1.ApprovalRequest,
	body, payload []byte,
	wrapSSHSIG bool,
	resp *ladulasv1.RemoteSignResponse,
) (*ladulasv1.RemoteSignResponse, error) {
	answer, decision, err := holder.answerFrom(
		resp.GetApproval(), msg.GetRequestId(), identity.Digest(body))
	if err != nil {
		return nil, err
	}

	return n.acceptBorrowedSignature(holder.Name(), msg, payload, wrapSSHSIG,
		answer, decision, resp.GetSignature())
}

// acceptBorrowedSignature is what the requester does with an answer whose
// artifact has already been checked against the trust record, the request
// identifier and the digest: it records the decision, and refuses a signature
// that is not one.
//
// Both roads to a holder end here, which is the point — a signature that arrived
// out of an inbox is trusted no further than one that came back down a link.
func (n *Node) acceptBorrowedSignature(
	holder string,
	msg *ladulasv1.ApprovalRequest,
	payload []byte,
	wrapSSHSIG bool,
	answer *approval.Answer,
	decision *ladulasv1.ApprovalResponse,
	signature []byte,
) (*ladulasv1.RemoteSignResponse, error) {
	// The peer's own account of who it is is not what gets recorded; the trust
	// record is, with the name this instance's user gave it.
	decision.Approver = answer.Approver
	decision.Reason = answer.Reason

	n.engine.Delegated(msg, decision, answer.Signed)

	out := &ladulasv1.RemoteSignResponse{
		Approval:  answer.Signed,
		Signature: signature,
	}

	if answer.Decision != ladulasv1.Decision_DECISION_APPROVE {
		return out, nil
	}

	if len(signature) == 0 {
		return nil, fmt.Errorf("peer: %s approved without signing", holder)
	}

	err := verifySignature(
		msg.GetKey(), payload, wrapSSHSIG, msg.GetSshsig(), signature)
	if err != nil {
		return nil, fmt.Errorf("peer: the signature from %s is not usable: %w",
			holder, err)
	}

	return out, nil
}

// verifySignature checks a borrowed signature against the key it claims to come
// from and the bytes this side asked to have signed.
//
// A holder that signed something else — a different commit, a login to a
// different host — would otherwise hand back bytes that git or an SSH server
// would happily accept for an operation nobody here asked for.
func verifySignature(
	key *ladulasv1.KeyRef,
	payload []byte,
	wrapSSHSIG bool,
	sig *ladulasv1.SshsigRequest,
	signature []byte,
) error {
	pub, err := ssh.ParsePublicKey(key.GetPublicKey())
	if err != nil {
		return fmt.Errorf("parse the key: %w", err)
	}

	blob, err := blobFor(payload, wrapSSHSIG, sig)
	if err != nil {
		return err
	}

	var parsed ssh.Signature

	if err := ssh.Unmarshal(signature, &parsed); err != nil {
		return fmt.Errorf("parse the signature: %w", err)
	}

	if err := pub.Verify(blob, &parsed); err != nil {
		return fmt.Errorf("the signature does not verify: %w", err)
	}

	return nil
}
