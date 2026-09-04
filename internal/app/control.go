package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	"github.com/hugowetterberg/ladulas/pkg/peer"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// controlService is the instance's complete management surface (§14), and the
// only way anything outside this process touches the store.
//
// It sits here rather than on the peer node because most of it is the peer
// node's, but the calls that matter when nothing else works are not: Status,
// Unlock and Initialize have to be answerable by an instance whose store is
// sealed or has never been created, and in neither case is there a node to
// answer them. So the service is the instance's, it answers those itself, and
// everything else it hands to the node when there is one — which is also,
// exactly, the surface shrinking to what needs no store.
type controlService struct {
	ladulasv1connect.UnimplementedControlServiceHandler

	app *App
}

var _ ladulasv1connect.ControlServiceHandler = (*controlService)(nil)

// peerControl is the node, or the reason there is not one. Every call below
// that needs the store goes through it or through vault, which is what keeps
// the reduced surfaces exactly as wide as they are documented to be.
func (s *controlService) peerControl() (*peer.Node, error) {
	node := s.app.Peer()
	if node != nil {
		return node, nil
	}

	if !s.app.Unsealed() {
		return nil, connect.NewError(
			connect.CodeFailedPrecondition, s.app.noStoreError())
	}

	return nil, connect.NewError(connect.CodeFailedPrecondition, ErrPeeringOff)
}

// vault is the open store, or the reason there is not one: sealed, or never
// created. The two want different things done about them, so they are different
// answers rather than one.
func (s *controlService) vault() (*keystore.Vault, error) {
	vault := s.app.Vault()
	if vault == nil {
		return nil, connect.NewError(
			connect.CodeFailedPrecondition, s.app.noStoreError())
	}

	return vault, nil
}

// Status is answerable in every state, because being told what state an
// instance is in is what a person reaching it over SSH needs first.
func (s *controlService) Status(
	ctx context.Context, req *connect.Request[ladulasv1.StatusRequest],
) (*connect.Response[ladulasv1.StatusResponse], error) {
	state, since, reason := s.app.StateDetail()

	resp := &ladulasv1.StatusResponse{
		LockState:    state,
		StateSince:   timestamppb.New(since),
		StateReason:  reason,
		UnlockPrompt: s.app.UnsealPrompt(),
		// Answerable in every state, sealed included: where the files are is
		// the first thing somebody asks of an instance that is not working.
		Locations: &ladulasv1.InstanceLocations{
			Store:         s.app.Config.StorePath(),
			Policy:        s.app.Config.PolicyPath(),
			AuditLog:      s.app.Config.AuditPath(),
			ProjectsDir:   s.app.Config.ProjectsDir(),
			AgentSocket:   s.app.Config.SocketPath,
			ControlSocket: s.app.Config.ControlSocket,
		},
	}

	vault := s.app.Vault()
	if vault == nil {
		// A sealed instance knows its own name from the directory it was
		// started with and nothing else: the instance name and the identity key
		// are both inside the store.
		resp.PassphraseWrapping = keystore.Exists(s.app.Config.DataDir)

		return connect.NewResponse(resp), nil
	}

	resp.InstanceName = vault.InstanceName()
	resp.Fingerprint = vault.Identity().Fingerprint()
	resp.PassphraseWrapping = vault.HasPassphraseWrapping()
	resp.KeyringEnrolled = vault.KeyringEnrolled()
	resp.Keys = int32(len(vault.Keys())) //nolint:gosec // a key set that overflows an int32 is not a key set

	grants, err := vault.Grants()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp.Grants = int32(len(grants)) //nolint:gosec // likewise

	// A key a peer handed over is waiting for a person, and on a headless box
	// reached over SSH this line is the only thing that will ever mention it
	// (decision S).
	resp.KeyOffers = int32(len(vault.PendingKeyOffers())) //nolint:gosec // the list is capped at eight

	node := s.app.Peer()
	if node == nil {
		return connect.NewResponse(resp), nil
	}

	fromNode, err := node.Status(ctx, req)
	if err != nil {
		return nil, err
	}

	resp.ListenAddresses = fromNode.Msg.GetListenAddresses()
	resp.Peers = fromNode.Msg.GetPeers()
	// The keys on other machines, including the machines that are not there
	// (decision N). It is the answer `ladulas keys list` is really after on a
	// keyless box, and the reason it is here rather than derived from the peer
	// rows is that a peer with no link has no rows to derive it from.
	resp.BorrowedKeys = fromNode.Msg.GetBorrowedKeys()

	// A pairing waiting for an answer is something somebody has to do something
	// about, and nothing else on this instance will ever remind them (§7).
	resp.PendingPairings = int32(len(node.PendingPairings())) //nolint:gosec // the pending set is bounded at sixteen

	return connect.NewResponse(resp), nil
}

// Initialize creates the store on an instance that has none, and is the only
// way one is ever created (§14).
//
// The passphrase travels the same road Unlock's does and is wiped the same way.
// What is different is what happens afterwards: the process that made the store
// is the process that owns it, so the instance is unlocked and fully serving
// when this returns, with no restart between creating a store and using it.
func (s *controlService) Initialize(
	_ context.Context, req *connect.Request[ladulasv1.InitializeRequest],
) (*connect.Response[ladulasv1.InitializeResponse], error) {
	message, err := s.app.Initialise(
		req.Msg.GetInstanceName(), req.Msg.GetPassphrase())

	keystore.Wipe(req.Msg.GetPassphrase())

	if errors.Is(err, keystore.ErrExists) {
		return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf(
			"this instance already has a store in %s", s.app.Config.DataDir))
	}

	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&ladulasv1.InitializeResponse{
		InstanceName: vault.InstanceName(),
		Fingerprint:  vault.Identity().Fingerprint(),
		State:        s.app.State(),
		StorePath:    s.app.Config.StorePath(),
		PolicyPath:   s.app.Config.PolicyPath(),
		Message:      message,
	}), nil
}

// Unlock is the other call a sealed instance answers.
//
// The passphrase arrived over a socket only this uid can open, which §14 says
// is the whole gate. What this side owes it is not to keep it: the bytes are
// wiped once the key encryption key has been derived from them.
func (s *controlService) Unlock(
	_ context.Context, req *connect.Request[ladulasv1.UnlockRequest],
) (*connect.Response[ladulasv1.UnlockResponse], error) {
	message, err := s.app.Unlock(req.Msg.GetPassphrase())

	// The request message holds the same bytes the app just wiped, and connect
	// keeps it alive until this handler returns.
	keystore.Wipe(req.Msg.GetPassphrase())

	switch {
	case errors.Is(err, ErrNotInitialised):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, keystore.ErrPassphraseNeeded):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case err != nil:
		return nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("unlock: %w", err))
	}

	return connect.NewResponse(&ladulasv1.UnlockResponse{
		State:   s.app.State(),
		Message: message,
	}), nil
}

// Lock suspends local approval authority, or seals.
func (s *controlService) Lock(
	_ context.Context, req *connect.Request[ladulasv1.LockRequest],
) (*connect.Response[ladulasv1.LockResponse], error) {
	err := s.app.Lock(req.Msg.GetSeal(), "asked for at the command line")
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}

	return connect.NewResponse(&ladulasv1.LockResponse{
		State: s.app.State(),
	}), nil
}

// AwaitState holds the call open until the store is in a state the caller is
// waiting for.
//
// The whole of it is a long poll, and the reasons it is one rather than
// something to poll are §14's: the daemon knows the moment the state changes,
// and anything else would find out by asking repeatedly and being told "no" —
// which on a machine somebody is not sitting at is a log full of nothing.
//
// A timeout that runs out is an ordinary answer with reached=false. A caller
// that hangs up is a context that is cancelled, which is the same thing without
// anybody to tell.
func (s *controlService) AwaitState(
	ctx context.Context, req *connect.Request[ladulasv1.AwaitStateRequest],
) (*connect.Response[ladulasv1.AwaitStateResponse], error) {
	want := map[ladulasv1.LockState]bool{}

	for _, state := range req.Msg.GetStates() {
		want[state] = true
	}

	if len(want) == 0 {
		// Unlocked is the only state in which everything works, so it is what
		// somebody who did not say means.
		want[ladulasv1.LockState_LOCK_STATE_UNLOCKED] = true
	}

	if timeout := req.Msg.GetTimeout().AsDuration(); timeout > 0 {
		var cancel context.CancelFunc

		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	state, reached := s.app.AwaitState(ctx, want)

	_, since, reason := s.app.StateDetail()

	return connect.NewResponse(&ladulasv1.AwaitStateResponse{
		State:       state,
		Reached:     reached,
		StateSince:  timestamppb.New(since),
		StateReason: reason,
	}), nil
}

// The keyring verbs are the daemon's, for the same reason unlocking is: what
// enrolment copies into the platform keychain is the data encryption key, and
// the daemon is the process holding it (decision I, §14).

func (s *controlService) KeyringStatus(
	_ context.Context, _ *connect.Request[ladulasv1.KeyringStatusRequest],
) (*connect.Response[ladulasv1.KeyringStatusResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&ladulasv1.KeyringStatusResponse{
		Enrolled:           vault.KeyringEnrolled(),
		PassphraseWrapping: vault.HasPassphraseWrapping(),
	}), nil
}

func (s *controlService) SetUnlockAtLogin(
	_ context.Context, req *connect.Request[ladulasv1.SetUnlockAtLoginRequest],
) (*connect.Response[ladulasv1.SetUnlockAtLoginResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	if err := s.app.UnlockAtLogin(req.Msg.GetEnrol()); err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}

	return connect.NewResponse(&ladulasv1.SetUnlockAtLoginResponse{
		Enrolled: vault.KeyringEnrolled(),
	}), nil
}

// PeerListen answers in every state, because "nothing is bound" is what
// somebody is looking at when they ask, and the reason differs (§14).
func (s *controlService) PeerListen(
	_ context.Context, _ *connect.Request[ladulasv1.PeerListenRequest],
) (*connect.Response[ladulasv1.PeerListenResponse], error) {
	return connect.NewResponse(&ladulasv1.PeerListenResponse{
		State: s.app.PeerListenState(),
	}), nil
}

// SetPeerListen needs the store, because that is where the setting goes. A
// sealed instance is told to unseal rather than being given somewhere to write
// it that the next unseal would not read.
func (s *controlService) SetPeerListen(
	_ context.Context, req *connect.Request[ladulasv1.SetPeerListenRequest],
) (*connect.Response[ladulasv1.SetPeerListenResponse], error) {
	if _, err := s.vault(); err != nil {
		return nil, err
	}

	detail, err := s.app.SetPeerListen(
		req.Msg.GetSpec(), req.Msg.GetAllowPublic(), req.Msg.GetClear())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	return connect.NewResponse(&ladulasv1.SetPeerListenResponse{
		State:  s.app.PeerListenState(),
		Detail: detail,
	}), nil
}

// The grants live in the store, so listing and revoking them are the daemon's
// too. They were the last verbs still opening the store behind a running
// instance, which on a box with no terminal meant they simply did not work.

func (s *controlService) ListGrants(
	_ context.Context, _ *connect.Request[ladulasv1.ListGrantsRequest],
) (*connect.Response[ladulasv1.ListGrantsResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	grants, err := vault.Grants()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&ladulasv1.ListGrantsResponse{
		Grants: grants,
	}), nil
}

// ExtendGrant puts more time on a promise that is still running.
//
// The order is the same as revoking's and for the same reason: the machine
// holding a delegation is told first, and only then is the record here amended.
// The two failures are opposite in shape and both matter — an undelivered
// revocation leaves somebody signing who should have stopped, and an
// undelivered extension would leave this list promising more than the machine
// acting on it will do.
func (s *controlService) ExtendGrant(
	ctx context.Context, req *connect.Request[ladulasv1.ExtendGrantRequest],
) (*connect.Response[ladulasv1.ExtendGrantResponse], error) {
	if _, err := s.vault(); err != nil {
		return nil, err
	}

	grant, err := s.app.Engine().ExtendGrant(
		ctx, req.Msg.GetGrantId(), req.Msg.GetExtendBy().AsDuration())

	switch {
	case errors.Is(err, approval.ErrNoSuchGrant):
		return nil, connect.NewError(connect.CodeNotFound, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}

	s.app.LogLifecycle("grant " + grant.GetGrantId() + " extended: " +
		grant.GetDescription())

	return connect.NewResponse(&ladulasv1.ExtendGrantResponse{
		Grant: grant,
	}), nil
}

// ListDelegations is the other half of ListGrants: the promises somebody else
// made about this instance, which it applies itself (decision P).
//
// They are read from the store rather than from the engine because that is
// where they live, and the count beside each is what it has actually done under
// it — a promise that never says what it covered is a promise nobody here can
// audit (§9), and until this verb existed a machine could self-approve for an
// hour with nothing local that even named the permission it was using.
func (s *controlService) ListDelegations(
	_ context.Context, _ *connect.Request[ladulasv1.ListDelegationsRequest],
) (*connect.Response[ladulasv1.ListDelegationsResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	held, err := vault.Delegations()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	out := make([]*ladulasv1.HeldDelegationInfo, 0, len(held))

	for _, item := range held {
		out = append(out, &ladulasv1.HeldDelegationInfo{
			Delegation:     item.GetDelegation(),
			ReceivedAt:     item.GetReceivedAt(),
			UseCount:       item.GetUseCount(),
			UnreportedUses: uint32(len(item.GetUnreportedUses())), //nolint:gosec // a ledger of unsent reports is not that long
		})
	}

	return connect.NewResponse(&ladulasv1.ListDelegationsResponse{
		Delegations: out,
	}), nil
}

func (s *controlService) RevokeGrant(
	ctx context.Context, req *connect.Request[ladulasv1.RevokeGrantRequest],
) (*connect.Response[ladulasv1.RevokeGrantResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	id := req.Msg.GetGrantId()

	// The other machine first, and only then the store.
	//
	// A delegated grant is a signed promise somebody else is holding and acting
	// on without asking (decision P), so the local record is the smaller half of
	// it: removing that half stops nothing. If the holder cannot be reached the
	// grant is marked instead of removed — still listed, visibly not finished —
	// because the promise is still being kept over there and a list that dropped
	// it would say the signing had stopped.
	if node := s.app.Peer(); node != nil {
		if _, err := node.RevokeDelegation(ctx, id); err != nil {
			if marked := vault.MarkRevokePending(id, time.Now()); marked != nil {
				return nil, connect.NewError(connect.CodeInternal, marked)
			}

			s.app.LogLifecycle("revoke of grant " + id + " is pending: " +
				err.Error())

			return connect.NewResponse(&ladulasv1.RevokeGrantResponse{
				GrantId: id,
				Pending: true,
				Detail:  err.Error(),
			}), nil
		}
	}

	// Revoking is idempotent in the store, which makes a typo look like a
	// success. Somebody taking a promise back wants to be told they took back
	// the one they meant, which is what RevokeLiveGrant is for.
	if err := vault.RevokeLiveGrant(id); err != nil {
		if errors.Is(err, keystore.ErrNoSuchGrant) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}

		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	s.app.LogLifecycle("revoked grant " + id)

	return connect.NewResponse(&ladulasv1.RevokeGrantResponse{
		GrantId: id,
	}), nil
}

// The key verbs are the daemon's too (§14).
//
// A CLI that opened the store itself to list a key would ask for a passphrase
// on a box whose daemon is already unlocked, and one that wrote to it would be
// rewriting, whole, a document the daemon holds its own whole copy of — nothing
// guards the file against the second writer, so whichever saved last would win.
// Going through the socket also means a generated key is offered by the agent
// the moment it exists, rather than at the next SIGHUP.

func (s *controlService) ListStoredKeys(
	_ context.Context, _ *connect.Request[ladulasv1.ListStoredKeysRequest],
) (*connect.Response[ladulasv1.ListStoredKeysResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	resp := &ladulasv1.ListStoredKeysResponse{}

	for _, key := range vault.Keys() {
		resp.Keys = append(resp.Keys, keystore.KeyInfo(key))
	}

	return connect.NewResponse(resp), nil
}

func (s *controlService) GenerateKey(
	_ context.Context, req *connect.Request[ladulasv1.GenerateKeyRequest],
) (*connect.Response[ladulasv1.GenerateKeyResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	key, err := vault.GenerateKey(req.Msg.GetLabel(), req.Msg.GetComment())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	s.app.LogLifecycle("generated key " + key.GetFingerprint())

	return connect.NewResponse(&ladulasv1.GenerateKeyResponse{
		Key: keystore.KeyInfo(key),
	}), nil
}

// ImportKey answers a passphrase-protected key file with a request for the
// passphrase rather than an error, because the daemon has no terminal to ask on
// and the caller does.
func (s *controlService) ImportKey(
	_ context.Context, req *connect.Request[ladulasv1.ImportKeyRequest],
) (*connect.Response[ladulasv1.ImportKeyResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	// The key and the passphrase that protects it both belong to the caller,
	// and connect keeps the request alive until this returns.
	defer keystore.Wipe(req.Msg.GetPrivateKey())
	defer keystore.Wipe(req.Msg.GetPassphrase())

	key, err := vault.ImportKey(req.Msg.GetPrivateKey(),
		string(req.Msg.GetPassphrase()), req.Msg.GetLabel())

	if errors.Is(err, keystore.ErrPassphraseRequired) {
		return connect.NewResponse(&ladulasv1.ImportKeyResponse{
			PassphraseRequired: true,
		}), nil
	}

	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	s.app.LogLifecycle("imported key " + key.GetFingerprint())

	return connect.NewResponse(&ladulasv1.ImportKeyResponse{
		Key: keystore.KeyInfo(key),
	}), nil
}

func (s *controlService) RemoveKey(
	_ context.Context, req *connect.Request[ladulasv1.RemoveKeyRequest],
) (*connect.Response[ladulasv1.RemoveKeyResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	ref := req.Msg.GetKey()

	key, ok := findKey(vault, ref)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("no key %q in the store", ref))
	}

	if err := vault.RemoveKey(ref); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	s.app.LogLifecycle("removed key " + key.GetFingerprint())

	return connect.NewResponse(&ladulasv1.RemoveKeyResponse{
		Fingerprint: key.GetFingerprint(),
	}), nil
}

func (s *controlService) SetKeyEnabled(
	_ context.Context, req *connect.Request[ladulasv1.SetKeyEnabledRequest],
) (*connect.Response[ladulasv1.SetKeyEnabledResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	ref := req.Msg.GetKey()

	if err := vault.SetKeyDisabled(ref, !req.Msg.GetEnabled()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	key, ok := findKey(vault, ref)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("no key %q in the store", ref))
	}

	return connect.NewResponse(&ladulasv1.SetKeyEnabledResponse{
		Key: keystore.KeyInfo(key),
	}), nil
}

// SetKeyAgentUse takes a key out of the agent's identity list, or puts it back
// (decision T).
//
// It is a weaker thing than disabling the key, and the difference is the whole
// reason it exists: what is switched off here is ssh being handed the key and
// told to try it, not the key. Anything that names the key — `user.signingkey`,
// a peer asking for a signature with it — goes on working.
// A peer that borrows the key is not told; it asks. A requester relearns what a
// holder offers on every heartbeat (§8), which is the same half-minute that
// `peers allow --key` already takes to reach it, and this instance's own agent
// stops offering the key at once because it reads the store per request.
func (s *controlService) SetKeyAgentUse(
	_ context.Context, req *connect.Request[ladulasv1.SetKeyAgentUseRequest],
) (*connect.Response[ladulasv1.SetKeyAgentUseResponse], error) {
	vault, err := s.vault()
	if err != nil {
		return nil, err
	}

	key, err := vault.SetKeyAgentUse(req.Msg.GetKey(), req.Msg.GetAgentUse())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	return connect.NewResponse(&ladulasv1.SetKeyAgentUseResponse{
		Key: keystore.KeyInfo(key),
	}), nil
}

func findKey(
	vault *keystore.Vault, ref string,
) (*storepb.StoredKey, bool) {
	for _, key := range vault.Keys() {
		if key.GetLabel() == ref || key.GetFingerprint() == ref {
			return key, true
		}
	}

	return nil, false
}

func (s *controlService) BeginPairing(
	ctx context.Context,
	req *connect.Request[ladulasv1.BeginPairingRequest],
	stream *connect.ServerStream[ladulasv1.PairingProgress],
) error {
	node, err := s.peerControl()
	if err != nil {
		return err
	}

	return node.BeginPairing(ctx, req, stream)
}

func (s *controlService) PairWithPeer(
	ctx context.Context,
	req *connect.Request[ladulasv1.PairWithPeerRequest],
	stream *connect.ServerStream[ladulasv1.PairingProgress],
) error {
	node, err := s.peerControl()
	if err != nil {
		return err
	}

	return node.PairWithPeer(ctx, req, stream)
}

func (s *controlService) AnswerPairing(
	ctx context.Context, req *connect.Request[ladulasv1.AnswerPairingRequest],
) (*connect.Response[ladulasv1.AnswerPairingResponse], error) {
	node, err := s.peerControl()
	if err != nil {
		return nil, err
	}

	return node.AnswerPairing(ctx, req)
}

// The pairings verbs are how a pairing that outlived the command that started
// it is answered (§7, §14). Like everything else here they are the daemon's:
// the pending pairings live in the encrypted store, so a sealed instance can
// neither list nor answer one — which is a cost that is stated rather than
// worked around, exactly as it is for the trust records themselves.

func (s *controlService) ListPendingPairings(
	ctx context.Context,
	req *connect.Request[ladulasv1.ListPendingPairingsRequest],
) (*connect.Response[ladulasv1.ListPendingPairingsResponse], error) {
	node, err := s.peerControl()
	if err != nil {
		return nil, err
	}

	return node.ListPendingPairings(ctx, req)
}

func (s *controlService) AnswerPendingPairing(
	ctx context.Context,
	req *connect.Request[ladulasv1.AnswerPendingPairingRequest],
) (*connect.Response[ladulasv1.AnswerPendingPairingResponse], error) {
	node, err := s.peerControl()
	if err != nil {
		return nil, err
	}

	return node.AnswerPendingPairing(ctx, req)
}

func (s *controlService) WithdrawPairing(
	ctx context.Context, req *connect.Request[ladulasv1.WithdrawPairingRequest],
) (*connect.Response[ladulasv1.WithdrawPairingResponse], error) {
	node, err := s.peerControl()
	if err != nil {
		return nil, err
	}

	return node.WithdrawPairing(ctx, req)
}

func (s *controlService) SetPeerDirections(
	ctx context.Context, req *connect.Request[ladulasv1.SetPeerDirectionsRequest],
) (*connect.Response[ladulasv1.SetPeerDirectionsResponse], error) {
	node, err := s.peerControl()
	if err != nil {
		return nil, err
	}

	return node.SetPeerDirections(ctx, req)
}

func (s *controlService) RenamePeer(
	ctx context.Context, req *connect.Request[ladulasv1.RenamePeerRequest],
) (*connect.Response[ladulasv1.RenamePeerResponse], error) {
	node, err := s.peerControl()
	if err != nil {
		return nil, err
	}

	return node.RenamePeer(ctx, req)
}

func (s *controlService) RevokePeer(
	ctx context.Context, req *connect.Request[ladulasv1.RevokePeerRequest],
) (*connect.Response[ladulasv1.RevokePeerResponse], error) {
	node, err := s.peerControl()
	if err != nil {
		return nil, err
	}

	return node.RevokePeer(ctx, req)
}

func (s *controlService) PublishProject(
	ctx context.Context, req *connect.Request[ladulasv1.PublishProjectRequest],
) (*connect.Response[ladulasv1.PublishProjectResponse], error) {
	node, err := s.peerControl()
	if err != nil {
		return nil, err
	}

	return node.PublishProject(ctx, req)
}

func (s *controlService) ListPublications(
	ctx context.Context, req *connect.Request[ladulasv1.ListPublicationsRequest],
) (*connect.Response[ladulasv1.ListPublicationsResponse], error) {
	node, err := s.peerControl()
	if err != nil {
		return nil, err
	}

	return node.ListPublications(ctx, req)
}

func (s *controlService) SetAutoPublish(
	ctx context.Context, req *connect.Request[ladulasv1.SetAutoPublishRequest],
) (*connect.Response[ladulasv1.SetAutoPublishResponse], error) {
	node, err := s.peerControl()
	if err != nil {
		return nil, err
	}

	return node.SetAutoPublish(ctx, req)
}

func (s *controlService) UnpublishProject(
	ctx context.Context, req *connect.Request[ladulasv1.UnpublishProjectRequest],
) (*connect.Response[ladulasv1.UnpublishProjectResponse], error) {
	node, err := s.peerControl()
	if err != nil {
		return nil, err
	}

	return node.UnpublishProject(ctx, req)
}
