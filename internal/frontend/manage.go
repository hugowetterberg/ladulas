package frontend

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/bridge"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The management calls the window makes that were `ladulas` subcommands and
// nothing else (§12): what can be done to a key the instance holds, and the
// per-instance settings beyond the signing budget. Each is one control call
// the daemon already served, and the daemon decides everything worth
// deciding — whether a key may be handed over, whether an address may be
// bound, whether the passphrase typed to confirm a transfer is the right one.

// rebindTimeout bounds the calls that do more than write a field: rebinding
// the peer channel, and handing a key to a machine that may have to be
// dialled first.
const rebindTimeout = 15 * time.Second

// keyRef is the KeyRef a KeyInfo reduces to for the bridge, which is the part
// a surface draws.
func keyRef(key *ladulasv1.KeyInfo) *ladulasv1.KeyRef {
	return &ladulasv1.KeyRef{
		Fingerprint: key.GetFingerprint(),
		Algorithm:   key.GetAlgorithm(),
		PublicKey:   key.GetPublicKey(),
		Comment:     key.GetComment(),
		Label:       key.GetLabel(),
		AgentUse:    key.AgentUse,
	}
}

// removeKey forgets a key the instance holds.
func (f *Frontend) removeKey(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	_, err := f.client.RemoveKey(ctx,
		connect.NewRequest(&ladulasv1.RemoveKeyRequest{Key: key}))
	if err != nil {
		return fmt.Errorf("remove the key: %w", err)
	}

	return nil
}

// setKeyAgentUse says whether the agent offers a key (decision T).
func (f *Frontend) setKeyAgentUse(
	ctx context.Context, key string, use bool,
) (*ladulasv1.KeyRef, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	resp, err := f.client.SetKeyAgentUse(ctx,
		connect.NewRequest(&ladulasv1.SetKeyAgentUseRequest{
			Key:      key,
			AgentUse: use,
		}))
	if err != nil {
		return nil, fmt.Errorf("change what the agent offers: %w", err)
	}

	return keyRef(resp.Msg.GetKey()), nil
}

// sendKey hands a portable key to a paired machine (decision S).
//
// The passphrase goes to the daemon as typed and is wiped here once the call
// is back, the way the command line wipes its own copy: this process is one
// more place the bytes have been, and it need not keep them.
func (f *Frontend) sendKey(
	ctx context.Context, key, peer string, passphrase []byte,
) (string, error) {
	defer keystore.Wipe(passphrase)

	ctx, cancel := context.WithTimeout(ctx, rebindTimeout)
	defer cancel()

	resp, err := f.client.SendKey(ctx,
		connect.NewRequest(&ladulasv1.SendKeyRequest{
			Key:        key,
			Peer:       peer,
			Passphrase: passphrase,
		}))
	if err != nil {
		return "", fmt.Errorf("hand the key over: %w", err)
	}

	return resp.Msg.GetPeerName(), nil
}

// listen is where the peer channel listens (§8), asked for on every paint of
// the instance view like the settings are.
func (f *Frontend) listen() (*ladulasv1.PeerListenState, error) {
	ctx, cancel := call()
	defer cancel()

	resp, err := f.client.PeerListen(ctx,
		connect.NewRequest(&ladulasv1.PeerListenRequest{}))
	if err != nil {
		return nil, fmt.Errorf("ask where the peer channel listens: %w", err)
	}

	return resp.Msg.GetState(), nil
}

// setListen changes where the peer channel listens, or clears the stored
// setting (§14). The daemon rebinds before answering, so this waits longer
// than a read does.
func (f *Frontend) setListen(
	ctx context.Context, spec string, allowPublic, clear bool,
) (*ladulasv1.SetPeerListenResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, rebindTimeout)
	defer cancel()

	resp, err := f.client.SetPeerListen(ctx,
		connect.NewRequest(&ladulasv1.SetPeerListenRequest{
			Spec:        spec,
			AllowPublic: allowPublic,
			Clear:       clear,
		}))
	if err != nil {
		return nil, fmt.Errorf("change where the peer channel listens: %w", err)
	}

	return resp.Msg, nil
}

// autoPublish is whether projects this instance asks for signatures in are
// published automatically (decision Q). It rides on the publications listing,
// which is the one call that knows.
func (f *Frontend) autoPublish() (bool, error) {
	ctx, cancel := call()
	defer cancel()

	resp, err := f.client.ListPublications(ctx,
		connect.NewRequest(&ladulasv1.ListPublicationsRequest{}))
	if err != nil {
		return false, fmt.Errorf("ask about publishing: %w", err)
	}

	return resp.Msg.GetAutoPublish(), nil
}

func (f *Frontend) setAutoPublish(ctx context.Context, enabled bool) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	_, err := f.client.SetAutoPublish(ctx,
		connect.NewRequest(&ladulasv1.SetAutoPublishRequest{Enabled: enabled}))
	if err != nil {
		return fmt.Errorf("change automatic publishing: %w", err)
	}

	return nil
}

// unlockAtLogin is whether the store opens from the platform keychain at
// login (decision I).
func (f *Frontend) unlockAtLogin() (bridge.UnlockAtLoginView, error) {
	ctx, cancel := call()
	defer cancel()

	resp, err := f.client.KeyringStatus(ctx,
		connect.NewRequest(&ladulasv1.KeyringStatusRequest{}))
	if err != nil {
		return bridge.UnlockAtLoginView{},
			fmt.Errorf("ask about the keychain: %w", err)
	}

	return bridge.UnlockAtLoginView{
		Enrolled:           resp.Msg.GetEnrolled(),
		PassphraseWrapping: resp.Msg.GetPassphraseWrapping(),
	}, nil
}

// setUnlockAtLogin enrols the keychain or forgets it. The daemon is the
// process holding the data encryption key, so the copy into the keychain is
// its to make; this asks.
func (f *Frontend) setUnlockAtLogin(ctx context.Context, enrol bool) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	resp, err := f.client.SetUnlockAtLogin(ctx,
		connect.NewRequest(&ladulasv1.SetUnlockAtLoginRequest{Enrol: enrol}))
	if err != nil {
		return fmt.Errorf("change unlocking at login: %w", err)
	}

	if resp.Msg.GetEnrolled() != enrol {
		return errors.New("the daemon answered with the setting unchanged")
	}

	return nil
}
