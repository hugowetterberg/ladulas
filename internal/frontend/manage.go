package frontend

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
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
) (*ladulasv1.KeyInfo, error) {
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

	return resp.Msg.GetKey(), nil
}

// setKeyEnabled turns a key off without removing it, or back on.
func (f *Frontend) setKeyEnabled(
	ctx context.Context, key string, enabled bool,
) (*ladulasv1.KeyInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	resp, err := f.client.SetKeyEnabled(ctx,
		connect.NewRequest(&ladulasv1.SetKeyEnabledRequest{
			Key:     key,
			Enabled: enabled,
		}))
	if err != nil {
		if enabled {
			return nil, fmt.Errorf("turn the key on: %w", err)
		}

		return nil, fmt.Errorf("turn the key off: %w", err)
	}

	return resp.Msg.GetKey(), nil
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

// publishing is what this instance publishes and whether it does so
// automatically (decision Q). It rides on the publications listing, which is
// the one call that knows both.
func (f *Frontend) publishing() (bridge.PublishingView, error) {
	ctx, cancel := call()
	defer cancel()

	resp, err := f.client.ListPublications(ctx,
		connect.NewRequest(&ladulasv1.ListPublicationsRequest{}))
	if err != nil {
		return bridge.PublishingView{}, fmt.Errorf("ask about publishing: %w", err)
	}

	view := bridge.PublishingView{AutoPublish: resp.Msg.GetAutoPublish()}

	for _, pub := range resp.Msg.GetPublished() {
		view.Published = append(view.Published, bridge.PublicationViewOf(pub))
	}

	return view, nil
}

// publishProject offers a directory's repository to this instance's approvers.
// The path is made absolute here rather than in the daemon because the daemon
// has no idea what directory the window thinks it is in — the CLI does the same
// before it asks.
func (f *Frontend) publishProject(
	ctx context.Context, path, name string,
) (bridge.PublicationView, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	abs, err := filepath.Abs(path)
	if err != nil {
		return bridge.PublicationView{}, fmt.Errorf("resolve %q: %w", path, err)
	}

	resp, err := f.client.PublishProject(ctx,
		connect.NewRequest(&ladulasv1.PublishProjectRequest{
			Path: abs,
			Name: name,
		}))
	if err != nil {
		return bridge.PublicationView{}, fmt.Errorf("publish %s: %w", abs, err)
	}

	return bridge.PublicationViewOf(resp.Msg.GetPublication()), nil
}

func (f *Frontend) unpublishProject(ctx context.Context, project string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	_, err := f.client.UnpublishProject(ctx,
		connect.NewRequest(&ladulasv1.UnpublishProjectRequest{
			Project: project,
		}))
	if err != nil {
		return fmt.Errorf("stop publishing %s: %w", project, err)
	}

	return nil
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
