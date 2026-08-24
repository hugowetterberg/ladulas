package app

import (
	"errors"
	"fmt"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// Where the peer channel listens is something a person changes, and decision AH
// is that they change it here rather than by editing a unit file.
//
// The flag stays what it was and still wins (see listenSetting), because a
// stored setting is exactly the thing that can lock somebody out: an address on
// an interface that has been renamed, or a tailnet the machine has left, is a
// listener that will not come up and a management surface that is behind it.
// What is new is that there is a stored setting at all, that changing it rebinds
// the channel rather than waiting for a restart, and that a bind which fails
// puts the previous addresses back rather than leaving the instance unreachable
// because of a typo.

// peerStopTimeout bounds waiting for a stopped peer channel to finish serving.
// A channel that has not stopped in this long is a goroutine to complain about
// rather than one to keep waiting for: the listener is closed either way.
const peerStopTimeout = 10 * time.Second

// PeerListenState describes where the peer channel is listening, for the
// management surface.
//
// It answers in every state, sealed included, and says why nothing is bound when
// nothing is. A sealed instance cannot be asked what its stored setting is — the
// setting is inside the store — so what it reports is the flag, or the automatic
// policy, and what that policy would choose if it were asked now. The
// distinction is in `detail` rather than left for somebody to infer from an
// empty list, which is the mistake §14 keeps coming back to: "off", "sealed" and
// "broken" must not look alike.
func (a *App) PeerListenState() *ladulasv1.PeerListenState {
	vault := a.Vault()

	setting := a.listenSettingOrFlag(vault)

	state := &ladulasv1.PeerListenState{
		Spec:        setting.spec,
		Source:      setting.source,
		AllowPublic: setting.allowPublic,
	}

	if vault != nil {
		if stored := vault.PeerListen(); stored != nil {
			state.StoredSpec = stored.GetSpec()
			state.StoredAllowPublic = stored.GetAllowPublic()
		}
	}

	node := a.Peer()
	if node == nil {
		state.Detail = a.whyNothingIsBound(setting)
		describeSelection(state, previewSelection(setting))

		return state
	}

	selection := node.ListenSelection()
	if selection == nil {
		state.Detail = "the peer channel has not bound yet"
		describeSelection(state, previewSelection(setting))

		return state
	}

	state.Bound = selection.Bind
	state.Advertised = node.Advertised()
	state.Tier = selection.Tier
	state.Skipped = skippedToWire(selection.Skipped)

	if len(state.GetBound()) == 0 {
		// An instance that dials and never listens, which is what a phone is
		// (§3) and what `none` asks for anywhere else.
		state.Detail = "this instance dials out and never listens"
	}

	return state
}

// whyNothingIsBound is the sentence that stops "off", "sealed" and "broken"
// looking alike.
func (a *App) whyNothingIsBound(setting listenSetting) string {
	switch {
	case setting.spec == PeeringOff:
		return "peering is switched off"
	case !a.Unsealed():
		return "the store is sealed, so there is no identity to " +
			"authenticate a channel with and nothing is bound"
	default:
		return "the peer channel is not running"
	}
}

// listenSettingOrFlag is listenSetting for a possibly sealed instance: with no
// store to read, the stored half simply is not there to be consulted.
func (a *App) listenSettingOrFlag(vault *keystore.Vault) listenSetting {
	if current := a.currentCore(); current != nil {
		return current.listen
	}

	if vault != nil {
		return a.listenSetting(vault)
	}

	if a.Config.PeerListen != "" {
		return listenSetting{
			spec:        a.Config.PeerListen,
			allowPublic: a.Config.PeerAllowPublic,
			source:      ladulasv1.ListenSource_LISTEN_SOURCE_FLAG,
		}
	}

	return listenSetting{
		spec:        transport.ListenAuto,
		allowPublic: a.Config.PeerAllowPublic,
		source:      ladulasv1.ListenSource_LISTEN_SOURCE_AUTOMATIC,
	}
}

// previewSelection is what the policy would choose, for an instance that has
// bound nothing. It is what makes `ladulas listen` worth running on a sealed box
// — the interfaces it would take and the ones it would pass over are a property
// of the machine, not of the store.
func previewSelection(setting listenSetting) *transport.Selection {
	if setting.spec == PeeringOff {
		return nil
	}

	selection, err := transport.Select(setting.spec, setting.allowPublic)
	if err != nil {
		return nil
	}

	return selection
}

// describeSelection fills in the parts of a state that describe a selection
// nothing was bound from, leaving Bound and Advertised empty: they are what
// happened, and nothing happened.
func describeSelection(
	state *ladulasv1.PeerListenState, selection *transport.Selection,
) {
	if selection == nil {
		return
	}

	state.Tier = selection.Tier
	state.Skipped = skippedToWire(selection.Skipped)
}

func skippedToWire(
	skipped []transport.SkippedAddress,
) []*ladulasv1.SkippedListenAddress {
	out := make([]*ladulasv1.SkippedListenAddress, 0, len(skipped))

	for _, one := range skipped {
		out = append(out, &ladulasv1.SkippedListenAddress{
			Address:   one.Address,
			Interface: one.Interface,
			Reason:    one.Reason,
		})
	}

	return out
}

// SetPeerListen records where the peer channel is to listen and rebinds it.
//
// The specification is validated before anything is written, because a stored
// specification that cannot be resolved is a store that has to be edited by hand
// to get the instance back. What cannot be validated in advance is the bind
// itself — a port in use, an address that has gone away — so the rebind keeps
// the previous setting and restores it when the new one fails to come up. The
// sentence it returns says which of those happened, and the caller prints it: a
// change that silently did not take is the failure mode this whole surface
// exists to avoid.
func (a *App) SetPeerListen(spec string, allowPublic, clear bool) (string, error) {
	vault, err := a.storeForListen()
	if err != nil {
		return "", err
	}

	var settings *storepb.PeerListenSettings

	if !clear {
		if err := validateListenSpec(spec, allowPublic); err != nil {
			return "", err
		}

		settings = &storepb.PeerListenSettings{
			Spec:        spec,
			AllowPublic: allowPublic,
		}
	}

	if err := vault.SetPeerListen(settings); err != nil {
		return "", fmt.Errorf("record where to listen: %w", err)
	}

	wanted := a.listenSetting(vault)

	current := a.currentCore()
	if current == nil {
		return "", ErrSealed
	}

	if wanted == current.listen {
		if wanted.source == ladulasv1.ListenSource_LISTEN_SOURCE_FLAG && !clear {
			return "the setting is stored, and the --peer-listen flag this " +
				"process was started with is still what decides; it takes " +
				"effect when the flag goes away", nil
		}

		return "that is already where it listens", nil
	}

	// Reaching here means the setting in force actually changed, which a flag
	// would have prevented: with one set, listenSetting returns it whatever was
	// stored, and that is the branch above.
	if err := a.rebindPeer(wanted); err != nil {
		return "", err
	}

	if wanted.spec == PeeringOff {
		return "peering is switched off, and nothing is listening", nil
	}

	return fmt.Sprintf("the peer channel is listening on %s",
		describeAddresses(a.PeerAddresses())), nil
}

// storeForListen is the open store, or the reason there is not one. Changing
// where to listen needs it, because that is where the setting goes.
func (a *App) storeForListen() (*keystore.Vault, error) {
	vault := a.Vault()
	if vault == nil {
		return nil, a.noStoreError()
	}

	return vault, nil
}

// validateListenSpec refuses a specification before it is written down.
func validateListenSpec(spec string, allowPublic bool) error {
	if spec == "" {
		return errors.New(
			"say where to listen: an address, `auto`, or `off`")
	}

	if spec == PeeringOff || spec == transport.ListenNone {
		return nil
	}

	if _, err := transport.Select(spec, allowPublic); err != nil {
		return err
	}

	return nil
}

// rebindPeer moves the peer channel to a new setting, putting the old one back
// if the new one cannot bind.
//
// Restoring means building the channel again from the previous setting rather
// than reviving what was stopped: a listener that has been closed stays closed,
// and pretending otherwise is how a "restored" channel becomes a process that
// says it is listening and is not.
func (a *App) rebindPeer(setting listenSetting) error {
	current := a.currentCore()
	if current == nil {
		return ErrSealed
	}

	previous := current.listen

	err := a.startPeerOn(current, setting)
	if err == nil {
		return nil
	}

	restoreErr := a.startPeerOn(current, previous)
	if restoreErr != nil {
		a.log.Error("the peer channel is down after a failed rebind",
			"error", err.Error(), "restore_error", restoreErr.Error())

		return fmt.Errorf(
			"%w — and the previous addresses could not be bound again either "+
				"(%v), so nothing is listening until this is fixed or the "+
				"daemon is restarted", err, restoreErr)
	}

	a.log.Warn("a peer channel rebind failed and was rolled back",
		"error", err.Error(), "restored", previous.spec)

	return fmt.Errorf("%w — the previous addresses are back", err)
}

// startPeerOn stops whatever the channel was and starts it on one setting.
func (a *App) startPeerOn(current *core, setting listenSetting) error {
	a.stopPeer(current)

	a.mu.Lock()
	current.listen = setting
	a.mu.Unlock()

	node, err := a.buildPeerNode(current)
	if err != nil {
		return err
	}

	a.mu.Lock()
	current.peer = node
	a.mu.Unlock()

	if node == nil {
		a.lifecycle("peering switched off")

		return nil
	}

	// Before Serve, there is no lifetime to start under and nothing to start:
	// Serve binds the core's channel itself when it gets there.
	if a.serveCtx == nil {
		return nil
	}

	if err := a.startPeer(a.serveCtx, current); err != nil {
		return err
	}

	a.lifecycle(fmt.Sprintf("peers on %s",
		describeAddresses(a.PeerAddresses())))

	return nil
}

// stopPeer takes the peer channel down without touching anything else the core
// holds, which is what tells it apart from tearDown: sealing wipes the keys as
// well, and rebinding must not.
func (a *App) stopPeer(current *core) {
	a.mu.Lock()
	node, stop, served := current.peer, current.stop, current.served
	current.peer, current.stop, current.served = nil, nil, nil
	a.mu.Unlock()

	if node == nil {
		return
	}

	// The engine's hooks reach the node that is going away, and a hook that
	// outlived it would be a signature reported to a channel nobody is serving.
	current.engine.ReportDelegatedUse(nil)
	current.engine.RenewDelegations(nil)
	current.engine.PublishEndorsements(nil)

	if stop != nil {
		stop()
	}

	if err := node.Close(); err != nil {
		a.log.Debug("could not close the peer channel", "error", err.Error())
	}

	if served == nil {
		return
	}

	select {
	case <-served:
	case <-time.After(peerStopTimeout):
		a.log.Warn("the peer channel did not stop")
	}
}
