package app

import (
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/proto"

	"github.com/hugowetterberg/ladulas/pkg/keystore"
	"github.com/hugowetterberg/ladulas/pkg/peer"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The tunnel upgrade, as the instance holds it (§8, decision AX).
//
// The engine is internal/tunnel's and the bookkeeping is pkg/peer's; what is
// here is the part that needs the store: the setting, the keys, the persisted
// region, and the factory a binary hands in so that this package never imports
// tailcat itself.

// TunnelSpec is what a tunnel is built from: the keys and the region out of
// the store, the DERP map from the setting, and where to persist a region
// picked for the first time.
type TunnelSpec struct {
	ServerKey    []byte
	PresharedKey []byte
	ClientKey    []byte
	Region       []byte
	DERPMapURL   string
	OnRegion     func(region []byte) error
	Logger       *slog.Logger
}

// TunnelFactory builds a tunnel from a spec. internal/tunnel provides the one
// that exists.
type TunnelFactory func(TunnelSpec) (peer.Tunnel, error)

// DefaultDERPMapURL is tailcat's DERP map, the default fleet (§8). It is
// repeated here, rather than read from internal/tunnel, for the reason the
// factory exists: this package does not import tailcat.
const DefaultDERPMapURL = "https://tailcat.dev/derpmap.json"

// The two sentences decision AX requires beside the switch, said by the daemon
// so that every surface offering it says the same thing.
const (
	// TunnelExposure is what turning it on exposes, in decision H's sense.
	TunnelExposure = "Turning this on makes this machine's peer listener " +
		"reachable from anywhere through a DERP relay and hole-punching, for " +
		"every client key a paired machine has offered — a public exposure " +
		"in the sense of --peer-listen-public, behind the same pinned TLS and " +
		"an allowlist on an experimental network stack."
	// TunnelMetadata is what the relay's operator learns.
	TunnelMetadata = "The DERP operator — Tailscale's public fleet unless a " +
		"self-hosted map is set — sees both machines' tunnel keys and " +
		"addresses and when each tunnel is set up, which is the pairing graph " +
		"and the timing of approvals, but never what crosses the tunnel."
)

// ObserveTunnel registers what is told about every tunnel event, for the
// metrics port. It is read at each event, so it does not matter whether the
// store was unsealed first.
func (a *App) ObserveTunnel(fn func(event string)) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.tunnelEvents = fn
}

func (a *App) tunnelObserver() func(event string) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.tunnelEvents
}

// buildTunnel builds the tunnel for a store, or nil when the upgrade is off or
// the build has no tailcat. A tunnel that cannot be built is logged and left
// out: the node then offers the withdrawal form, which is true.
func (a *App) buildTunnel(vault *keystore.Vault) peer.Tunnel {
	settings := vault.TunnelSettings()
	if !settings.GetEnabled() || a.Config.Tunnels == nil {
		return nil
	}

	tunnel, err := a.Config.Tunnels(TunnelSpec{
		ServerKey:    settings.GetServerKey(),
		PresharedKey: settings.GetPresharedKey(),
		ClientKey:    settings.GetClientKey(),
		Region:       settings.GetRegion(),
		DERPMapURL:   settings.GetDerpMapUrl(),
		OnRegion:     vault.SetTunnelRegion,
		Logger:       a.log,
	})
	if err != nil {
		a.log.Error("could not build the tunnel", "error", err.Error())

		return nil
	}

	return tunnel
}

// TunnelState reports the tunnel upgrade for the control socket.
func (a *App) TunnelState() *ladulasv1.TunnelState {
	state := &ladulasv1.TunnelState{
		Available:         a.Config.Tunnels != nil,
		DefaultDerpMapUrl: DefaultDERPMapURL,
		Exposure:          TunnelExposure,
		Metadata:          TunnelMetadata,
	}

	vault := a.Vault()
	if vault == nil {
		state.Detail = "the store is sealed"

		return state
	}

	settings := vault.TunnelSettings()
	state.Enabled = settings.GetEnabled()
	state.DerpMapUrl = settings.GetDerpMapUrl()

	node := a.Peer()

	switch {
	case !state.GetAvailable():
		state.Detail = "this build does not carry tailcat"
	case !state.GetEnabled():
		state.Detail = "the tunnel is off"
	case node == nil:
		state.Detail = "peering is switched off"
	default:
		status := node.TunnelStatus()
		state.Running = status.Running
		state.Region = status.Region
		state.Version = uint32(max(status.Version, 0))
		state.Detail = status.Detail

		if !status.Configured && state.GetDetail() == "" {
			state.Detail = "the tunnel could not be built; the daemon's log says why"
		}
	}

	return state
}

// SetTunnel changes the upgrade's setting and puts it into effect without a
// restart (§14): the keys are generated the first time it is turned on, and
// the node is handed a new tunnel, or none, which is what starts the server
// or closes it and changes what every carrier offers.
func (a *App) SetTunnel(msg *ladulasv1.SetTunnelRequest) (*ladulasv1.TunnelState, error) {
	vault := a.Vault()
	if vault == nil {
		return nil, a.noStoreError()
	}

	before := vault.TunnelSettings()

	if msg.SetDerpMapUrl {
		if _, err := vault.SetTunnelDERPMap(msg.GetDerpMapUrl(), msg.GetRepickRegion()); err != nil {
			return nil, fmt.Errorf("record the DERP map: %w", err)
		}
	} else if msg.GetRepickRegion() {
		return nil, errors.New("re-picking the region needs the DERP map to pick it from; " +
			"say which, or the empty string for the default")
	}

	if msg.Enabled != nil {
		if _, err := vault.SetTunnelEnabled(msg.GetEnabled()); err != nil {
			return nil, fmt.Errorf("record the tunnel setting: %w", err)
		}
	}

	// Only when the save changed something, or the node does not have what the
	// setting says it should — a tunnel that failed to build is retried by
	// saving again. Handing the node a tunnel closes the running server and
	// starts another, and while that happens it offers nothing; re-saving the
	// setting it already has should cost nobody that.
	after := vault.TunnelSettings()
	wantTunnel := after.GetEnabled() && a.Config.Tunnels != nil

	if node := a.Peer(); node != nil &&
		(!proto.Equal(before, after) || node.TunnelStatus().Configured != wantTunnel) {
		node.SetTunnel(a.buildTunnel(vault))
	}

	a.lifecycle(tunnelLifecycle(vault.TunnelSettings().GetEnabled(), a.Config.Tunnels != nil))

	return a.TunnelState(), nil
}

func tunnelLifecycle(enabled, available bool) string {
	switch {
	case enabled && available:
		return "the tunnel is on"
	case enabled:
		return "the tunnel is on in the store, and this build does not carry tailcat"
	default:
		return "the tunnel is off"
	}
}
