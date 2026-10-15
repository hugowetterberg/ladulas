package app_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/internal/app"
	"github.com/hugowetterberg/ladulas/pkg/peer"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// stubTunnel is a tunnel that starts at once and accepts nothing, standing in
// for tailcat, which needs a DERP region to start at all.
type stubTunnel struct {
	spec   app.TunnelSpec
	closed chan struct{}
	once   sync.Once
}

func (s *stubTunnel) Version() int32 { return 1 }

func (s *stubTunnel) Start() (string, error) {
	if s.spec.OnRegion != nil {
		if err := s.spec.OnRegion([]byte(`{"RegionID":900}`)); err != nil {
			return "", err
		}
	}

	return "tcstub", nil
}

func (s *stubTunnel) ClientKey() []byte { return s.spec.ClientKey }

func (s *stubTunnel) Listen() (transport.TunnelListener, error) { return s, nil }

func (s *stubTunnel) Accept() (transport.TunnelConn, error) {
	<-s.closed

	return nil, net.ErrClosed
}

func (s *stubTunnel) Admit([]byte)  {}
func (s *stubTunnel) Revoke([]byte) {}

func (s *stubTunnel) RelayRegion(string) (string, error) {
	return "", errors.New("not used")
}

func (s *stubTunnel) KnownRelays() string { return "" }
func (s *stubTunnel) Region() string      { return "stub" }

func (s *stubTunnel) Close() error {
	s.once.Do(func() { close(s.closed) })

	return nil
}

// The switch goes through the control socket, puts the change into effect
// without a restart, keeps the keys across off and on, and persists the region
// the first start picked (decision AX).
func TestTheTunnelSwitch(t *testing.T) {
	var (
		mu    sync.Mutex
		built []app.TunnelSpec
	)

	i := startWith(t, func(cfg *app.Config) {
		cfg.Tunnels = func(spec app.TunnelSpec) (peer.Tunnel, error) {
			mu.Lock()
			built = append(built, spec)
			mu.Unlock()

			return &stubTunnel{spec: spec, closed: make(chan struct{})}, nil
		}
	})

	ctx := context.Background()

	read := func() *ladulasv1.TunnelState {
		resp, err := i.client.Control().Tunnel(ctx,
			connect.NewRequest(&ladulasv1.TunnelRequest{}))
		if err != nil {
			t.Fatalf("tunnel: %v", err)
		}

		return resp.Msg.GetState()
	}

	if state := read(); !state.GetAvailable() || state.GetEnabled() ||
		state.GetExposure() == "" || state.GetMetadata() == "" {
		t.Fatalf("before the switch: %v", state)
	}

	on := true

	if _, err := i.client.Control().SetTunnel(ctx, connect.NewRequest(
		&ladulasv1.SetTunnelRequest{Enabled: &on})); err != nil {
		t.Fatalf("turn on: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)

	for !read().GetRunning() {
		if time.Now().After(deadline) {
			t.Fatalf("the tunnel never came up: %v", read())
		}

		time.Sleep(10 * time.Millisecond)
	}

	if state := read(); state.GetRegion() != "stub" || state.GetVersion() != 1 {
		t.Errorf("running: %v", state)
	}

	if string(i.Vault().TunnelSettings().GetRegion()) != `{"RegionID":900}` {
		t.Error("the region the first start picked was not persisted")
	}

	off := false

	if _, err := i.client.Control().SetTunnel(ctx, connect.NewRequest(
		&ladulasv1.SetTunnelRequest{Enabled: &off})); err != nil {
		t.Fatalf("turn off: %v", err)
	}

	if state := read(); state.GetEnabled() || state.GetRunning() {
		t.Errorf("after turning off: %v", state)
	}

	if _, err := i.client.Control().SetTunnel(ctx, connect.NewRequest(
		&ladulasv1.SetTunnelRequest{Enabled: &on})); err != nil {
		t.Fatalf("turn on again: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(built) != 2 {
		t.Fatalf("built %d tunnels, want 2", len(built))
	}

	if string(built[0].ServerKey) != string(built[1].ServerKey) ||
		len(built[1].Region) == 0 {
		t.Error("turning the tunnel back on did not reuse the keys and the region")
	}
}

// A build without tailcat says so, and still lets the setting be stored: the
// store may be opened by a build that has it.
func TestATunnelSwitchWithoutTailcat(t *testing.T) {
	i := start(t)

	on := true

	resp, err := i.client.Control().SetTunnel(context.Background(),
		connect.NewRequest(&ladulasv1.SetTunnelRequest{Enabled: &on}))
	if err != nil {
		t.Fatalf("turn on: %v", err)
	}

	state := resp.Msg.GetState()
	if state.GetAvailable() || !state.GetEnabled() || state.GetRunning() {
		t.Errorf("without tailcat: %v", state)
	}
}
