package integration_test

import (
	"context"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/internal/app"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// TestListenSettingSurvivesAndRebinds is the management half of decision AH,
// driven the way a person drives it: the instance is started with no flag, told
// where to listen, and told again while it is running.
//
// The rebind is the part worth an integration test rather than a unit one. It
// stops a serving listener, builds another, and starts it under the lifetime the
// first one was serving under — and the failure mode if any of that is wrong is
// an instance that reports addresses nothing is accepting on.
func TestListenSettingSurvivesAndRebinds(t *testing.T) {
	runtime := shortDir(t)

	cfg := app.Config{
		DataDir:       t.TempDir(),
		ConfigDir:     t.TempDir(),
		SocketPath:    filepath.Join(runtime, "agent.sock"),
		ControlSocket: filepath.Join(runtime, "control.sock"),
		InstanceName:  "listener",
		// No PeerListen: this is the instance that has nobody telling it where
		// to listen, which is the only instance a stored setting decides for.
		NoKeyring: true,
		Passphrase: func(string, bool) ([]byte, error) {
			return []byte(testPassphrase), nil
		},
	}

	instance, err := app.Create(cfg)
	if err != nil {
		t.Fatalf("create the instance: %v", err)
	}

	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Errorf("close the instance: %v", err)
		}
	})

	// Before serving, so that the automatic policy does not bind this machine's
	// real addresses on the real port while the tests run.
	first := freeAddress(t)

	if _, err := instance.SetPeerListen(first, false, false); err != nil {
		t.Fatalf("set the listen address: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)

	go func() {
		served <- instance.Serve(ctx)
	}()

	t.Cleanup(func() {
		cancel()

		select {
		case err := <-served:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("the instance did not stop")
		}
	})

	waitForSocket(t, cfg.ControlSocket)

	state := instance.PeerListenState()

	if !slices.Equal(state.GetBound(), []string{first}) {
		t.Fatalf("bound %v, want %v", state.GetBound(), first)
	}

	if state.GetSource() != ladulasv1.ListenSource_LISTEN_SOURCE_STORED {
		t.Errorf("the setting came from %s, want the store", state.GetSource())
	}

	if !slices.Equal(state.GetAdvertised(), []string{first}) {
		t.Errorf("advertises %v, want the address it bound", state.GetAdvertised())
	}

	// A second address, while it is running. The first listener has to be gone:
	// a rebind that left it up would be two channels on one identity, and the
	// address a peer was told about would be the one nobody was serving.
	second := freeAddress(t)

	detail, err := instance.SetPeerListen(second, false, false)
	if err != nil {
		t.Fatalf("rebind: %v", err)
	}

	if !strings.Contains(detail, second) {
		t.Errorf("the rebind said %q, which does not name %s", detail, second)
	}

	if bound := instance.PeerAddresses(); !slices.Equal(bound, []string{second}) {
		t.Fatalf("bound %v after the rebind, want %v", bound, second)
	}

	if accepting(t, first) {
		t.Error("the previous address is still being served")
	}

	if !accepting(t, second) {
		t.Error("the new address is not being served")
	}

	// Switching peering off takes the listener away and leaves the instance
	// answering its control socket, which is the state a machine that is only
	// ever approved for locally runs in.
	if _, err := instance.SetPeerListen(app.PeeringOff, false, false); err != nil {
		t.Fatalf("switch peering off: %v", err)
	}

	if instance.Peer() != nil {
		t.Error("the peer node survived peering being switched off")
	}

	off := instance.PeerListenState()

	if off.GetDetail() == "" {
		t.Error("nothing was bound and nothing said why")
	}

	if accepting(t, second) {
		t.Error("an address is still being served with peering off")
	}

	// And back on, which is the same path in reverse: a node has to be built
	// where there was none.
	third := freeAddress(t)

	if _, err := instance.SetPeerListen(third, false, false); err != nil {
		t.Fatalf("switch peering back on: %v", err)
	}

	if !accepting(t, third) {
		t.Error("the channel did not come back")
	}

	// Clearing is not exercised here on purpose: with no flag it goes back to
	// the automatic policy, which binds this machine's real addresses on the
	// real port — and the daemon on a developer's machine is already there. It
	// is covered below, on an instance that has a flag.
}

// accepting says whether anything accepts a connection at an address. A TLS
// listener accepts the connection before it decides anything about the peer, so
// a plain dial is enough to tell "bound" from "gone".
func accepting(t *testing.T, address string) bool {
	t.Helper()

	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return false
	}

	if err := conn.Close(); err != nil {
		t.Errorf("close the probe connection: %v", err)
	}

	return true
}

// TestARefusedListenSettingIsNotWrittenIntoTheStore covers the way somebody
// locks themselves out: a stored address that cannot be resolved is a store to
// be edited by hand before the instance listens again.
func TestARefusedListenSettingIsNotWrittenIntoTheStore(t *testing.T) {
	instance := startPeerInstance(t, "guarded")

	before := instance.app.PeerListenState()

	if _, err := instance.app.SetPeerListen("8.8.8.8:7373", false, false); err == nil {
		t.Fatal("a public address was accepted without being asked for")
	}

	after := instance.app.PeerListenState()

	if after.GetStoredSpec() != before.GetStoredSpec() {
		t.Errorf("the refused setting was stored anyway: %q",
			after.GetStoredSpec())
	}

	if !slices.Equal(after.GetBound(), before.GetBound()) {
		t.Errorf("the listener moved from %v to %v on a refused setting",
			before.GetBound(), after.GetBound())
	}

	// And the flag this instance was started with keeps deciding, whatever is
	// stored. It is the way back into a machine whose stored setting names an
	// address that no longer exists, so a stored setting must not quietly take
	// over from it — and the answer has to say so, or somebody spends an
	// afternoon on a setting that is doing nothing.
	stored := freeAddress(t)

	detail, err := instance.app.SetPeerListen(stored, false, false)
	if err != nil {
		t.Fatalf("store a setting behind the flag: %v", err)
	}

	if !strings.Contains(detail, "flag") {
		t.Errorf("storing a setting behind a flag said %q, which does not "+
			"mention the flag", detail)
	}

	behind := instance.app.PeerListenState()

	if behind.GetStoredSpec() != stored {
		t.Errorf("the setting was not stored: %q", behind.GetStoredSpec())
	}

	if behind.GetSource() != ladulasv1.ListenSource_LISTEN_SOURCE_FLAG {
		t.Errorf("the flag stopped deciding: %s", behind.GetSource())
	}

	if !slices.Equal(behind.GetBound(), before.GetBound()) {
		t.Errorf("the listener moved to %v behind the flag", behind.GetBound())
	}

	if _, err := instance.app.SetPeerListen("", false, true); err != nil {
		t.Fatalf("clear the setting: %v", err)
	}

	if cleared := instance.app.PeerListenState(); cleared.GetStoredSpec() != "" {
		t.Errorf("the stored setting survived being cleared: %q",
			cleared.GetStoredSpec())
	}
}
