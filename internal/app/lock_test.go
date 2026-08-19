package app_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/internal/app"
	"github.com/hugowetterberg/ladulas/internal/localapi"
	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// §10's three states, driven through the control socket, because that is how a
// box with no display is driven (§14).

const testPassphrase = "the store passphrase"

type instance struct {
	*app.App

	client *localapi.Client
}

// start creates an instance, serves it, and hands back a client of its control
// socket.
func start(t *testing.T) *instance {
	t.Helper()

	// A socket path has to fit in sun_path, and a test temporary directory does
	// not always leave room.
	runtime, err := os.MkdirTemp("", "ldl")
	if err != nil {
		t.Fatalf("runtime directory: %v", err)
	}

	t.Cleanup(func() {
		if err := os.RemoveAll(runtime); err != nil {
			t.Errorf("clean up: %v", err)
		}
	})

	cfg := app.Config{
		DataDir:       t.TempDir(),
		ConfigDir:     t.TempDir(),
		SocketPath:    filepath.Join(runtime, "agent.sock"),
		ControlSocket: filepath.Join(runtime, "control.sock"),
		InstanceName:  "test",
		PeerListen:    "127.0.0.1:0",
		NoKeyring:     true,
		Passphrase: func(string, bool) ([]byte, error) {
			return []byte(testPassphrase), nil
		},
	}

	created, err := app.Create(cfg)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := created.Vault().GenerateKey("work", "test@example.test"); err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)

	go func() {
		served <- created.Serve(ctx)
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

		if err := created.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	waitForSocket(t, cfg.ControlSocket)

	return &instance{App: created, client: localapi.NewClient(cfg.ControlSocket)}
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}

		time.Sleep(5 * time.Millisecond)
	}

	t.Fatalf("%s never appeared", path)
}

func (i *instance) status(t *testing.T) *ladulasv1.StatusResponse {
	t.Helper()

	resp, err := i.client.Control().Status(context.Background(),
		connect.NewRequest(&ladulasv1.StatusRequest{}))
	if err != nil {
		t.Fatalf("status: %v", err)
	}

	return resp.Msg
}

func (i *instance) unlock(t *testing.T, passphrase string) error {
	t.Helper()

	_, err := i.client.Control().Unlock(context.Background(),
		connect.NewRequest(&ladulasv1.UnlockRequest{
			Passphrase: []byte(passphrase),
		}))

	return err
}

func (i *instance) lock(t *testing.T, seal bool) {
	t.Helper()

	_, err := i.client.Control().Lock(context.Background(),
		connect.NewRequest(&ladulasv1.LockRequest{Seal: seal}))
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
}

// The whole of what §10 says a sealed instance does, checked one clause at a
// time: no keys, no signatures, no peer listener, and a control surface that
// has shrunk to Status and Unlock.
func TestSealedInstanceRefusesWhatItPromisesTo(t *testing.T) {
	inst := start(t)

	if len(inst.KeyRefs()) != 1 {
		t.Fatalf("the unlocked instance offers %d keys", len(inst.KeyRefs()))
	}

	if len(inst.PeerAddresses()) != 1 {
		t.Fatalf("the unlocked instance listens on %v", inst.PeerAddresses())
	}

	inst.lock(t, true)

	status := inst.status(t)

	if status.GetLockState() != ladulasv1.LockState_LOCK_STATE_SEALED {
		t.Fatalf("state %v after sealing", status.GetLockState())
	}

	if len(inst.KeyRefs()) != 0 {
		t.Error("a sealed instance still offers keys to the agent")
	}

	if _, _, err := inst.Signer("SHA256:whatever"); !errors.Is(err, app.ErrSealed) {
		t.Errorf("signing while sealed: %v, want a refusal", err)
	}

	if addresses := inst.PeerAddresses(); len(addresses) != 0 {
		t.Errorf("a sealed instance is still listening on %v", addresses)
	}

	if len(status.GetListenAddresses()) != 0 {
		t.Errorf("a sealed instance reports listening on %v",
			status.GetListenAddresses())
	}

	// The identity and the instance name live inside the store, so a sealed
	// instance cannot report them — which is the same fact as the listener
	// being down.
	if status.GetFingerprint() != "" {
		t.Errorf("a sealed instance reported an identity: %s",
			status.GetFingerprint())
	}

	// Everything else on the control service is refused, and says why.
	_, err := inst.client.Control().ListPublications(context.Background(),
		connect.NewRequest(&ladulasv1.ListPublicationsRequest{}))
	if err == nil {
		t.Fatal("a sealed instance answered a call that needs the store")
	}

	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("code %v, want failed-precondition", connect.CodeOf(err))
	}

	if !strings.Contains(err.Error(), "sealed") {
		t.Errorf("the refusal does not say why: %v", err)
	}

	// A decision cannot be made either: there is no identity key to sign one
	// with, and an unsignable decision is not an approval.
	resp, err := inst.Submit(context.Background(), &ladulasv1.ApprovalRequest{
		RequestId: "sealed",
		Kind:      ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
	})
	if err != nil {
		t.Fatalf("submit while sealed: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Errorf("a sealed instance decided %v", resp.GetDecision())
	}
}

func TestUnlockNeedsTheRightPassphrase(t *testing.T) {
	inst := start(t)
	inst.lock(t, true)

	if err := inst.unlock(t, "hunter2"); err == nil {
		t.Fatal("the store opened with the wrong passphrase")
	}

	if state := inst.State(); state != ladulasv1.LockState_LOCK_STATE_SEALED {
		t.Fatalf("state %v after a failed unlock", state)
	}

	err := inst.unlock(t, "")
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("unlock with nothing: %v, want the passphrase to be asked for", err)
	}

	if err := inst.unlock(t, testPassphrase); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	status := inst.status(t)

	if status.GetLockState() != ladulasv1.LockState_LOCK_STATE_UNLOCKED {
		t.Fatalf("state %v after unlocking", status.GetLockState())
	}

	if status.GetKeys() != 1 {
		t.Errorf("the unlocked instance reports %d keys", status.GetKeys())
	}

	if len(inst.KeyRefs()) != 1 {
		t.Error("the agent has no keys after unlocking")
	}

	if len(inst.PeerAddresses()) != 1 {
		t.Errorf("the peer listener did not come back: %v", inst.PeerAddresses())
	}
}

// A soft lock keeps everything and takes away only the right to answer here.
func TestSoftLockKeepsTheKeysAndTheListener(t *testing.T) {
	inst := start(t)

	here := &countingHandler{}
	inst.RegisterApprover(here)

	inst.lock(t, false)

	status := inst.status(t)

	if status.GetLockState() != ladulasv1.LockState_LOCK_STATE_LOCKED {
		t.Fatalf("state %v after locking", status.GetLockState())
	}

	if len(inst.KeyRefs()) != 1 {
		t.Error("a soft lock took the keys away")
	}

	if len(inst.PeerAddresses()) != 1 {
		t.Error("a soft lock took the peer listener down")
	}

	if status.GetFingerprint() == "" {
		t.Error("a soft-locked instance cannot say who it is")
	}

	if inst.Engine().HasLocalApprover() {
		t.Error("a locked instance still claims somebody here can answer")
	}

	// And the control surface is still the whole surface.
	if _, err := inst.client.Control().ListPublications(context.Background(),
		connect.NewRequest(&ladulasv1.ListPublicationsRequest{})); err != nil {
		t.Errorf("a soft-locked instance refused a management call: %v", err)
	}

	if err := inst.unlock(t, testPassphrase); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	if !inst.Engine().HasLocalApprover() {
		t.Error("the local approver did not come back")
	}
}

// An approver registered while the store was sealed is attached the moment
// there is an engine to attach it to: the tray does not restart when the store
// does.
func TestApproversSurviveSealing(t *testing.T) {
	inst := start(t)
	inst.lock(t, true)

	here := &countingHandler{}
	remove := inst.RegisterApprover(here)

	if err := inst.unlock(t, testPassphrase); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	if !inst.Engine().HasLocalApprover() {
		t.Fatal("the approver was not attached to the new engine")
	}

	remove()

	if inst.Engine().HasLocalApprover() {
		t.Error("the approver survived being removed")
	}
}

// Every transition is in the log, which is the only account of what happened to
// a machine nobody was sitting at (§10).
func TestTransitionsAreAudited(t *testing.T) {
	inst := start(t)

	inst.lock(t, false)
	inst.lock(t, true)

	if err := inst.unlock(t, testPassphrase); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	entries, err := approval.ReadAuditLog(inst.Config.AuditPath(), 0)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}

	var lifecycle []string

	for _, entry := range entries {
		if entry.GetEvent() == ladulasv1.AuditEvent_AUDIT_EVENT_LIFECYCLE {
			lifecycle = append(lifecycle, entry.GetDetail())
		}
	}

	want := []string{
		"local approval was suspended",
		"the store was sealed",
		"the store was unlocked",
	}

	for _, phrase := range want {
		if !containsPhrase(lifecycle, phrase) {
			t.Errorf("the log does not record %q: %v", phrase, lifecycle)
		}
	}
}

func containsPhrase(entries []string, phrase string) bool {
	for _, entry := range entries {
		if strings.Contains(entry, phrase) {
			return true
		}
	}

	return false
}

// countingHandler is a local prompt that nobody answers; what it is for is
// being in or out of the eligible set.
type countingHandler struct{}

var (
	_ approval.Handler     = (*countingHandler)(nil)
	_ approval.LocalPrompt = (*countingHandler)(nil)
)

func (h *countingHandler) ID() string {
	return "test"
}

func (h *countingHandler) LocalPrompt() {
}

func (h *countingHandler) Decide(
	ctx context.Context, _ *approval.Request,
) (*approval.Answer, error) {
	<-ctx.Done()

	return nil, ctx.Err()
}
