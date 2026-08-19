package observe_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/internal/app"
	"github.com/hugowetterberg/ladulas/internal/observe"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The state gauges are read off the instance at scrape time, so they say what
// is true when asked rather than what was true when something last changed.
func TestDaemonStateFollowsTheInstance(t *testing.T) {
	t.Parallel()

	instance, reg := instrumented(t)

	expect(t, reg, `
# HELP ladulas_lock_state Which lock state the store is in, 1 for the current one. sealed means the key is not in memory and nothing here can sign; locked means it is, but approving here is suspended and paired approvers still answer.
# TYPE ladulas_lock_state gauge
ladulas_lock_state{state="locked"} 0
ladulas_lock_state{state="sealed"} 0
ladulas_lock_state{state="unlocked"} 1
ladulas_lock_state{state="uninitialized"} 0
`, "ladulas_lock_state")

	if _, err := instance.Vault().GenerateKey("work", "test@example.test"); err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	expect(t, reg, `
# HELP ladulas_keys SSH keys held in this instance's own store.
# TYPE ladulas_keys gauge
ladulas_keys 1
`, "ladulas_keys")

	// Sealing takes the key out of memory, and with it the ability to answer
	// how many keys there are. The gauge goes away rather than reading zero:
	// "no keys" and "cannot say" are different answers, and a graph that
	// confused them would show every seal as a machine losing its keys.
	if err := instance.Seal("test"); err != nil {
		t.Fatalf("seal: %v", err)
	}

	expect(t, reg, ``, "ladulas_keys")

	expect(t, reg, `
# HELP ladulas_lock_state Which lock state the store is in, 1 for the current one. sealed means the key is not in memory and nothing here can sign; locked means it is, but approving here is suspended and paired approvers still answer.
# TYPE ladulas_lock_state gauge
ladulas_lock_state{state="locked"} 0
ladulas_lock_state{state="sealed"} 1
ladulas_lock_state{state="unlocked"} 0
ladulas_lock_state{state="uninitialized"} 0
`, "ladulas_lock_state")

	lint(t, reg)
}

// Everything the daemon counts, it counts by watching the audit log: the one
// place every request, decision and signature already goes.
func TestDaemonCountsFromTheAuditLog(t *testing.T) {
	t.Parallel()

	instance, reg := instrumented(t)

	created := time.Now()
	request := &ladulasv1.ApprovalRequest{
		RequestId: "req-1",
		CreatedAt: timestamppb.New(created),
		Kind:      ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH,
		Requester: &ladulasv1.RequesterInfo{Local: true},
	}

	record := func(entry *ladulasv1.AuditEntry) {
		t.Helper()

		if err := instance.Audit.Append(entry); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	record(&ladulasv1.AuditEntry{
		Event:   ladulasv1.AuditEvent_AUDIT_EVENT_REQUEST,
		Request: request,
	})

	record(&ladulasv1.AuditEntry{
		Event:   ladulasv1.AuditEvent_AUDIT_EVENT_DECISION,
		Request: request,
		Response: &ladulasv1.ApprovalResponse{
			Decision:  ladulasv1.Decision_DECISION_APPROVE,
			Source:    ladulasv1.DecisionSource_DECISION_SOURCE_USER,
			DecidedAt: timestamppb.New(created.Add(2 * time.Second)),
		},
	})

	record(&ladulasv1.AuditEntry{
		Event: ladulasv1.AuditEvent_AUDIT_EVENT_SIGNATURE,
	})

	// A request from a paired peer is the same shape counted apart, because
	// "somebody else's machine used a key that lives here" is the line worth
	// watching.
	remote := &ladulasv1.ApprovalRequest{
		RequestId: "req-2",
		Kind:      ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
		Requester: &ladulasv1.RequesterInfo{Name: "phone"},
	}

	record(&ladulasv1.AuditEntry{
		Event:   ladulasv1.AuditEvent_AUDIT_EVENT_REQUEST,
		Request: remote,
	})

	record(&ladulasv1.AuditEntry{
		Event:   ladulasv1.AuditEvent_AUDIT_EVENT_DECISION,
		Request: remote,
		Response: &ladulasv1.ApprovalResponse{
			Decision: ladulasv1.Decision_DECISION_DENY,
			Source:   ladulasv1.DecisionSource_DECISION_SOURCE_TIMEOUT,
		},
	})

	expect(t, reg, `
# HELP ladulas_approval_requests_total Approval requests received, by where they came from and what they want. A rise in ssh_auth from a peer is somebody else's machine using a key that lives here.
# TYPE ladulas_approval_requests_total counter
ladulas_approval_requests_total{kind="git_sign",origin="peer"} 1
ladulas_approval_requests_total{kind="ssh_auth",origin="local"} 1
`, "ladulas_approval_requests_total")

	expect(t, reg, `
# HELP ladulas_approval_decisions_total Approval decisions, by what was decided and what decided it. source=user is a person answering a prompt; policy and grant are answers given in advance; no_approver and timeout are requests nobody was there for.
# TYPE ladulas_approval_decisions_total counter
ladulas_approval_decisions_total{decision="approve",origin="local",source="user"} 1
ladulas_approval_decisions_total{decision="deny",origin="peer",source="timeout"} 1
`, "ladulas_approval_decisions_total")

	expect(t, reg, `
# HELP ladulas_signatures_total Signatures actually produced with a key held here. It trails approvals: a request can be approved and then never signed, which is what a requester giving up looks like.
# TYPE ladulas_signatures_total counter
ladulas_signatures_total 1
`, "ladulas_signatures_total")

	lint(t, reg)
}

// instrumented is an unlocked instance with its metrics registered, and no
// sockets served: the numbers come from the instance itself, and serving it
// would only add ways for the test to be slow.
func instrumented(t *testing.T) (*app.App, *prometheus.Registry) {
	t.Helper()

	runtime, err := os.MkdirTemp("", "ldl")
	if err != nil {
		t.Fatalf("runtime directory: %v", err)
	}

	t.Cleanup(func() {
		if err := os.RemoveAll(runtime); err != nil {
			t.Errorf("clean up: %v", err)
		}
	})

	instance, err := app.Create(app.Config{
		DataDir:       t.TempDir(),
		ConfigDir:     t.TempDir(),
		SocketPath:    filepath.Join(runtime, "agent.sock"),
		ControlSocket: filepath.Join(runtime, "control.sock"),
		InstanceName:  "test",
		PeerListen:    app.PeeringOff,
		NoKeyring:     true,
		Passphrase: func(string, bool) ([]byte, error) {
			return []byte("the store passphrase"), nil
		},
	})
	if err != nil {
		t.Fatalf("create the instance: %v", err)
	}

	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	reg := prometheus.NewPedanticRegistry()

	if err := observe.RegisterDaemon(reg, instance); err != nil {
		t.Fatalf("register: %v", err)
	}

	return instance, reg
}
