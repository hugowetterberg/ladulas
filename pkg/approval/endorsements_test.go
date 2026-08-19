package approval_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The engine's half of decision AG, and what it is asked to be is narrow: an
// endorsement answers a borrowed signature from the machine it names, within
// its scope, for no longer than this instance would ever promise anything. The
// artifact's own truthfulness was settled before it reached the store; these
// are the checks that could not be made anywhere else.

// memoryEndorsements is an EndorsementStore that keeps promises in memory. It
// answers with everything it was given: the questions the real store filters on
// — does this instance hold the key, does it take approvals from the issuer,
// has anybody retracted it — are the store's, and this is the engine's test.
type memoryEndorsements struct {
	mu    sync.Mutex
	held  []*ladulasv1.Endorsement
	uses  []*ladulasv1.GrantUse
	fails error
}

func (m *memoryEndorsements) UsableEndorsements() ([]*ladulasv1.Endorsement, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.fails != nil {
		return nil, m.fails
	}

	out := make([]*ladulasv1.Endorsement, len(m.held))
	copy(out, m.held)

	return out, nil
}

func (m *memoryEndorsements) RecordEndorsementUse(use *ladulasv1.GrantUse) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.uses = append(m.uses, use)

	return nil
}

// borrowedRequest is what a keyless requester sends a holder: the same request
// as any other, with the requesting instance named by the channel rather than
// by the message.
func borrowedRequest(requester string) *ladulasv1.ApprovalRequest {
	msg := proto.CloneOf(gitSignRequest())
	msg.RequestId = "borrowed-1"
	msg.Requester = &ladulasv1.RequesterInfo{
		InstanceId: requester,
		Name:       "pietro",
	}

	return msg
}

func liveEndorsement(requester string, ttl time.Duration) *ladulasv1.Endorsement {
	now := time.Now()

	return &ladulasv1.Endorsement{
		EndorsementId: "grant-1",
		Scope: &ladulasv1.GrantScope{
			KeyFingerprint:      "SHA256:workkey",
			Kind:                ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
			RequesterInstanceId: requester,
		},
		CreatedAt:            timestamppb.New(now),
		ExpiresAt:            timestamppb.New(now.Add(ttl)),
		Description:          "sign for an hour",
		IssuerFingerprint:    "SHA256:iphone",
		IssuerName:           "iPhone",
		RequesterFingerprint: requester,
		RequesterName:        "pietro",
		KeyFingerprint:       "SHA256:workkey",
	}
}

func endorsedEngine(
	t *testing.T, held ...*ladulasv1.Endorsement,
) (*approval.Engine, *memoryEndorsements) {
	t.Helper()

	id, _, err := identity.Generate("guppy")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	store := &memoryEndorsements{held: held}

	engine, err := approval.New(approval.Options{
		Identity:     id,
		Policy:       approval.DefaultPolicy(),
		Grants:       &memoryGrants{},
		Endorsements: store,
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	return engine, store
}

// The promise a holder made is kept by another holder, with nobody asked. This
// is the whole feature: guppy signs for pietro under a promise the phone made,
// while the phone is asleep.
func TestAnotherHoldersPromiseAnswersABorrowedSignature(t *testing.T) {
	engine, store := endorsedEngine(t, liveEndorsement("SHA256:pietro", time.Hour))

	resp, _, err := engine.SubmitPeerSigning(context.Background(),
		borrowedRequest("SHA256:pietro"), []byte("body"))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("decision %v, reason %q", resp.GetDecision(), resp.GetReason())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_GRANT {
		t.Errorf("source %v", resp.GetSource())
	}

	// Answered without a prompt, and said so: a promise spent silently is what
	// §9 will not have.
	if !resp.GetNotifyOnly() {
		t.Error("an endorsed approval did not ask for a notification")
	}

	// And the issuer is owed an account of what its promise did.
	if len(store.uses) != 1 || store.uses[0].GetGrantId() != "grant-1" {
		t.Errorf("the ledger recorded %+v", store.uses)
	}
}

// An endorsement names one machine, and the name is checked against the
// identity the channel authenticated — which signForPeer has already written
// into the request by the time the engine sees it. A copy presented by anybody
// else matches nothing.
func TestAnEndorsementIsOnlyForTheMachineItNames(t *testing.T) {
	engine, _ := endorsedEngine(t, liveEndorsement("SHA256:pietro", time.Hour))

	resp, _, err := engine.SubmitPeerSigning(context.Background(),
		borrowedRequest("SHA256:someone-else"), []byte("body"))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() == ladulasv1.Decision_DECISION_APPROVE {
		t.Fatal("another machine spent a promise made about pietro")
	}

	// Denied for having nobody to ask rather than by a rule: the endorsement
	// simply did not match, and what is left is an ordinary request.
	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER {
		t.Errorf("source %v", resp.GetSource())
	}
}

// The ceiling nobody else can raise. An issuer that wrote itself a month is
// refused by a holder whose policy tops out at eight hours, and the request
// becomes an ordinary one.
func TestAPromiseLongerThanThisInstanceMakesIsNotHonoured(t *testing.T) {
	engine, _ := endorsedEngine(t,
		liveEndorsement("SHA256:pietro", 30*24*time.Hour))

	resp, _, err := engine.SubmitPeerSigning(context.Background(),
		borrowedRequest("SHA256:pietro"), []byte("body"))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() == ladulasv1.Decision_DECISION_APPROVE {
		t.Fatal("a month-long promise was honoured by an instance that promises hours")
	}
}

func TestAnExpiredEndorsementIsNotHonoured(t *testing.T) {
	engine, _ := endorsedEngine(t, liveEndorsement("SHA256:pietro", -time.Minute))

	resp, _, err := engine.SubmitPeerSigning(context.Background(),
		borrowedRequest("SHA256:pietro"), []byte("body"))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() == ladulasv1.Decision_DECISION_APPROVE {
		t.Fatal("an expired promise was honoured")
	}
}

// An endorsement answers a borrowed signature and nothing else. A request that
// arrived for a *decision* belongs to a peer that holds the key itself, and one
// made here is this instance's own to answer from its own grants — passing
// either through a promise made about a third machine would be lending out
// something nobody promised.
func TestAnEndorsementDoesNotAnswerAnythingButABorrowedSignature(t *testing.T) {
	for _, tc := range []struct {
		name   string
		submit func(*approval.Engine, *ladulasv1.ApprovalRequest) (*ladulasv1.ApprovalResponse, error)
	}{
		{
			name: "a request decided here",
			submit: func(
				e *approval.Engine, msg *ladulasv1.ApprovalRequest,
			) (*ladulasv1.ApprovalResponse, error) {
				return e.Submit(context.Background(), msg)
			},
		},
		{
			name: "a peer asking for a decision",
			submit: func(
				e *approval.Engine, msg *ladulasv1.ApprovalRequest,
			) (*ladulasv1.ApprovalResponse, error) {
				resp, _, err := e.SubmitPeer(
					context.Background(), msg, []byte("body"))

				return resp, err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, _ := endorsedEngine(t,
				liveEndorsement("SHA256:pietro", time.Hour))

			resp, err := tc.submit(engine, borrowedRequest("SHA256:pietro"))
			if err != nil {
				t.Fatalf("submit: %v", err)
			}

			if resp.GetDecision() == ladulasv1.Decision_DECISION_APPROVE {
				t.Fatal("an endorsement answered something it was not about")
			}
		})
	}
}
