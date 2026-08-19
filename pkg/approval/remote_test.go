package approval_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// remoteStub is a stubHandler that claims to be a paired peer.
type remoteStub struct {
	stubHandler

	peer string
}

func (h *remoteStub) Peer() string {
	return h.peer
}

var _ approval.RemoteHandler = (*remoteStub)(nil)

func durationOf(d time.Duration) *durationpb.Duration {
	return durationpb.New(d)
}

// TestUnreachableApproversDenyAtOnce: when every approver has failed there is
// nothing left to wait for, and "the desktop was not there" is a different
// thing from "nobody answered in time" — on the terminal and in the log.
func TestUnreachableApproversDenyAtOnce(t *testing.T) {
	f := newEngine(t, approval.NewPolicy(&ladulasv1.PolicyDocument{
		Defaults: &ladulasv1.Defaults{
			SignTimeout: durationOf(30 * time.Second),
		},
	}))

	f.engine.Register(&remoteStub{
		stubHandler: stubHandler{id: "desktop", err: errors.New("connection refused")},
		peer:        "SHA256:desktop",
	})
	f.engine.Register(&remoteStub{
		stubHandler: stubHandler{id: "laptop", err: errors.New("no route to host")},
		peer:        "SHA256:laptop",
	})

	start := time.Now()

	resp, err := f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the engine waited %s for approvers that had already failed", elapsed)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Errorf("decision %v", resp.GetDecision())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER {
		t.Errorf("source %v, want no-approver", resp.GetSource())
	}
}

// TestAPairingIsOfferedNoPromise: a pairing happens once and has no key, so
// "approve for a while" is a question about it that cannot be answered. The
// offer used to be sized from the policy for every kind alike, which put a
// reach, a clock and an hour's worth of buttons under "is this the machine on
// the other screen".
func TestAPairingIsOfferedNoPromise(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	handler := &stubHandler{
		id: "desktop",
		answer: &approval.Answer{
			Decision: ladulasv1.Decision_DECISION_APPROVE,
			Reason:   "confirmed at the desktop",
			// A surface asking for one anyway is answering a question it was
			// not shown, and gets nothing rather than a promise.
			GrantTTL: time.Hour,
		},
	}

	f.engine.Register(handler)

	resp, err := f.engine.Submit(context.Background(), pairingRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("decision %v", resp.GetDecision())
	}

	shown := handler.lastRequest()
	if shown == nil {
		t.Fatal("the approver was never shown anything")
	}

	if shown.GrantMaxTTL != 0 || len(shown.GrantTTLs) != 0 {
		t.Errorf("the pairing card was offered a promise: max %s, %d lengths",
			shown.GrantMaxTTL, len(shown.GrantTTLs))
	}

	if resp.GetGrant() != nil || resp.GetDelegation() != nil {
		t.Error("confirming a pairing made a standing promise")
	}

	grants, err := f.grants.Grants()
	if err != nil {
		t.Fatalf("read grants: %v", err)
	}

	if len(grants) != 0 {
		t.Errorf("a pairing left %d grants behind", len(grants))
	}
}

func pairingRequest() *ladulasv1.ApprovalRequest {
	return &ladulasv1.ApprovalRequest{
		RequestId: "pair-1",
		Kind:      ladulasv1.RequestKind_REQUEST_KIND_PAIRING,
		Requester: &ladulasv1.RequesterInfo{
			InstanceId: "SHA256:thepeer", Name: "builder",
		},
		Operation: &ladulasv1.ApprovalRequest_Pairing{
			Pairing: &ladulasv1.PairingRequest{
				PeerName:         "builder",
				PeerFingerprint:  "SHA256:thepeer",
				PeerMayRequest:   true,
				LocalName:        "desktop",
				LocalFingerprint: "SHA256:ourselves",
			},
		},
	}
}

// noApproverAnswer is what a peer with nobody to ask sends back: a well-formed
// denial that says, in its source, that nothing was asked of anybody.
func noApproverAnswer(peer string) *approval.Answer {
	return &approval.Answer{
		Decision: ladulasv1.Decision_DECISION_DENY,
		Source:   ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER,
		Reason:   peer + ": no approver is available to answer",
	}
}

// TestAPeerWithNobodyToAskDoesNotSettleTheRequest is decision AC, and it is the
// race the local human cannot win: the peer's answer is instant because nothing
// was asked of anybody, and a desktop prompt takes as long as a person takes.
// Pairing an instance that cannot approve was removing the only way to get an
// answer rather than adding a second one.
func TestAPeerWithNobodyToAskDoesNotSettleTheRequest(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	here := &localStub{stubHandler{
		id:     "desktop",
		answer: approveAnswer(),
		delay:  50 * time.Millisecond,
	}}

	f.engine.Register(here)
	f.engine.Register(&remoteStub{
		stubHandler: stubHandler{id: "pietro", answer: noApproverAnswer("pietro")},
		peer:        "SHA256:pietro",
	})

	resp, err := f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Errorf("decision %v (%s), want the desktop's approval",
			resp.GetDecision(), resp.GetReason())
	}

	if here.promptCount() != 1 {
		t.Errorf("the desktop was asked %d times", here.promptCount())
	}
}

// And when the peer is the only approver there is, its report is still the end
// of the request: nothing is left to wait for, and the source says why.
func TestAPeerWithNobodyToAskEndsARequestItIsAloneOn(t *testing.T) {
	f := newEngine(t, approval.NewPolicy(&ladulasv1.PolicyDocument{
		Defaults: &ladulasv1.Defaults{
			SignTimeout: durationOf(30 * time.Second),
		},
	}))

	f.engine.Register(&remoteStub{
		stubHandler: stubHandler{id: "pietro", answer: noApproverAnswer("pietro")},
		peer:        "SHA256:pietro",
	})

	start := time.Now()

	resp, err := f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the engine waited %s for a peer that had already reported", elapsed)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Errorf("decision %v", resp.GetDecision())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER {
		t.Errorf("source %v, want no-approver", resp.GetSource())
	}
}

// A peer's actual answer still wins the race, which is the other half of
// decision AC: what is not a decision is NO_APPROVER, and not a peer that
// answered.
func TestAPeerThatAnsweredStillSettlesTheRequest(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	here := &localStub{stubHandler{
		id:     "desktop",
		answer: approveAnswer(),
		delay:  time.Minute,
	}}

	f.engine.Register(here)
	f.engine.Register(&remoteStub{
		stubHandler: stubHandler{id: "pietro", answer: denyAnswer()},
		peer:        "SHA256:pietro",
	})

	resp, err := f.engine.Submit(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_DENY {
		t.Errorf("decision %v, want the peer's refusal", resp.GetDecision())
	}

	if resp.GetSource() != ladulasv1.DecisionSource_DECISION_SOURCE_USER {
		t.Errorf("source %v, want a person's answer", resp.GetSource())
	}
}

// TestPeerRequestsAreNotPassedOn: an instance decides what a peer asks it, and
// never forwards it to a third instance. Two instances that each named the
// other as an approver would otherwise bounce a request between them.
func TestPeerRequestsAreNotPassedOn(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	local := &stubHandler{id: "gui", answer: approveAnswer()}
	remote := &remoteStub{
		stubHandler: stubHandler{
			id: "desktop", answer: approveAnswer(), delay: time.Millisecond,
		},
		peer: "SHA256:desktop",
	}

	f.engine.Register(local)
	f.engine.Register(remote)

	msg := gitSignRequest()

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	resp, _, err := f.engine.SubmitPeer(context.Background(), msg, body)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		t.Fatalf("decision %v", resp.GetDecision())
	}

	if remote.promptCount() != 0 {
		t.Error("a request from a peer was passed on to another peer")
	}

	if local.promptCount() != 1 {
		t.Errorf("the local approver saw the request %d times", local.promptCount())
	}

	// A local request still reaches both.
	if _, err := f.engine.Submit(context.Background(), gitSignRequest()); err != nil {
		t.Fatalf("submit: %v", err)
	}

	if remote.promptCount() != 1 {
		t.Errorf("the peer saw %d local requests, want 1", remote.promptCount())
	}
}

// TestPeerSubmissionDigestsWhatArrived: the approver signs a digest of the
// bytes it received, not of a re-serialization of them, so the requester can
// check the answer against what it sent.
func TestPeerSubmissionDigestsWhatArrived(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())
	f.engine.Register(&stubHandler{id: "gui", answer: approveAnswer()})

	msg := gitSignRequest()
	msg.RequestId = "from-the-wire"

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	resp, signed, err := f.engine.SubmitPeer(context.Background(), msg, body)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	want := identity.Digest(body)

	if string(resp.GetRequestDigest()) != string(want) {
		t.Error("the response digests something other than what arrived")
	}

	// And the artifact the requester will verify carries that same digest.
	verified, _, err := identity.VerifyApproval(signed)
	if err != nil {
		t.Fatalf("verify the artifact: %v", err)
	}

	if string(verified.GetRequestDigest()) != string(want) {
		t.Error("the signed artifact digests something else")
	}

	if verified.GetRequestId() != "from-the-wire" {
		t.Errorf("the artifact answers %q", verified.GetRequestId())
	}
}

// TestRemoteAnswerKeepsItsApprover: a decision a peer made keeps the peer's
// name on it, and the peer's own artifact reaches the audit log beside this
// instance's signature.
func TestRemoteAnswerKeepsItsApprover(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	peerIdentity, _, err := identity.Generate("desktop")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	artifact, err := peerIdentity.SignApproval(&ladulasv1.ApprovalResponse{
		RequestId: "somewhere-else",
		Decision:  ladulasv1.Decision_DECISION_APPROVE,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	f.engine.Register(&remoteStub{
		stubHandler: stubHandler{
			id: "desktop",
			answer: &approval.Answer{
				Decision: ladulasv1.Decision_DECISION_APPROVE,
				Reason:   "approved on the desktop",
				Approver: peerIdentity.ApproverInfo(false),
				Signed:   artifact,
			},
		},
		peer: peerIdentity.Fingerprint(),
	})

	resp, _, err := f.engine.SubmitSigned(context.Background(), gitSignRequest())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if resp.GetApprover().GetInstanceId() != peerIdentity.Fingerprint() {
		t.Errorf("the decision is attributed to %v", resp.GetApprover())
	}

	if resp.GetApprover().GetLocal() {
		t.Error("a remote decision was recorded as a local one")
	}

	entries, err := approval.ReadAuditLog(f.auditLog, 0)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}

	var found bool

	for _, entry := range entries {
		if entry.GetEvent() != ladulasv1.AuditEvent_AUDIT_EVENT_DECISION {
			continue
		}

		remote := entry.GetRemoteApproval()
		if remote == nil {
			continue
		}

		found = true

		if remote.GetApproverFingerprint() != peerIdentity.Fingerprint() {
			t.Errorf("the log holds an artifact from %s",
				remote.GetApproverFingerprint())
		}

		// The requester's log holds evidence, not its own account: the
		// artifact verifies under the approver's key alone.
		if _, _, err := identity.VerifyApproval(remote); err != nil {
			t.Errorf("the logged artifact does not verify: %v", err)
		}
	}

	if !found {
		t.Error("the audit log holds no artifact from the approving peer")
	}
}

// TestRemoteGrantsStayOnTheApprover: a grant is the approver's promise, so the
// requester never stores one (§18).
func TestRemoteGrantsStayOnTheApprover(t *testing.T) {
	f := newEngine(t, approval.DefaultPolicy())

	f.engine.Register(&remoteStub{
		stubHandler: stubHandler{
			id: "desktop",
			answer: &approval.Answer{
				Decision: ladulasv1.Decision_DECISION_APPROVE,
				Reason:   "approved on the desktop for 3 hours",
			},
		},
		peer: "SHA256:desktop",
	})

	if _, err := f.engine.Submit(context.Background(), gitSignRequest()); err != nil {
		t.Fatalf("submit: %v", err)
	}

	grants, err := f.grants.Grants()
	if err != nil {
		t.Fatalf("read grants: %v", err)
	}

	if len(grants) != 0 {
		t.Errorf("the requester stored %d grants on a peer's say-so", len(grants))
	}
}
