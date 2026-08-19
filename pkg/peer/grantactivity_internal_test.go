package peer

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// A phone cannot be dialled, so nothing can be pushed to it. What it gets is a
// flag on the poll it was already making, and it comes back for the account
// itself (decision P).
//
// This is the path that matters in practice: the approver that most wants to
// know what its promises have been doing is the one that is hardest to tell.
func TestAPhoneIsToldThereIsActivityToCollect(t *testing.T) {
	phone := newPhone(t, "phone")
	requester := newInstance(t, "builder")

	scanQR(t, requester, phone)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The phone promised something and handed it over; the requester has been
	// applying it while nobody was looking.
	grantID := "grant-1"

	addGrant(t, phone, &ladulasv1.Grant{
		GrantId:             grantID,
		Description:         "git signing in /home/hugo/foo, for 1 hour",
		ExpiresAt:           inAnHour(),
		Delegated:           true,
		DelegateFingerprint: requester.identity.Fingerprint(),
		DelegateName:        "builder",
	})

	addDelegation(t, requester, &ladulasv1.Delegation{
		DelegationId:         grantID,
		ExpiresAt:            inAnHour(),
		ApproverFingerprint:  phone.identity.Fingerprint(),
		RequesterFingerprint: requester.identity.Fingerprint(),
	})

	for _, id := range []string{"req-1", "req-2"} {
		if err := requester.ledger.RecordDelegationUse(&ladulasv1.GrantUse{
			GrantId:   grantID,
			RequestId: id,
			Kind:      ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
			Subject:   "a commit in /home/hugo/foo",
		}); err != nil {
			t.Fatalf("record a use: %v", err)
		}
	}

	// The requester cannot reach the phone to push any of that, which is the
	// whole reason the flag exists.
	if requester.node.link(phone.identity.Fingerprint()) != nil {
		t.Fatal("the requester holds a link to a phone it cannot dial")
	}

	// One round of poll-on-open. There is nothing waiting to approve — the
	// only thing to collect is the account.
	if err := phone.node.Collect(ctx, 0); err != nil {
		t.Fatalf("collect: %v", err)
	}

	filed := phone.ledger.recorded()

	if len(filed) != 2 {
		t.Fatalf("the phone recorded %d uses, want 2: %+v", len(filed), filed)
	}

	for _, use := range filed {
		if use.GetGrantId() != grantID {
			t.Errorf("a use was filed against %q", use.GetGrantId())
		}
	}

	// And the requester has been told they arrived, so a second round does not
	// report them again.
	if owed := requester.ledger.UnreportedUses(
		phone.identity.Fingerprint()); len(owed) != 0 {
		t.Errorf("the requester still owes %d uses", len(owed))
	}

	if err := phone.node.Collect(ctx, 0); err != nil {
		t.Fatalf("collect again: %v", err)
	}

	if filed := phone.ledger.recorded(); len(filed) != 2 {
		t.Errorf("a second round filed %d uses in total, want 2", len(filed))
	}
}

// A peer may report against promises this instance actually made to it. The
// check is worth having because the report is the one direction a requester
// drives, and what it names is entirely its own choosing — a delegation this
// instance has since taken back must not be able to file anything.
func TestAReportAgainstAPromiseThatIsGoneIsIgnored(t *testing.T) {
	approver := newInstance(t, "desktop")
	requester := newInstance(t, "builder")

	pair(t, approver, requester)

	// The requester holds a delegation the approver has no record of, which is
	// what a revoked or expired promise looks like from the other side.
	addDelegation(t, requester, &ladulasv1.Delegation{
		DelegationId:         "long-gone",
		ExpiresAt:            inAnHour(),
		ApproverFingerprint:  approver.identity.Fingerprint(),
		RequesterFingerprint: requester.identity.Fingerprint(),
	})

	if err := requester.ledger.RecordDelegationUse(&ladulasv1.GrantUse{
		GrantId:   "long-gone",
		RequestId: "req-1",
	}); err != nil {
		t.Fatalf("record a use: %v", err)
	}

	requester.node.PushGrantActivity(approver.identity.Fingerprint())

	// Give the push every chance to be wrong.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(approver.ledger.recorded()) > 0 {
			t.Fatal("the approver filed a use against a promise it never made")
		}

		time.Sleep(20 * time.Millisecond)
	}

	// And the requester still owes it, because nothing acknowledged it.
	if owed := requester.ledger.UnreportedUses(
		approver.identity.Fingerprint()); len(owed) != 1 {
		t.Errorf("the requester owes %d uses, want 1 — an unacknowledged "+
			"report should stay in the ledger", len(owed))
	}
}

func inAnHour() *timestamppb.Timestamp {
	return timestamppb.New(time.Now().Add(time.Hour))
}

func addGrant(t *testing.T, inst *instance, grant *ladulasv1.Grant) {
	t.Helper()

	if err := inst.ledger.AddGrant(grant); err != nil {
		t.Fatalf("add a grant: %v", err)
	}
}

func addDelegation(t *testing.T, inst *instance, d *ladulasv1.Delegation) {
	t.Helper()

	if err := inst.ledger.AddDelegation(nil, d); err != nil {
		t.Fatalf("add a delegation: %v", err)
	}
}
