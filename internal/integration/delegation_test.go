package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/internal/testutil"
	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// TestADelegatedGrantOutlivesItsApprover is the whole of what M7 is for.
//
// Approve for a while, then take the approver away entirely — no handler, no
// human, nothing that could answer — and commit again. Before decision P the
// second commit waited for somebody to wake up and then failed with
// NO_APPROVER, which on a phone is the ordinary state of the world. The
// delegation is what makes an hour mean an hour.
//
// The key is the requester's own, which is the case decision P is about. The
// approver holds nothing, so it has nothing to be in the loop about.
func TestADelegatedGrantOutlivesItsApprover(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)
	signer := buildSigner(t)

	requester := startPeerInstance(t, "workstation")
	approver := startPeerInstance(t, "phone")

	human := &handHandler{
		name: "phone",
		answer: &approval.Answer{
			Decision: ladulasv1.Decision_DECISION_APPROVE,
			Reason:   "approved for an hour",
			GrantTTL: time.Hour,
		},
	}

	unregister := approver.app.RegisterApprover(human)

	pairOverTheCommandLine(t, cli, approver, requester)

	// Both commits are in the same repository, because a grant is scoped to
	// one: two commits in two temporary directories would be two scopes, and
	// the second would rightly not be covered.
	repo := t.TempDir()

	// The first commit is answered by a person, who says "and for the next
	// hour as well".
	verified, err := signIn(t, repo, requester, signer, git,
		"tighten the socket permissions")
	if err != nil {
		t.Fatalf("the first commit was not signed: %v\n%s", err, verified)
	}

	if len(human.seenRequests()) != 1 {
		t.Fatalf("the approver was asked %d times about the first commit",
			len(human.seenRequests()))
	}

	// The approver goes away. Not asleep, not slow — gone: nothing registered
	// that could answer anything.
	unregister()

	verified, err = signIn(t, repo, requester, signer, git,
		"say what the socket permissions are for, at greater length")
	if err != nil {
		t.Fatalf("the second commit was not signed with nobody to ask: %v\n%s",
			err, verified)
	}

	if !strings.Contains(verified, `Good "git" signature`) {
		t.Fatalf("git did not verify the second signature:\n%s", verified)
	}

	if len(human.seenRequests()) != 1 {
		t.Errorf("the approver was asked %d times, want 1 — "+
			"the delegation did not answer the second commit", len(human.seenRequests()))
	}

	// The approver kept a record of what it promised, marked as handed over,
	// or it could never list or revoke it.
	grants, err := approver.app.Vault().Grants()
	if err != nil {
		t.Fatalf("read the approver's grants: %v", err)
	}

	if len(grants) != 1 {
		t.Fatalf("the approver kept %d grants", len(grants))
	}

	if !grants[0].GetDelegated() {
		t.Error("the approver kept the promise instead of handing it over")
	}

	if grants[0].GetDelegateFingerprint() != requester.fingerprint() {
		t.Errorf("the promise was handed to %q",
			grants[0].GetDelegateFingerprint())
	}

	// Both commits are listed against the promise, and the first one is there
	// too: somebody who says "approve, and for the next hour as well" approved
	// this one, and a list that started at the second would be missing the only
	// entry anybody actually looked at.
	//
	// The second arrived by the push — the approver here is a desktop that can
	// be dialled, so the requester reported it the moment it happened.
	waitForGrantUses(t, approver, grants[0].GetGrantId(), 2)

	// Nothing is left owing, because it was acknowledged as it was reported.
	if owed := requester.app.Vault().UnreportedUses(
		approver.fingerprint()); len(owed) != 0 {
		t.Errorf("the requester still owes %d uses after reporting them",
			len(owed))
	}

	// And the machine acting on the promise can say which promise it is.
	//
	// `grants list` reads what this instance promised, and a delegation is in
	// another part of the store entirely — so until `delegations list` existed
	// the requester could self-approve for an hour with nothing local that even
	// named the permission it was using, which is not a promise anybody there
	// could audit (§9).
	held := runCLI(t, cli, requester, "delegations", "list")

	if !strings.Contains(held, approver.name) {
		t.Errorf("the listing does not say who promised it:\n%s", held)
	}

	if !strings.Contains(held, "git signing") {
		t.Errorf("the listing does not say what it covers:\n%s", held)
	}

	// The promises this instance made are a different list, and it is empty:
	// the requester made nobody any promises.
	if own := runCLI(t, cli, requester, "grants", "list"); !strings.Contains(
		own, "No live grants") {
		t.Errorf("a delegation turned up among the promises made here:\n%s", own)
	}

	// And the approver can give it more time, which means re-signing it and
	// getting it across (decision V). The requester is holding the artifact, so
	// the only thing that proves the extension is the artifact it holds after.
	before := heldExpiry(t, requester, grants[0].GetGrantId())

	runCLI(t, cli, approver, "grants", "extend", grants[0].GetGrantId(), "4h")

	after := heldExpiry(t, requester, grants[0].GetGrantId())

	if !after.After(before) {
		t.Errorf("the machine holding the promise still stops at %s", before)
	}

	// One promise, still: the same identifier, and the account of what it has
	// covered carried across rather than started again.
	held = runCLI(t, cli, requester, "delegations", "list")

	if strings.Count(held, grants[0].GetGrantId()) != 1 {
		t.Errorf("the extension left more than one promise:\n%s", held)
	}

	if !strings.Contains(held, "2") {
		t.Errorf("the extension reset what the promise had covered:\n%s", held)
	}
}

// heldExpiry is when the machine acting on a promise thinks it runs out, which
// is the only thing an extension can be measured by: the artifact it holds is
// what it honours, whatever the approver's own record says.
func heldExpiry(
	t *testing.T, inst *peerInstance, id string,
) time.Time {
	t.Helper()

	held, err := inst.app.Vault().Delegations()
	if err != nil {
		t.Fatalf("read the delegations: %v", err)
	}

	for _, item := range held {
		if item.GetDelegation().GetDelegationId() == id {
			return item.GetDelegation().GetExpiresAt().AsTime()
		}
	}

	t.Fatalf("the requester holds no delegation %s", id)

	return time.Time{}
}

// Revoking a delegated grant has to stop the signing, and it has to stop it
// now.
//
// The local record is the smaller half of the promise: the requester holds a
// signed delegation and honours it without asking anybody, so removing the
// approver's copy and waiting for reconciliation leaves a window in which the
// grant has been revoked everywhere except where it is being used. That window
// is the whole of what somebody revoking a grant is trying to close.
func TestRevokingADelegationStopsTheSigningAtOnce(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)
	signer := buildSigner(t)

	requester := startPeerInstance(t, "workstation")
	approver := startPeerInstance(t, "phone")

	human := &handHandler{
		name: "phone",
		answer: &approval.Answer{
			Decision: ladulasv1.Decision_DECISION_APPROVE,
			Reason:   "approved for an hour",
			GrantTTL: time.Hour,
		},
	}

	unregister := approver.app.RegisterApprover(human)

	pairOverTheCommandLine(t, cli, approver, requester)

	repo := t.TempDir()

	if _, err := signIn(t, repo, requester, signer, git,
		"tighten the socket permissions"); err != nil {
		t.Fatalf("the first commit was not signed: %v", err)
	}

	grants, err := approver.app.Vault().Grants()
	if err != nil {
		t.Fatalf("read the approver's grants: %v", err)
	}

	if len(grants) != 1 || !grants[0].GetDelegated() {
		t.Fatalf("the approver holds %d grants, delegated %v",
			len(grants), len(grants) == 1 && grants[0].GetDelegated())
	}

	// The approver takes the promise back. The human stays registered this
	// time, so that a request reaching the approver would be approved — which
	// makes the test about the delegation and not about there being nobody
	// home.
	runCLI(t, cli, approver, "grants", "revoke", grants[0].GetGrantId())

	// The requester must have been told as part of revoking, rather than at
	// the next reconciliation.
	held, err := requester.app.Vault().Delegations()
	if err != nil {
		t.Fatalf("read the requester's delegations: %v", err)
	}

	if len(held) != 0 {
		t.Fatalf("the requester still holds %d delegations after the revoke",
			len(held))
	}

	// And now the approver goes away, so that anything signed from here on
	// could only have been signed by a delegation that outlived its
	// revocation.
	unregister()

	if _, err := signIn(t, repo, requester, signer, git,
		"say what the socket permissions are for"); err == nil {
		t.Fatal("a commit was signed after the grant behind it was revoked")
	}
}

// A revocation that could not be delivered is kept, shown, and finished later.
//
// Neither tidy answer is true when the holder is unreachable. Removing the
// grant would say the signing had stopped while the machine goes on signing
// without asking anybody; refusing the revoke outright would throw the
// intent away, and the next reconciliation would renew a promise somebody had
// already taken back. So the grant stays, marked, and the next contact ends it.
func TestARevocationThatCouldNotBeDeliveredIsPending(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)
	signer := buildSigner(t)

	requester := startPeerInstance(t, "workstation")
	approver := startPeerInstance(t, "phone")

	human := &handHandler{
		name: "phone",
		answer: &approval.Answer{
			Decision: ladulasv1.Decision_DECISION_APPROVE,
			Reason:   "approved for an hour",
			GrantTTL: time.Hour,
		},
	}

	approver.app.RegisterApprover(human)

	pairOverTheCommandLine(t, cli, approver, requester)

	repo := t.TempDir()

	if _, err := signIn(t, repo, requester, signer, git,
		"tighten the socket permissions"); err != nil {
		t.Fatalf("the first commit was not signed: %v", err)
	}

	grants, err := approver.app.Vault().Grants()
	if err != nil {
		t.Fatalf("read the approver's grants: %v", err)
	}

	if len(grants) != 1 || !grants[0].GetDelegated() {
		t.Fatalf("the approver holds %d grants", len(grants))
	}

	id := grants[0].GetGrantId()

	// The holder goes off the air before the revoke, which is the case this is
	// about: a laptop shut, a phone out of range. Pointing the approver's
	// record of it at a closed port is the same thing from here, and unlike
	// stopping the instance it can be undone.
	record, ok := approver.app.Vault().Peer(requester.fingerprint())
	if !ok {
		t.Fatal("the approver does not know the requester")
	}

	reachable := record.GetAddresses()

	record.Addresses = []string{"127.0.0.1:1"}
	if err := approver.app.Vault().PutPeer(record); err != nil {
		t.Fatalf("take the requester off the air: %v", err)
	}

	runCLI(t, cli, approver, "grants", "revoke", id)

	// Still listed, and marked. A grant that vanished here would say the
	// signing had stopped.
	grants, err = approver.app.Vault().Grants()
	if err != nil {
		t.Fatalf("read the approver's grants: %v", err)
	}

	if len(grants) != 1 {
		t.Fatalf("the undelivered revoke left %d grants", len(grants))
	}

	if !grants[0].GetRevokePending() {
		t.Fatal("the grant is not marked as pending revoke")
	}

	// And the holder is still honouring it, which is what the marking says.
	held, err := requester.app.Vault().Delegations()
	if err != nil {
		t.Fatalf("read the requester's delegations: %v", err)
	}

	if len(held) != 1 {
		t.Fatalf("the requester holds %d delegations", len(held))
	}

	// The holder comes back, and the next reconciliation finishes what the
	// revoke started — on both sides.
	record.Addresses = reachable
	if err := approver.app.Vault().PutPeer(record); err != nil {
		t.Fatalf("put the requester back on the air: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	approver.app.Peer().ReconcileDelegations(ctx)

	waitFor(t, "the delegation to be taken back", func() bool {
		held, err := requester.app.Vault().Delegations()

		return err == nil && len(held) == 0
	})

	waitFor(t, "the pending grant to be removed", func() bool {
		grants, err := approver.app.Vault().Grants()

		return err == nil && len(grants) == 0
	})
}

// waitFor polls a condition, because reconciliation is bookkeeping that runs
// beside the thing anybody was waiting for.
func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)

	for time.Now().Before(deadline) {
		if done() {
			return
		}

		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %s", what)
}

// waitForGrantUses waits for an account to arrive, since reporting one is not
// what the commit was waiting for and does not happen on its way out.
func waitForGrantUses(
	t *testing.T, inst *peerInstance, grantID string, want int,
) []*ladulasv1.GrantUse {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	var got []*ladulasv1.GrantUse

	for time.Now().Before(deadline) {
		grants, err := inst.app.Vault().Grants()
		if err != nil {
			t.Fatalf("read the grants: %v", err)
		}

		for _, grant := range grants {
			if grant.GetGrantId() != grantID {
				continue
			}

			got = grant.GetRecentUses()

			if int(grant.GetUseCount()) >= want {
				return got
			}
		}

		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("the grant lists %d uses, want %d: %+v", len(got), want, got)

	return nil
}

// A key the approver holds itself is the other half of decision P, and is the
// case that cannot be delegated: the private half never moves, so the requester
// has to come back for every signature whatever anybody agreed to.
//
// Taking the approver away therefore stops the next commit, and should. This is
// the test that would fail if somebody made delegation unconditional.
func TestAGrantOverABorrowedKeyStaysWithItsHolder(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)
	signer := buildSigner(t)

	// The requester holds no keys; the holder lends it one.
	requester := startKeylessInstance(t, "workstation")
	holder := startPeerInstance(t, "phone")

	human := &handHandler{
		name: "phone",
		answer: &approval.Answer{
			Decision: ladulasv1.Decision_DECISION_APPROVE,
			Reason:   "approved for an hour",
			GrantTTL: time.Hour,
		},
	}

	unregister := holder.app.RegisterApprover(human)
	defer unregister()

	pairOverTheCommandLine(t, cli, holder, requester)

	// Pairing grants directions, never keys. Lending one is a third decision
	// and a separate command (§7), and it is what makes this the borrowed-key
	// case rather than the requester's-own-key one.
	keys := holder.app.Vault().KeyRefs()
	if len(keys) != 1 {
		t.Fatalf("the holder holds %d keys", len(keys))
	}

	runCLI(t, cli, holder,
		"peers", "allow", "workstation", "--request", "--key", "work")

	waitForBorrowedKey(t, requester, keys[0].GetFingerprint())

	// The key it signs with is the holder's, so that is the public half git is
	// pointed at.
	_, verified, err := signOnWith(t, requester, holder.publicKey, signer, git,
		"tighten the socket permissions")
	if err != nil {
		t.Fatalf("the first commit was not signed: %v\n%s", err, verified)
	}

	grants, err := holder.app.Vault().Grants()
	if err != nil {
		t.Fatalf("read the holder's grants: %v", err)
	}

	if len(grants) != 1 {
		t.Fatalf("the holder kept %d grants", len(grants))
	}

	if grants[0].GetDelegated() {
		t.Fatal("a promise about a key the holder holds was handed over")
	}

	// The requester holds nothing it could apply, because there was nothing to
	// hand over.
	held, err := requester.app.Vault().UsableDelegations()
	if err != nil {
		t.Fatalf("read the requester's delegations: %v", err)
	}

	if len(held) != 0 {
		t.Errorf("the requester holds %d delegations for a key it cannot use",
			len(held))
	}
}
