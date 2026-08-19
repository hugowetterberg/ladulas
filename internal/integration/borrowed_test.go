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

// Decision N, driven the way dogfooding found it missing: a machine borrows a
// key from a machine that is not always there, and wants to be able to see the
// key anyway.
//
// The holder here is sealed rather than switched off, which is the same thing
// from the requester's side and is a real thing to do to a desktop — a sealed
// instance has no identity key and therefore no peer listener at all (§10). A
// phone is the case that actually matters, and it differs only in that it is
// like this most of the time rather than for the length of a test.

// borrowedRows is the "Offered by paired instances" part of `keys list`, which
// is the whole of what a keyless box has to show.
func borrowedRows(t *testing.T, cli string, inst *peerInstance) string {
	t.Helper()

	listing := runCLI(t, cli, inst, "keys", "list")

	_, after, found := strings.Cut(listing, "Offered by paired instances:")
	if !found {
		return ""
	}

	return after
}

// waitForBorrowedState blocks until `keys list` says what the test is waiting
// for.
//
// It asks the holder again on every turn rather than waiting for the presence
// loop, for the reason the signing path does the same: the reconnection backoff
// tops out at a minute (§8), and what is being tested is what the listing says
// rather than how long a link takes to notice.
func waitForBorrowedState(
	t *testing.T, cli string, inst *peerInstance, want string,
) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	deadline := time.Now().Add(30 * time.Second)

	var rows string

	for time.Now().Before(deadline) {
		inst.app.RefreshKeys(ctx)

		rows = borrowedRows(t, cli, inst)
		if strings.Contains(rows, want) {
			return rows
		}

		time.Sleep(200 * time.Millisecond)
	}

	t.Fatalf("%s never reported %q among its borrowed keys:\n%s",
		inst.name, want, rows)

	return rows
}

// TestABorrowedKeyOutlivesItsHolder is the complaint this answers, in the order
// it was made: the key is there, the holder goes away, and the key is still
// there — visibly unusable rather than silently absent.
func TestABorrowedKeyOutlivesItsHolder(t *testing.T) {
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)

	desktop := startPeerInstance(t, "desktop")
	headless := startKeylessInstance(t, "headless")

	defer desktop.app.RegisterApprover(&handHandler{
		name: "desktop",
		answer: &approval.Answer{
			Decision: ladulasv1.Decision_DECISION_APPROVE,
			Reason:   "approved at the desktop",
		},
	})()

	pairOverTheCommandLine(t, cli, desktop, headless)

	keys := desktop.app.Vault().KeyRefs()

	runCLI(t, cli, desktop, "peers", "allow", "headless", "--request", "--key", "work")
	waitForBorrowedKey(t, headless, keys[0].GetFingerprint())

	available := waitForBorrowedState(t, cli, headless, "available")
	if !strings.Contains(available, "work") ||
		!strings.Contains(available, "desktop") {
		t.Fatalf("the borrowed key is not described:\n%s", available)
	}

	// The holder goes away. Sealing takes its peer listener down, because the
	// identity key that authenticates the channel lives inside the store.
	mustLadulas(t, cli, desktop, "", "lock", "--seal")

	gone := waitForBorrowedState(t, cli, headless, "holder not reachable")

	if !strings.Contains(gone, "work") {
		t.Errorf("the key vanished when its holder did:\n%s", gone)
	}

	if !strings.Contains(gone, "desktop") {
		t.Errorf("the listing no longer says whose key it is:\n%s", gone)
	}

	// And it says when, because "asleep since a minute ago" and "asleep since
	// March" are different situations.
	if !strings.Contains(gone, "last seen") {
		t.Errorf("the listing does not say when the holder was last there:\n%s", gone)
	}

	// The agent socket is the one surface that does not advertise it, because
	// ssh would spend one of the server's authentication attempts on a key that
	// cannot sign (§4, decision N).
	if offered := agentKeys(t, headless); len(offered) != 0 {
		t.Errorf("the agent offers %d keys it cannot sign with", len(offered))
	}

	// The other direction — the key going back to available when the holder
	// comes back — is what the "available" assertion above is, and is not
	// re-tested here: these instances bind 127.0.0.1:0, so a holder that is
	// sealed and unsealed comes back on a port its peer has never been told
	// about. That is an artefact of the harness rather than of the design.
}

// TestASigningAttemptOnAnUnreachableHolderFailsLegibly is the other half of
// showing the key: it has to be possible to try, and the try has to end quickly
// and say what happened.
//
// What it must not be is a hang or a denial. A borrowed key whose holder is
// asleep is neither refused nor pending — nobody was asked.
func TestASigningAttemptOnAnUnreachableHolderFailsLegibly(t *testing.T) {
	git := testutil.RequireTool(t, "git")
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)
	signer := buildSigner(t)

	desktop := startPeerInstance(t, "desktop")
	headless := startKeylessInstance(t, "headless")

	defer desktop.app.RegisterApprover(&handHandler{
		name: "desktop",
		answer: &approval.Answer{
			Decision: ladulasv1.Decision_DECISION_APPROVE,
			Reason:   "approved at the desktop",
		},
	})()

	pairOverTheCommandLine(t, cli, desktop, headless)

	keys := desktop.app.Vault().KeyRefs()

	runCLI(t, cli, desktop, "peers", "allow", "headless", "--request", "--key", "work")
	waitForBorrowedKey(t, headless, keys[0].GetFingerprint())

	mustLadulas(t, cli, desktop, "", "lock", "--seal")
	waitForBorrowedState(t, cli, headless, "holder not reachable")

	started := time.Now()

	_, out, err := signOnWith(t, headless, desktop.publicKey, signer, git,
		"a commit nobody is awake to sign")

	took := time.Since(started)

	t.Logf("the attempt took %s and said:\n%s", took, out)

	if err == nil {
		t.Fatal("the commit was signed by an instance that is sealed")
	}

	// The default budget for a signature is five minutes (§9). Anything near it
	// means this waited for a timeout rather than answering from what it knew.
	if took > time.Minute {
		t.Errorf("the attempt took %s, which is a wait rather than an answer", took)
	}

	if !strings.Contains(out, "desktop") {
		t.Errorf("the failure does not name the machine that holds the key:\n%s", out)
	}

	if !strings.Contains(out, "cannot be reached") {
		t.Errorf("the failure does not say the holder is unreachable:\n%s", out)
	}

	// And it is not a refusal. Somebody who reads "denied" goes and looks at
	// their policy; somebody who reads "not reachable" goes and unlocks a
	// laptop.
	if strings.Contains(strings.ToLower(out), "denied") {
		t.Errorf("an unreachable holder was reported as a denial:\n%s", out)
	}

	// Nor is it handed to ssh-keygen. The private half is in the other
	// machine's store, so falling back can only bury the sentence above under
	// whatever ssh-keygen says about a socket it cannot find (§5).
	if strings.Contains(out, "ssh-keygen") {
		t.Errorf("a borrowed key was handed to ssh-keygen, which cannot have it:\n%s",
			out)
	}
}

// TestAKeyTheHolderStopsOfferingDisappears is the other direction: the cache is
// a cache, and a refresh that succeeds is authoritative.
func TestAKeyTheHolderStopsOfferingDisappears(t *testing.T) {
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)

	desktop := startPeerInstance(t, "desktop")
	headless := startKeylessInstance(t, "headless")

	pairOverTheCommandLine(t, cli, desktop, headless)

	keys := desktop.app.Vault().KeyRefs()

	runCLI(t, cli, desktop, "peers", "allow", "headless", "--request", "--key", "work")
	waitForBorrowedKey(t, headless, keys[0].GetFingerprint())
	waitForBorrowedState(t, cli, headless, "available")

	// The lending is taken back on the holder, which is where it was given.
	runCLI(t, cli, desktop, "peers", "allow", "headless", "--request")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	deadline := time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		headless.app.RefreshKeys(ctx)

		if borrowedRows(t, cli, headless) == "" {
			// Forgotten in the store as well, so a restart does not resurrect
			// it: this is a cache and a successful refresh is authoritative.
			if borrowed := headless.app.Vault().BorrowedKeys(); len(borrowed) != 0 {
				t.Fatalf("the store still holds %d withdrawn keys", len(borrowed))
			}

			return
		}

		time.Sleep(200 * time.Millisecond)
	}

	t.Fatalf("the key is still borrowed after the holder stopped offering it:\n%s",
		borrowedRows(t, cli, headless))
}

// TestRevokingAPeerDropsItsKeys follows the shape revocation already had for
// published documentation (§7): a peer that is no longer trusted stops
// occupying the surfaces it was on.
func TestRevokingAPeerDropsItsKeys(t *testing.T) {
	testutil.RequireTool(t, "ssh-keygen")

	cli := buildCLI(t)

	desktop := startPeerInstance(t, "desktop")
	headless := startKeylessInstance(t, "headless")

	pairOverTheCommandLine(t, cli, desktop, headless)

	keys := desktop.app.Vault().KeyRefs()

	runCLI(t, cli, desktop, "peers", "allow", "headless", "--request", "--key", "work")
	waitForBorrowedKey(t, headless, keys[0].GetFingerprint())
	waitForBorrowedState(t, cli, headless, "available")

	revoked := runCLI(t, cli, headless, "peers", "revoke", "desktop")

	t.Logf("headless: ladulas peers revoke desktop\n%s", revoked)

	if rows := borrowedRows(t, cli, headless); rows != "" {
		t.Errorf("a revoked peer's keys are still listed:\n%s", rows)
	}

	// And the store itself has forgotten them, so a restart does not bring them
	// back.
	if borrowed := headless.app.Vault().BorrowedKeys(); len(borrowed) != 0 {
		t.Errorf("the store still holds %d keys from a revoked peer", len(borrowed))
	}
}
