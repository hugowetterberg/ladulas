package keystore_test

import (
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

func peerKey(t *testing.T, name string) ssh.PublicKey {
	t.Helper()

	id, _, err := identity.Generate(name)
	if err != nil {
		t.Fatalf("generate an identity: %v", err)
	}

	return id.PublicKey()
}

// TestTrustRecordsSurviveTheStore: trust records live in the encrypted document
// with the keys (§10), so a paired peer is still paired after a restart, and
// the record that comes back is the one that went in.
func TestTrustRecordsSurviveTheStore(t *testing.T) {
	vault, opts := newVault(t)

	key := peerKey(t, "desktop")
	record := trust.NewRecord("desktop", key,
		[]string{"100.64.0.2:7373", "127.0.0.1:7373"}, true, false, false)

	if err := vault.PutPeer(record); err != nil {
		t.Fatalf("store a peer: %v", err)
	}

	reopened, err := keystore.Open(opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	peers := reopened.Peers()
	if len(peers) != 1 {
		t.Fatalf("the reopened store holds %d peers", len(peers))
	}

	got := peers[0]

	if got.GetFingerprint() != ssh.FingerprintSHA256(key) {
		t.Errorf("the peer came back as %s", got.GetFingerprint())
	}

	if !got.GetMayApprove() || got.GetMayRequest() {
		t.Errorf("the directions came back as approve=%v request=%v",
			got.GetMayApprove(), got.GetMayRequest())
	}

	if len(got.GetAddresses()) != 2 {
		t.Errorf("the addresses came back as %v", got.GetAddresses())
	}

	// And the record's key parses back to the identity it names.
	if _, err := trust.PublicKey(got); err != nil {
		t.Errorf("the stored record does not parse: %v", err)
	}
}

// TestPeerLookupByNameOrFingerprint is what the command line depends on: nobody
// types a fingerprint when the peer has a name.
func TestPeerLookupByNameOrFingerprint(t *testing.T) {
	vault, _ := newVault(t)

	key := peerKey(t, "desktop")
	fingerprint := ssh.FingerprintSHA256(key)

	if err := vault.PutPeer(
		trust.NewRecord("Desktop", key, nil, true, true, false)); err != nil {
		t.Fatalf("store a peer: %v", err)
	}

	for _, ref := range []string{"Desktop", "desktop", fingerprint} {
		if _, ok := vault.Peer(ref); !ok {
			t.Errorf("the peer could not be found by %q", ref)
		}
	}

	if _, ok := vault.Peer("nobody"); ok {
		t.Error("a peer was found that is not there")
	}
}

// TestRepairingReplacesTheRecord: re-pairing a machine that was reinstalled is
// ordinary, and the identity key is what decides whether it is the same peer.
func TestRepairingReplacesTheRecord(t *testing.T) {
	vault, _ := newVault(t)

	key := peerKey(t, "desktop")

	if err := vault.PutPeer(
		trust.NewRecord("desktop", key, nil, true, false, false)); err != nil {
		t.Fatalf("store a peer: %v", err)
	}

	if err := vault.PutPeer(
		trust.NewRecord("desktop", key, nil, true, true, false)); err != nil {
		t.Fatalf("re-store a peer: %v", err)
	}

	if peers := vault.Peers(); len(peers) != 1 {
		t.Fatalf("re-pairing produced %d records", len(peers))
	}

	// A different key is a different peer, and gets a record of its own.
	if err := vault.PutPeer(trust.NewRecord(
		"reinstalled", peerKey(t, "reinstalled"), nil, true, true, false)); err != nil {
		t.Fatalf("store a second peer: %v", err)
	}

	if peers := vault.Peers(); len(peers) != 2 {
		t.Fatalf("a new identity produced %d records", len(peers))
	}
}

// TestDirectionsAndRevocation covers what the command line does to a record.
func TestDirectionsAndRevocation(t *testing.T) {
	vault, _ := newVault(t)

	key := peerKey(t, "desktop")
	fingerprint := ssh.FingerprintSHA256(key)

	if err := vault.PutPeer(
		trust.NewRecord("desktop", key, nil, true, true, false)); err != nil {
		t.Fatalf("store a peer: %v", err)
	}

	updated, err := vault.SetPeerDirections("desktop", trust.Directions{MayRequest: true})
	if err != nil {
		t.Fatalf("set directions: %v", err)
	}

	if updated.GetMayApprove() || !updated.GetMayRequest() {
		t.Errorf("the directions are approve=%v request=%v",
			updated.GetMayApprove(), updated.GetMayRequest())
	}

	removed, err := vault.RemovePeer("desktop")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if removed != fingerprint {
		t.Errorf("revoking reported %s, want %s", removed, fingerprint)
	}

	if peers := vault.Peers(); len(peers) != 0 {
		t.Errorf("%d peers survived revocation", len(peers))
	}

	if _, err := vault.RemovePeer("desktop"); !errors.Is(err, trust.ErrNoSuchPeer) {
		t.Errorf("revoking a forgotten peer gave %v", err)
	}

	if _, err := vault.SetPeerDirections("desktop", trust.Directions{MayApprove: true, MayRequest: true}); !errors.Is(
		err, trust.ErrNoSuchPeer) {
		t.Errorf("changing a forgotten peer gave %v", err)
	}
}

// TestBorrowedKeysAreNamedByFingerprint: a peer's key access is written down as
// fingerprints whatever the caller typed, because a label is a name this
// instance chose and can change, and a fingerprint is the key.
func TestBorrowedKeysAreNamedByFingerprint(t *testing.T) {
	vault, _ := newVault(t)

	work, err := vault.GenerateKey("work", "work@example.test")
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	if _, err := vault.GenerateKey("spare", "spare@example.test"); err != nil {
		t.Fatalf("generate a second key: %v", err)
	}

	key := peerKey(t, "headless")

	if err := vault.PutPeer(
		trust.NewRecord("headless", key, nil, false, true, false)); err != nil {
		t.Fatalf("store a peer: %v", err)
	}

	// A record starts with no key access at all: pairing grants directions, not
	// keys (§7).
	record, _ := vault.Peer("headless")
	if trust.MayUseKey(record, work.GetFingerprint()) {
		t.Error("a freshly paired peer may already borrow a key")
	}

	// Named by label, stored as a fingerprint, and repeated names collapse.
	record, err = vault.SetPeerDirections("headless", trust.Directions{
		MayRequest:  true,
		AllowedKeys: []string{"work", work.GetFingerprint()},
	})
	if err != nil {
		t.Fatalf("allow a key: %v", err)
	}

	if got := record.GetAllowedKeyFingerprints(); len(got) != 1 ||
		got[0] != work.GetFingerprint() {
		t.Fatalf("the record allows %v", record.GetAllowedKeyFingerprints())
	}

	if !trust.MayUseKey(record, work.GetFingerprint()) {
		t.Error("the allowed key is not allowed")
	}

	if trust.MayUseKey(record, "SHA256:somebody-elses-key") {
		t.Error("a key that was never named is allowed")
	}

	// Leaving --key out takes the access away, since the flags describe the
	// state wanted rather than a change to make.
	record, err = vault.SetPeerDirections("headless",
		trust.Directions{MayRequest: true})
	if err != nil {
		t.Fatalf("withdraw the key: %v", err)
	}

	if trust.MayUseKey(record, work.GetFingerprint()) {
		t.Error("the key survived being left out")
	}

	// All-keys covers a key generated afterwards, which is the whole reason it
	// is a flag rather than a list of everything held at the time.
	record, err = vault.SetPeerDirections("headless",
		trust.Directions{MayRequest: true, AllKeys: true})
	if err != nil {
		t.Fatalf("allow all keys: %v", err)
	}

	later, err := vault.GenerateKey("later", "later@example.test")
	if err != nil {
		t.Fatalf("generate a later key: %v", err)
	}

	if !trust.MayUseKey(record, later.GetFingerprint()) {
		t.Error("all-keys does not cover a key added afterwards")
	}

	// And a key that does not exist is a mistake worth reporting rather than a
	// permission that quietly covers nothing.
	if _, err := vault.SetPeerDirections("headless", trust.Directions{
		AllowedKeys: []string{"no-such-key"},
	}); !errors.Is(err, keystore.ErrNoSuchKey) {
		t.Errorf("allowing an unknown key gave %v", err)
	}
}

// TestAHandedOutRecordIsNeverWrittenTo: the store keeps trust.Store's rule, at
// the layer that has to keep it.
//
// The peer node reads a record it was handed earlier — a link keeps one for the
// life of a connection, and every incoming request is authorized by reading
// fields off one — without taking a lock, while the same store goes on serving
// `ladulas peers allow` and `ladulas peers rename`. That is only safe if a
// record, once handed out, is never written to again, and it is the kind of
// property that is quietly optimised away by somebody removing a clone.
func TestAHandedOutRecordIsNeverWrittenTo(t *testing.T) {
	vault, _ := newVault(t)

	work, err := vault.GenerateKey("work", "work@example.test")
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	key := peerKey(t, "phone")

	err = vault.PutPeer(trust.NewRecord("phone", key, nil, true, false, false))
	if err != nil {
		t.Fatalf("store a peer: %v", err)
	}

	// What a link would be holding, and what a request would be authorized
	// against.
	held, ok := vault.Peer("phone")
	if !ok {
		t.Fatal("the peer that was just stored is not there")
	}

	listed := vault.Peers()

	// Everything that changes a peer, in one go.
	if _, err := vault.SetPeerDirections("phone", trust.Directions{
		MayApprove:  false,
		MayRequest:  true,
		AllowedKeys: []string{"work"},
	}); err != nil {
		t.Fatalf("set directions: %v", err)
	}

	if _, err := vault.RenamePeer("phone", "hugo's phone"); err != nil {
		t.Fatalf("rename: %v", err)
	}

	if !held.GetMayApprove() || held.GetMayRequest() {
		t.Error("the record handed out earlier had its directions rewritten")
	}

	if trust.MayUseKey(held, work.GetFingerprint()) {
		t.Error("the record handed out earlier had a key access granted on it")
	}

	if held.GetName() != "phone" {
		t.Errorf("the record handed out earlier was renamed to %q", held.GetName())
	}

	if len(listed) != 1 || listed[0].GetName() != "phone" {
		t.Errorf("the listing handed out earlier was rewritten: %v", listed)
	}

	// And the change did land, so none of the above is passing because nothing
	// happened.
	current, ok := vault.Peer("hugo's phone")
	if !ok {
		t.Fatal("the peer cannot be found under its new name")
	}

	if !current.GetMayRequest() || !trust.MayUseKey(current, work.GetFingerprint()) {
		t.Error("the change did not reach the store")
	}

	// A record the caller was given is the caller's: scribbling on it must not
	// reach the store either.
	current.Name = "somebody else"
	current.MayRequest = false

	again, ok := vault.Peer("hugo's phone")
	if !ok {
		t.Fatal("writing to a returned record renamed the stored peer")
	}

	if !again.GetMayRequest() {
		t.Error("writing to a returned record changed the stored permissions")
	}
}

// TestAHandedOutPairingIsTheCallersOwn: the store keeps the same rule for the
// pairings under way that it keeps for the records they turn into.
//
// Everything that moves a pairing on changes it — an answer here, the peer's
// answer, the id of the card it raised — and every one of those reads the entry,
// changes what it read, and puts it back. That is a change to one entry rather
// than to whatever the command that started the pairing, the reconciliation loop
// and the confirmation on screen are all holding, and the reason is here: a read
// hands out a copy, and a write takes one.
func TestAHandedOutPairingIsTheCallersOwn(t *testing.T) {
	vault, _ := newVault(t)

	pending := &storepb.PendingPairing{
		SessionId:   "session-under-test",
		Fingerprint: "SHA256:phone",
		Name:        "phone",
		StartedAt:   timestamppb.Now(),
	}

	if err := vault.PutPendingPairing(pending); err != nil {
		t.Fatalf("write down the pairing: %v", err)
	}

	// The message that went in stays the caller's: writing to it afterwards is
	// not a way into the store.
	pending.Name = "somebody else"

	// What a listing and a lookup hand out are the caller's as well. Both are
	// scribbled on here, and neither scribble may reach the store.
	listed := vault.PendingPairings()
	if len(listed) != 1 {
		t.Fatalf("the store lists %d pairings", len(listed))
	}

	listed[0].Name = "the listing was scribbled on"

	held, ok := vault.PendingPairing("session-under-test")
	if !ok {
		t.Fatal("the pairing that was just written down is not there")
	}

	held.Name = "the lookup was scribbled on"

	fresh, ok := vault.PendingPairing("session-under-test")
	if !ok {
		t.Fatal("the pairing went missing")
	}

	if fresh.GetName() != "phone" {
		t.Errorf("the stored pairing is now called %q", fresh.GetName())
	}

	// And a change made the way the pairing machinery makes one does land,
	// without reaching into anything that was handed out earlier.
	fresh.OurAnswer = ladulasv1.PairingAnswer_PAIRING_ANSWER_ACCEPTED
	fresh.ConfirmationRequestId = "req-under-test"

	if err := vault.PutPendingPairing(fresh); err != nil {
		t.Fatalf("record the answer: %v", err)
	}

	current, ok := vault.PendingPairing("session-under-test")
	if !ok {
		t.Fatal("the answered pairing is gone")
	}

	if current.GetOurAnswer() !=
		ladulasv1.PairingAnswer_PAIRING_ANSWER_ACCEPTED ||
		current.GetConfirmationRequestId() != "req-under-test" {
		t.Error("the answer did not reach the store")
	}

	if listed[0].GetOurAnswer() !=
		ladulasv1.PairingAnswer_PAIRING_ANSWER_UNSPECIFIED ||
		held.GetOurAnswer() !=
			ladulasv1.PairingAnswer_PAIRING_ANSWER_UNSPECIFIED {
		t.Error("a pairing that had been handed out was written to")
	}
}
