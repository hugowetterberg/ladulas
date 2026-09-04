package trust_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

func newKey(t *testing.T, name string) ssh.PublicKey {
	t.Helper()

	id, _, err := identity.Generate(name)
	if err != nil {
		t.Fatalf("generate an identity: %v", err)
	}

	return id.PublicKey()
}

// TestSecretIsTypable checks the shape of the thing a person reads off one
// screen and types into another.
func TestSecretIsTypable(t *testing.T) {
	secret, err := trust.NewSecret()
	if err != nil {
		t.Fatalf("generate a secret: %v", err)
	}

	display := secret.Display()

	if len(display) != 11 || display[5] != '-' {
		t.Errorf("a code displays as %q, want two groups of five", display)
	}

	for _, r := range strings.ToLower(display) {
		if r == '-' {
			continue
		}

		if strings.ContainsRune("ilou", r) {
			t.Errorf("the code %q contains %q, which is misread", display, r)
		}
	}

	// Typed back with the separator, in the wrong case, and with the
	// look-alikes a person will produce anyway.
	parsed, err := trust.ParseSecret(" " + strings.ToUpper(display) + " ")
	if err != nil {
		t.Fatalf("parse a displayed code: %v", err)
	}

	if !parsed.Equal(secret) {
		t.Errorf("%q parsed back as %q", display, parsed)
	}
}

// TestSecretParsingForgivesLookAlikes covers the substitutions that exist
// because the alphabet leaves those characters out.
func TestSecretParsingForgivesLookAlikes(t *testing.T) {
	// The alphabet has no i, l, o or u, so a code can never legitimately
	// contain one; when a person types one, they meant the character that
	// looks like it.
	parsed, err := trust.ParseSecret("K7N4I-9QRAO")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if parsed != "k7n419qra0" {
		t.Errorf("parsed as %q, want k7n419qra0", parsed)
	}

	for _, bad := range []string{"", "k7n4c", "k7n4c-9qra2x", "k7n4c-9qr!2"} {
		if _, err := trust.ParseSecret(bad); !errors.Is(err, trust.ErrBadCode) {
			t.Errorf("ParseSecret(%q) = %v, want a bad-code error", bad, err)
		}
	}
}

// TestProofBindsToBothIdentities is the argument that makes a ten-character
// code safe: the proof is worthless on any channel but the one it was computed
// for, so a relay cannot forward it.
func TestProofBindsToBothIdentities(t *testing.T) {
	secret, err := trust.NewSecret()
	if err != nil {
		t.Fatalf("generate a secret: %v", err)
	}

	listener := newKey(t, "desktop")
	dialler := newKey(t, "headless")
	relay := newKey(t, "relay")

	proof := trust.Proof(secret, listener, dialler)

	if !trust.VerifyProof(secret, listener, dialler, proof) {
		t.Fatal("an honest proof did not verify")
	}

	// What a relay ends up holding: the dialler computed its proof over the
	// relay's key, because that is the key the relay presented.
	relayed := trust.Proof(secret, relay, dialler)

	if trust.VerifyProof(secret, listener, dialler, relayed) {
		t.Error("a proof computed against a relay verified against the listener")
	}

	// And the relay cannot turn the proof it was given round and use it.
	if trust.VerifyProof(secret, listener, relay, proof) {
		t.Error("a proof verified for a different dialler")
	}

	other, err := trust.NewSecret()
	if err != nil {
		t.Fatalf("generate a secret: %v", err)
	}

	if trust.VerifyProof(other, listener, dialler, proof) {
		t.Error("a proof verified under the wrong secret")
	}
}

// TestConfirmationIsNotAProof checks the domain separation. Without it a relay
// that captured a dialler's proof could turn it round and pose as the listener.
func TestConfirmationIsNotAProof(t *testing.T) {
	secret, err := trust.NewSecret()
	if err != nil {
		t.Fatalf("generate a secret: %v", err)
	}

	listener := newKey(t, "desktop")
	dialler := newKey(t, "headless")

	proof := trust.Proof(secret, listener, dialler)
	confirmation := trust.Confirmation(secret, listener, dialler)

	if trust.VerifyConfirmation(secret, listener, dialler, proof) {
		t.Error("a proof was accepted as a confirmation")
	}

	if trust.VerifyProof(secret, listener, dialler, confirmation) {
		t.Error("a confirmation was accepted as a proof")
	}
}

// TestFullCodeCarriesTheIdentity is what makes the QR variant of M5 the same
// mechanism: the code carries the listening side's key, so the dialler pins
// before it connects.
func TestFullCodeCarriesTheIdentity(t *testing.T) {
	secret, err := trust.NewSecret()
	if err != nil {
		t.Fatalf("generate a secret: %v", err)
	}

	key := newKey(t, "desktop")
	addresses := []string{"100.64.0.2:7373", "127.0.0.1:7373"}

	encoded, err := trust.EncodeCode(trust.NewCode(
		secret, "desktop", key, addresses, time.Now().Add(trust.CodeValidity)))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, err := trust.DecodeCode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.GetSecret() != string(secret) {
		t.Errorf("the code carries the secret %q", decoded.GetSecret())
	}

	if decoded.GetInstanceName() != "desktop" {
		t.Errorf("the code names %q", decoded.GetInstanceName())
	}

	if len(decoded.GetAddresses()) != 2 || decoded.GetAddresses()[0] != addresses[0] {
		t.Errorf("the code carries the addresses %v", decoded.GetAddresses())
	}

	carried, err := trust.CodeKey(decoded)
	if err != nil {
		t.Fatalf("read the identity out of the code: %v", err)
	}

	if carried == nil || ssh.FingerprintSHA256(carried) != ssh.FingerprintSHA256(key) {
		t.Error("the code did not carry the identity key")
	}
}

// TestTypedCodeIsTheSameExchange: a typed secret decodes to a code with nothing
// but the secret in it, and the caller supplies the address it was told.
func TestTypedCodeIsTheSameExchange(t *testing.T) {
	secret, err := trust.NewSecret()
	if err != nil {
		t.Fatalf("generate a secret: %v", err)
	}

	decoded, err := trust.DecodeCode(secret.Display())
	if err != nil {
		t.Fatalf("decode a typed code: %v", err)
	}

	if decoded.GetSecret() != string(secret) {
		t.Errorf("a typed code decoded to %q", decoded.GetSecret())
	}

	key, err := trust.CodeKey(decoded)
	if err != nil {
		t.Fatalf("read the identity out of a typed code: %v", err)
	}

	if key != nil {
		t.Error("a typed code produced an identity key out of nowhere")
	}
}

// TestExpiredCodeIsRefused covers the expiry half of the replay story.
func TestExpiredCodeIsRefused(t *testing.T) {
	secret, err := trust.NewSecret()
	if err != nil {
		t.Fatalf("generate a secret: %v", err)
	}

	encoded, err := trust.EncodeCode(trust.NewCode(
		secret, "desktop", newKey(t, "desktop"),
		[]string{"127.0.0.1:7373"}, time.Now().Add(-time.Second)))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	if _, err := trust.DecodeCode(encoded); !errors.Is(err, trust.ErrCodeExpired) {
		t.Errorf("an expired code decoded with %v", err)
	}
}

// TestGarbledFullCodeIsRefused: nothing that is not a code should be mistaken
// for one, and a truncated one should say so rather than produce a secret that
// fails an HMAC for reasons nobody can see.
func TestGarbledFullCodeIsRefused(t *testing.T) {
	for _, bad := range []string{
		"ladulas-pair-v1.not base64",
		"ladulas-pair-v1.QUJD",
		"ladulas-pair-v2.QUJD",
	} {
		if _, err := trust.DecodeCode(bad); err == nil {
			t.Errorf("DecodeCode(%q) succeeded", bad)
		}
	}
}

// TestRecordHalvesMustAgree: the identity key is the record and the fingerprint
// is display, so a record whose two halves disagree is not something to
// authorize against.
func TestRecordHalvesMustAgree(t *testing.T) {
	key := newKey(t, "desktop")
	record := trust.NewRecord("desktop", key, nil, true, false, false)

	if _, err := trust.PublicKey(record); err != nil {
		t.Fatalf("an honest record did not parse: %v", err)
	}

	record.Fingerprint = ssh.FingerprintSHA256(newKey(t, "somebody else"))

	if _, err := trust.PublicKey(record); err == nil {
		t.Error("a record whose fingerprint names a different key was accepted")
	}
}

// TestDescribeSeparatesTheDirections: the two directions are different
// decisions, and a prompt that collapsed them would hide the one that matters.
func TestDescribeSeparatesTheDirections(t *testing.T) {
	both := trust.Describe(true, true)
	approve := trust.Describe(true, false)
	request := trust.Describe(false, true)
	neither := trust.Describe(false, false)

	for _, pair := range [][2]string{
		{both, approve}, {both, request}, {approve, request}, {approve, neither},
	} {
		if pair[0] == pair[1] {
			t.Errorf("two different pairings describe the same: %q", pair[0])
		}
	}
}

// TestChangingARecordLeavesTheOldOneAlone: the rule trust.Store rests on.
//
// A record that has been handed out is read without a lock, by a link that
// holds it for the length of a connection and by every request authorized
// against it. So changing a peer builds the replacement rather than reaching
// into the record that is out there being read — otherwise `ladulas peers
// allow`, which sets a direction and a key list at once, could be observed part
// way through and authorize against a state neither user asked for.
func TestChangingARecordLeavesTheOldOneAlone(t *testing.T) {
	key := newKey(t, "phone")
	record := trust.NewRecord("phone", key, nil, true, false, false)

	record.AllowedKeyFingerprints = []string{"SHA256:old"}

	revised := trust.Directions{
		MayApprove:  false,
		MayRequest:  true,
		AllowedKeys: []string{"SHA256:new"},
		AllKeys:     true,
	}.Applied(record)

	if !record.GetMayApprove() || record.GetMayRequest() ||
		record.GetMayUseAllKeys() {
		t.Error("Applied changed the directions on the record it was given")
	}

	if got := record.GetAllowedKeyFingerprints(); len(got) != 1 ||
		got[0] != "SHA256:old" {
		t.Errorf("Applied changed the key list on the record it was given: %v", got)
	}

	if revised.GetMayApprove() || !revised.GetMayRequest() ||
		!revised.GetMayUseAllKeys() {
		t.Error("the revised record does not carry the new directions")
	}

	if got := revised.GetAllowedKeyFingerprints(); len(got) != 1 ||
		got[0] != "SHA256:new" {
		t.Errorf("the revised record allows %v", got)
	}

	// The same rule for the name, which is what every prompt and listing calls
	// the peer.
	renamed := trust.Renamed(record, "hugo's phone")

	if record.GetName() != "phone" {
		t.Errorf("Renamed changed the record it was given, to %q", record.GetName())
	}

	if renamed.GetName() != "hugo's phone" {
		t.Errorf("the renamed record is called %q", renamed.GetName())
	}
}

// What "not connected" means depends on which side does the dialling, and this
// is the distinction: a machine that listens is missing when there is no link,
// and a phone with no link is a phone in a pocket.
//
// It is worth a test rather than a reading because the wrong answer is the
// reassuring-sounding one. Calling a phone "offline" says its keys cannot be
// reached, when a push is all it would take (§11, decision T) — and it said
// exactly that for as long as the state was derived from a failed dial, on a
// peer nothing ever dialled successfully in the first place.
func TestDescribeStateOfADeviceThatDialsIn(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 20, 30, 0, 0, time.UTC)
	phone := func(lastSeen time.Time) string {
		return trust.DescribeState(false, nil, true, "", lastSeen, now)
	}

	if state := phone(now.Add(-4 * time.Minute)); state != "last seen 4m ago" {
		t.Errorf("a phone seen four minutes ago is %q", state)
	}

	if state := phone(now.Add(-50 * time.Hour)); state != "last seen 2d ago" {
		t.Errorf("a phone seen two days ago is %q", state)
	}

	if state := phone(time.Time{}); state != "waiting to hear from it" {
		t.Errorf("a phone that has never been here is %q", state)
	}

	// The epoch, which is what a nil protobuf timestamp becomes: not IsZero, and
	// so not caught by the obvious check. It reached a screen as "last seen 20683
	// days ago", counted from 1970.
	if state := phone(time.Unix(0, 0)); state != "waiting to hear from it" {
		t.Errorf("a phone whose last contact is the epoch is %q", state)
	}

	// The one state a phone shares with everything else, because it means the
	// same thing for both: there is a link, and it is up.
	if state := trust.DescribeState(
		true, nil, true, "", now, now); state != "connected" {
		t.Errorf("a phone holding a link open is %q", state)
	}

	// A phone is never "offline", even when a dial failed — nothing dialled it.
	if state := phone(now.Add(-time.Minute)); state == "offline" {
		t.Error("a phone with no link is being called offline")
	}
}

// A machine that listens keeps the words it had, because for it they are true.
func TestDescribeStateOfAMachineThatListens(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 20, 30, 0, 0, time.UTC)
	addresses := []string{"192.168.1.10:7373"}

	cases := []struct {
		name       string
		online     bool
		mayApprove bool
		lastError  string
		want       string
	}{
		{"a link is up", true, true, "", "connected"},
		{"trying", false, true, "", "connecting"},
		{"a dial failed", false, true, "connection refused", "offline"},
		// A peer that only asks this instance to approve is never dialled from
		// here, so there is nothing to report either way.
		{"only asks", false, false, "", "listening"},
	}

	for _, test := range cases {
		state := trust.DescribeState(
			test.online, addresses, test.mayApprove, test.lastError, now, now)

		if state != test.want {
			t.Errorf("%s: got %q, want %q", test.name, state, test.want)
		}
	}
}

// TestReaddressedLeavesTheOldOneAlone: the same rule, for the one other field a
// running instance rewrites (decision AQ).
func TestReaddressedLeavesTheOldOneAlone(t *testing.T) {
	key := newKey(t, "desk")
	record := trust.NewRecord("desk", key,
		[]string{"old.example:7373"}, true, false, false)

	revised := trust.Readdressed(record, []string{"new.example:7373"})

	if got := record.GetAddresses(); len(got) != 1 || got[0] != "old.example:7373" {
		t.Errorf("Readdressed changed the addresses on the record it was given: %v", got)
	}

	if got := revised.GetAddresses(); len(got) != 1 || got[0] != "new.example:7373" {
		t.Errorf("the revised record dials %v", got)
	}

	if !revised.GetMayApprove() || revised.GetMayRequest() {
		t.Error("Readdressed changed the directions")
	}
}
