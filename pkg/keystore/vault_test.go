package keystore_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

const testPassphrase = "correct horse battery staple"

func staticPassphrase(phrase string) keystore.PassphraseFunc {
	return func(string, bool) ([]byte, error) {
		return []byte(phrase), nil
	}
}

func newVault(t *testing.T) (*keystore.Vault, keystore.Options) {
	t.Helper()

	opts := keystore.Options{
		Dir:          t.TempDir(),
		Keyring:      &keystore.MemoryKeyring{},
		Passphrase:   staticPassphrase(testPassphrase),
		InstanceName: "test-desktop",
		// Keep the suite quick; the code path is the same as in production.
		ScryptWorkFactor: 10,
	}

	v, err := keystore.Create(opts)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	return v, opts
}

func TestCreateAndReopen(t *testing.T) {
	v, opts := newVault(t)

	fingerprint := v.Identity().Fingerprint()

	if v.InstanceName() != "test-desktop" {
		t.Errorf("instance name not stored: %q", v.InstanceName())
	}

	if !v.HasPassphraseWrapping() {
		t.Error("expected passphrase wrapping to have been established")
	}

	reopened, err := keystore.Open(opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	if got := reopened.Identity().Fingerprint(); got != fingerprint {
		t.Errorf("identity changed across reopen: %s != %s", got, fingerprint)
	}
}

// Without the keychain, the passphrase alone must open the store — this is the
// headless Linux path and the recovery path.
func TestReopenWithPassphraseOnly(t *testing.T) {
	v, opts := newVault(t)

	fingerprint := v.Identity().Fingerprint()

	passphraseOnly := opts
	passphraseOnly.Keyring = keystore.NoKeyring{}

	reopened, err := keystore.Open(passphraseOnly)
	if err != nil {
		t.Fatalf("reopen with passphrase only: %v", err)
	}

	if got := reopened.Identity().Fingerprint(); got != fingerprint {
		t.Errorf("identity changed: %s != %s", got, fingerprint)
	}
}

func TestReopenWithWrongPassphraseFails(t *testing.T) {
	_, opts := newVault(t)

	wrong := opts
	wrong.Keyring = keystore.NoKeyring{}
	wrong.Passphrase = staticPassphrase("hunter2")

	_, err := keystore.Open(wrong)
	if err == nil {
		t.Fatal("store opened with the wrong passphrase")
	}

	// The sentinel, not just a failure. It is what lets a gate say "that
	// passphrase does not open this store" instead of showing age's account of
	// why the file would not decrypt (§10).
	if !errors.Is(err, keystore.ErrWrongPassphrase) {
		t.Errorf("open with the wrong passphrase: %v, want ErrWrongPassphrase", err)
	}
}

func TestCreateRefusesWithoutAnyWrapping(t *testing.T) {
	_, err := keystore.Create(keystore.Options{
		Dir:     t.TempDir(),
		Keyring: keystore.NoKeyring{},
	})
	if err == nil {
		t.Fatal("created a store that nothing can unlock")
	}
}

// The design promises (§18) that a store backup is recoverable with standalone
// age tooling and the passphrase. This walks exactly that path: decrypt dek.age
// with a scrypt identity to get the AGE-SECRET-KEY, then decrypt store.age with
// it — using nothing from the keystore package.
func TestBackupIsRecoverableWithPlainAge(t *testing.T) {
	v, _ := newVault(t)

	if _, err := v.GenerateKey("work", "hugo@example.com"); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	wrapped, err := os.ReadFile(filepath.Join(v.Dir(), "dek.age"))
	if err != nil {
		t.Fatalf("read dek.age: %v", err)
	}

	scryptID, err := age.NewScryptIdentity(testPassphrase)
	if err != nil {
		t.Fatalf("scrypt identity: %v", err)
	}

	r, err := age.Decrypt(armor.NewReader(strings.NewReader(string(wrapped))), scryptID)
	if err != nil {
		t.Fatalf("decrypt dek.age: %v", err)
	}

	dekText, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read dek: %v", err)
	}

	if !strings.HasPrefix(string(dekText), "AGE-SECRET-KEY-1") {
		t.Fatalf("dek.age did not yield an age identity: %q", dekText)
	}

	dek, err := age.ParseX25519Identity(strings.TrimSpace(string(dekText)))
	if err != nil {
		t.Fatalf("parse dek: %v", err)
	}

	storeRaw, err := os.ReadFile(filepath.Join(v.Dir(), "store.age"))
	if err != nil {
		t.Fatalf("read store.age: %v", err)
	}

	sr, err := age.Decrypt(strings.NewReader(string(storeRaw)), dek)
	if err != nil {
		t.Fatalf("decrypt store.age: %v", err)
	}

	body, err := io.ReadAll(sr)
	if err != nil {
		t.Fatalf("read store body: %v", err)
	}

	if len(body) == 0 {
		t.Fatal("recovered an empty store")
	}
}

func TestStoreFilePermissions(t *testing.T) {
	v, _ := newVault(t)

	for _, name := range []string{"store.age", "dek.age"} {
		info, err := os.Stat(filepath.Join(v.Dir(), name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}

		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s has mode %o, want 600", name, perm)
		}
	}
}

func TestGenerateKey(t *testing.T) {
	v, opts := newVault(t)

	key, err := v.GenerateKey("work", "hugo@example.com")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if key.GetAlgorithm() != "ssh-ed25519" {
		t.Errorf("want ed25519, got %s", key.GetAlgorithm())
	}

	if key.GetComment() != "hugo@example.com" {
		t.Errorf("comment not preserved: %q", key.GetComment())
	}

	if key.GetOrigin() != storepb.KeyOrigin_KEY_ORIGIN_GENERATED {
		t.Errorf("wrong origin %v", key.GetOrigin())
	}

	// The key must be usable, and survive a reopen.
	reopened, err := keystore.Open(opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	signer, stored, err := reopened.Signer(key.GetFingerprint())
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	if stored.GetLabel() != "work" {
		t.Errorf("label lost: %q", stored.GetLabel())
	}

	sig, err := signer.Sign(rand.Reader, []byte("payload"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := signer.PublicKey().Verify([]byte("payload"), sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

func TestGenerateKeyRejectsDuplicateLabel(t *testing.T) {
	v, _ := newVault(t)

	if _, err := v.GenerateKey("work", ""); err != nil {
		t.Fatalf("generate: %v", err)
	}

	if _, err := v.GenerateKey("work", ""); err == nil {
		t.Fatal("accepted a duplicate label")
	}
}

func makeOpenSSHKey(t *testing.T, comment, passphrase string) []byte {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var block *pem.Block

	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, comment)
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(
			priv, comment, []byte(passphrase))
	}

	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return pem.EncodeToMemory(block)
}

// 1Password exports unencrypted OpenSSH keys, comment and all.
func TestImportUnencryptedKey(t *testing.T) {
	v, _ := newVault(t)

	keyPEM := makeOpenSSHKey(t, "hugo@1password", "")

	key, err := v.ImportKey(keyPEM, "", "imported")
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	if key.GetComment() != "hugo@1password" {
		t.Errorf("comment not recovered from the key file: %q", key.GetComment())
	}

	if key.GetOrigin() != storepb.KeyOrigin_KEY_ORIGIN_IMPORTED {
		t.Errorf("wrong origin %v", key.GetOrigin())
	}

	if _, _, err := v.Signer(key.GetFingerprint()); err != nil {
		t.Errorf("imported key is not usable: %v", err)
	}
}

func TestImportPassphraseProtectedKey(t *testing.T) {
	v, _ := newVault(t)

	keyPEM := makeOpenSSHKey(t, "hugo@laptop", "s3cret")

	_, err := v.ImportKey(keyPEM, "", "locked")
	if !errors.Is(err, keystore.ErrPassphraseRequired) {
		t.Fatalf("want ErrPassphraseRequired, got %v", err)
	}

	if _, err := v.ImportKey(keyPEM, "wrong", "locked"); err == nil {
		t.Fatal("accepted the wrong key passphrase")
	}

	key, err := v.ImportKey(keyPEM, "s3cret", "locked")
	if err != nil {
		t.Fatalf("import with passphrase: %v", err)
	}

	if _, _, err := v.Signer(key.GetFingerprint()); err != nil {
		t.Errorf("imported key is not usable: %v", err)
	}
}

func TestImportRejectsDuplicateKey(t *testing.T) {
	v, _ := newVault(t)

	keyPEM := makeOpenSSHKey(t, "hugo@laptop", "")

	if _, err := v.ImportKey(keyPEM, "", "first"); err != nil {
		t.Fatalf("import: %v", err)
	}

	_, err := v.ImportKey(keyPEM, "", "second")
	if !errors.Is(err, keystore.ErrDuplicateKey) {
		t.Fatalf("want ErrDuplicateKey, got %v", err)
	}
}

// Keys as ssh-keygen actually writes them, which is the shape that matters for
// dogfooding an existing key.
func TestImportRealSSHKeygenKeys(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not available")
	}

	for _, tc := range []struct {
		name       string
		args       []string
		passphrase string
	}{
		{name: "ed25519", args: []string{"-t", "ed25519"}},
		{name: "ed25519-encrypted", args: []string{"-t", "ed25519"}, passphrase: "s3cret"},
		{name: "ecdsa", args: []string{"-t", "ecdsa", "-b", "256"}},
		{name: "rsa", args: []string{"-t", "rsa", "-b", "2048"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "id")

			args := append([]string{}, tc.args...)
			args = append(args,
				"-f", path, "-N", tc.passphrase, "-C", "hugo@keygen", "-q")

			cmd := exec.Command(keygen, args...)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("ssh-keygen: %v: %s", err, out)
			}

			keyPEM, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read key: %v", err)
			}

			v, _ := newVault(t)

			key, err := v.ImportKey(keyPEM, tc.passphrase, "imported")
			if err != nil {
				t.Fatalf("import: %v", err)
			}

			pubBytes, err := os.ReadFile(path + ".pub")
			if err != nil {
				t.Fatalf("read public key: %v", err)
			}

			pub, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
			if err != nil {
				t.Fatalf("parse public key: %v", err)
			}

			if got := ssh.FingerprintSHA256(pub); got != key.GetFingerprint() {
				t.Errorf("fingerprint mismatch: %s != %s", got, key.GetFingerprint())
			}

			if tc.passphrase == "" && key.GetComment() != "hugo@keygen" {
				t.Errorf("comment not recovered: %q", key.GetComment())
			}

			signer, _, err := v.Signer(key.GetFingerprint())
			if err != nil {
				t.Fatalf("signer: %v", err)
			}

			sig, err := signer.Sign(rand.Reader, []byte("payload"))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}

			if err := pub.Verify([]byte("payload"), sig); err != nil {
				t.Errorf("signature does not verify against the public key file: %v", err)
			}
		})
	}
}

func TestRemoveAndDisableKey(t *testing.T) {
	v, _ := newVault(t)

	key, err := v.GenerateKey("work", "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if err := v.SetKeyDisabled("work", true); err != nil {
		t.Fatalf("disable: %v", err)
	}

	if len(v.KeyRefs()) != 0 {
		t.Error("disabled key is still offered by the agent")
	}

	if _, _, err := v.Signer(key.GetFingerprint()); !errors.Is(err, keystore.ErrNoSuchKey) {
		t.Errorf("disabled key still signs: %v", err)
	}

	if err := v.SetKeyDisabled("work", false); err != nil {
		t.Fatalf("enable: %v", err)
	}

	if len(v.KeyRefs()) != 1 {
		t.Error("re-enabled key is not offered")
	}

	if err := v.RemoveKey("work"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	if len(v.Keys()) != 0 {
		t.Error("key survived removal")
	}

	if err := v.RemoveKey("work"); !errors.Is(err, keystore.ErrNoSuchKey) {
		t.Errorf("want ErrNoSuchKey, got %v", err)
	}
}

// Taking a key out of the agent's identity list is not disabling it
// (decision T): it goes on signing, and the only thing that changes is what an
// agent hands ssh.
func TestAKeyCanBeKeptOutOfTheAgentAndStillSign(t *testing.T) {
	v, _ := newVault(t)

	key, err := v.GenerateKey("work", "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// A key that has never been asked about is in the list. Every key written
	// before the field existed is in exactly that state, and one that dropped
	// out of an agent because the store was upgraded would be a key that had
	// silently stopped working.
	if !keystore.AgentUse(key) {
		t.Error("a fresh key is not offered to the agent")
	}

	if !keystore.RefAgentUse(v.KeyRefs()[0]) {
		t.Error("the key reference says the key is not offered to the agent")
	}

	hidden, err := v.SetKeyAgentUse("work", false)
	if err != nil {
		t.Fatalf("hide: %v", err)
	}

	if keystore.AgentUse(hidden) {
		t.Error("the key is still offered to the agent")
	}

	// Still there, still signs. The filtering happens where the identity list is
	// built, so that everything which resolves a key by name or by blob is
	// untouched.
	if len(v.KeyRefs()) != 1 {
		t.Fatal("the hidden key left the store's key list")
	}

	if keystore.RefAgentUse(v.KeyRefs()[0]) {
		t.Error("the key reference still says the key is offered to the agent")
	}

	if _, _, err := v.Signer(key.GetFingerprint()); err != nil {
		t.Errorf("the hidden key cannot sign: %v", err)
	}

	if _, err := v.SetKeyAgentUse("nothing", true); !errors.Is(
		err, keystore.ErrNoSuchKey) {
		t.Errorf("want ErrNoSuchKey, got %v", err)
	}
}

func TestGrantsPersistAndExpire(t *testing.T) {
	v, opts := newVault(t)

	live := &ladulasv1.Grant{
		GrantId:   "live",
		CreatedAt: timestamppb.Now(),
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
		Scope:     &ladulasv1.GrantScope{Destination: "github.com"},
	}

	expired := &ladulasv1.Grant{
		GrantId:   "expired",
		CreatedAt: timestamppb.New(time.Now().Add(-2 * time.Hour)),
		ExpiresAt: timestamppb.New(time.Now().Add(-time.Hour)),
	}

	for _, g := range []*ladulasv1.Grant{live, expired} {
		if err := v.AddGrant(g); err != nil {
			t.Fatalf("add grant: %v", err)
		}
	}

	reopened, err := keystore.Open(opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	grants, err := reopened.Grants()
	if err != nil {
		t.Fatalf("grants: %v", err)
	}

	if len(grants) != 1 || grants[0].GetGrantId() != "live" {
		t.Fatalf("expected only the live grant, got %d: %v", len(grants), grants)
	}

	if err := reopened.RevokeGrant("live"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	grants, err = reopened.Grants()
	if err != nil {
		t.Fatalf("grants: %v", err)
	}

	if len(grants) != 0 {
		t.Errorf("grant survived revocation: %v", grants)
	}
}

// Decision I in the store: a new store is wrapped by its passphrase and by
// nothing else, so a machine that is stolen while powered off is one
// passphrase away from the keys rather than one login password away.
func TestCreateDoesNotEnrolTheKeychain(t *testing.T) {
	keyring := &keystore.MemoryKeyring{}

	v, err := keystore.Create(keystore.Options{
		Dir:              t.TempDir(),
		Keyring:          keyring,
		Passphrase:       staticPassphrase(testPassphrase),
		InstanceName:     "fresh",
		ScryptWorkFactor: 10,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if v.KeyringEnrolled() {
		t.Error("a new store put its key in the keychain without being asked")
	}

	if !v.HasPassphraseWrapping() {
		t.Error("a new store has no passphrase wrapping")
	}
}

func TestCreateRefusesWithoutAPassphrase(t *testing.T) {
	_, err := keystore.Create(keystore.Options{
		Dir:     t.TempDir(),
		Keyring: &keystore.MemoryKeyring{},
	})
	if !errors.Is(err, keystore.ErrNoWrapping) {
		t.Fatalf("create without a passphrase: %v", err)
	}
}

// Enrolling "unlock at login" is a deliberate act with a deliberate undo, and
// both wrappings coexist afterwards.
func TestEnrolAndForgetTheKeychain(t *testing.T) {
	v, opts := newVault(t)

	if err := v.StoreInKeyring(); err != nil {
		t.Fatalf("enrol: %v", err)
	}

	if !v.KeyringEnrolled() {
		t.Fatal("the keychain was not enrolled")
	}

	// With an entry there, opening needs no prompt at all.
	silent := opts
	silent.Passphrase = nil

	reopened, err := keystore.Open(silent)
	if err != nil {
		t.Fatalf("open at login: %v", err)
	}

	if got := reopened.Identity().Fingerprint(); got != v.Identity().Fingerprint() {
		t.Errorf("identity changed: %s", got)
	}

	if err := v.ForgetKeyring(); err != nil {
		t.Fatalf("forget: %v", err)
	}

	if v.KeyringEnrolled() {
		t.Error("the keychain entry survived being forgotten")
	}

	if _, err := keystore.Open(silent); !errors.Is(err, keystore.ErrPassphraseNeeded) {
		t.Errorf("open after forgetting: %v, want the passphrase to be asked for", err)
	}
}

// A typed passphrase is checked even when the keychain would have opened the
// store, which is the bug that made a gate accept anything at all.
//
// The keyring here is enrolled and working — the case where the old code
// returned the key before it ever looked at what had been typed. Both halves
// matter: the wrong one is refused, and the right one still works, because a fix
// that made the enrolled path refuse everything would be the same bug wearing a
// different face.
func TestATypedPassphraseIsCheckedEvenWithAWorkingKeyring(t *testing.T) {
	v, opts := newVault(t)

	if err := v.StoreInKeyring(); err != nil {
		t.Fatalf("enrol: %v", err)
	}

	if !v.KeyringEnrolled() {
		t.Fatal("the keyring is not enrolled, so this proves nothing")
	}

	typed := opts
	typed.Passphrase = nil
	typed.GivenPassphrase = []byte("hunter2")

	_, err := keystore.Open(typed)
	if err == nil {
		t.Fatal("the store opened with the wrong passphrase because the " +
			"keychain answered first — any passphrase unlocks it")
	}

	if !errors.Is(err, keystore.ErrWrongPassphrase) {
		t.Errorf("wrong passphrase with an enrolled keyring: %v, "+
			"want ErrWrongPassphrase", err)
	}

	right := opts
	right.Passphrase = nil
	right.GivenPassphrase = []byte(testPassphrase)

	if _, err := keystore.Open(right); err != nil {
		t.Errorf("the right passphrase was refused: %v", err)
	}

	// And with nothing typed the keychain is still the way in, which is the
	// whole of what enrolling bought (decision I).
	silent := opts
	silent.Passphrase = nil

	if _, err := keystore.Open(silent); err != nil {
		t.Errorf("an enrolled store did not open on its own: %v", err)
	}
}

// The daemon's own startup is the other caller, and it must keep reaching for
// the keychain first: a Passphrase func there is a terminal prompt, and an
// enrolled machine is one that asked not to be asked (decision I).
func TestAPromptIsNotACredential(t *testing.T) {
	v, opts := newVault(t)

	if err := v.StoreInKeyring(); err != nil {
		t.Fatalf("enrol: %v", err)
	}

	asked := false

	startup := opts
	startup.Passphrase = func(string, bool) ([]byte, error) {
		asked = true

		return []byte(testPassphrase), nil
	}

	if _, err := keystore.Open(startup); err != nil {
		t.Fatalf("open at startup: %v", err)
	}

	if asked {
		t.Error("an enrolled instance prompted for its passphrase at startup, " +
			"which is the cost enrolling was supposed to remove")
	}
}

// An explicit name is what a store on a platform whose paths move uses instead
// of one derived from its directory, and it has to be the name every part of the
// keyring dance agrees on — the write, the probe and the read (§10).
func TestAnExplicitKeyringNameIsUsedThroughout(t *testing.T) {
	kr := &keystore.MemoryKeyring{}

	opts := keystore.Options{
		Dir:              t.TempDir(),
		Keyring:          kr,
		KeyringName:      "store-dek:somewhere stable",
		Passphrase:       staticPassphrase(testPassphrase),
		InstanceName:     "test-phone",
		ScryptWorkFactor: 10,
	}

	v, err := keystore.Create(opts)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := v.StoreInKeyring(); err != nil {
		t.Fatalf("enrol: %v", err)
	}

	if got := kr.Names(); len(got) != 1 || got[0] != opts.KeyringName {
		t.Fatalf("the key is filed under %q, want only %q",
			got, opts.KeyringName)
	}

	if !v.KeyringEnrolled() || !keystore.Enrolled(opts) {
		t.Error("the entry was written and neither probe can find it")
	}

	// And the read: reopening with no passphrase has only the keychain to go on.
	silent := opts
	silent.Passphrase = nil

	if _, err := keystore.Open(silent); err != nil {
		t.Errorf("reopen from the keychain alone: %v", err)
	}
}

// Enrolling under an explicit name clears out an entry left under the
// path-derived one, which is what an install that predates having a name of its
// own has sitting there: a copy of the store key that nothing will read again.
func TestEnrollingUnderANameClearsThePathDerivedEntry(t *testing.T) {
	kr := &keystore.MemoryKeyring{}

	legacy := keystore.Options{
		Dir:              t.TempDir(),
		Keyring:          kr,
		Passphrase:       staticPassphrase(testPassphrase),
		InstanceName:     "test-phone",
		ScryptWorkFactor: 10,
	}

	v, err := keystore.Create(legacy)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := v.StoreInKeyring(); err != nil {
		t.Fatalf("enrol under the path: %v", err)
	}

	before := kr.Names()
	if len(before) != 1 {
		t.Fatalf("the keyring holds %q, want one path-derived entry", before)
	}

	// The same store, opened by a build that now has a name for it.
	named := legacy
	named.KeyringName = "store-dek:somewhere stable"

	renamed, err := keystore.Open(named)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	if err := renamed.StoreInKeyring(); err != nil {
		t.Fatalf("enrol under the name: %v", err)
	}

	if got := kr.Names(); len(got) != 1 || got[0] != named.KeyringName {
		t.Errorf("the keyring holds %q, want only %q — the old copy of the "+
			"store key is still there", got, named.KeyringName)
	}
}

// Lifting a soft lock checks the passphrase without unwrapping anything: the
// key never left (§10).
func TestVerifyPassphrase(t *testing.T) {
	v, _ := newVault(t)

	if err := v.VerifyPassphrase([]byte(testPassphrase)); err != nil {
		t.Errorf("the right passphrase was refused: %v", err)
	}

	if err := v.VerifyPassphrase([]byte("hunter2")); !errors.Is(
		err, keystore.ErrWrongPassphrase) {
		t.Errorf("the wrong passphrase: %v, want ErrWrongPassphrase", err)
	}

	if err := v.VerifyPassphrase(nil); !errors.Is(err, keystore.ErrPassphraseNeeded) {
		t.Errorf("empty passphrase: %v, want the passphrase to be asked for", err)
	}

	// On an instance that unlocks at login, the keychain answers instead.
	if err := v.StoreInKeyring(); err != nil {
		t.Fatalf("enrol: %v", err)
	}

	if err := v.VerifyPassphrase(nil); err != nil {
		t.Errorf("an enrolled instance was still asked for a passphrase: %v", err)
	}
}

func TestWipeClearsTheBuffer(t *testing.T) {
	secret := []byte(testPassphrase)

	keystore.Wipe(secret)

	for i, b := range secret {
		if b != 0 {
			t.Fatalf("byte %d survived the wipe: %q", i, b)
		}
	}
}
