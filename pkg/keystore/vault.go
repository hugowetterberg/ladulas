// Package keystore is the encrypted local store: SSH private keys, the
// instance identity key, TTL grants and trust records (docs/architecture.md
// §10).
//
// The store file is age-encrypted to a random X25519 identity — the data
// encryption key. The DEK itself is wrapped by a passphrase, always, and by
// the platform keychain for the instances that have deliberately asked to
// unlock at login (decision I). Both wrappings coexist; the passphrase is the
// one that is always there, because it is also the recovery path.
//
// The two-layer arrangement is what makes a backup recoverable with nothing
// but standalone age tooling and the passphrase (§18): age forbids combining a
// scrypt recipient with any other recipient in one file, so the passphrase
// protects a small separate file holding the DEK rather than the store itself.
package keystore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"filippo.io/age"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/hardware"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

const (
	storeFile   = "store.age"
	dekFile     = "dek.age"
	storeFormat = 1
)

// ErrExists is returned when creating a store over an existing one.
var ErrExists = errors.New("keystore: store already exists")

// ErrNoStore is returned when opening a store that has not been created.
var ErrNoStore = errors.New("keystore: no store in directory")

// ErrNoSuchKey is returned when a key is referenced that the store does not
// hold.
var ErrNoSuchKey = errors.New("keystore: no such key")

// Options configures opening or creating a store.
type Options struct {
	// Dir is the store directory. Created with mode 0700 if missing.
	Dir string
	// Keyring is where an instance that has enrolled "unlock at login" keeps
	// its copy of the DEK. Defaults to the platform keychain; pass NoKeyring{}
	// to leave it alone entirely. Nothing is ever written to it by opening or
	// creating a store — enrolling is a deliberate act, see StoreInKeyring.
	Keyring Keyring
	// KeyringName is the name the DEK is kept under, for a platform where the
	// store's path is not a stable identity for it. Empty derives the name from
	// Dir, which is what a desktop wants: several stores on one machine are told
	// apart by where they are, and that is somewhere they stay.
	//
	// A phone is the other case, and this field exists because of what happened
	// without it. An iOS store lives under the app's data container, whose path
	// carries a UUID that Apple explicitly declines to promise is stable across
	// launches and updates — so the name was recomputed each launch from a path
	// that could move, the lookup missed, the read reported "no entry", and the
	// gate fell through to the passphrase with no biometric prompt at all. The
	// store files moved with the container and were found; only the name they
	// were remembered under did not survive. See §10.
	KeyringName string
	// Passphrase is asked for when the keychain has no entry, and when
	// establishing the wrapping at creation time. Creating a store without one
	// is refused: the passphrase is the recovery path, and a store with no way
	// back into it is not a store.
	//
	// It is permission to ask, not a credential. Set it for a daemon starting
	// up, where the keychain is meant to answer first and the prompt is the
	// fallback (decision I); use GivenPassphrase when somebody has actually
	// typed something.
	Passphrase PassphraseFunc
	// GivenPassphrase is a passphrase the caller already holds — typed into a
	// gate, or arrived over the control socket — as opposed to Passphrase, which
	// is only permission to ask for one.
	//
	// The distinction is the whole of a bypass this had. Both used to arrive as
	// a PassphraseFunc, so by the time the store saw them there was no way to
	// tell "check this" from "ask if you need to"; unwrapping tried the keychain
	// first for both, and on a store whose keychain entry worked it returned
	// before it ever looked at what had been typed. A gate that asked for a
	// passphrase therefore accepted **any** passphrase. Which credential opened
	// the store was still Face ID or the right passphrase and never neither — so
	// nothing opened that should not have — but a field that ignores what is
	// typed into it is a lie about what is guarding the thing, and that is the
	// whole product here. See §10.
	GivenPassphrase []byte
	// InstanceName names this instance in prompts and trust records. Only used
	// when creating.
	InstanceName string
	// Hardware is the platform's secure element, on the instances that have one
	// (§10). With one, the identity key and any generated SSH keys live in it
	// and the document holds handles rather than private halves. Without one —
	// every desktop — the store is exactly what it was.
	Hardware hardware.Backend
	// ScryptWorkFactor overrides DefaultScryptWorkFactor for the passphrase
	// wrapping. Lower is faster to unlock and cheaper to attack offline.
	ScryptWorkFactor int
	// SignGate is asked before every signature made with a key whose private
	// half is in this store (decision S). Nil on the desktop, where the store's
	// unlock and the approval engine are the gates; set on a phone, where a
	// portable key must prompt the way an enclave key does.
	SignGate SignGate
}

func (o Options) keyring() Keyring {
	if o.Keyring == nil {
		return SystemKeyring{}
	}

	return o.Keyring
}

// passphraseFor resolves the passphrase to unwrap with: the one the caller
// handed over, or the answer to a prompt. The second return says whether it is
// ours to wipe — a passphrase we were given belongs to the caller, who is
// holding it for reasons of their own and wipes it themselves.
func (o Options) passphraseFor(reason string, confirm bool) ([]byte, bool, error) {
	if len(o.GivenPassphrase) > 0 {
		return o.GivenPassphrase, false, nil
	}

	if o.Passphrase == nil {
		return nil, false, nil
	}

	phrase, err := o.Passphrase(reason, confirm)
	if err != nil {
		return nil, false, fmt.Errorf("read passphrase: %w", err)
	}

	return phrase, true, nil
}

// hasPassphrase reports whether there is any way to get one, without asking.
func (o Options) hasPassphrase() bool {
	return len(o.GivenPassphrase) > 0 || o.Passphrase != nil
}

// keyringEntry is the name to keep the DEK under, and the only place that
// decision is made. Everything that reads, writes or probes the entry goes
// through here or through the copy a Vault holds, because a name computed in
// more than one place is a name that can differ between the write and the read.
func (o Options) keyringEntry() string {
	if o.KeyringName != "" {
		return o.KeyringName
	}

	return keyringName(o.Dir)
}

// Vault is an open store. It is safe for concurrent use.
type Vault struct {
	dir     string
	keyring Keyring
	// entry is the name the DEK is kept in the keyring under, resolved once when
	// the store was opened rather than recomputed per call.
	entry      string
	workFactor int
	hardware   hardware.Backend

	gate SignGate

	mu       sync.RWMutex
	dek      *age.X25519Identity
	doc      *storepb.StoreDocument
	identity *identity.Identity
}

// Exists reports whether a store has been created in dir.
func Exists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, storeFile))

	return err == nil
}

// Create initialises a new store, generating the instance identity key (§7).
//
// The passphrase is the whole of the wrapping a new store gets. The keychain is
// not touched: enrolling it removes the cost of typing a passphrase per boot
// and the protection that comes with it, and that trade is the user's to make
// afterwards, per instance (decision I).
func Create(opts Options) (*Vault, error) {
	if Exists(opts.Dir) {
		return nil, ErrExists
	}

	if !opts.hasPassphrase() {
		return nil, fmt.Errorf(
			"%w: a new store needs a passphrase, which is also its recovery path",
			ErrNoWrapping)
	}

	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("create store directory: %w", err)
	}

	dek, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate data encryption key: %w", err)
	}

	phrase, ours, err := opts.passphraseFor(
		"Passphrase for the Ladulås store", true)
	if err != nil {
		return nil, err
	}

	if ours {
		defer Wipe(phrase)
	}

	if len(phrase) == 0 {
		return nil, fmt.Errorf("%w: the passphrase was empty", ErrNoWrapping)
	}

	err = writeWrappedDEK(
		filepath.Join(opts.Dir, dekFile), dek, phrase, opts.ScryptWorkFactor)
	if err != nil {
		return nil, fmt.Errorf("wrap store key with passphrase: %w", err)
	}

	kr := opts.keyring()

	name := opts.InstanceName
	if name == "" {
		name, _ = os.Hostname()
	}

	doc := &storepb.StoreDocument{
		Version:      storeFormat,
		InstanceName: name,
		CreatedAt:    timestamppb.Now(),
	}

	var id *identity.Identity

	if opts.Hardware != nil {
		id, doc.IdentityHandle, doc.IdentityPublicKey, err =
			createHardwareIdentity(opts.Hardware, name)
	} else {
		id, doc.IdentityKey, err = identity.Generate(name)
	}

	if err != nil {
		return nil, fmt.Errorf("generate instance identity: %w", err)
	}

	v := &Vault{
		dir:        opts.Dir,
		keyring:    kr,
		entry:      opts.keyringEntry(),
		workFactor: opts.ScryptWorkFactor,
		hardware:   opts.Hardware,
		gate:       opts.SignGate,
		dek:        dek,
		doc:        doc,
		identity:   id,
	}

	if err := v.save(); err != nil {
		return nil, err
	}

	return v, nil
}

// Open unlocks an existing store, taking the DEK from the keychain when it is
// there and falling back to the passphrase prompt.
func Open(opts Options) (*Vault, error) {
	if !Exists(opts.Dir) {
		return nil, ErrNoStore
	}

	kr := opts.keyring()

	dek, err := unwrapDEK(opts, kr)
	if err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(filepath.Join(opts.Dir, storeFile))
	if err != nil {
		return nil, fmt.Errorf("read store: %w", err)
	}

	body, err := decryptBytes(raw, dek)
	if err != nil {
		return nil, fmt.Errorf("decrypt store: %w", err)
	}

	var doc storepb.StoreDocument

	if err := proto.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse store: %w", err)
	}

	if doc.GetVersion() != storeFormat {
		return nil, fmt.Errorf(
			"unsupported store format %d, this build understands %d",
			doc.GetVersion(), storeFormat)
	}

	id, err := loadIdentity(&doc, opts.Hardware)
	if err != nil {
		return nil, err
	}

	return &Vault{
		dir:        opts.Dir,
		keyring:    kr,
		entry:      opts.keyringEntry(),
		workFactor: opts.ScryptWorkFactor,
		hardware:   opts.Hardware,
		gate:       opts.SignGate,
		dek:        dek,
		doc:        &doc,
		identity:   id,
	}, nil
}

// OpenOrCreate opens the store, creating it first if it does not exist.
func OpenOrCreate(opts Options) (*Vault, error) {
	if Exists(opts.Dir) {
		return Open(opts)
	}

	return Create(opts)
}

// unwrapDEK recovers the data encryption key.
//
// The keychain goes first when nobody typed anything, because an entry there
// only exists on an instance that asked for one and answering from it without a
// prompt is the whole of what enrolling bought (decision I).
//
// **A passphrase that was actually typed is checked, and the keychain is not
// consulted at all.** That order is not a preference, it is the difference
// between a gate and a decoration: the keychain used to be tried first whatever
// the caller held, so on an instance whose entry worked this returned before
// looking at what had been typed, and every wrong passphrase opened the store.
// Somebody who hands over a credential is asking to be checked against it, and
// getting in anyway is not a kindness — it is the gate telling them it is
// guarding something it is not. If the typed passphrase is wrong the answer is
// ErrWrongPassphrase, even when a face would have opened it a moment earlier.
func unwrapDEK(opts Options, kr Keyring) (*age.X25519Identity, error) {
	if len(opts.GivenPassphrase) == 0 {
		secret, err := kr.Get(opts.keyringEntry())

		switch {
		case err == nil:
			dek, err := age.ParseX25519Identity(secret)
			if err != nil {
				return nil, fmt.Errorf("parse keychain-held store key: %w", err)
			}

			return dek, nil
		case errors.Is(err, ErrNotFound):
			// The ordinary case since decision I: nothing was ever enrolled. Fall
			// through to the passphrase.
		case !opts.hasPassphrase():
			// A keychain that is present but failing is worth reporting rather
			// than silently falling through, when there is nothing to fall
			// through to.
			return nil, fmt.Errorf("keychain unavailable: %w", err)
		}
	}

	dekPath := filepath.Join(opts.Dir, dekFile)

	if _, statErr := os.Stat(dekPath); statErr != nil {
		return nil, fmt.Errorf(
			"%w: keychain has no entry and there is no passphrase-wrapped key",
			ErrNoWrapping)
	}

	if !opts.hasPassphrase() {
		return nil, fmt.Errorf("%w: this store opens with its passphrase",
			ErrPassphraseNeeded)
	}

	phrase, ours, err := opts.passphraseFor("Passphrase for the Ladulås store", false)
	if err != nil {
		return nil, err
	}

	if ours {
		defer Wipe(phrase)
	}

	if len(phrase) == 0 {
		return nil, fmt.Errorf("%w: no passphrase was given", ErrPassphraseNeeded)
	}

	return readWrappedDEK(dekPath, phrase)
}

// Dir returns the store directory.
func (v *Vault) Dir() string {
	return v.dir
}

// Wipe zeros the private key material this vault holds in memory, as a best
// effort before it is dropped on seal (M5). It runs once the core has been
// detached and every in-flight signature has finished, so nothing is still
// reading from these slices.
//
// The limit is worth stating, the way Wipe(passphrase) states its own: the
// DEK's scalar is unexported inside age and cannot be reached to zero, the
// parsed ssh.Signers hold their own copies, and the collector may already have
// moved a slice's backing array. What this reliably removes is the recognisable
// material — the PEM-armoured private keys, the identity key, the portable keys
// still queued or waiting to be accepted — each a grep target in a memory image,
// so a core dump or a same-uid read after the seal finds fewer of them. It does
// not make sealing safe on its own; it narrows the window that dropping the DEK
// reference already opens (§10).
func (v *Vault) Wipe() {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.doc != nil {
		Wipe(v.doc.GetIdentityKey())

		for _, key := range v.doc.GetKeys() {
			Wipe(key.GetPrivateKey())
		}

		for _, offer := range v.doc.GetPendingKeyOffers() {
			Wipe(offer.GetPrivateKey())
		}

		for _, handover := range v.doc.GetQueuedKeyHandovers() {
			Wipe(handover.GetPrivateKey())
		}
	}

	v.dek = nil
	v.doc = nil
	v.identity = nil
}

// Reload re-reads the store from disk with the data encryption key already in
// hand.
//
// A running daemon holds the store in memory, so a key imported by a separate
// `ladulas keys import` would otherwise be invisible until a restart. The
// daemon reloads on SIGHUP and from the tray menu.
func (v *Vault) Reload() error {
	raw, err := os.ReadFile(filepath.Join(v.dir, storeFile))
	if err != nil {
		return fmt.Errorf("read store: %w", err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	body, err := decryptBytes(raw, v.dek)
	if err != nil {
		return fmt.Errorf("decrypt store: %w", err)
	}

	var doc storepb.StoreDocument

	if err := proto.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("parse store: %w", err)
	}

	id, err := loadIdentity(&doc, v.hardware)
	if err != nil {
		return err
	}

	v.doc = &doc
	v.identity = id

	return nil
}

// Identity returns the instance identity (§7).
func (v *Vault) Identity() *identity.Identity {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.identity
}

// InstanceName returns the human assigned name of this instance.
func (v *Vault) InstanceName() string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.doc.GetInstanceName()
}

// SetInstanceName renames the instance.
func (v *Vault) SetInstanceName(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.doc.InstanceName = name

	id, err := loadIdentity(v.doc, v.hardware)
	if err != nil {
		return fmt.Errorf("reload identity: %w", err)
	}

	v.identity = id

	return v.save()
}

// HasPassphraseWrapping reports whether the store can be unlocked, and a backup
// recovered, with a passphrase.
func (v *Vault) HasPassphraseWrapping() bool {
	_, err := os.Stat(filepath.Join(v.dir, dekFile))

	return err == nil
}

// SetPassphrase establishes or replaces the passphrase wrapping.
func (v *Vault) SetPassphrase(phrase []byte) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return writeWrappedDEK(
		filepath.Join(v.dir, dekFile), v.dek, phrase, v.workFactor)
}

// VerifyPassphrase reports whether a passphrase opens this store, without
// changing anything.
//
// It is what lifting a soft lock asks: the data encryption key never left, so
// there is nothing to unwrap, and what is being checked is that the person at
// the keyboard is the one who locked it. On an instance that unlocks at login
// the keychain answers instead — there the lock is a deliberateness gate rather
// than a cryptographic one (§10).
func (v *Vault) VerifyPassphrase(phrase []byte) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if len(phrase) == 0 {
		return v.verifyByKeyring()
	}

	if !v.HasPassphraseWrapping() {
		return fmt.Errorf("%w: there is no passphrase wrapping to check against",
			ErrNoWrapping)
	}

	dek, err := readWrappedDEK(filepath.Join(v.dir, dekFile), phrase)
	if err != nil {
		return err
	}

	// Compare the public halves, not the secret ones. For an X25519 identity the
	// recipient is the scalar times the base point, so two identities share a
	// recipient exactly when they share a scalar — the check is the same — but
	// the recipient is public and, unlike dek.String(), does not mint a fresh
	// unwipeable copy of the store key on the heap every time a soft lock is
	// lifted (M5).
	if dek.Recipient().String() != v.dek.Recipient().String() {
		return fmt.Errorf("%w: it belongs to another store key", ErrWrongPassphrase)
	}

	return nil
}

// verifyByKeyring is the empty-passphrase half of VerifyPassphrase: the
// keychain answers instead of a person.
//
// It reads the item rather than probing for it, and that is the whole point on
// a phone — the read is the Face ID sheet, so lifting a soft lock with nothing
// typed costs a face (§10). Comparing what comes back with the key already in
// memory is what keeps it a check rather than a formality: an item that belongs
// to some other store would otherwise lift this store's lock.
//
// Callers hold at least a read lock.
func (v *Vault) verifyByKeyring() error {
	secret, err := v.keyring.Get(v.entry)

	switch {
	case errors.Is(err, ErrNotFound):
		return fmt.Errorf("%w: this store unlocks with its passphrase",
			ErrPassphraseNeeded)
	case err != nil:
		return fmt.Errorf("read the keychain: %w", err)
	}

	dek, err := age.ParseX25519Identity(secret)
	if err != nil {
		return fmt.Errorf("parse keychain-held store key: %w", err)
	}

	// Public halves again (M5): equality-equivalent for X25519, and no secret
	// string minted on a soft-lock lift, which on a phone is every biometric
	// unlock.
	if dek.Recipient().String() != v.dek.Recipient().String() {
		return errors.New("keystore: the keychain holds another store's key")
	}

	return nil
}

// KeyringEnrolled reports whether this instance has opted down to unlocking at
// login (decision I), and on a phone whether biometrics are the way in at all
// (§10).
//
// It probes rather than reads, so that asking costs nothing on the platform
// where reading costs a biometric prompt. What it can honestly say is that
// there is an entry to try; whether the platform will still hand the key over
// is something only a read finds out, which is why every surface that offers
// biometrics also offers the passphrase.
func (v *Vault) KeyringEnrolled() bool {
	enrolled, err := v.keyring.Has(v.entry)
	if err != nil {
		return false
	}

	return enrolled
}

// Enrolled is the same question asked of a store that is not open.
//
// The unlock panel and the phone's gate are the callers that need it: they are
// drawn while the store is shut, which is the one moment there is no vault to
// ask, and what they draw depends on whether there is a biometric unlock to
// offer at all (§10).
//
// It takes the whole Options rather than a directory so that it asks about the
// same entry the open would read. A probe that resolved the name its own way
// could answer "there is one to try" about an entry nothing unlocks with.
func Enrolled(opts Options) bool {
	enrolled, err := opts.keyring().Has(opts.keyringEntry())
	if err != nil {
		return false
	}

	return enrolled
}

// StoreInKeyring enrols "unlock at login": the DEK is copied into the platform
// keychain, and from then on the daemon starts unsealed without anybody typing
// anything.
//
// What that gives up is written down in §10 and worth repeating where it
// happens: the Secret Service has no per-application ACL, so on Linux any
// process running as this user can read the key back with one D-Bus call. The
// approval engine still gates every use of a key; what the passphrase gated was
// silent theft of the keys themselves.
func (v *Vault) StoreInKeyring() error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !v.HasPassphraseWrapping() {
		return fmt.Errorf(
			"%w: enrol the keychain beside a passphrase, never instead of one",
			ErrNoWrapping)
	}

	if err := v.keyring.Set(v.entry, v.dek.String()); err != nil {
		return err
	}

	// An instance that has been given an explicit name may have an older entry
	// under the path-derived one, from before it had a name of its own. It is a
	// copy of the store key that nothing will ever read again, so it goes.
	//
	// Best effort, and it can only ever be partial: an entry left under a path
	// the store has since moved away from cannot be named from here at all, so
	// this catches the install that has not moved yet and nothing else. A
	// failure is not worth failing an enrolment over — the new entry is written,
	// which is what was asked for.
	if legacy := keyringName(v.dir); legacy != v.entry {
		_ = v.keyring.Delete(legacy)
	}

	return nil
}

// ForgetKeyring removes the keychain wrapping, leaving the passphrase as the
// only way in.
func (v *Vault) ForgetKeyring() error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !v.HasPassphraseWrapping() {
		return fmt.Errorf(
			"%w: removing the keychain wrapping would lock the store out",
			ErrNoWrapping)
	}

	err := v.keyring.Delete(v.entry)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	return nil
}

// save writes the document. Callers must hold at least a read lock; it is
// called under the write lock from every mutator.
func (v *Vault) save() error {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(v.doc)
	if err != nil {
		return fmt.Errorf("marshal store: %w", err)
	}

	recipient := v.dek.Recipient()

	return writeFileAtomic(filepath.Join(v.dir, storeFile), 0o600, func(f io.Writer) error {
		w, err := age.Encrypt(f, recipient)
		if err != nil {
			return fmt.Errorf("encrypt store: %w", err)
		}

		if _, err := w.Write(body); err != nil {
			return fmt.Errorf("write store: %w", err)
		}

		if err := w.Close(); err != nil {
			return fmt.Errorf("close age writer: %w", err)
		}

		return nil
	})
}

// Seal encrypts bytes to the store's own data encryption key, and Unseal reads
// them back.
//
// They exist for content that belongs to the instance but does not belong in
// the store document: the project documentation peers publish (§6), which is
// megabytes of bulk text that would otherwise force a re-encryption of the key
// store every time a README changed. Sealing it separately keeps the property
// that matters — nothing interesting lies beside the ciphertext — without
// making the document carry it.
func (v *Vault) Seal(plaintext []byte) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var out bytes.Buffer

	w, err := age.Encrypt(&out, v.dek.Recipient())
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close the age writer: %w", err)
	}

	return out.Bytes(), nil
}

// Unseal decrypts what Seal produced.
func (v *Vault) Unseal(ciphertext []byte) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	body, err := decryptBytes(ciphertext, v.dek)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return body, nil
}

func decryptBytes(raw []byte, dek *age.X25519Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(raw), dek)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(r)
}

// Grants returns the live TTL grants, dropping any that have expired. Expired
// grants are pruned from the store as a side effect.
func (v *Vault) Grants() ([]*ladulasv1.Grant, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()

	var (
		live    []*ladulasv1.Grant
		changed bool
	)

	for _, g := range v.doc.GetGrants() {
		if g.GetExpiresAt().AsTime().After(now) {
			live = append(live, g)

			continue
		}

		changed = true
	}

	if changed {
		v.doc.Grants = live

		if err := v.save(); err != nil {
			return nil, err
		}
	}

	out := make([]*ladulasv1.Grant, 0, len(live))
	for _, g := range live {
		out = append(out, proto.CloneOf(g))
	}

	return out, nil
}

// AddGrant records a TTL grant. Grants are approver-side state (§18).
func (v *Vault) AddGrant(g *ladulasv1.Grant) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.doc.Grants = append(v.doc.GetGrants(), proto.CloneOf(g))

	return v.save()
}

// RevokeGrant drops a grant by ID.
func (v *Vault) RevokeGrant(id string) error {
	_, err := v.revoke(id)

	return err
}

// ErrNoSuchGrant is what RevokeLiveGrant returns when there was nothing to
// revoke.
var ErrNoSuchGrant = errors.New("keystore: no live grant with that id")

// RevokeLiveGrant drops a grant and says whether there was one.
//
// Dropping a grant is idempotent, which is the right behaviour for the store
// and the wrong answer for a person: somebody taking a promise back wants to be
// told they took back the one they meant, and a typo that reports success is a
// grant still running. The check and the removal happen under the one lock,
// because doing them as two calls is a race against the sweep in Grants.
func (v *Vault) RevokeLiveGrant(id string) error {
	found, err := v.revoke(id)
	if err != nil {
		return err
	}

	if !found {
		return fmt.Errorf("%w: %s", ErrNoSuchGrant, id)
	}

	return nil
}

// LiveGrant returns a copy of one live grant, or ErrNoSuchGrant.
//
// A copy, because the caller is going to build something out of it — an
// extended promise, a re-signed delegation — and the document belongs to the
// vault. Handing out the stored message would let a caller edit the store by
// accident and without saving it.
func (v *Vault) LiveGrant(id string) (*ladulasv1.Grant, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()

	for _, g := range v.doc.GetGrants() {
		if g.GetGrantId() != id {
			continue
		}

		if !g.GetExpiresAt().AsTime().After(now) {
			break
		}

		return proto.CloneOf(g), nil
	}

	return nil, fmt.Errorf("%w: %s", ErrNoSuchGrant, id)
}

// ReplaceGrant puts an amended promise in place of the one it was made from.
//
// It is how a promise gets more time on it: same identifier, same ledger, a
// later expiry and the sentence re-rendered to match (decision V). The ledger
// is carried across here rather than trusted from the caller, because what has
// been done under a promise is the store's account and not something an
// extension is allowed to rewrite.
func (v *Vault) ReplaceGrant(g *ladulasv1.Grant) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	for i, existing := range v.doc.GetGrants() {
		if existing.GetGrantId() != g.GetGrantId() {
			continue
		}

		amended := proto.CloneOf(g)
		amended.UseCount = existing.GetUseCount()
		amended.RecentUses = existing.GetRecentUses()

		v.doc.Grants[i] = amended

		return v.save()
	}

	return fmt.Errorf("%w: %s", ErrNoSuchGrant, g.GetGrantId())
}

// MarkRevokePending records that a grant has been revoked here and the machine
// holding the delegation could not be told.
//
// It is the honest middle state, and it exists because neither of the tidy
// answers is true. Removing the grant would say the signing had stopped while
// the holder goes on signing without asking anybody; refusing the revoke would
// throw away the intent, so the next reconciliation would renew a promise
// somebody has already taken back. So the record stays, marked, and the next
// contact with the holder ends it.
func (v *Vault) MarkRevokePending(id string, at time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	for _, g := range v.doc.GetGrants() {
		if g.GetGrantId() != id {
			continue
		}

		if g.GetRevokePending() {
			// Asking twice is not an error. The answer is the same and so is
			// the state: still revoked here, still not delivered.
			return nil
		}

		g.RevokePending = true
		g.RevokeRequestedAt = timestamppb.New(at)

		return v.save()
	}

	return fmt.Errorf("%w: %s", ErrNoSuchGrant, id)
}

// PendingRevocations lists the grants delegated to one peer whose revocation
// has not been delivered, which is what the next reconciliation with that peer
// owes it.
func (v *Vault) PendingRevocations(fingerprint string) []string {
	v.mu.Lock()
	defer v.mu.Unlock()

	var out []string

	for _, g := range v.doc.GetGrants() {
		if g.GetRevokePending() && g.GetDelegated() &&
			g.GetDelegateFingerprint() == fingerprint {
			out = append(out, g.GetGrantId())
		}
	}

	return out
}

func (v *Vault) revoke(id string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	var found bool

	kept := make([]*ladulasv1.Grant, 0, len(v.doc.GetGrants()))

	for _, g := range v.doc.GetGrants() {
		if g.GetGrantId() == id {
			found = true

			continue
		}

		kept = append(kept, g)
	}

	v.doc.Grants = kept

	if err := v.save(); err != nil {
		return false, err
	}

	return found, nil
}
