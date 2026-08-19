package keystore

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/zalando/go-keyring"
)

// ErrNoWrapping is returned when a store's data encryption key cannot be
// recovered by any configured means.
var ErrNoWrapping = errors.New("keystore: no way to unwrap the data encryption key")

// ErrNotFound is returned by a Keyring that has no entry under a name.
var ErrNotFound = errors.New("keystore: no keyring entry")

// ErrPassphraseNeeded is returned when the store can only be opened with a
// passphrase and none was supplied. It is what the control socket turns into
// "run `ladulas unlock`" rather than a failure.
var ErrPassphraseNeeded = errors.New("keystore: the store passphrase is needed")

// ErrWrongPassphrase is returned when a passphrase does not unwrap the data
// encryption key.
//
// It exists because this is the single most common thing that goes wrong at any
// gate this program has, and without a sentinel the only thing a gate could
// show for it was age's account of itself: "decrypt wrapped key: no identity
// matched any of the recipients". That is a true sentence about a file format
// and a useless one to somebody who mistyped. A caller that wants to say so in
// its own words now has something to test for.
var ErrWrongPassphrase = errors.New("keystore: wrong passphrase")

// keyringService is the service name Ladulås registers under in the platform
// keychain.
const keyringService = "ladulas"

// Keyring wraps the platform keychain. It stores exactly one small secret per
// store: the age identity that decrypts the store file.
//
// Library choice (docs/architecture.md §18 open question 3):
// zalando/go-keyring over 99designs/keyring. What Ladulås needs from a
// keychain is a single get/set/delete of a 74-character string, and go-keyring
// is a thin, cgo-free wrapper over exactly that — DBus Secret Service on
// Linux, the `security` binary on macOS, wincred on Windows.
// 99designs/keyring's extra value is its alternative backends (file, pass,
// kwallet, keyctl), and those duplicate the passphrase wrapping Ladulås has to
// implement anyway for headless boxes, at the cost of a much larger dependency
// tree in the security-critical path.
type Keyring interface {
	// Get returns the secret stored under name, or ErrNotFound.
	Get(name string) (string, error)
	// Has reports whether there is an entry under name, without reading it.
	//
	// The distinction is nothing on a desktop and everything on a phone, where
	// the item's access control makes reading it the Face ID prompt (§10). "Is
	// this instance enrolled" is a question a status pane asks every time it
	// draws, and answering it by reading the secret would put a biometric sheet
	// in front of somebody who only wanted to look at a list.
	//
	// It says whether there is an item to try, which is not the same as saying
	// the item still works: an entry invalidated by a biometric change may well
	// still be there and fail on the first read. That is what the passphrase
	// fallback and the re-enrolment behind it are for.
	Has(name string) (bool, error)
	Set(name, secret string) error
	Delete(name string) error
}

// SystemKeyring is the platform keychain.
type SystemKeyring struct{}

// Get implements Keyring.
func (SystemKeyring) Get(name string) (string, error) {
	secret, err := keyring.Get(keyringService, name)

	switch {
	case errors.Is(err, keyring.ErrNotFound):
		return "", ErrNotFound
	case err != nil:
		return "", fmt.Errorf("read keyring entry: %w", err)
	}

	return secret, nil
}

// Has implements Keyring.
//
// A platform keychain that is readable without a prompt has nothing cheaper to
// offer than a read, so this is one.
func (k SystemKeyring) Has(name string) (bool, error) {
	_, err := k.Get(name)

	switch {
	case errors.Is(err, ErrNotFound):
		return false, nil
	case err != nil:
		return false, err
	}

	return true, nil
}

// Set implements Keyring.
func (SystemKeyring) Set(name, secret string) error {
	if err := keyring.Set(keyringService, name, secret); err != nil {
		return fmt.Errorf("write keyring entry: %w", err)
	}

	return nil
}

// Delete implements Keyring.
func (SystemKeyring) Delete(name string) error {
	err := keyring.Delete(keyringService, name)

	switch {
	case errors.Is(err, keyring.ErrNotFound):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("delete keyring entry: %w", err)
	}

	return nil
}

// NoKeyring disables keychain wrapping, leaving the passphrase as the only way
// in. This is what a headless box without a session keyring gets.
type NoKeyring struct{}

// Get implements Keyring.
func (NoKeyring) Get(string) (string, error) {
	return "", ErrNotFound
}

// Has implements Keyring.
func (NoKeyring) Has(string) (bool, error) {
	return false, nil
}

// Set implements Keyring.
func (NoKeyring) Set(string, string) error {
	return errors.New("keystore: no keyring available")
}

// Delete implements Keyring.
func (NoKeyring) Delete(string) error {
	return ErrNotFound
}

// MemoryKeyring is a keyring that lives for the lifetime of the process. It
// exists for tests and for running a second instance against a scratch store;
// it provides no protection at rest, so the store it wraps is only as safe as
// its passphrase wrapping.
type MemoryKeyring struct {
	mu      sync.Mutex
	secrets map[string]string
}

// Get implements Keyring.
func (m *MemoryKeyring) Get(name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret, ok := m.secrets[name]
	if !ok {
		return "", ErrNotFound
	}

	return secret, nil
}

// Has implements Keyring.
func (m *MemoryKeyring) Has(name string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.secrets[name]

	return ok, nil
}

// Set implements Keyring.
func (m *MemoryKeyring) Set(name, secret string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.secrets == nil {
		m.secrets = map[string]string{}
	}

	m.secrets[name] = secret

	return nil
}

// Names is what is in here, sorted. A real keychain is not enumerable like
// this; a test is, and what it buys is the ability to assert on the name an
// entry was filed under rather than only on whether a read happened to work —
// which is the difference between catching a name that mentions a path and
// waiting for the path to move.
func (m *MemoryKeyring) Names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	names := make([]string, 0, len(m.secrets))

	for name := range m.secrets {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

// Clear forgets everything, which is a platform keychain deciding an item is
// no longer valid — on iOS, a re-enrolled face invalidating an item bound to
// the biometric set that was current when it was written (§10).
func (m *MemoryKeyring) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.secrets = nil
}

// Delete implements Keyring.
func (m *MemoryKeyring) Delete(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.secrets[name]; !ok {
		return ErrNotFound
	}

	delete(m.secrets, name)

	return nil
}

// PassphraseFunc asks the user for a passphrase. confirm is set when the
// passphrase is being established rather than checked, so the prompt should ask
// twice.
//
// It hands back bytes rather than a string because the caller wipes what it was
// given (§14), and a string cannot be wiped.
type PassphraseFunc func(prompt string, confirm bool) ([]byte, error)

// Wipe overwrites a passphrase buffer.
//
// It is worth being precise about what this does and does not achieve. It
// clears the buffer this process owns, which is what "the daemon derives the
// key encryption key and wipes the input" (§14) can honestly mean; it cannot
// reach the copies scrypt and age make internally, and it cannot undo a page
// that has already been swapped. What it removes is the passphrase sitting in a
// long-lived daemon's heap for the rest of the boot.
func Wipe(secret []byte) {
	for i := range secret {
		secret[i] = 0
	}
}

// keyringName is the keychain entry name for a store directory. Including the
// path lets several stores coexist, which matters for tests and for anyone
// running a second instance.
func keyringName(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}

	return "store-dek:" + abs
}

// DefaultScryptWorkFactor is age's log2 work factor for passphrase wrapping.
// age's own default is 18; 19 roughly doubles the cost of an offline guessing
// attack against a store backup and still unwraps in about a second, which is
// fine for something typed at most once per boot.
const DefaultScryptWorkFactor = 19

// writeWrappedDEK writes the passphrase-wrapped copy of the data encryption
// key. The file is ASCII armored age, so recovering a backup is
//
//	age -d dek.age            # gives the AGE-SECRET-KEY-1… identity
//	age -d -i <that> store.age
//
// with nothing but standalone age tooling and the passphrase (§18).
func writeWrappedDEK(
	path string, dek *age.X25519Identity, passphrase []byte, workFactor int,
) error {
	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return fmt.Errorf("build passphrase recipient: %w", err)
	}

	if workFactor <= 0 {
		workFactor = DefaultScryptWorkFactor
	}

	recipient.SetWorkFactor(workFactor)

	return writeFileAtomic(path, 0o600, func(f io.Writer) error {
		armorWriter := armor.NewWriter(f)

		w, err := age.Encrypt(armorWriter, recipient)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}

		if _, err := io.WriteString(w, dek.String()); err != nil {
			return fmt.Errorf("write: %w", err)
		}

		if err := w.Close(); err != nil {
			return fmt.Errorf("close age writer: %w", err)
		}

		if err := armorWriter.Close(); err != nil {
			return fmt.Errorf("close armor writer: %w", err)
		}

		return nil
	})
}

// readWrappedDEK unwraps the passphrase-protected data encryption key.
func readWrappedDEK(path string, passphrase []byte) (*age.X25519Identity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read wrapped key: %w", err)
	}

	id, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, fmt.Errorf("build passphrase identity: %w", err)
	}

	// A wrong passphrase and a corrupt wrapping are the same failure to age, and
	// telling them apart is not worth a format change: the file is this
	// program's own armoured scrypt blob, written once and never edited, so a
	// passphrase that does not open it is overwhelmingly a passphrase that is
	// wrong. The detail stays on the error for a log to keep.
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(string(raw))), id)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWrongPassphrase, err)
	}

	body, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read wrapped key body: %w", err)
	}

	dek, err := age.ParseX25519Identity(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, fmt.Errorf("parse data encryption key: %w", err)
	}

	return dek, nil
}
