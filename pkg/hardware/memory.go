package hardware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Memory is a Backend that keeps the private halves in this process.
//
// It exists so the rest of Ladulås can be tested on a machine with no secure
// element, and so the iOS simulator — which has no Secure Enclave to speak of —
// can run the app at all. It is not a fallback: nothing selects it
// automatically, and an instance running on one is an instance whose keys are
// as exposed as its memory. The real backends are the platform ones.
type Memory struct {
	mu   sync.Mutex
	keys map[string]*memoryKey
	// Prompted records the reasons Sign was asked to display, so a test can
	// assert that a biometric key was actually used behind a prompt.
	Prompted []string
	// Fail, when set, is returned by Sign — the "the user cancelled Face ID"
	// case, which is an ordinary outcome rather than an error to be surprised by.
	Fail error
}

type memoryKey struct {
	key       *ecdsa.PrivateKey
	biometric bool
}

var _ Backend = (*Memory)(nil)

// NewMemory creates an empty software backend.
func NewMemory() *Memory {
	return &Memory{keys: map[string]*memoryKey{}}
}

// ErrNoSuchHandle is returned for a handle the backend does not know.
var ErrNoSuchHandle = errors.New("hardware: no key under that handle")

// Generate implements Backend.
func (m *Memory) Generate(handle string, biometric bool) ([]byte, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate a P-256 key: %w", err)
	}

	public, err := ssh.NewPublicKey(&private.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("wrap the public key: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys[handle] = &memoryKey{key: private, biometric: biometric}

	return public.Marshal(), nil
}

// PublicKey implements Backend.
func (m *Memory) PublicKey(handle string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	held, ok := m.keys[handle]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchHandle, handle)
	}

	public, err := ssh.NewPublicKey(&held.key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("wrap the public key: %w", err)
	}

	return public.Marshal(), nil
}

// Sign implements Backend.
func (m *Memory) Sign(handle string, digest []byte, reason string) ([]byte, error) {
	m.mu.Lock()

	held, ok := m.keys[handle]
	failure := m.Fail

	if ok && held.biometric {
		m.Prompted = append(m.Prompted, reason)
	}

	m.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchHandle, handle)
	}

	if failure != nil {
		return nil, failure
	}

	signature, err := ecdsa.SignASN1(rand.Reader, held.key, digest)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return signature, nil
}

// Delete implements Backend.
func (m *Memory) Delete(handle string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.keys, handle)

	return nil
}

// Prompts returns the reasons the backend has been asked to display.
func (m *Memory) Prompts() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]string(nil), m.Prompted...)
}
