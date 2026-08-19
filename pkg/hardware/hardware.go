// Package hardware is the seam for keys this process cannot read: an iOS
// Secure Enclave key, and later an Android Keystore one (docs/architecture.md
// §7, §10).
//
// Everything on this side of the seam is a handle and a public key. The private
// half never exists as bytes anywhere Go can reach, so what a caller gets back
// is a crypto.Signer that asks the platform for each signature — which is also
// what makes the per-use biometric gate work at all: the prompt happens inside
// the platform's Sign, and Go finds out only whether it produced a signature.
//
// The curve is P-256 and is not a choice. Apple's Secure Enclave is P-256 by
// documentation and StrongBox's KeyMint HAL excludes curve 25519, so a
// hardware-resident SSH key is `ecdsa-sha2-nistp256` or it is not
// hardware-resident (§10).
package hardware

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Backend is the platform's secure element, as the rest of Ladulås needs it.
//
// It is deliberately four calls over strings and byte slices, because on iOS
// the implementation is Swift on the far side of a gomobile binding and that
// boundary carries nothing richer (decision B1).
type Backend interface {
	// Generate creates a P-256 keypair the platform will know by handle, and
	// returns its public half in SSH wire format. A biometric key requires a
	// successful user authentication for every signature; the instance identity
	// key is not one, because a handshake cannot ask for a fingerprint (§7).
	Generate(handle string, biometric bool) ([]byte, error)

	// PublicKey returns the public half of an existing key, in SSH wire format.
	// It is how a store that has a handle checks that the key is still there.
	PublicKey(handle string) ([]byte, error)

	// Sign returns an ASN.1 DER ECDSA signature over a SHA-256 digest. Reason is
	// what the platform shows the user when the key is biometric-gated.
	Sign(handle string, digest []byte, reason string) ([]byte, error)

	// Delete removes a key. A handle the platform does not know is not an error:
	// the store forgetting a key it no longer has should succeed.
	Delete(handle string) error
}

// ErrNoBackend is returned when something in the store names a hardware key on
// an instance that has no secure element to ask.
var ErrNoBackend = errors.New("hardware: this instance has no secure element")

// ErrWrongCurve is returned for a public key that is not P-256.
var ErrWrongCurve = errors.New("hardware: the key is not ecdsa-sha2-nistp256")

// Key is a hardware-resident keypair: a handle, a public half, and the backend
// that will sign with it.
type Key struct {
	backend Backend
	handle  string
	reason  string
	public  ssh.PublicKey
	ecdsa   *ecdsa.PublicKey

	once   sync.Once
	signer ssh.Signer
	err    error
}

var _ crypto.Signer = (*Key)(nil)

// Generate creates a key in the secure element.
func Generate(backend Backend, handle, reason string, biometric bool) (*Key, error) {
	if backend == nil {
		return nil, ErrNoBackend
	}

	blob, err := backend.Generate(handle, biometric)
	if err != nil {
		return nil, fmt.Errorf("hardware: generate %q: %w", handle, err)
	}

	return newKey(backend, handle, reason, blob)
}

// Open builds a key from what the store recorded about it.
//
// The public key comes from the store rather than from the platform, so that
// opening a store does not depend on the secure element being willing to talk.
// A key whose handle has gone — a reinstalled app, a wiped enclave — fails when
// it is asked to sign, which is where the failure is meaningful.
func Open(backend Backend, handle, reason string, public []byte) (*Key, error) {
	if backend == nil {
		return nil, ErrNoBackend
	}

	return newKey(backend, handle, reason, public)
}

func newKey(backend Backend, handle, reason string, blob []byte) (*Key, error) {
	public, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, fmt.Errorf("hardware: parse the public key of %q: %w", handle, err)
	}

	point, err := ecdsaPublicKey(public)
	if err != nil {
		return nil, err
	}

	return &Key{
		backend: backend,
		handle:  handle,
		reason:  reason,
		public:  public,
		ecdsa:   point,
	}, nil
}

func ecdsaPublicKey(public ssh.PublicKey) (*ecdsa.PublicKey, error) {
	holder, ok := public.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: it is %s", ErrWrongCurve, public.Type())
	}

	point, ok := holder.CryptoPublicKey().(*ecdsa.PublicKey)
	if !ok || point.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: it is %s", ErrWrongCurve, public.Type())
	}

	return point, nil
}

// Handle is what the platform knows the key by.
func (k *Key) Handle() string {
	return k.handle
}

// SSHPublicKey is the public half in the shape the rest of Ladulås uses.
func (k *Key) SSHPublicKey() ssh.PublicKey {
	return k.public
}

// Fingerprint identifies the key in trust records, policy and prompts.
func (k *Key) Fingerprint() string {
	return ssh.FingerprintSHA256(k.public)
}

// Public implements crypto.Signer, which is what puts a hardware key in a TLS
// certificate (§8).
func (k *Key) Public() crypto.PublicKey {
	return k.ecdsa
}

// Sign implements crypto.Signer by handing the digest to the platform.
//
// The rand reader is ignored, and has to be: the nonce is generated inside the
// secure element, which is a large part of why the key is in there.
func (k *Key) Sign(
	_ io.Reader, digest []byte, opts crypto.SignerOpts,
) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf(
			"hardware: %q signs SHA-256 digests, not %s", k.handle, opts.HashFunc())
	}

	if len(digest) != crypto.SHA256.Size() {
		return nil, fmt.Errorf(
			"hardware: %q was handed %d bytes where a SHA-256 digest was expected",
			k.handle, len(digest))
	}

	signature, err := k.backend.Sign(k.handle, digest, k.reason)
	if err != nil {
		return nil, fmt.Errorf("hardware: sign with %q: %w", k.handle, err)
	}

	return signature, nil
}

// Signer wraps the key as an ssh.Signer.
//
// x/crypto/ssh does the re-encoding: it hashes with SHA-256 for a P-256 key,
// calls Sign, and converts the ASN.1 signature the platform returned into the
// SSH format. So the whole of what Swift has to produce is a plain DER ECDSA
// signature, which is what SecKeyCreateSignature hands back.
func (k *Key) Signer() (ssh.Signer, error) {
	k.once.Do(func() {
		k.signer, k.err = ssh.NewSignerFromSigner(k)
	})

	if k.err != nil {
		return nil, fmt.Errorf("hardware: wrap %q as a signer: %w", k.handle, k.err)
	}

	return k.signer, nil
}

// Delete removes the key from the secure element.
func (k *Key) Delete() error {
	if err := k.backend.Delete(k.handle); err != nil {
		return fmt.Errorf("hardware: delete %q: %w", k.handle, err)
	}

	return nil
}
