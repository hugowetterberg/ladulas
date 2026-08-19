package keystore_test

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/pkg/hardware"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
)

// A store on a phone: the identity and the SSH keys are handles, the trust
// records and grants are the same document, and reopening it produces the same
// instance rather than a new one.
func newHardwareVault(t *testing.T) (*keystore.Vault, keystore.Options, *hardware.Memory) {
	t.Helper()

	backend := hardware.NewMemory()

	opts := keystore.Options{
		Dir:              t.TempDir(),
		Keyring:          &keystore.MemoryKeyring{},
		Passphrase:       staticPassphrase(testPassphrase),
		InstanceName:     "phone",
		Hardware:         backend,
		ScryptWorkFactor: 10,
	}

	v, err := keystore.Create(opts)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	return v, opts, backend
}

func TestHardwareIdentitySurvivesReopening(t *testing.T) {
	v, opts, _ := newHardwareVault(t)

	fingerprint := v.Identity().Fingerprint()

	if got := v.Identity().PublicKey().Type(); got != ssh.KeyAlgoECDSA256 {
		t.Errorf("a phone identity is %s, not %s", got, ssh.KeyAlgoECDSA256)
	}

	reopened, err := keystore.Open(opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	if reopened.Identity().Fingerprint() != fingerprint {
		t.Errorf("the reopened instance is %s, not %s",
			reopened.Identity().Fingerprint(), fingerprint)
	}
}

// The document holds no private half at all — which is the property the whole
// arrangement exists for, and the one worth asserting rather than trusting.
func TestAHardwareStoreHoldsNoPrivateKeys(t *testing.T) {
	v, _, _ := newHardwareVault(t)

	if _, err := v.GenerateHardwareKey("phone-p256", "hugo@phone"); err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	for _, key := range v.Keys() {
		if len(key.GetPrivateKey()) != 0 {
			t.Errorf("%q has a private half in the store", key.GetLabel())
		}

		if key.GetHardwareHandle() == "" {
			t.Errorf("%q has no handle", key.GetLabel())
		}

		if key.GetAlgorithm() != ssh.KeyAlgoECDSA256 {
			t.Errorf("%q is %s; the enclave only does P-256",
				key.GetLabel(), key.GetAlgorithm())
		}
	}
}

func TestAHardwareKeySignsThroughTheStore(t *testing.T) {
	v, _, backend := newHardwareVault(t)

	stored, err := v.GenerateHardwareKey("phone-p256", "")
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	signer, found, err := v.Signer(stored.GetFingerprint())
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	if found.GetLabel() != "phone-p256" {
		t.Errorf("the store returned %q", found.GetLabel())
	}

	payload := []byte("SSHSIG...")

	signature, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	public, err := ssh.ParsePublicKey(stored.GetPublicKey())
	if err != nil {
		t.Fatalf("parse the public key: %v", err)
	}

	if err := public.Verify(payload, signature); err != nil {
		t.Fatalf("the signature does not verify: %v", err)
	}

	// The signature came out from behind a prompt, and the prompt named the key.
	prompts := backend.Prompts()
	if len(prompts) != 1 || !strings.Contains(prompts[0], "phone-p256") {
		t.Errorf("the platform was asked to display %q", prompts)
	}
}

// Removing a key takes it out of the enclave too, so a revoked key does not
// linger where nothing can see it.
func TestRemovingAHardwareKeyForgetsTheHandle(t *testing.T) {
	v, _, backend := newHardwareVault(t)

	stored, err := v.GenerateHardwareKey("phone-p256", "")
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	if err := v.RemoveKey("phone-p256"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	if _, err := backend.PublicKey(stored.GetHardwareHandle()); !errors.Is(
		err, hardware.ErrNoSuchHandle) {
		t.Errorf("the enclave still holds the key: %v", err)
	}
}

// A store whose identity is a handle cannot be opened by a build with no secure
// element. Failing here is the honest place: an instance that opened and then
// could not prove an identity would look paired until it tried to be.
func TestAHardwareStoreNeedsItsBackendToOpen(t *testing.T) {
	_, opts, _ := newHardwareVault(t)

	opts.Hardware = nil

	if _, err := keystore.Open(opts); !errors.Is(err, hardware.ErrNoBackend) {
		t.Errorf("opening without the enclave gave %v", err)
	}
}

// And a desktop store is untouched by any of it.
func TestASoftwareStoreStillHasItsKeys(t *testing.T) {
	v, _ := newVault(t)

	if _, err := v.GenerateKey("desktop", ""); err != nil {
		t.Fatalf("generate: %v", err)
	}

	for _, key := range v.Keys() {
		if len(key.GetPrivateKey()) == 0 {
			t.Errorf("%q lost its private half", key.GetLabel())
		}

		if key.GetHardwareHandle() != "" {
			t.Errorf("%q grew a handle", key.GetLabel())
		}
	}

	if _, err := v.GenerateHardwareKey("enclave", ""); !errors.Is(
		err, hardware.ErrNoBackend) {
		t.Errorf("a desktop generated a hardware key: %v", err)
	}
}
