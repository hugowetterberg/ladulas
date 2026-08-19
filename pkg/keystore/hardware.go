package keystore

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/hardware"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// A store on a phone holds the same document as one on a desktop, minus the
// private halves: they are in the secure element and the document records the
// handles the platform knows them by (§10). Everything else — trust records,
// grants, the instance name — is the same, and so is the age encryption around
// it, because a handle is not a secret but the list of who this instance trusts
// still is.

// identityHandle is what the platform knows the instance identity key by. One
// store, one identity, so it does not need to be unique across anything.
const identityHandle = "ladulas-identity"

// identityReason is empty on purpose: the identity key is not biometric-gated,
// so nothing is ever shown for it (§7).
const identityReason = ""

// createHardwareIdentity generates the instance identity inside the secure
// element and returns the document fields that record it.
func createHardwareIdentity(
	backend hardware.Backend, name string,
) (*identity.Identity, string, []byte, error) {
	key, err := hardware.Generate(backend, identityHandle, identityReason, false)
	if err != nil {
		return nil, "", nil, err
	}

	id, err := identity.FromSigner(name, key)
	if err != nil {
		return nil, "", nil, err
	}

	return id, key.Handle(), key.SSHPublicKey().Marshal(), nil
}

// loadIdentity is the one place a store decides where its identity key lives.
//
// A document with a handle in it names a key this process cannot read, and an
// instance with no secure element to ask cannot open such a store at all — as
// opposed to opening it and failing later, which would leave a phone believing
// it had an identity right up until it tried to prove one.
func loadIdentity(
	doc *storepb.StoreDocument, backend hardware.Backend,
) (*identity.Identity, error) {
	handle := doc.GetIdentityHandle()
	if handle == "" {
		id, err := identity.FromPEM(doc.GetIdentityKey(), doc.GetInstanceName())
		if err != nil {
			return nil, fmt.Errorf("load instance identity: %w", err)
		}

		return id, nil
	}

	if backend == nil {
		return nil, fmt.Errorf(
			"%w, and this store's identity key is in one", hardware.ErrNoBackend)
	}

	key, err := hardware.Open(
		backend, handle, identityReason, doc.GetIdentityPublicKey())
	if err != nil {
		return nil, fmt.Errorf("load instance identity: %w", err)
	}

	id, err := identity.FromSigner(doc.GetInstanceName(), key)
	if err != nil {
		return nil, fmt.Errorf("load instance identity: %w", err)
	}

	return id, nil
}

// GenerateHardwareKey creates an SSH key inside the secure element (§10).
//
// The key is biometric-gated per use, which is the whole point of it being
// there: the approval prompt says what is being signed, and the platform's own
// prompt is what actually releases the signature. The two are separate gates on
// purpose — app unlock is state, this is a signature.
func (v *Vault) GenerateHardwareKey(label, comment string) (*storepb.StoredKey, error) {
	if v.hardware == nil {
		return nil, hardware.ErrNoBackend
	}

	if comment == "" {
		comment = label
	}

	handle, err := newKeyHandle()
	if err != nil {
		return nil, err
	}

	key, err := hardware.Generate(v.hardware, handle, signingReason(label), true)
	if err != nil {
		return nil, err
	}

	stored, err := v.addHardwareKey(key, label, comment)
	if err != nil {
		// A key nobody recorded is a key nobody can use, and leaving it in the
		// enclave would leak a slot per failed attempt.
		if deleteErr := key.Delete(); deleteErr != nil {
			return nil, fmt.Errorf("%w (and the key was left behind: %w)",
				err, deleteErr)
		}

		return nil, err
	}

	return stored, nil
}

// signingReason is what the platform shows when the key is used.
//
// It names the key rather than the operation, because the store does not know
// what a signature is for and the approval prompt — which does — is already on
// screen by the time this appears. The platform prompt's job here is to be the
// gate, not the explanation.
func signingReason(label string) string {
	return "Sign with " + label
}

func (v *Vault) addHardwareKey(
	key *hardware.Key, label, comment string,
) (*storepb.StoredKey, error) {
	public := key.SSHPublicKey()

	v.mu.Lock()
	defer v.mu.Unlock()

	if err := v.checkNewKey(public, label); err != nil {
		return nil, err
	}

	stored := &storepb.StoredKey{
		Label:          label,
		Fingerprint:    key.Fingerprint(),
		Algorithm:      public.Type(),
		Comment:        comment,
		PublicKey:      public.Marshal(),
		AddedAt:        timestamppb.Now(),
		Origin:         storepb.KeyOrigin_KEY_ORIGIN_GENERATED,
		HardwareHandle: key.Handle(),
	}

	v.doc.Keys = append(v.doc.GetKeys(), stored)

	if err := v.save(); err != nil {
		return nil, err
	}

	return stored, nil
}

// checkNewKey refuses a key the store already has, and a label already in use.
// Callers hold the write lock.
func (v *Vault) checkNewKey(public ssh.PublicKey, label string) error {
	fingerprint := ssh.FingerprintSHA256(public)

	for _, k := range v.doc.GetKeys() {
		if k.GetFingerprint() == fingerprint {
			return fmt.Errorf("%w as %q", ErrDuplicateKey, k.GetLabel())
		}
	}

	if label == "" {
		return errors.New("keystore: a hardware key needs a label")
	}

	for _, k := range v.doc.GetKeys() {
		if strings.EqualFold(k.GetLabel(), label) {
			return fmt.Errorf("keystore: label %q is already in use", label)
		}
	}

	return nil
}

// hardwareSigner produces the signer for a key whose private half is not here.
func (v *Vault) hardwareSigner(k *storepb.StoredKey) (ssh.Signer, error) {
	if v.hardware == nil {
		return nil, fmt.Errorf("%w, and %q is in one",
			hardware.ErrNoBackend, k.GetLabel())
	}

	key, err := hardware.Open(v.hardware, k.GetHardwareHandle(),
		signingReason(k.GetLabel()), k.GetPublicKey())
	if err != nil {
		return nil, err
	}

	signer, err := key.Signer()
	if err != nil {
		return nil, err
	}

	return signer, nil
}

// handleEncoding keeps handles short and free of characters a keychain query
// would have to escape.
var handleEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func newKeyHandle() (string, error) {
	var buf [10]byte

	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("keystore: no randomness for a key handle: %w", err)
	}

	return "ladulas-key-" + strings.ToLower(handleEncoding.EncodeToString(buf[:])), nil
}
