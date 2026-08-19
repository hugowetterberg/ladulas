package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// ErrPassphraseRequired is returned by ImportKey when the private key is
// passphrase protected and no passphrase was supplied. 1Password exports
// unencrypted keys, but ssh-keygen-generated ones are usually encrypted.
var ErrPassphraseRequired = errors.New("keystore: private key is passphrase protected")

// ErrDuplicateKey is returned when importing a key the store already holds.
var ErrDuplicateKey = errors.New("keystore: key already in the store")

// ImportKey adds an existing OpenSSH-format private key to the store, in the
// shape 1Password exports it (§14). The key is decrypted on the way in and
// re-stored unencrypted inside the age-encrypted store, so the store's own
// unlock is the only passphrase in the daily path.
//
// A passphrase-protected key with an empty passphrase returns
// ErrPassphraseRequired so the caller can prompt and retry.
func (v *Vault) ImportKey(keyPEM []byte, passphrase, label string) (*storepb.StoredKey, error) {
	signer, normalized, err := parsePrivateKey(keyPEM, passphrase)
	if err != nil {
		return nil, err
	}

	return v.addKey(signer, normalized, label,
		storepb.KeyOrigin_KEY_ORIGIN_IMPORTED)
}

// GenerateKey creates a fresh ed25519 key in the store (§10). This is the
// recommended path — per-device keys, rotated into GitHub and authorized_keys,
// rather than one key copied everywhere.
func (v *Vault) GenerateKey(label, comment string) (*storepb.StoredKey, error) {
	if comment == "" {
		comment = label
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(block)

	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("reparse generated key: %w", err)
	}

	return v.addKey(signer, keyPEM, label,
		storepb.KeyOrigin_KEY_ORIGIN_GENERATED)
}

// parsePrivateKey decrypts and normalizes a private key to an unencrypted
// OpenSSH PEM block, whatever format it arrived in.
func parsePrivateKey(keyPEM []byte, passphrase string) (ssh.Signer, []byte, error) {
	var (
		raw any
		err error
	)

	if passphrase == "" {
		raw, err = ssh.ParseRawPrivateKey(keyPEM)

		var missing *ssh.PassphraseMissingError

		if errors.As(err, &missing) {
			return nil, nil, ErrPassphraseRequired
		}
	} else {
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(keyPEM, []byte(passphrase))
	}

	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(raw, keyComment(keyPEM))
	if err != nil {
		return nil, nil, fmt.Errorf("normalize private key: %w", err)
	}

	normalized := pem.EncodeToMemory(block)

	signer, err := ssh.ParsePrivateKey(normalized)
	if err != nil {
		return nil, nil, fmt.Errorf("reparse private key: %w", err)
	}

	return signer, normalized, nil
}

func (v *Vault) addKey(
	signer ssh.Signer, keyPEM []byte, label string, origin storepb.KeyOrigin,
) (*storepb.StoredKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	return v.addKeyLocked(signer, keyPEM, label, origin, nil)
}

// addKeyLocked is addKey for a caller that already holds the write lock and has
// more to do under it — accepting an offered key is a removal and an addition
// that must not be seen half done (decision S). from is where the key came
// from, on a key that came from a peer, and nil otherwise.
func (v *Vault) addKeyLocked(
	signer ssh.Signer, keyPEM []byte, label string, origin storepb.KeyOrigin,
	from *storepb.KeyTransfer,
) (*storepb.StoredKey, error) {
	pub := signer.PublicKey()
	fingerprint := ssh.FingerprintSHA256(pub)

	for _, k := range v.doc.GetKeys() {
		if k.GetFingerprint() == fingerprint {
			return nil, fmt.Errorf("%w as %q", ErrDuplicateKey, k.GetLabel())
		}
	}

	if label == "" {
		label = defaultLabel(pub, len(v.doc.GetKeys()))
	}

	for _, k := range v.doc.GetKeys() {
		if strings.EqualFold(k.GetLabel(), label) {
			return nil, fmt.Errorf("keystore: label %q is already in use", label)
		}
	}

	key := &storepb.StoredKey{
		Label:        label,
		Fingerprint:  fingerprint,
		Algorithm:    pub.Type(),
		Comment:      keyComment(keyPEM),
		PublicKey:    pub.Marshal(),
		PrivateKey:   keyPEM,
		AddedAt:      timestamppb.Now(),
		Origin:       origin,
		ReceivedFrom: from,
	}

	v.doc.Keys = append(v.doc.GetKeys(), key)

	if err := v.save(); err != nil {
		return nil, err
	}

	return proto.CloneOf(key), nil
}

func defaultLabel(pub ssh.PublicKey, n int) string {
	algo := strings.TrimPrefix(pub.Type(), "ssh-")
	algo = strings.TrimPrefix(algo, "ecdsa-sha2-")

	if n == 0 {
		return algo
	}

	return fmt.Sprintf("%s-%d", algo, n+1)
}

// Keys returns the keys the store holds, private halves included. Callers that
// only need to display keys should use KeyRefs.
func (v *Vault) Keys() []*storepb.StoredKey {
	v.mu.RLock()
	defer v.mu.RUnlock()

	out := make([]*storepb.StoredKey, 0, len(v.doc.GetKeys()))
	for _, k := range v.doc.GetKeys() {
		out = append(out, proto.CloneOf(k))
	}

	return out
}

// KeyRefs returns the public halves of the enabled keys, in the form the
// protocol and the approval prompts use.
func (v *Vault) KeyRefs() []*ladulasv1.KeyRef {
	v.mu.RLock()
	defer v.mu.RUnlock()

	out := make([]*ladulasv1.KeyRef, 0, len(v.doc.GetKeys()))

	for _, k := range v.doc.GetKeys() {
		if k.GetDisabled() {
			continue
		}

		out = append(out, KeyRef(k))
	}

	return out
}

// KeyRef projects a stored key onto the wire type.
func KeyRef(k *storepb.StoredKey) *ladulasv1.KeyRef {
	use := AgentUse(k)

	return &ladulasv1.KeyRef{
		Fingerprint: k.GetFingerprint(),
		Algorithm:   k.GetAlgorithm(),
		PublicKey:   k.GetPublicKey(),
		Comment:     k.GetComment(),
		Label:       k.GetLabel(),
		AgentUse:    &use,
	}
}

// AgentUse reports whether a key belongs in an agent's identity list
// (decision T).
//
// Unset means yes, and that is the whole reason this function exists rather than
// a call to GetAgentUse: every key written before the field did is unset, and a
// key that dropped out of the agent because the store was upgraded would be a
// key that had silently stopped working.
func AgentUse(k *storepb.StoredKey) bool {
	return k.AgentUse == nil || k.GetAgentUse()
}

// RefAgentUse is AgentUse for a key that arrived over the channel, where unset
// means the same thing and for the same reason: a peer that has not heard of the
// setting still offers its keys.
func RefAgentUse(ref *ladulasv1.KeyRef) bool {
	return ref.AgentUse == nil || ref.GetAgentUse()
}

// AuthorizedKeyLine renders a stored key the way OpenSSH writes one: the
// algorithm, the base64 blob and the comment, on one line.
//
// It is what has to be copied into GitHub, authorized_keys and allowed_signers,
// and for every key that is not deliberately handed to a peer (decision S) it is
// the only thing that ever leaves the device — which makes it worth having in
// one place rather than assembled by every front end that shows a key.
func AuthorizedKeyLine(k *storepb.StoredKey) (string, error) {
	pub, err := ssh.ParsePublicKey(k.GetPublicKey())
	if err != nil {
		return "", fmt.Errorf("parse the public key of %q: %w", k.GetLabel(), err)
	}

	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))

	if comment := k.GetComment(); comment != "" {
		line += " " + comment
	}

	return line, nil
}

// Signer returns a signer for the key with the given fingerprint.
func (v *Vault) Signer(fingerprint string) (ssh.Signer, *storepb.StoredKey, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	for _, k := range v.doc.GetKeys() {
		if k.GetFingerprint() != fingerprint || k.GetDisabled() {
			continue
		}

		// A key with a handle has no private half here, and asking the platform
		// for it is where the biometric prompt happens (§10).
		if k.GetHardwareHandle() != "" {
			signer, err := v.hardwareSigner(k)
			if err != nil {
				return nil, nil, err
			}

			return signer, proto.CloneOf(k), nil
		}

		signer, err := ssh.ParsePrivateKey(k.GetPrivateKey())
		if err != nil {
			return nil, nil, fmt.Errorf("load key %q: %w", k.GetLabel(), err)
		}

		// A portable key on a platform that installed a gate prompts per
		// signature the way the key next to it in the enclave does (decision S).
		// The gate is wrapped around the signer rather than called here, so that
		// it happens when the signature does and outside this lock — it draws a
		// sheet and waits for a person.
		if v.gate != nil {
			signer = &gatedSigner{
				signer: signer,
				gate:   v.gate,
				reason: signingReason(k.GetLabel()),
			}
		}

		return signer, proto.CloneOf(k), nil
	}

	return nil, nil, fmt.Errorf("%w: %s", ErrNoSuchKey, fingerprint)
}

// RemoveKey deletes a key from the store, by fingerprint or by label.
//
// A hardware key is removed from the secure element too. The order is
// deliberate: the document is written first, so a platform that refuses to
// forget leaves a key the store no longer offers rather than a store still
// offering a key that has gone.
func (v *Vault) RemoveKey(ref string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	kept := make([]*storepb.StoredKey, 0, len(v.doc.GetKeys()))

	var removed *storepb.StoredKey

	for _, k := range v.doc.GetKeys() {
		if k.GetFingerprint() == ref || strings.EqualFold(k.GetLabel(), ref) {
			removed = k

			continue
		}

		kept = append(kept, k)
	}

	if removed == nil {
		return fmt.Errorf("%w: %s", ErrNoSuchKey, ref)
	}

	v.doc.Keys = kept

	if err := v.save(); err != nil {
		return err
	}

	if handle := removed.GetHardwareHandle(); handle != "" && v.hardware != nil {
		if err := v.hardware.Delete(handle); err != nil {
			return fmt.Errorf(
				"keystore: %q was removed from the store, but the secure element "+
					"still holds it: %w", removed.GetLabel(), err)
		}
	}

	return nil
}

// SetKeyDisabled turns a key on or off without removing it. A disabled key is
// not offered by the agent.
func (v *Vault) SetKeyDisabled(ref string, disabled bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	for _, k := range v.doc.GetKeys() {
		if k.GetFingerprint() == ref || strings.EqualFold(k.GetLabel(), ref) {
			k.Disabled = disabled

			return v.save()
		}
	}

	return fmt.Errorf("%w: %s", ErrNoSuchKey, ref)
}

// SetKeyAgentUse takes a key out of the agent's identity list, or puts it back
// (decision T), and returns the key as it now stands.
//
// It changes nothing about what the key may do. Somebody who has just hidden a
// key can go on signing commits with it, which is exactly the case the setting
// is for: a key that git names and ssh should not be handed.
func (v *Vault) SetKeyAgentUse(ref string, use bool) (*storepb.StoredKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	for _, k := range v.doc.GetKeys() {
		if k.GetFingerprint() != ref && !strings.EqualFold(k.GetLabel(), ref) {
			continue
		}

		k.AgentUse = &use

		if err := v.save(); err != nil {
			return nil, err
		}

		return proto.CloneOf(k), nil
	}

	return nil, fmt.Errorf("%w: %s", ErrNoSuchKey, ref)
}
