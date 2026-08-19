// Package sshsig implements the SSHSIG signature format that git uses for
// commit and tag signatures (docs/architecture.md §17, PROTOCOL.sshsig in
// openssh).
//
// Ladulås needs both halves of it. The signing blob — preamble, namespace and
// message digest — is what the SSH agent receives and what pkg/agent
// classifies, and the armoured signature file is what ladulas-sign writes for
// git. The reason the wrapper is built here rather than at the caller is §5:
// ladulas-sign submits the raw commit object, and the signing instance computes
// the wrapper itself, so the approver sees the object and not a digest.
package sshsig

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	// Magic is the six raw bytes an SSHSIG blob starts with. It carries no
	// length prefix, which is what makes agent request classification
	// unambiguous (§4).
	Magic = "SSHSIG"

	// Version is the only SSHSIG version that exists.
	Version = 1

	// HashSHA512 and HashSHA256 are the two hash algorithms the format allows.
	// git and ssh-keygen both default to sha512.
	HashSHA512 = "sha512"
	HashSHA256 = "sha256"

	// DefaultHash is what an empty hash algorithm means.
	DefaultHash = HashSHA512

	// GitNamespace is the namespace git signs commits and tags under.
	GitNamespace = "git"

	armorBegin = "-----BEGIN SSH SIGNATURE-----"
	armorEnd   = "-----END SSH SIGNATURE-----"

	// armorWidth is where ssh-keygen wraps the base64 body. Matching it keeps
	// signature files byte-identical to the ones ssh-keygen writes, which is
	// worth something when the two are meant to be interchangeable.
	armorWidth = 70
)

// ErrNotSSHSIG is returned for data that is not an SSHSIG signature at all.
var ErrNotSSHSIG = errors.New("sshsig: not an SSHSIG signature")

// Hash digests a message with one of the two permitted algorithms.
func Hash(algorithm string, message []byte) ([]byte, error) {
	switch algorithm {
	case HashSHA512, "":
		sum := sha512.Sum512(message)

		return sum[:], nil
	case HashSHA256:
		sum := sha256.Sum256(message)

		return sum[:], nil
	default:
		return nil, fmt.Errorf("sshsig: unsupported hash algorithm %q", algorithm)
	}
}

// NormaliseHash resolves an empty hash algorithm to the default.
func NormaliseHash(algorithm string) string {
	if algorithm == "" {
		return DefaultHash
	}

	return algorithm
}

// blobBody is everything after the magic preamble in the data that gets signed.
type blobBody struct {
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Hash          string
}

// SigningBlob builds the byte string a signer actually signs: the preamble, the
// namespace and the digest of the message. This is the payload the SSH agent
// receives from ssh-keygen, and the one Ladulås builds for itself when it signs
// on behalf of ladulas-sign.
func SigningBlob(namespace, hashAlgorithm string, digest []byte) []byte {
	body := ssh.Marshal(blobBody{
		Namespace:     namespace,
		HashAlgorithm: NormaliseHash(hashAlgorithm),
		Hash:          string(digest),
	})

	out := make([]byte, 0, len(Magic)+len(body))
	out = append(out, Magic...)
	out = append(out, body...)

	return out
}

// SigningBlobFor digests a message and builds the blob to sign over it.
func SigningBlobFor(namespace, hashAlgorithm string, message []byte) ([]byte, error) {
	digest, err := Hash(hashAlgorithm, message)
	if err != nil {
		return nil, err
	}

	return SigningBlob(namespace, hashAlgorithm, digest), nil
}

// Signature is a parsed SSHSIG signature.
type Signature struct {
	PublicKey     ssh.PublicKey
	Namespace     string
	HashAlgorithm string
	Signature     *ssh.Signature
}

// wire is the signature file's structure after the magic preamble.
type wire struct {
	Version       uint32
	PublicKey     string
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Signature     string
}

// Marshal returns the binary signature, which is what the armour wraps.
func (s *Signature) Marshal() []byte {
	body := ssh.Marshal(wire{
		Version:       Version,
		PublicKey:     string(s.PublicKey.Marshal()),
		Namespace:     s.Namespace,
		HashAlgorithm: NormaliseHash(s.HashAlgorithm),
		Signature:     string(ssh.Marshal(s.Signature)),
	})

	out := make([]byte, 0, len(Magic)+len(body))
	out = append(out, Magic...)
	out = append(out, body...)

	return out
}

// Armored returns the signature in the PEM-like form ssh-keygen writes to
// <file>.sig and git embeds in the gpgsig header.
func (s *Signature) Armored() string {
	encoded := base64.StdEncoding.EncodeToString(s.Marshal())

	var b strings.Builder

	b.WriteString(armorBegin)
	b.WriteString("\n")

	for len(encoded) > armorWidth {
		b.WriteString(encoded[:armorWidth])
		b.WriteString("\n")

		encoded = encoded[armorWidth:]
	}

	b.WriteString(encoded)
	b.WriteString("\n")
	b.WriteString(armorEnd)
	b.WriteString("\n")

	return b.String()
}

// Sign wraps a message in SSHSIG and signs it with the signer.
//
// The signature algorithm follows what OpenSSH does: RSA keys sign with
// rsa-sha2-512, because ssh-rsa is SHA-1 and no longer acceptable to anything
// that will be verifying these signatures.
func Sign(
	signer ssh.Signer, namespace, hashAlgorithm string, message []byte,
) (*Signature, error) {
	if namespace == "" {
		return nil, errors.New("sshsig: empty namespace")
	}

	blob, err := SigningBlobFor(namespace, hashAlgorithm, message)
	if err != nil {
		return nil, err
	}

	sig, err := SignBlob(signer, blob)
	if err != nil {
		return nil, err
	}

	return &Signature{
		PublicKey:     signer.PublicKey(),
		Namespace:     namespace,
		HashAlgorithm: NormaliseHash(hashAlgorithm),
		Signature:     sig,
	}, nil
}

// SignBlob signs an already-built SSHSIG blob, picking the signature algorithm
// the key calls for.
func SignBlob(signer ssh.Signer, blob []byte) (*ssh.Signature, error) {
	if signer.PublicKey().Type() != ssh.KeyAlgoRSA {
		sig, err := signer.Sign(rand.Reader, blob)
		if err != nil {
			return nil, fmt.Errorf("sign: %w", err)
		}

		return sig, nil
	}

	as, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New(
			"sshsig: an RSA key that cannot sign with rsa-sha2-512 is not usable here")
	}

	sig, err := as.SignWithAlgorithm(rand.Reader, blob, ssh.KeyAlgoRSASHA512)
	if err != nil {
		return nil, fmt.Errorf("sign with rsa-sha2-512: %w", err)
	}

	return sig, nil
}

// Parse reads an armoured signature.
func Parse(armored string) (*Signature, error) {
	body, err := unarmor(armored)
	if err != nil {
		return nil, err
	}

	return ParseBinary(body)
}

// ParseBinary reads the binary form of a signature.
func ParseBinary(body []byte) (*Signature, error) {
	if len(body) < len(Magic) || string(body[:len(Magic)]) != Magic {
		return nil, ErrNotSSHSIG
	}

	var w wire

	if err := ssh.Unmarshal(body[len(Magic):], &w); err != nil {
		return nil, fmt.Errorf("sshsig: parse signature: %w", err)
	}

	if w.Version != Version {
		return nil, fmt.Errorf("sshsig: unsupported version %d", w.Version)
	}

	pub, err := ssh.ParsePublicKey([]byte(w.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("sshsig: parse public key: %w", err)
	}

	var sig ssh.Signature

	if err := ssh.Unmarshal([]byte(w.Signature), &sig); err != nil {
		return nil, fmt.Errorf("sshsig: parse inner signature: %w", err)
	}

	return &Signature{
		PublicKey:     pub,
		Namespace:     w.Namespace,
		HashAlgorithm: w.HashAlgorithm,
		Signature:     &sig,
	}, nil
}

// Verify checks a signature over a message. Ladulås does not need this to sign,
// but it is what makes the signing path testable without shelling out, and M3
// wants it for verifying what a peer produced.
func (s *Signature) Verify(namespace string, message []byte) error {
	if s.Namespace != namespace {
		return fmt.Errorf("sshsig: signature namespace %q, want %q",
			s.Namespace, namespace)
	}

	blob, err := SigningBlobFor(s.Namespace, s.HashAlgorithm, message)
	if err != nil {
		return err
	}

	if err := s.PublicKey.Verify(blob, s.Signature); err != nil {
		return fmt.Errorf("sshsig: verify: %w", err)
	}

	return nil
}

func unarmor(armored string) ([]byte, error) {
	trimmed := strings.TrimSpace(armored)

	begin := strings.Index(trimmed, armorBegin)
	if begin < 0 {
		return nil, ErrNotSSHSIG
	}

	rest := trimmed[begin+len(armorBegin):]

	end := strings.Index(rest, armorEnd)
	if end < 0 {
		return nil, fmt.Errorf("%w: no end marker", ErrNotSSHSIG)
	}

	encoded := strings.Join(strings.Fields(rest[:end]), "")

	body, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("sshsig: decode armour: %w", err)
	}

	return body, nil
}
