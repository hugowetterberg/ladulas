// Package identity holds an instance's identity keypair and the
// approval-as-artifact signing built on it.
//
// Every Ladulås instance generates an identity keypair at first run, distinct
// from any SSH keys it holds (docs/architecture.md §7). From M3 the key
// authenticates the peer channel; already in M1 it signs approval responses so
// that every decision in the audit log is an artifact that cannot be forged
// without the key.
package identity

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// approvalSigningPrefix domain-separates approval signatures from every other
// use of the identity key. A signature produced here can never be replayed as a
// signature over something else, and vice versa.
const approvalSigningPrefix = "ladulas-approval-v1\x00"

// delegationSigningPrefix does the same for delegated grants (decision P).
//
// It is a different prefix and not a version of the same one, because the two
// artifacts say different things: an approval answers one request that has
// already been described in full, and a delegation is a standing permission
// over a scope. A signature over one must not verify as the other even if the
// bytes could be made to parse both ways.
const delegationSigningPrefix = "ladulas-delegation-v1\x00"

// Identity is an instance's identity keypair.
//
// The same key is held twice over: as an ssh.Signer, which is what signs
// approval artifacts and produces the fingerprint every UI shows, and as a
// crypto.Signer, which is what the transport wraps in a TLS certificate (§8).
// They are one key — the SPKI the channel pins and the fingerprint the user
// reads are two renderings of the same public half.
type Identity struct {
	name   string
	signer ssh.Signer
	key    crypto.Signer
}

// Generate creates a fresh ed25519 identity and returns it together with the
// OpenSSH-format private key to persist in the encrypted store.
func Generate(name string) (*Identity, []byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "ladulas instance identity")
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(block)

	id, err := FromPEM(keyPEM, name)
	if err != nil {
		return nil, nil, err
	}

	return id, keyPEM, nil
}

// FromPEM loads an identity from an unencrypted OpenSSH private key.
//
// The key is parsed twice, because the two things an identity does need two
// shapes of it and neither can be derived from the other: x/crypto/ssh hides
// the private key inside a Signer, and crypto/x509 cannot build a certificate
// around anything else.
func FromPEM(keyPEM []byte, name string) (*Identity, error) {
	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse identity key: %w", err)
	}

	raw, err := ssh.ParseRawPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse identity key: %w", err)
	}

	key, err := cryptoSigner(raw)
	if err != nil {
		return nil, err
	}

	return &Identity{name: name, signer: signer, key: key}, nil
}

// FromSigner builds an identity around a key this process cannot read.
//
// A phone's identity is a P-256 key in the Secure Enclave (§7), so there is no
// PEM to load and the private half is a handle rather than a number. What the
// rest of Ladulås needs of an identity is the two shapes above, and both can be
// had from a crypto.Signer: x/crypto/ssh wraps one directly, and crypto/x509
// wanted one to begin with.
//
// Nothing else changes. The fingerprint is the same rendering of the same
// public half, the approval artifacts are signed the same way, and the channel
// pins the same SPKI — a hardware identity is a normal identity that happens to
// answer more slowly.
func FromSigner(name string, key crypto.Signer) (*Identity, error) {
	if key == nil {
		return nil, errors.New("identity: no signer")
	}

	signer, err := ssh.NewSignerFromSigner(key)
	if err != nil {
		return nil, fmt.Errorf("wrap the identity key: %w", err)
	}

	return &Identity{name: name, signer: signer, key: key}, nil
}

// cryptoSigner normalises what ParseRawPrivateKey hands back. ed25519 arrives
// as a pointer and everything else as one already; both shapes sign.
func cryptoSigner(raw any) (crypto.Signer, error) {
	if pointer, ok := raw.(*ed25519.PrivateKey); ok {
		return *pointer, nil
	}

	key, ok := raw.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("identity key of type %T cannot sign", raw)
	}

	return key, nil
}

// CryptoSigner returns the identity key in the shape crypto/x509 wants, so the
// transport can wrap it in a self-signed certificate (§8).
//
// Nothing here assumes ed25519: a mobile identity is a hardware-resident P-256
// key (§7, §10), and a P-256 crypto.Signer fits a TLS certificate exactly as
// well.
func (i *Identity) CryptoSigner() crypto.Signer {
	return i.key
}

// Name returns the human-assigned instance name.
func (i *Identity) Name() string {
	return i.name
}

// PublicKey returns the identity public key.
func (i *Identity) PublicKey() ssh.PublicKey {
	return i.signer.PublicKey()
}

// Fingerprint returns the SSH-style SHA256 fingerprint that identifies the
// instance in UIs, policy rules and trust records.
func (i *Identity) Fingerprint() string {
	return ssh.FingerprintSHA256(i.signer.PublicKey())
}

// ApproverInfo describes this instance as an approver.
func (i *Identity) ApproverInfo(local bool) *ladulasv1.ApproverInfo {
	return &ladulasv1.ApproverInfo{
		InstanceId: i.Fingerprint(),
		Name:       i.name,
		Local:      local,
	}
}

// RequesterInfo describes this instance as a requester.
func (i *Identity) RequesterInfo(local bool) *ladulasv1.RequesterInfo {
	return &ladulasv1.RequesterInfo{
		InstanceId: i.Fingerprint(),
		Name:       i.name,
		Local:      local,
	}
}

// SignApproval turns a decision into the signed artifact that goes into the
// audit log on both ends (§18).
//
// The artifact carries the exact serialized response that was signed, because
// protobuf serialization is not canonical and re-marshalling a response could
// produce bytes the signature does not cover.
func (i *Identity) SignApproval(resp *ladulasv1.ApprovalResponse) (*ladulasv1.SignedApproval, error) {
	if resp == nil {
		return nil, errors.New("nil response")
	}

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}

	sig, err := i.signer.Sign(rand.Reader, signingInput(body))
	if err != nil {
		return nil, fmt.Errorf("sign response: %w", err)
	}

	return &ladulasv1.SignedApproval{
		Response:            body,
		ApproverPublicKey:   i.signer.PublicKey().Marshal(),
		ApproverFingerprint: i.Fingerprint(),
		SignatureAlgorithm:  sig.Format,
		Signature:           ssh.Marshal(sig),
	}, nil
}

// VerifyApproval checks the signature over a signed approval and returns the
// response it covers. The response is only unmarshalled after the signature
// verifies, so nothing an attacker controls is parsed on the strength of the
// artifact alone.
//
// The caller still has to decide whether the signing key is one it trusts.
func VerifyApproval(sa *ladulasv1.SignedApproval) (*ladulasv1.ApprovalResponse, ssh.PublicKey, error) {
	if sa == nil {
		return nil, nil, errors.New("nil approval")
	}

	pub, err := ssh.ParsePublicKey(sa.GetApproverPublicKey())
	if err != nil {
		return nil, nil, fmt.Errorf("parse approver public key: %w", err)
	}

	if got := ssh.FingerprintSHA256(pub); got != sa.GetApproverFingerprint() {
		return nil, nil, fmt.Errorf(
			"approver fingerprint %q does not match public key %q",
			sa.GetApproverFingerprint(), got)
	}

	var sig ssh.Signature

	if err := ssh.Unmarshal(sa.GetSignature(), &sig); err != nil {
		return nil, nil, fmt.Errorf("parse signature: %w", err)
	}

	if err := pub.Verify(signingInput(sa.GetResponse()), &sig); err != nil {
		return nil, nil, fmt.Errorf("verify approval signature: %w", err)
	}

	var resp ladulasv1.ApprovalResponse

	if err := proto.Unmarshal(sa.GetResponse(), &resp); err != nil {
		return nil, nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &resp, pub, nil
}

// SignDelegation turns a standing permission into the artifact the requester
// keeps and applies (decision P).
//
// The delegation names the instance it is for, and this signs that name along
// with everything else: an artifact lifted off the wire and presented at a
// third machine that happens to hold the same key does not verify as being
// about that machine.
func (i *Identity) SignDelegation(
	d *ladulasv1.Delegation,
) (*ladulasv1.SignedDelegation, error) {
	if d == nil {
		return nil, errors.New("nil delegation")
	}

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("marshal delegation: %w", err)
	}

	sig, err := i.signer.Sign(rand.Reader, delegationInput(body))
	if err != nil {
		return nil, fmt.Errorf("sign delegation: %w", err)
	}

	return &ladulasv1.SignedDelegation{
		Delegation:          body,
		ApproverPublicKey:   i.signer.PublicKey().Marshal(),
		ApproverFingerprint: i.Fingerprint(),
		SignatureAlgorithm:  sig.Format,
		Signature:           ssh.Marshal(sig),
	}, nil
}

// VerifyDelegation checks the signature and returns what it covers.
//
// As with VerifyApproval, nothing is unmarshalled until the signature has
// verified, and the caller still has to decide whether the signing key is one
// it trusts — here, that it belongs to a peer allowed to approve for it.
func VerifyDelegation(
	sd *ladulasv1.SignedDelegation,
) (*ladulasv1.Delegation, ssh.PublicKey, error) {
	if sd == nil {
		return nil, nil, errors.New("nil delegation")
	}

	pub, err := ssh.ParsePublicKey(sd.GetApproverPublicKey())
	if err != nil {
		return nil, nil, fmt.Errorf("parse approver public key: %w", err)
	}

	if got := ssh.FingerprintSHA256(pub); got != sd.GetApproverFingerprint() {
		return nil, nil, fmt.Errorf(
			"approver fingerprint %q does not match public key %q",
			sd.GetApproverFingerprint(), got)
	}

	var sig ssh.Signature

	if err := ssh.Unmarshal(sd.GetSignature(), &sig); err != nil {
		return nil, nil, fmt.Errorf("parse signature: %w", err)
	}

	if err := pub.Verify(delegationInput(sd.GetDelegation()), &sig); err != nil {
		return nil, nil, fmt.Errorf("verify delegation signature: %w", err)
	}

	var d ladulasv1.Delegation

	if err := proto.Unmarshal(sd.GetDelegation(), &d); err != nil {
		return nil, nil, fmt.Errorf("unmarshal delegation: %w", err)
	}

	// The artifact says who signed it and the delegation inside says who
	// granted it. They are the same claim and they have to agree, or a
	// delegation could name one approver while being signed by another.
	if d.GetApproverFingerprint() != sd.GetApproverFingerprint() {
		return nil, nil, fmt.Errorf(
			"the delegation names approver %q and was signed by %q",
			d.GetApproverFingerprint(), sd.GetApproverFingerprint())
	}

	return &d, pub, nil
}

func signingInput(body []byte) []byte {
	return prefixed(approvalSigningPrefix, body)
}

func delegationInput(body []byte) []byte {
	return prefixed(delegationSigningPrefix, body)
}

func prefixed(prefix string, body []byte) []byte {
	input := make([]byte, 0, len(prefix)+len(body))
	input = append(input, prefix...)
	input = append(input, body...)

	return input
}

// Digest returns the SHA-256 of a byte slice, as used for request digests and
// payload digests throughout the protocol.
func Digest(b []byte) []byte {
	sum := sha256.Sum256(b)

	return sum[:]
}

// requestIDEncoding keeps request identifiers short and easy to read back.
var requestIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewRequestID returns a random request identifier. Requests are correlated by
// it across the audit log, the prompt and — from M3 — the wire, so it has to be
// unguessable as well as unique.
func NewRequestID() string {
	var buf [10]byte

	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand does not fail on any platform Ladulås targets, and a
		// request without an identifier is worse than a panic here.
		panic("identity: no randomness available: " + err.Error())
	}

	return strings.ToLower(requestIDEncoding.EncodeToString(buf[:]))
}
