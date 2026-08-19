package identity

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
)

// The two artifacts decision AG adds, and the one thing that makes them
// different from everything else this package signs: they carry a second
// signature, made with an SSH key of the user's rather than with an instance
// identity, and the two say different things.
//
// The identity signature says **who**. Without it the key signature proves that
// some holder wrote this and not which one, and a holder could issue in another
// holder's name — which matters, because the receiving side checks the issuer
// against its own trust records and honours an endorsement only from a peer it
// would have taken a live approval from.
//
// The key signature says **that the issuer held the key**, and it is what makes
// the mechanism safe rather than merely authenticated: a holder promising
// unattended use of a key promises nothing it could not do itself. Without it
// an approver holding no copy could write standing cheques on somebody else's
// key.
//
// It is an SSHSIG under a namespace of its own rather than a raw signature
// under a prefix, and that is not decoration. This is a *user* key signing
// something that is not a git commit and not an SSH login, and SSHSIG's
// preamble and namespace field are the standard way of saying so — a signature
// made here cannot be replayed as either (§5).

// The SSHSIG namespaces. They are distinct for the same reason the identity
// prefixes are: a promise and the taking back of a promise must not be
// confusable as bytes, whatever a parser could be persuaded to read them as.
const (
	EndorsementNamespace = "endorsement@ladulas"
	RetractionNamespace  = "retraction@ladulas"
)

const (
	endorsementSigningPrefix = "ladulas-endorsement-v1\x00"
	retractionSigningPrefix  = "ladulas-retraction-v1\x00"
)

func endorsementInput(body []byte) []byte {
	return prefixed(endorsementSigningPrefix, body)
}

func retractionInput(body []byte) []byte {
	return prefixed(retractionSigningPrefix, body)
}

// SignEndorsement turns a promise about a key into the artifact a requester
// carries and a fellow holder acts on (decision AG).
//
// The key signer is the endorsed key's own. On a phone that is a portable key
// and reaching for it goes through the per-use gate like any other signature
// with it (decision S) — one more prompt at the moment the promise is made,
// which is the moment somebody is already looking at the screen.
func (i *Identity) SignEndorsement(
	e *ladulasv1.Endorsement, key ssh.Signer,
) (*ladulasv1.SignedEndorsement, error) {
	if e == nil {
		return nil, errors.New("nil endorsement")
	}

	if key == nil {
		return nil, errors.New("no key to endorse with")
	}

	// An endorsement about a key that did not sign it is the one shape this
	// must never produce: the receiving side reads key_fingerprint to decide
	// which key's authority it is looking at.
	if got := ssh.FingerprintSHA256(key.PublicKey()); got != e.GetKeyFingerprint() {
		return nil, fmt.Errorf(
			"the endorsement is about %s and would be signed by %s",
			e.GetKeyFingerprint(), got)
	}

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("marshal endorsement: %w", err)
	}

	sig, err := i.signer.Sign(rand.Reader, endorsementInput(body))
	if err != nil {
		return nil, fmt.Errorf("sign endorsement: %w", err)
	}

	keySig, err := sshsig.Sign(key, EndorsementNamespace, "sha512", body)
	if err != nil {
		return nil, fmt.Errorf("sign endorsement with the key: %w", err)
	}

	return &ladulasv1.SignedEndorsement{
		Endorsement:        body,
		IssuerPublicKey:    i.signer.PublicKey().Marshal(),
		IssuerFingerprint:  i.Fingerprint(),
		SignatureAlgorithm: sig.Format,
		Signature:          ssh.Marshal(sig),
		KeySignature:       keySig.Marshal(),
	}, nil
}

// VerifyEndorsement checks both signatures and returns what they cover.
//
// Nothing is unmarshalled until both have verified, and the caller still has to
// decide the two things this cannot: whether it holds the key at all, and
// whether the issuer is a peer it would have taken a live approval from.
func VerifyEndorsement(
	se *ladulasv1.SignedEndorsement,
) (*ladulasv1.Endorsement, error) {
	if se == nil {
		return nil, errors.New("nil endorsement")
	}

	body := se.GetEndorsement()

	if err := verifyIdentityHalf(
		se.GetIssuerPublicKey(), se.GetIssuerFingerprint(),
		se.GetSignature(), endorsementInput(body),
	); err != nil {
		return nil, err
	}

	keyPrint, err := verifyKeyHalf(
		se.GetKeySignature(), EndorsementNamespace, body)
	if err != nil {
		return nil, err
	}

	var e ladulasv1.Endorsement

	if err := proto.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("unmarshal endorsement: %w", err)
	}

	// Three claims about identity travel here and every one of them is checked
	// against a signature rather than read: who issued it, which key's
	// authority it rests on, and which key the scope is about. An endorsement
	// naming one key in its scope and signed by another would otherwise spend a
	// promise about the second on requests for the first.
	if e.GetIssuerFingerprint() != se.GetIssuerFingerprint() {
		return nil, fmt.Errorf(
			"the endorsement names issuer %q and was signed by %q",
			e.GetIssuerFingerprint(), se.GetIssuerFingerprint())
	}

	if e.GetKeyFingerprint() != keyPrint {
		return nil, fmt.Errorf(
			"the endorsement is about %q and was signed by %q",
			e.GetKeyFingerprint(), keyPrint)
	}

	if scope := e.GetScope().GetKeyFingerprint(); scope != keyPrint {
		return nil, fmt.Errorf(
			"the endorsement's scope is about %q and it was signed by %q",
			scope, keyPrint)
	}

	return &e, nil
}

// SignRetraction takes an endorsement back (decision AG).
//
// It is signed the same two ways an endorsement is and only one of them
// authorizes anything: holding the key is the standing to retract, and the
// identity half is there so a list can say who did it.
func (i *Identity) SignRetraction(
	r *ladulasv1.Retraction, key ssh.Signer,
) (*ladulasv1.SignedRetraction, error) {
	if r == nil {
		return nil, errors.New("nil retraction")
	}

	if key == nil {
		return nil, errors.New("no key to retract with")
	}

	if got := ssh.FingerprintSHA256(key.PublicKey()); got != r.GetKeyFingerprint() {
		return nil, fmt.Errorf(
			"the retraction is about %s and would be signed by %s",
			r.GetKeyFingerprint(), got)
	}

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("marshal retraction: %w", err)
	}

	sig, err := i.signer.Sign(rand.Reader, retractionInput(body))
	if err != nil {
		return nil, fmt.Errorf("sign retraction: %w", err)
	}

	keySig, err := sshsig.Sign(key, RetractionNamespace, "sha512", body)
	if err != nil {
		return nil, fmt.Errorf("sign retraction with the key: %w", err)
	}

	return &ladulasv1.SignedRetraction{
		Retraction:         body,
		IssuerPublicKey:    i.signer.PublicKey().Marshal(),
		IssuerFingerprint:  i.Fingerprint(),
		SignatureAlgorithm: sig.Format,
		Signature:          ssh.Marshal(sig),
		KeySignature:       keySig.Marshal(),
	}, nil
}

// VerifyRetraction checks both signatures and returns what they cover.
func VerifyRetraction(
	sr *ladulasv1.SignedRetraction,
) (*ladulasv1.Retraction, error) {
	if sr == nil {
		return nil, errors.New("nil retraction")
	}

	body := sr.GetRetraction()

	if err := verifyIdentityHalf(
		sr.GetIssuerPublicKey(), sr.GetIssuerFingerprint(),
		sr.GetSignature(), retractionInput(body),
	); err != nil {
		return nil, err
	}

	keyPrint, err := verifyKeyHalf(
		sr.GetKeySignature(), RetractionNamespace, body)
	if err != nil {
		return nil, err
	}

	var r ladulasv1.Retraction

	if err := proto.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("unmarshal retraction: %w", err)
	}

	if r.GetIssuerFingerprint() != sr.GetIssuerFingerprint() {
		return nil, fmt.Errorf(
			"the retraction names issuer %q and was signed by %q",
			r.GetIssuerFingerprint(), sr.GetIssuerFingerprint())
	}

	if r.GetKeyFingerprint() != keyPrint {
		return nil, fmt.Errorf(
			"the retraction is about %q and was signed by %q",
			r.GetKeyFingerprint(), keyPrint)
	}

	// One target, and exactly one. A retraction that named both would take back
	// an endorsement and a span of time at once, and a reader deciding which it
	// meant is a reader guessing.
	byID := r.GetEndorsementId() != ""
	byTime := r.GetIssuedBefore() != nil

	if byID == byTime {
		return nil, errors.New(
			"a retraction names one endorsement or one moment, not both and not neither")
	}

	return &r, nil
}

// verifyIdentityHalf is the signature every other artifact in this package
// carries, checked the same way: the fingerprint against the key, and the key
// against the bytes.
func verifyIdentityHalf(
	publicKey []byte, fingerprint string, signature, input []byte,
) error {
	pub, err := ssh.ParsePublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("parse issuer public key: %w", err)
	}

	if got := ssh.FingerprintSHA256(pub); got != fingerprint {
		return fmt.Errorf(
			"issuer fingerprint %q does not match public key %q",
			fingerprint, got)
	}

	var sig ssh.Signature

	if err := ssh.Unmarshal(signature, &sig); err != nil {
		return fmt.Errorf("parse issuer signature: %w", err)
	}

	if err := pub.Verify(input, &sig); err != nil {
		return fmt.Errorf("verify issuer signature: %w", err)
	}

	return nil
}

// verifyKeyHalf checks the SSHSIG and answers which key made it.
//
// The signature carries its own public key, so the fingerprint comes out of the
// verification rather than being taken from a field beside it — which is what
// lets the caller compare it with what the artifact claims.
func verifyKeyHalf(
	signature []byte, namespace string, body []byte,
) (string, error) {
	sig, err := sshsig.ParseBinary(signature)
	if err != nil {
		return "", fmt.Errorf("parse the key signature: %w", err)
	}

	if err := sig.Verify(namespace, body); err != nil {
		return "", fmt.Errorf("verify the key signature: %w", err)
	}

	return ssh.FingerprintSHA256(sig.PublicKey), nil
}
