package trust

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The pairing code, and what it is for.
//
// Pairing is trust on first use, and the thing being established is that the
// identity key on the other end of this connection belongs to the machine whose
// screen the user is looking at. Two mechanisms carry that, and they do
// different jobs.
//
// The code proves the dialling side saw the listening side's screen. That is
// what keeps a stranger who can reach the listening port from raising a prompt
// on it at all — without it, pairing would be an unauthenticated way to make
// somebody's desktop ask them a question, which is approval fatigue delivered
// as a service (§15).
//
// The confirmation on each side proves a human agreed. The code cannot replace
// it and does not try to: pairing always prompts, and no policy can turn that
// off (§9).
//
// What makes a ten-character code enough is that it is never sent. What is sent
// is an HMAC over both identity keys of the channel it travels on, so a relay
// that persuaded the dialling side to connect to it computes its proof over its
// own key, which the real listener rejects, and it cannot compute the right one
// without the secret. An attacker who can reach the listener directly is left
// with online guessing against a single-use secret that expires in five minutes
// and dies after a handful of wrong answers.
const (
	// CodeValidity is how long a displayed code stays good. Long enough to walk
	// to the other machine, short enough that a code left on a screen over
	// lunch is not a standing invitation.
	CodeValidity = 5 * time.Minute

	// MaxAttempts is how many wrong proofs a pairing window survives. Guessing
	// fifty bits needs rather more than five tries, so the cap costs an honest
	// user nothing and takes online guessing off the table entirely.
	MaxAttempts = 5

	// secretLength is the typed code's length in characters. Each character is
	// five bits of the alphabet below, so ten of them is fifty bits.
	secretLength = 10

	// codeVersion is the version of the full code's encoding.
	codeVersion = 1

	// codePrefix marks a full code, which is what a QR carries (M5) and what
	// can be copied and pasted today.
	codePrefix = "ladulas-pair-v1."
)

// secretAlphabet is Crockford's base32 in lower case: no i, l, o or u, so
// nothing in a code can be misread as something else or spell anything.
const secretAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"

// ErrBadCode is returned when a code cannot be read.
var ErrBadCode = errors.New("trust: the pairing code is not readable")

// ErrCodeExpired is returned when a full code has aged out. The listening side
// checks its own window as well; this is so the dialling side can say something
// useful before it connects.
var ErrCodeExpired = errors.New("trust: the pairing code has expired")

// Secret is the material a pairing code carries: ten characters, normalised.
//
// The secret is the string, not a decoding of it, so there is no encoding to
// disagree about between the side that displays it and the side that types it.
type Secret string

// NewSecret generates a pairing secret.
func NewSecret() (Secret, error) {
	buf := make([]byte, secretLength)

	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("trust: no randomness for a pairing code: %w", err)
	}

	// The alphabet has exactly 32 entries, so masking the low five bits of each
	// random byte is uniform.
	out := make([]byte, secretLength)
	for i, b := range buf {
		out[i] = secretAlphabet[b&0x1f]
	}

	return Secret(out), nil
}

// Display renders a secret the way it should be shown and typed: two groups,
// because a run of ten characters is read wrongly and a run of five is not.
func (s Secret) Display() string {
	if len(s) != secretLength {
		return string(s)
	}

	return string(s[:5]) + "-" + string(s[5:])
}

// ParseSecret normalises a typed code.
//
// It forgives the things a person typing off a screen gets wrong — case, the
// separator, spaces, and the four characters the alphabet leaves out precisely
// because they are misread — and refuses everything else rather than quietly
// producing a secret that will fail an HMAC for reasons nobody can see.
func ParseSecret(text string) (Secret, error) {
	var b strings.Builder

	for _, r := range strings.ToLower(strings.TrimSpace(text)) {
		switch r {
		case '-', ' ', '\t':
			continue
		case 'i', 'l':
			r = '1'
		case 'o':
			r = '0'
		case 'u':
			r = 'v'
		}

		if !strings.ContainsRune(secretAlphabet, r) {
			return "", fmt.Errorf("%w: %q is not part of a pairing code", ErrBadCode, r)
		}

		b.WriteRune(r)
	}

	if b.Len() != secretLength {
		return "", fmt.Errorf("%w: a pairing code is %d characters, this one is %d",
			ErrBadCode, secretLength, b.Len())
	}

	return Secret(b.String()), nil
}

// Equal compares two secrets without leaking how far they agreed.
func (s Secret) Equal(other Secret) bool {
	return subtle.ConstantTimeCompare([]byte(s), []byte(other)) == 1
}

// The two domain separators. A proof and a confirmation are HMACs over the same
// material, and being able to replay one as the other would let a relay that
// captured a dialler's proof turn it round and pose as the listener.
const (
	proofPrefix        = "ladulas-pairing-v1"
	confirmationPrefix = "ladulas-pairing-v1-response"
)

// Proof is what the dialling side sends: possession of the code, bound to the
// two identity keys of the channel it is being sent over.
func Proof(secret Secret, listener, dialler ssh.PublicKey) []byte {
	return mac(secret, proofPrefix, listener, dialler)
}

// Confirmation is what the listening side sends back, proving that the instance
// the dialler reached is the one displaying the code.
//
// Without it, a dialler that typed the address wrongly would be shown a
// stranger's fingerprint and asked to confirm it — which is the one moment when
// a fingerprint is hardest to check, because there is nothing to check it
// against but the screen that is lying.
func Confirmation(secret Secret, listener, dialler ssh.PublicKey) []byte {
	return mac(secret, confirmationPrefix, listener, dialler)
}

// VerifyProof checks a proof in constant time.
func VerifyProof(secret Secret, listener, dialler ssh.PublicKey, proof []byte) bool {
	return hmac.Equal(Proof(secret, listener, dialler), proof)
}

// VerifyConfirmation checks a confirmation in constant time.
func VerifyConfirmation(
	secret Secret, listener, dialler ssh.PublicKey, confirmation []byte,
) bool {
	return hmac.Equal(Confirmation(secret, listener, dialler), confirmation)
}

func mac(secret Secret, prefix string, listener, dialler ssh.PublicKey) []byte {
	h := hmac.New(sha256.New, []byte(secret))

	h.Write([]byte(prefix))
	h.Write([]byte{0})

	// Length prefixes, so that the two keys cannot be slid past each other to
	// produce one input from a different pair of keys.
	for _, key := range []ssh.PublicKey{listener, dialler} {
		var blob []byte
		if key != nil {
			blob = key.Marshal()
		}

		var length [4]byte

		binary.BigEndian.PutUint32(length[:], uint32(len(blob)))

		h.Write(length[:])
		h.Write(blob)
	}

	return h.Sum(nil)
}

// EncodeCode renders the full code: the same secret, plus the address and the
// identity key, so that a dialler that has it needs to type nothing and knows
// who it is connecting to before it connects. This is what a QR will carry.
func EncodeCode(code *ladulasv1.PairingCode) (string, error) {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(code)
	if err != nil {
		return "", fmt.Errorf("trust: encode the pairing code: %w", err)
	}

	return codePrefix + base64.RawURLEncoding.EncodeToString(body), nil
}

// NewCode builds the full code for a pairing window.
func NewCode(
	secret Secret, name string, pub ssh.PublicKey,
	addresses []string, expires time.Time,
) *ladulasv1.PairingCode {
	return &ladulasv1.PairingCode{
		Version:           codeVersion,
		Secret:            string(secret),
		IdentityPublicKey: pub.Marshal(),
		Addresses:         addresses,
		InstanceName:      name,
		ExpiresAt:         timestamppb.New(expires),
	}
}

// DecodeCode reads whatever the user pasted or typed.
//
// A full code yields everything; a typed secret yields a code with nothing in
// it but the secret, and the caller supplies the address it was told separately.
// Both are the same exchange from there on.
func DecodeCode(text string) (*ladulasv1.PairingCode, error) {
	text = strings.TrimSpace(text)

	if !strings.HasPrefix(text, codePrefix) {
		secret, err := ParseSecret(text)
		if err != nil {
			return nil, err
		}

		return &ladulasv1.PairingCode{
			Version: codeVersion,
			Secret:  string(secret),
		}, nil
	}

	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(text, codePrefix))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadCode, err)
	}

	var code ladulasv1.PairingCode

	if err := proto.Unmarshal(body, &code); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadCode, err)
	}

	if code.GetVersion() != codeVersion {
		return nil, fmt.Errorf("%w: it is version %d and this build speaks %d",
			ErrBadCode, code.GetVersion(), codeVersion)
	}

	secret, err := ParseSecret(code.GetSecret())
	if err != nil {
		return nil, err
	}

	code.Secret = string(secret)

	if expires := code.GetExpiresAt(); expires != nil &&
		!expires.AsTime().After(time.Now()) {
		return nil, ErrCodeExpired
	}

	return &code, nil
}

// CodeKey parses the identity key a full code carries, or returns nil when the
// code was typed and carries none.
//
// A code that carries the key is the stronger pairing: the dialling side pins
// before it connects, so the visual channel is the integrity root and there is
// nothing left for the user to compare character by character. A typed code
// leaves that comparison to the two screens, which is what §7 describes and
// what a headless box gets.
func CodeKey(code *ladulasv1.PairingCode) (ssh.PublicKey, error) {
	blob := code.GetIdentityPublicKey()
	if len(blob) == 0 {
		return nil, nil // no key is a normal, meaningful answer
	}

	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, fmt.Errorf("%w: the identity key does not parse: %w", ErrBadCode, err)
	}

	return pub, nil
}
