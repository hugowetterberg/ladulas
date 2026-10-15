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
	"math/big"
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
// The code proves the joining side saw the listening side's screen. That is
// what keeps a stranger who can reach the listening port from raising a prompt
// on it at all — without it, pairing would be an unauthenticated way to make
// somebody's desktop ask them a question, which is approval fatigue delivered
// as a service (§15).
//
// The confirmation on each side proves a human agreed. The code cannot replace
// it and does not try to: pairing always prompts, and no policy can turn that
// off (§9). What the confirmation defends now is a PIN somebody else saw.
//
// The code is a six-digit PIN (decision AV). Twenty bits is what a person will
// actually type, and it is safe only because it is never fed to anything that
// can be searched offline: it is the password of a CPace exchange (see
// pkg/peer's pake.go and internal/cpace), where each run is one online guess,
// and the window allows five. That is five in a million per code. **The PIN
// never goes into an HMAC**, on any path — an HMAC over twenty bits falls to an
// offline search in milliseconds, and an impostor that answered a joiner in the
// listener's place would hold one.
//
// For one release the window also holds a ten-character secret, independent of
// the PIN, for joiners that predate it: an older phone scanning a new QR, an
// older box typing a code. That one is proved the old way — an HMAC over both
// identity keys of the channel, so a relay computes its proof over its own key
// and the real listener rejects it — and fifty bits is what makes the offline
// search that relay could run hopeless inside five minutes. Both draw on the
// window's one attempt counter.
const (
	// CodeValidity is how long a displayed code stays good. Long enough to walk
	// to the other machine, short enough that a code left on a screen over
	// lunch is not a standing invitation.
	CodeValidity = 5 * time.Minute

	// MaxAttempts is how many attempts a pairing window allows, across the PIN
	// exchange and the older proof together. An attempt is charged when it
	// starts and refunded only when it is verified, so an exchange that is
	// started and abandoned counts. Against a six-digit PIN five is five in a
	// million per code: enough that a typo costs an honest user nothing, few
	// enough that guessing is not a plan. Exhausting them is a denial, not a
	// break, and the displaying side offers a new PIN.
	MaxAttempts = 5

	// PINLength is the PIN's length in digits.
	PINLength = 6

	// secretLength is the older typed code's length in characters. Each
	// character is five bits of the alphabet below, so ten of them is fifty
	// bits.
	secretLength = 10

	// codeVersion is the version of the full code's encoding. It stays at 1
	// through the overlap release, because an older build refuses any other;
	// the PIN is a field an older decoder ignores (decision AV).
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

// ErrBadPIN is returned when a typed PIN is not six digits.
var ErrBadPIN = errors.New("trust: a pairing PIN is six digits")

// PIN is the six-digit code a joining machine types (decision AV), as six
// ASCII digits. It is a CPace password and nothing else.
type PIN string

// NewPIN draws a PIN uniformly from the million there are.
func NewPIN() (PIN, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("trust: no randomness for a pairing PIN: %w", err)
	}

	return PIN(fmt.Sprintf("%06d", n.Int64())), nil
}

// Display renders a PIN in two groups of three, which is how it is read off a
// screen without losing your place.
func (p PIN) Display() string {
	if len(p) != PINLength {
		return string(p)
	}

	return string(p[:3]) + " " + string(p[3:])
}

// ParsePIN normalises a typed PIN: spaces and dashes are forgiven, and
// anything that is not six digits is refused.
func ParsePIN(text string) (PIN, error) {
	var b strings.Builder

	for _, r := range strings.TrimSpace(text) {
		switch {
		case r == ' ' || r == '-' || r == '\t':
			continue
		case r < '0' || r > '9':
			return "", fmt.Errorf("%w: %q is not a digit", ErrBadPIN, r)
		}

		b.WriteRune(r)
	}

	if b.Len() != PINLength {
		return "", fmt.Errorf("%w, and this is %d", ErrBadPIN, b.Len())
	}

	return PIN(b.String()), nil
}

// Secret is the ten-character code an older joiner types, normalised. It is
// the overlap release's v1 secret (decision AV), independent of the PIN.
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

// The two domain separators of the older proof. A proof and a confirmation are
// HMACs over the same material, and being able to replay one as the other would
// let a relay that captured a dialler's proof turn it round and pose as the
// listener.
//
// Everything from here to EncodeCode is the overlap release's v1 proof
// (decision AV). It is keyed with the ten-character Secret and never with a
// PIN, which the type of its first argument is there to make hard to get
// wrong.
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

// EncodeCode renders the full code: the PIN and the older secret, plus the
// addresses and the identity key, so that a joiner that has it needs to type
// nothing and knows who it is connecting to before it connects. This is what a
// QR carries.
func EncodeCode(code *ladulasv1.PairingCode) (string, error) {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(code)
	if err != nil {
		return "", fmt.Errorf("trust: encode the pairing code: %w", err)
	}

	return codePrefix + base64.RawURLEncoding.EncodeToString(body), nil
}

// NewCode builds the full code for a pairing window.
func NewCode(
	pin PIN, secret Secret, name string, pub ssh.PublicKey,
	addresses []string, expires time.Time,
) *ladulasv1.PairingCode {
	return &ladulasv1.PairingCode{
		Version:           codeVersion,
		Pin:               string(pin),
		Secret:            string(secret),
		IdentityPublicKey: pub.Marshal(),
		Addresses:         addresses,
		InstanceName:      name,
		ExpiresAt:         timestamppb.New(expires),
	}
}

// DecodeCode reads whatever the user pasted or typed.
//
// A full code yields everything; a typed PIN yields a code with nothing in it
// but the PIN, and a typed ten-character code one with nothing but the older
// secret. For the typed ones the caller supplies the address it was told
// separately. From there each is the same exchange as the full code would
// have been — the PIN exchange when there is a PIN, the older proof only when
// there is not.
func DecodeCode(text string) (*ladulasv1.PairingCode, error) {
	text = strings.TrimSpace(text)

	if !strings.HasPrefix(text, codePrefix) {
		if pin, err := ParsePIN(text); err == nil {
			return &ladulasv1.PairingCode{Version: codeVersion, Pin: string(pin)}, nil
		}

		secret, err := ParseSecret(text)
		if err != nil {
			return nil, fmt.Errorf("%w: it is neither a six-digit PIN nor a "+
				"ten-character code", ErrBadCode)
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

	// A code from an older instance has no PIN, and one from a later one may
	// have no ten-character secret. Either is enough; neither is not.
	if code.GetPin() == "" && code.GetSecret() == "" {
		return nil, fmt.Errorf("%w: it carries neither a PIN nor a secret", ErrBadCode)
	}

	if code.GetPin() != "" {
		pin, err := ParsePIN(code.GetPin())
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBadCode, err)
		}

		code.Pin = string(pin)
	}

	if code.GetSecret() != "" {
		secret, err := ParseSecret(code.GetSecret())
		if err != nil {
			return nil, err
		}

		code.Secret = string(secret)
	}

	if expires := code.GetExpiresAt(); expires != nil &&
		!expires.AsTime().After(time.Now()) {
		return nil, ErrCodeExpired
	}

	return &code, nil
}

// CodeKey parses the identity key a full code carries, or returns nil when the
// code was typed and carries none.
//
// A code that carries the key is the stronger pairing: the joining side pins
// before it connects, so the visual channel is the integrity root and there is
// nothing left for the user to compare character by character. On that path
// the PIN's remaining job is the other direction — authenticating the joiner
// to the listener — and a pinned handshake that fails stops a wrong address
// from ever receiving a guess. A typed PIN leaves the comparison to the two
// screens, which is what §7 describes and what a headless box gets.
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
