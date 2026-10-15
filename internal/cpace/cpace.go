// Package cpace is CPace, the balanced password-authenticated key exchange of
// draft-irtf-cfrg-cpace-21, in the one cipher suite Ladulås uses:
// CPACE-RISTR255-SHA512, initiator-responder, with the explicit key
// confirmation of the draft's §10.4.
//
// It exists for the six-digit pairing PIN (§7, decision AV). A PIN is twenty
// bits, and anything that lets somebody check a guess offline — an HMAC keyed
// with it, a hash of it, a key derived from it and then used — gives all twenty
// up in milliseconds. A PAKE is the construction where each run leaks exactly
// one online guess and nothing that can be searched afterwards, and CPace is
// the one the CFRG recommended and sent to the RFC Editor.
//
// It is written here, on github.com/gtank/ristretto255, rather than vendored.
// The one maintained Go CPace (github.com/the-sarge/cpace) is a single-author
// project that says it is unreviewed and declares a newer Go than this module,
// and the protocol is small enough that the review it needs is cheaper to give
// to two hundred lines that follow the draft step by step than to somebody
// else's abstractions. Every function below names the draft section it
// implements, and the draft's own ristretto255 test vectors (Appendix B.3) are
// the tests.
//
// What is fixed here and what the caller supplies:
//
//   - The group is ristretto255 (draft §8.3), the hash SHA-512, so
//     H.s_in_bytes is 128 and the generator hash is 64 bytes.
//   - Scalars are sampled as the draft RECOMMENDS for the group abstractions:
//     32 random bytes with the bits from 252 upward cleared.
//   - Transcripts are transcript_ir: the roles are fixed, A speaks first.
//   - Key confirmation is §10.4's: mac_key = SHA-512("CPaceMac" || sid ||
//     ISK), and each side's tag is HMAC-SHA-512(mac_key, lv_cat(Y, AD)) over
//     the message it sent. The draft names HMAC as a suitable MAC without
//     fixing the hash; SHA-512 is the suite's.
//   - A session id is required. The draft makes it optional and RECOMMENDS
//     one; every caller here has one, and refusing an empty one keeps a call
//     site from forgetting it.
//
// The caller owns the encoding of PRS, CI, sid and the associated data (draft
// §4.3) and the party identities in them (draft §10.1). K is never exposed
// (draft §10.3).
package cpace

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"github.com/gtank/ristretto255"
)

const (
	// DSI is G_Ristretto255.DSI (draft §8.3).
	DSI = "CPaceRistretto255"

	// ShareSize is the length of an encoded group element, which is what each
	// side sends.
	ShareSize = 32

	// sInBytes is H.s_in_bytes for SHA-512 (draft §6.2).
	sInBytes = 128

	// fieldSizeBytes is G_Ristretto255.field_size_bytes (draft §8.3).
	fieldSizeBytes = 32
)

// ErrInvalidShare is a received share that does not decode to a group element,
// or that leads to the neutral element. The draft says to abort (§7.2), and
// both are what a peer that is not running the protocol honestly sends.
var ErrInvalidShare = errors.New("cpace: the other side's share is not a valid group element")

// ErrNoSessionID is an exchange started without a session id.
var ErrNoSessionID = errors.New("cpace: a session id is required")

// ErrSpent is a second use of an initiator, whose scalar is single use.
var ErrSpent = errors.New("cpace: this exchange has already finished")

// Inputs are what both sides must agree on for their keys to match: the
// password-related string, the channel identifier and the session id (draft
// §4.1). The associated data is per side and is passed separately.
type Inputs struct {
	PRS []byte
	CI  []byte
	SID []byte
}

// Initiator is party A: it speaks first, and finishes when B's share arrives.
type Initiator struct {
	in    Inputs
	y     *ristretto255.Scalar
	share []byte
	ad    []byte
	done  bool
}

// NewInitiator samples A's scalar and computes Ya (draft §7.2).
func NewInitiator(in Inputs, ad []byte) (*Initiator, error) {
	return newInitiator(in, ad, rand.Reader)
}

func newInitiator(in Inputs, ad []byte, random io.Reader) (*Initiator, error) {
	if len(in.SID) == 0 {
		return nil, ErrNoSessionID
	}

	y, err := sampleScalar(random)
	if err != nil {
		return nil, err
	}

	g, err := calculateGenerator(in.PRS, in.CI, in.SID)
	if err != nil {
		return nil, err
	}

	return &Initiator{
		in:    in,
		y:     y,
		share: scalarMult(y, g),
		ad:    clone(ad),
	}, nil
}

// Share is Ya, which A sends to B along with its associated data.
func (a *Initiator) Share() []byte {
	return clone(a.share)
}

// Finish takes B's share and associated data and derives the session (draft
// §7.2). It can be called once: the scalar is forgotten whether or not it
// worked, because an initiator that could be finished twice would be one an
// attacker could feed two shares.
func (a *Initiator) Finish(peerShare, peerAD []byte) (*Session, error) {
	if a.done {
		return nil, ErrSpent
	}

	a.done = true
	y := a.y
	a.y = nil

	k, err := scalarMultVfy(y, peerShare)
	if err != nil {
		return nil, err
	}

	ownMsg := LVCat(a.share, a.ad)
	peerMsg := LVCat(peerShare, peerAD)

	return newSession(a.in.SID, k, ownMsg, peerMsg, ownMsg, peerMsg), nil
}

// Respond is party B in one step: it computes Yb, derives the session from A's
// message, and returns both (draft §7.2). B has everything it needs as soon as
// A's message arrives, which is what makes the responder the side that can be
// made to commit first.
func Respond(in Inputs, ad, peerShare, peerAD []byte) ([]byte, *Session, error) {
	return respond(in, ad, peerShare, peerAD, rand.Reader)
}

func respond(
	in Inputs, ad, peerShare, peerAD []byte, random io.Reader,
) ([]byte, *Session, error) {
	if len(in.SID) == 0 {
		return nil, nil, ErrNoSessionID
	}

	y, err := sampleScalar(random)
	if err != nil {
		return nil, nil, err
	}

	g, err := calculateGenerator(in.PRS, in.CI, in.SID)
	if err != nil {
		return nil, nil, err
	}

	share := scalarMult(y, g)

	k, err := scalarMultVfy(y, peerShare)
	if err != nil {
		return nil, nil, err
	}

	ownMsg := LVCat(share, ad)
	peerMsg := LVCat(peerShare, peerAD)

	// transcript_ir is always A's message then B's, whichever side computes it.
	return share, newSession(in.SID, k, ownMsg, peerMsg, peerMsg, ownMsg), nil
}

// Session is a finished exchange: the intermediate session key, and the key
// confirmation of draft §10.4.
type Session struct {
	isk     []byte
	macKey  []byte
	ownMsg  []byte
	peerMsg []byte
}

// newSession computes ISK = H.hash(lv_cat(DSI || "_ISK", sid, K) ||
// transcript_ir(Ya, ADa, Yb, ADb)) (draft §7.2, §6.3) and the MAC key of §10.4.
func newSession(sid, k, ownMsg, peerMsg, msgA, msgB []byte) *Session {
	h := sha512.New()
	h.Write(LVCat([]byte(DSI+"_ISK"), sid, k))
	h.Write(msgA)
	h.Write(msgB)
	isk := h.Sum(nil)

	m := sha512.New()
	m.Write([]byte("CPaceMac"))
	m.Write(sid)
	m.Write(isk)

	return &Session{
		isk:     isk,
		macKey:  m.Sum(nil),
		ownMsg:  ownMsg,
		peerMsg: peerMsg,
	}
}

// ISK is the intermediate session key. The draft RECOMMENDS a KDF before using
// it as a key (§10.3).
func (s *Session) ISK() []byte {
	return clone(s.isk)
}

// Confirmation is this side's tag: a MAC over the message it sent (draft
// §10.4). The two sides' tags are over different messages, so one can never
// be reflected back as the other.
func (s *Session) Confirmation() []byte {
	return tag(s.macKey, s.ownMsg)
}

// Verify checks the other side's tag in constant time. A false is the one
// signal that the other side used a different PRS, CI, sid or associated data,
// and the draft says to abort on it.
func (s *Session) Verify(peerTag []byte) bool {
	return hmac.Equal(tag(s.macKey, s.peerMsg), peerTag)
}

func tag(key, msg []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(msg)

	return mac.Sum(nil)
}

// calculateGenerator is G.calculate_generator for the group abstractions
// (draft §8.3): hash the generator string to 2*field_size_bytes and map it to
// the group with ristretto255's element derivation (RFC 9496 §4.3.4).
func calculateGenerator(prs, ci, sid []byte) (*ristretto255.Element, error) {
	sum := sha512.Sum512(generatorString([]byte(DSI), prs, ci, sid, sInBytes))

	g, err := ristretto255.NewIdentityElement().SetUniformBytes(sum[:2*fieldSizeBytes])
	if err != nil {
		return nil, fmt.Errorf("cpace: derive the generator: %w", err)
	}

	return g, nil
}

// generatorString is generator_string(DSI, PRS, CI, sid, s_in_bytes) (draft
// §8.1, Appendix A.2): the zero padding fills the first hash block after DSI
// and PRS, so for a short PRS the amount hashed does not depend on its length.
func generatorString(dsi, prs, ci, sid []byte, sInBytes int) []byte {
	zpad := max(0, sInBytes-1-len(prependLen(prs))-len(prependLen(dsi)))

	return LVCat(dsi, prs, make([]byte, zpad), ci, sid)
}

// sampleScalar is G.sample_scalar as the draft RECOMMENDS for the group
// abstractions (§8.3): sample_random_bytes(32), clear the bits above
// group_size_bits (252), read it little-endian. Every such value is below the
// group order, so it is always canonical. Zero is refused, at a probability of
// 2^-252, because a zero scalar sends the neutral element.
func sampleScalar(random io.Reader) (*ristretto255.Scalar, error) {
	var buf [32]byte

	for {
		if _, err := io.ReadFull(random, buf[:]); err != nil {
			return nil, fmt.Errorf("cpace: no randomness for a scalar: %w", err)
		}

		buf[31] &= 0x0f

		s, err := ristretto255.NewScalar().SetCanonicalBytes(buf[:])
		if err != nil {
			return nil, fmt.Errorf("cpace: sample a scalar: %w", err)
		}

		if s.Equal(ristretto255.NewScalar()) == 0 {
			return s, nil
		}
	}
}

// scalarMult is G.scalar_mult: y times a decoded point, returned encoded.
func scalarMult(y *ristretto255.Scalar, g *ristretto255.Element) []byte {
	return ristretto255.NewIdentityElement().ScalarMult(y, g).Bytes()
}

// scalarMultVfy is G.scalar_mult_vfy (draft §8.3) with §7.2's abort folded in:
// an encoding that does not decode, and a product that is the neutral element,
// are both ErrInvalidShare rather than G.I for the caller to compare against.
func scalarMultVfy(y *ristretto255.Scalar, encoded []byte) ([]byte, error) {
	if y == nil {
		return nil, ErrSpent
	}

	x, err := ristretto255.NewIdentityElement().SetCanonicalBytes(encoded)
	if err != nil {
		return nil, ErrInvalidShare
	}

	k := ristretto255.NewIdentityElement().ScalarMult(y, x)

	if k.Equal(ristretto255.NewIdentityElement()) == 1 {
		return nil, ErrInvalidShare
	}

	return k.Bytes(), nil
}

// prependLen is prepend_len (draft §6.3, Appendix A.1.1): the LEB128 encoding
// of the length, then the bytes.
func prependLen(data []byte) []byte {
	out := make([]byte, 0, len(data)+2)
	length := len(data)

	for {
		if length < 128 {
			out = append(out, byte(length))
		} else {
			out = append(out, byte(length&0x7f)|0x80)
		}

		length >>= 7

		if length == 0 {
			break
		}
	}

	return append(out, data...)
}

// LVCat is lv_cat (draft §6.3, Appendix A.1.3): each argument with its length
// prepended. It is exported because the caller encodes CI with it, so that
// the party identities in the channel identifier are framed the way the draft
// frames everything else.
func LVCat(parts ...[]byte) []byte {
	var out []byte

	for _, part := range parts {
		out = append(out, prependLen(part)...)
	}

	return out
}

func clone(b []byte) []byte {
	return append([]byte(nil), b...)
}
