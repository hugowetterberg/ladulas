package cpace

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/gtank/ristretto255"
)

// The vectors below are draft-irtf-cfrg-cpace-21's, copied from Appendix A.1
// to A.3 and B.3 with the hex de-wrapped. They are the reason this package can
// be believed to implement the draft rather than something that merely agrees
// with itself.

func unhex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatalf("bad hex in a test vector: %v", err)
	}

	return b
}

func expect(t *testing.T, what string, got, want []byte) {
	t.Helper()

	if !bytes.Equal(got, want) {
		t.Errorf("%s:\n got %x\nwant %x", what, got, want)
	}
}

// Appendix A.1.2.
func TestPrependLenVectors(t *testing.T) {
	expect(t, "prepend_len(b\"\")", prependLen(nil), unhex(t, "00"))
	expect(t, "prepend_len(b\"1234\")", prependLen([]byte("1234")),
		unhex(t, "0431323334"))

	r127 := make([]byte, 127)
	r128 := make([]byte, 128)

	for i := range r128 {
		r128[i] = byte(i)
		if i < 127 {
			r127[i] = byte(i)
		}
	}

	expect(t, "prepend_len(range(127))", prependLen(r127),
		append([]byte{0x7f}, r127...))
	expect(t, "prepend_len(range(128))", prependLen(r128),
		append([]byte{0x80, 0x01}, r128...))
}

// Appendix A.1.4 and A.3.5.
func TestLVCatAndTranscriptVectors(t *testing.T) {
	expect(t, "lv_cat",
		LVCat([]byte("1234"), []byte("5"), nil, []byte("678")),
		unhex(t, "043132333401350003363738"))

	ir := func(ya, ada, yb, adb string) []byte {
		return append(LVCat([]byte(ya), []byte(ada)), LVCat([]byte(yb), []byte(adb))...)
	}

	expect(t, "transcript_ir 1", ir("123", "PartyA", "234", "PartyB"),
		unhex(t, "03313233065061727479410332333406506172747942"))
	expect(t, "transcript_ir 2", ir("3456", "PartyA", "2345", "PartyB"),
		unhex(t, "043334353606506172747941043233343506506172747942"))
}

// b3 is the B.3 test case: ristretto255, SHA-512.
type b3 struct {
	in  Inputs
	ya  []byte
	yb  []byte
	ada []byte
	adb []byte
}

func vectorB3(t *testing.T) b3 {
	t.Helper()

	return b3{
		in: Inputs{
			PRS: []byte("Password"),
			CI:  unhex(t, "0b415f696e69746961746f720b425f726573706f6e646572"),
			SID: unhex(t, "7e4b4791d6a8ef019b936c79fb7f2c57"),
		},
		ya: unhex(t, `da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4f
			f0976d08`),
		yb: unhex(t, `d2316b454718c35362d83d69df6320f38578ed5984651435e2949762
			d900b80d`),
		ada: []byte("ADa"),
		adb: []byte("ADb"),
	}
}

// B.3.1.
func TestGeneratorVector(t *testing.T) {
	v := vectorB3(t)

	expect(t, "generator_string",
		generatorString([]byte(DSI), v.in.PRS, v.in.CI, v.in.SID, sInBytes),
		unhex(t, `11435061636552697374726574746f3235350850617373776f726464
			00000000000000000000000000000000000000000000000000000000
			00000000000000000000000000000000000000000000000000000000
			00000000000000000000000000000000000000000000000000000000
			00000000000000000000000000000000180b415f696e69746961746f
			720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f
			2c57`))

	g, err := calculateGenerator(v.in.PRS, v.in.CI, v.in.SID)
	if err != nil {
		t.Fatal(err)
	}

	expect(t, "encoded generator g", g.Bytes(),
		unhex(t, `222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5
			698c7e56`))
}

// B.3.2 to B.3.5: both messages, K on both sides, and the
// initiator-responder ISK, driven through the public flow with the vector's
// scalars standing in for the randomness.
func TestExchangeVector(t *testing.T) {
	v := vectorB3(t)

	wantYa := unhex(t, `d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec
		482b9157`)
	wantYb := unhex(t, `3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7
		433f7258`)
	wantK := unhex(t, `80b69a8a76457ab6a4d7f887a4bf6b55a2f80ac19c333f917a05fc98
		87c8b40f`)
	wantISK := unhex(t, `b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dc
		ae7b35cd2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c
		3fa2068af7900447`)

	a, err := newInitiator(v.in, v.ada, bytes.NewReader(v.ya))
	if err != nil {
		t.Fatal(err)
	}

	expect(t, "Ya", a.Share(), wantYa)

	// K is checked through the internal function, because the package never
	// hands it out (draft §10.3).
	ya, _ := ristretto255.NewScalar().SetCanonicalBytes(v.ya)

	k, err := scalarMultVfy(ya, wantYb)
	if err != nil {
		t.Fatal(err)
	}

	expect(t, "scalar_mult_vfy(ya, Yb)", k, wantK)

	yb, bSession, err := respond(v.in, v.adb, a.Share(), v.ada, bytes.NewReader(v.yb))
	if err != nil {
		t.Fatal(err)
	}

	expect(t, "Yb", yb, wantYb)

	aSession, err := a.Finish(yb, v.adb)
	if err != nil {
		t.Fatal(err)
	}

	expect(t, "ISK at A", aSession.ISK(), wantISK)
	expect(t, "ISK at B", bSession.ISK(), wantISK)

	// The draft gives no vector for §10.4, so what is checked is that each
	// side accepts the other's tag and neither accepts its own.
	if !aSession.Verify(bSession.Confirmation()) || !bSession.Verify(aSession.Confirmation()) {
		t.Error("the two sides do not accept each other's confirmation")
	}
}

// B.3.10 and B.3.11.
func TestScalarMultVfyVectors(t *testing.T) {
	s, err := ristretto255.NewScalar().SetCanonicalBytes(unhex(t,
		"7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := scalarMultVfy(s, unhex(t,
		"2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c"))
	if err != nil {
		t.Fatal(err)
	}

	expect(t, "scalar_mult_vfy(s, X)", got, unhex(t,
		"7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e7f6b600e"))

	for name, invalid := range map[string][]byte{
		"Y_i1":          unhex(t, "2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c"),
		"Y_i2 (G.I)":    make([]byte, 32),
		"short":         make([]byte, 31),
		"non-canonical": bytes.Repeat([]byte{0xff}, 32),
		"empty":         nil,
	} {
		if _, err := scalarMultVfy(s, invalid); !errors.Is(err, ErrInvalidShare) {
			t.Errorf("%s: got %v, want ErrInvalidShare", name, err)
		}
	}
}

// run is one honest exchange with the given inputs on each side, returning
// both sessions or the error that stopped it.
func run(
	t *testing.T, aIn, bIn Inputs, ada, adb []byte,
) (*Session, *Session) {
	t.Helper()

	a, err := NewInitiator(aIn, ada)
	if err != nil {
		t.Fatal(err)
	}

	yb, bSession, err := Respond(bIn, adb, a.Share(), ada)
	if err != nil {
		t.Fatal(err)
	}

	aSession, err := a.Finish(yb, adb)
	if err != nil {
		t.Fatal(err)
	}

	return aSession, bSession
}

func inputs(prs, ci, sid string) Inputs {
	return Inputs{PRS: []byte(prs), CI: []byte(ci), SID: []byte(sid)}
}

func TestMatchingInputsConfirm(t *testing.T) {
	in := inputs("123456", "joiner|listener", "session")

	a, b := run(t, in, in, []byte("A"), []byte("B"))

	if !b.Verify(a.Confirmation()) || !a.Verify(b.Confirmation()) {
		t.Fatal("an honest exchange did not confirm")
	}
}

// Every input both sides have to agree on, disagreed about one at a time. In
// each case the exchange itself completes — a PAKE message reveals nothing,
// so there is nothing to refuse until a tag arrives — and the tags do not
// verify in either direction.
func TestMismatchedInputsDoNotConfirm(t *testing.T) {
	base := inputs("123456", "joiner|listener", "session")

	cases := map[string]struct {
		a, b    Inputs
		peerADa []byte // what B believes A's associated data was
	}{
		"wrong PIN":       {a: base, b: inputs("123457", "joiner|listener", "session")},
		"wrong party ids": {a: base, b: inputs("123456", "listener|joiner", "session")},
		"wrong sid":       {a: base, b: inputs("123456", "joiner|listener", "other")},
		"wrong AD":        {a: base, b: base, peerADa: []byte("ladulas-pairing-v1")},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ada := []byte("A")
			adb := []byte("B")

			a, err := NewInitiator(c.a, ada)
			if err != nil {
				t.Fatal(err)
			}

			seenADa := ada
			if c.peerADa != nil {
				seenADa = c.peerADa
			}

			yb, bSession, err := Respond(c.b, adb, a.Share(), seenADa)
			if err != nil {
				t.Fatal(err)
			}

			aSession, err := a.Finish(yb, adb)
			if err != nil {
				t.Fatal(err)
			}

			if bSession.Verify(aSession.Confirmation()) {
				t.Error("B accepted A's tag")
			}

			if aSession.Verify(bSession.Confirmation()) {
				t.Error("A accepted B's tag")
			}

			if bytes.Equal(aSession.ISK(), bSession.ISK()) {
				t.Error("the two sides derived the same key")
			}
		})
	}
}

// A tag is over the message its sender sent, so handing a side its own tag —
// a relay reflecting it — is refused, and so is a tag from another exchange.
func TestReflectedAndReplayedTagsAreRefused(t *testing.T) {
	in := inputs("123456", "joiner|listener", "session")

	a, b := run(t, in, in, []byte("A"), []byte("B"))

	if a.Verify(a.Confirmation()) {
		t.Error("A accepted its own tag reflected back")
	}

	if b.Verify(b.Confirmation()) {
		t.Error("B accepted its own tag reflected back")
	}

	// The same associated data on both sides is the case where a reflection
	// would only be stopped by the shares differing; it still is.
	same, _ := run(t, in, in, []byte("AD"), []byte("AD"))
	if same.Verify(same.Confirmation()) {
		t.Error("a tag was reflectable with identical associated data")
	}

	other, _ := run(t, in, in, []byte("A"), []byte("B"))
	if b.Verify(other.Confirmation()) {
		t.Error("B accepted a tag from another exchange")
	}

	if b.Verify(nil) || b.Verify(make([]byte, 64)) {
		t.Error("B accepted an empty or zero tag")
	}
}

func TestInvalidSharesAbort(t *testing.T) {
	in := inputs("123456", "joiner|listener", "session")

	for name, share := range map[string][]byte{
		"identity":     make([]byte, ShareSize),
		"not a point":  bytes.Repeat([]byte{0xff}, ShareSize),
		"wrong length": make([]byte, ShareSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Respond(in, nil, share, nil); !errors.Is(err, ErrInvalidShare) {
				t.Errorf("Respond: got %v, want ErrInvalidShare", err)
			}

			a, err := NewInitiator(in, nil)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := a.Finish(share, nil); !errors.Is(err, ErrInvalidShare) {
				t.Errorf("Finish: got %v, want ErrInvalidShare", err)
			}
		})
	}
}

func TestAnInitiatorFinishesOnce(t *testing.T) {
	in := inputs("123456", "joiner|listener", "session")

	a, err := NewInitiator(in, nil)
	if err != nil {
		t.Fatal(err)
	}

	yb, _, err := Respond(in, nil, a.Share(), nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := a.Finish(yb, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := a.Finish(yb, nil); !errors.Is(err, ErrSpent) {
		t.Errorf("second Finish: got %v, want ErrSpent", err)
	}

	// A failed finish spends it too.
	b, err := NewInitiator(in, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := b.Finish(make([]byte, ShareSize), nil); !errors.Is(err, ErrInvalidShare) {
		t.Fatalf("got %v", err)
	}

	if _, err := b.Finish(yb, nil); !errors.Is(err, ErrSpent) {
		t.Errorf("finish after a failure: got %v, want ErrSpent", err)
	}
}

func TestASessionIDIsRequired(t *testing.T) {
	in := inputs("123456", "ci", "")

	if _, err := NewInitiator(in, nil); !errors.Is(err, ErrNoSessionID) {
		t.Errorf("NewInitiator: got %v", err)
	}

	if _, _, err := Respond(in, nil, make([]byte, ShareSize), nil); !errors.Is(err, ErrNoSessionID) {
		t.Errorf("Respond: got %v", err)
	}
}
