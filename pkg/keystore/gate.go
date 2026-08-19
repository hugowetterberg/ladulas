package keystore

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

// A portable key on a phone has to prompt per signature the way an enclave key
// does, and cannot do it the same way (§10, decision S). An enclave key gets the
// prompt for free: the signature happens on the far side of it, and Go only
// finds out whether one came back. A portable key's private half is already in
// this process, so the prompt is something Ladulås asks for on the way past.
//
// SignGate is that ask. It is a seam rather than a call into LocalAuthentication
// because the store has no business knowing what platform it is on, and because
// the desktop deliberately installs none — there the store's own unlock and the
// approval engine are the gates, and a second passphrase per signature is
// exactly the daily cost this project exists to remove.

// SignGate authorizes the use of a key whose private half is in the store.
//
// It is called once per signature, outside every lock the store holds, because
// the implementation draws a sheet and waits for a person. Returning an error is
// an ordinary outcome — a dismissed prompt is a refusal to sign and nothing more
// alarming than that.
type SignGate interface {
	Authorize(reason string) error
}

// ErrSignatureRefused is what a gate should return, or wrap, when the person
// declined. It exists so a caller can tell "the user said no" from "the gate
// itself is broken", and so nothing up the stack has to match on strings.
var ErrSignatureRefused = errors.New("keystore: the signature was not authorized")

// gatedSigner asks the gate, then signs.
//
// It wraps rather than replaces so that everything above it keeps working with
// an ssh.Signer: the agent, remote signing and the SSHSIG path all take one, and
// two of them reach for ssh.AlgorithmSigner to pin an RSA hash, which is why
// that interface is carried through rather than quietly dropped.
type gatedSigner struct {
	signer ssh.Signer
	gate   SignGate
	reason string
}

var (
	_ ssh.Signer          = (*gatedSigner)(nil)
	_ ssh.AlgorithmSigner = (*gatedSigner)(nil)
)

func (g *gatedSigner) PublicKey() ssh.PublicKey {
	return g.signer.PublicKey()
}

func (g *gatedSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	if err := g.gate.Authorize(g.reason); err != nil {
		return nil, err
	}

	sig, err := g.signer.Sign(rand, data)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return sig, nil
}

func (g *gatedSigner) SignWithAlgorithm(
	rand io.Reader, data []byte, algorithm string,
) (*ssh.Signature, error) {
	as, ok := g.signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf(
			"keystore: this key cannot sign with %s", algorithm)
	}

	if err := g.gate.Authorize(g.reason); err != nil {
		return nil, err
	}

	sig, err := as.SignWithAlgorithm(rand, data, algorithm)
	if err != nil {
		return nil, fmt.Errorf("sign with %s: %w", algorithm, err)
	}

	return sig, nil
}
