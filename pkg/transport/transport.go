// Package transport is the peer channel: TLS 1.3 between instances, mutually
// authenticated by pinning the SHA-256 of each other's SubjectPublicKeyInfo
// (docs/architecture.md §8, decision A1).
//
// Each instance wraps its identity key in a self-signed certificate. The server
// asks for a client certificate and does not verify it as a certificate; the
// client skips verification too. Both then run a VerifyPeerCertificate that
// compares the peer's SPKI hash against what it expected. The certificate is
// packaging, and pinning the key inside it rather than the certificate around
// it means an instance can reissue its certificate — a new expiry, a new
// serial — without becoming a different peer. That is Syncthing's trust model
// with Syncthing's own early mistake left out.
//
// Nothing here knows about ed25519. An SPKI is an SPKI, so a desktop's ed25519
// identity and a phone's Secure Enclave P-256 identity (§7, §10) pin the same
// way and interoperate without a second code path.
//
// connect-go rides on top as plain net/http over the pinned tls.Config, with
// HTTP/2 negotiated by ALPN — which is what makes cancelling one streamed
// approval leave the rest of the connection alone.
package transport

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Pin is the SHA-256 of a peer's SubjectPublicKeyInfo — the identity the
// channel authenticates.
type Pin [sha256.Size]byte

// String renders a pin for logs, in the same SHA256:base64 shape as an SSH
// fingerprint so the two are not mistaken for each other's format while still
// reading alike.
func (p Pin) String() string {
	return "SPKI256:" + strings.TrimRight(
		base64.StdEncoding.EncodeToString(p[:]), "=")
}

// Equal compares two pins without leaking where they differ.
func (p Pin) Equal(other Pin) bool {
	return subtle.ConstantTimeCompare(p[:], other[:]) == 1
}

// ErrUnknownPeer is returned when a handshake presents an identity that is not
// the expected one, or not one this instance knows at all.
var ErrUnknownPeer = errors.New("transport: the peer is not the expected identity")

// PinFor computes the pin of an SSH public key, which is how a trust record —
// which holds SSH public keys, because that is what the user sees a fingerprint
// of — turns into something a TLS handshake can check.
func PinFor(pub ssh.PublicKey) (Pin, error) {
	crypto, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return Pin{}, fmt.Errorf(
			"transport: %s keys carry no standard public key", pub.Type())
	}

	der, err := x509.MarshalPKIXPublicKey(crypto.CryptoPublicKey())
	if err != nil {
		return Pin{}, fmt.Errorf("transport: encode public key: %w", err)
	}

	return sha256.Sum256(der), nil
}

// PeerIdentity is who the other end of a connection turned out to be.
//
// It is derived from the certificate the peer presented and from nothing the
// peer said in a message, which is what makes it usable as an authorization
// subject: an RPC that names an instance is checked against this, never
// believed on its own.
type PeerIdentity struct {
	// PublicKey is the peer's identity key.
	PublicKey ssh.PublicKey
	// Fingerprint is the SSH-style SHA256 fingerprint shown in every UI.
	Fingerprint string
	// Pin is what the channel pinned.
	Pin Pin
	// RemoteAddr is where the connection came from. Corroborating only.
	RemoteAddr string
}

// identityFromCert derives a peer identity from a presented certificate.
//
// The pin comes from the certificate's own SubjectPublicKeyInfo bytes rather
// than from a re-encoding of the parsed key, so what is pinned is what was on
// the wire. A certificate whose SPKI is encoded unusually simply fails to match
// anything, which is the safe direction to fail in.
func identityFromCert(cert *x509.Certificate, remote string) (*PeerIdentity, error) {
	pub, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("transport: unusable peer key: %w", err)
	}

	return &PeerIdentity{
		PublicKey:   pub,
		Fingerprint: ssh.FingerprintSHA256(pub),
		Pin:         sha256.Sum256(cert.RawSubjectPublicKeyInfo),
		RemoteAddr:  remote,
	}, nil
}

// leafFrom parses the peer's leaf certificate out of the raw chain a
// VerifyPeerCertificate callback is handed.
func leafFrom(rawCerts [][]byte) (*x509.Certificate, error) {
	if len(rawCerts) == 0 {
		return nil, errors.New("transport: the peer presented no certificate")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, fmt.Errorf("transport: parse peer certificate: %w", err)
	}

	return cert, nil
}
