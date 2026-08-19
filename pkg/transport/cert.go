package transport

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/identity"
)

// certValidity is how long a channel certificate claims to be good for.
//
// Nothing checks it: both ends skip certificate verification and pin the key
// instead, so the dates are documentation for whoever tcpdumps the handshake.
// A long life is therefore harmless, and a short one would only mean an
// instance that had been up for a year stopped being able to talk to itself.
const certValidity = 20 * 365 * 24 * time.Hour

// selfSigned wraps an identity key in a certificate for the TLS handshake.
//
// The subject names the fingerprint, so a packet capture or an openssl s_client
// says which instance answered without any of it being load-bearing. What is
// load-bearing is the public key, and that is the identity key itself.
func selfSigned(id *identity.Identity) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transport: serial number: %w", err)
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   id.Fingerprint(),
			Organization: []string{"Ladulås"},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(certValidity),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{tlsServerName},
	}

	signer := id.CryptoSigner()

	der, err := x509.CreateCertificate(
		rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transport: create certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transport: reparse certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  signer,
		Leaf:        leaf,
	}, nil
}

// tlsServerName is the SNI name both ends use. It is a constant rather than the
// address being dialled because nothing validates it, and sending the peer's
// host name in the clear on every connection would give a network observer the
// one thing the channel otherwise does not tell it.
const tlsServerName = "ladulas"

// alpn is what the two ends negotiate. HTTP/2 is not an optimization here: a
// requester that fans a request out and then cancels the losers has to be able
// to cancel one stream without dropping the connection the next request will
// use, and HTTP/1.1 has no way to say that.
var alpn = []string{"h2"}
