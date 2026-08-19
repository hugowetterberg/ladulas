package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/pkg/identity"
)

// ClientOptions configures a dialler.
type ClientOptions struct {
	// Identity is this instance's identity key, presented as the client
	// certificate. Required: the far end asks for one.
	Identity *identity.Identity
	// Expect is the peer's identity key. When set, a handshake with any other
	// key fails before a byte of protocol is exchanged.
	//
	// It is left empty for exactly one case: the first contact of a pairing,
	// where there is nothing to expect yet. The dialler then pins whatever it
	// meets for the rest of its life, and the pairing exchange is what decides
	// whether that identity was the right one.
	Expect ssh.PublicKey
}

// Client dials one peer.
//
// A Client is bound to an identity rather than to an address, because a peer
// can advertise several addresses and they are all the same peer. It is not
// bound to a connection: net/http keeps the HTTP/2 connection alive underneath
// and redials when it has to, and the pin is checked on every handshake.
type Client struct {
	http   *http.Client
	tls    *tls.Config
	expect *Pin

	mu   sync.Mutex
	peer *PeerIdentity
}

// NewClient creates a dialler.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Identity == nil {
		return nil, errors.New("transport: no instance identity")
	}

	certificate, err := selfSigned(opts.Identity)
	if err != nil {
		return nil, err
	}

	client := &Client{}

	if opts.Expect != nil {
		pin, err := PinFor(opts.Expect)
		if err != nil {
			return nil, err
		}

		client.expect = &pin
	}

	client.tls = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   alpn,
		ServerName:   tlsServerName,
		// Not a lapse: there is no certificate authority in this design and no
		// name to check. VerifyPeerCertificate below does the whole of the
		// authentication, against the key rather than against a chain.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: client.verifyPeer,
	}

	client.http = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: client.tls,
			DialContext: (&net.Dialer{
				Timeout: DialTimeout,
			}).DialContext,
			TLSHandshakeTimeout: DialTimeout,
			// A custom TLS configuration switches HTTP/2 off unless it is asked
			// for, and the approval stream needs it (see cert.go).
			ForceAttemptHTTP2: true,
		},
		// No client timeout. What is being waited for is a human deciding, and
		// §9 gives that minutes; the context is what bounds a call.
	}

	return client, nil
}

// DialTimeout bounds reaching a peer that is not there.
//
// It exists so that an approver which has gone away fails rather than hangs: a
// request fans out to every approver at once, and the engine gives up as soon
// as they have all failed. A blackholed address that took the whole approval
// timeout to admit defeat would turn a peer being switched off into a minute
// and a half of nothing happening.
const DialTimeout = 10 * time.Second

// Handshake connects, authenticates, and hangs up.
//
// Pairing needs it: the proof a dialler sends is computed over the key the far
// end presents, so the key has to be in hand before the first RPC. It also
// fixes the pin for a dialler that started with nothing to expect, so
// everything after the handshake is pinned to what the handshake met.
func (c *Client) Handshake(ctx context.Context, address string) (*PeerIdentity, error) {
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: DialTimeout},
		Config:    c.tls,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("transport: connect to %s: %w", address, err)
	}

	defer func() {
		_ = conn.Close()
	}()

	peer := c.Peer()
	if peer == nil {
		return nil, fmt.Errorf("transport: %s completed a handshake without an identity",
			address)
	}

	peer.RemoteAddr = conn.RemoteAddr().String()

	return peer, nil
}

// HTTP returns the client the connect-go stubs are built on.
func (c *Client) HTTP() *http.Client {
	return c.http
}

// URL is the base URL for an address.
func (c *Client) URL(address string) string {
	return (&url.URL{Scheme: "https", Host: address}).String()
}

// Peer returns the identity the last handshake authenticated, or nil when
// nothing has connected yet.
func (c *Client) Peer() *PeerIdentity {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.peer
}

// CloseIdle drops the connections this client is holding, which is how a
// revocation stops one being reused.
func (c *Client) CloseIdle() {
	c.http.CloseIdleConnections()
}

func (c *Client) verifyPeer(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	cert, err := leafFrom(rawCerts)
	if err != nil {
		return err
	}

	peer, err := identityFromCert(cert, "")
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	expect := c.expect

	// A dialler that started out expecting nothing still only ever meets one
	// peer: the first handshake fixes the identity, and a reconnection that
	// arrives as somebody else is a reconnection to somebody else.
	if expect == nil && c.peer != nil {
		expect = &c.peer.Pin
	}

	if expect != nil && !expect.Equal(peer.Pin) {
		return fmt.Errorf("%w: got %s, expected %s",
			ErrUnknownPeer, peer.Fingerprint, expect)
	}

	c.peer = peer

	return nil
}
