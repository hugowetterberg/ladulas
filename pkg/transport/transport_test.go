package transport_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// newIdentity makes an ed25519 instance identity, the desktop kind (§7).
func newIdentity(t *testing.T, name string) *identity.Identity {
	t.Helper()

	id, _, err := identity.Generate(name)
	if err != nil {
		t.Fatalf("generate an identity: %v", err)
	}

	return id
}

// newP256Identity makes the kind of identity a phone has: P-256, because that
// is what the Secure Enclave and StrongBox do (§10). Nothing in the transport
// may assume otherwise, and this is what says so.
func newP256Identity(t *testing.T, name string) *identity.Identity {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a P-256 key: %v", err)
	}

	block, err := ssh.MarshalPrivateKey(key, name)
	if err != nil {
		t.Fatalf("marshal the P-256 key: %v", err)
	}

	id, err := identity.FromPEM(pem.EncodeToMemory(block), name)
	if err != nil {
		t.Fatalf("load the P-256 identity: %v", err)
	}

	return id
}

// echoHandler reports the authenticated caller and the protocol it arrived on,
// and records that it was reached at all.
func echoHandler(reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true

		peer := transport.PeerFrom(r.Context())
		if peer == nil {
			http.Error(w, "no peer identity", http.StatusForbidden)

			return
		}

		fmt.Fprintf(w, "%s %s", peer.Fingerprint, r.Proto)
	})
}

// serve starts a listener on loopback and returns it with its address.
func serve(t *testing.T, opts transport.ServerOptions) (*transport.Server, string) {
	t.Helper()

	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:0"
	}

	server, err := transport.NewServer(opts)
	if err != nil {
		t.Fatalf("create the server: %v", err)
	}

	if err := server.Listen(); err != nil {
		t.Fatalf("bind: %v", err)
	}

	addresses := server.Addresses()
	if len(addresses) != 1 {
		t.Fatalf("bound %v, want one address", addresses)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		done <- server.Serve(ctx)
	}()

	t.Cleanup(func() {
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the server did not stop")
		}
	})

	return server, addresses[0]
}

func get(client *transport.Client, address string) (string, error) {
	resp, err := client.HTTP().Get(client.URL(address) + "/")
	if err != nil {
		return "", err // the test wants the error as it is
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err // the test wants the error as it is
	}

	return string(body), nil
}

// TestPinnedChannelAuthenticatesBothEnds is the whole of decision A1 in one
// test: each end learns who the other is from the key in its certificate, and
// the RPC layer above sees an authenticated caller.
func TestPinnedChannelAuthenticatesBothEnds(t *testing.T) {
	serverID := newIdentity(t, "desktop")
	clientID := newIdentity(t, "headless")

	var reached bool

	_, address := serve(t, transport.ServerOptions{
		Identity: serverID,
		Handler:  echoHandler(&reached),
	})

	client, err := transport.NewClient(transport.ClientOptions{
		Identity: clientID,
		Expect:   serverID.PublicKey(),
	})
	if err != nil {
		t.Fatalf("create the client: %v", err)
	}

	body, err := get(client, address)
	if err != nil {
		t.Fatalf("call the peer: %v", err)
	}

	if !strings.HasPrefix(body, clientID.Fingerprint()) {
		t.Errorf("the server saw %q, want the client's fingerprint %s",
			body, clientID.Fingerprint())
	}

	// HTTP/2 is not incidental: cancelling one streamed approval must not take
	// the connection the next request needs down with it.
	if !strings.HasSuffix(body, "HTTP/2.0") {
		t.Errorf("the connection is %q, want HTTP/2.0", body)
	}

	if peer := client.Peer(); peer == nil ||
		peer.Fingerprint != serverID.Fingerprint() {
		t.Errorf("the client authenticated %v, want %s",
			peer, serverID.Fingerprint())
	}
}

// TestReissuedCertificateKeepsTheIdentity is the mistake the design names: pin
// the key, not the certificate around it. Two servers built from one identity
// have different certificates — different serial, different dates — and are the
// same peer.
func TestReissuedCertificateKeepsTheIdentity(t *testing.T) {
	serverID := newIdentity(t, "desktop")
	clientID := newIdentity(t, "headless")

	var reached bool

	_, first := serve(t, transport.ServerOptions{
		Identity: serverID,
		Handler:  echoHandler(&reached),
	})

	_, second := serve(t, transport.ServerOptions{
		Identity: serverID,
		Handler:  echoHandler(&reached),
	})

	client, err := transport.NewClient(transport.ClientOptions{
		Identity: clientID,
		Expect:   serverID.PublicKey(),
	})
	if err != nil {
		t.Fatalf("create the client: %v", err)
	}

	for _, address := range []string{first, second} {
		if _, err := get(client, address); err != nil {
			t.Fatalf("a reissued certificate broke the pin at %s: %v", address, err)
		}
	}
}

// TestWrongKeyIsRefusedBeforeAnyRPC checks that the refusal happens in the
// handshake. A peer that is not the expected one should not reach a handler at
// all, however well formed its request is.
func TestWrongKeyIsRefusedBeforeAnyRPC(t *testing.T) {
	serverID := newIdentity(t, "desktop")
	otherID := newIdentity(t, "impostor")
	clientID := newIdentity(t, "headless")

	var reached bool

	_, address := serve(t, transport.ServerOptions{
		Identity: serverID,
		Handler:  echoHandler(&reached),
	})

	client, err := transport.NewClient(transport.ClientOptions{
		Identity: clientID,
		Expect:   otherID.PublicKey(),
	})
	if err != nil {
		t.Fatalf("create the client: %v", err)
	}

	if _, err := get(client, address); err == nil {
		t.Fatal("the client accepted a peer it did not expect")
	}

	if reached {
		t.Error("the request reached the handler despite the failed handshake")
	}
}

// TestGateRefusesUnknownIdentities covers the other direction: the listener's
// outer door, which is what keeps an unpaired identity from reaching the RPC
// layer at all (§15).
func TestGateRefusesUnknownIdentities(t *testing.T) {
	serverID := newIdentity(t, "desktop")
	knownID := newIdentity(t, "known")
	strangerID := newIdentity(t, "stranger")

	var reached bool

	_, address := serve(t, transport.ServerOptions{
		Identity: serverID,
		Handler:  echoHandler(&reached),
		Gate: func(peer *transport.PeerIdentity) error {
			if peer.Fingerprint != knownID.Fingerprint() {
				return errors.New("not paired")
			}

			return nil
		},
	})

	stranger, err := transport.NewClient(transport.ClientOptions{
		Identity: strangerID,
		Expect:   serverID.PublicKey(),
	})
	if err != nil {
		t.Fatalf("create the client: %v", err)
	}

	if _, err := get(stranger, address); err == nil {
		t.Fatal("the gate let a stranger through")
	}

	if reached {
		t.Error("a refused connection still reached the handler")
	}

	known, err := transport.NewClient(transport.ClientOptions{
		Identity: knownID,
		Expect:   serverID.PublicKey(),
	})
	if err != nil {
		t.Fatalf("create the client: %v", err)
	}

	if _, err := get(known, address); err != nil {
		t.Fatalf("the gate refused a known peer: %v", err)
	}
}

// TestP256IdentitiesInteroperate is the deciding argument for pinned TLS over
// Noise (§8): a phone's hardware P-256 identity has to work, and against an
// ed25519 desktop at that.
func TestP256IdentitiesInteroperate(t *testing.T) {
	serverID := newP256Identity(t, "phone")
	clientID := newIdentity(t, "desktop")

	var reached bool

	_, address := serve(t, transport.ServerOptions{
		Identity: serverID,
		Handler:  echoHandler(&reached),
	})

	client, err := transport.NewClient(transport.ClientOptions{
		Identity: clientID,
		Expect:   serverID.PublicKey(),
	})
	if err != nil {
		t.Fatalf("create the client: %v", err)
	}

	if _, err := get(client, address); err != nil {
		t.Fatalf("a P-256 peer could not be reached: %v", err)
	}

	// And the other way round, so neither end is the one doing the assuming.
	var back bool

	_, backAddress := serve(t, transport.ServerOptions{
		Identity: clientID,
		Handler:  echoHandler(&back),
	})

	phone, err := transport.NewClient(transport.ClientOptions{
		Identity: serverID,
		Expect:   clientID.PublicKey(),
	})
	if err != nil {
		t.Fatalf("create the client: %v", err)
	}

	body, err := get(phone, backAddress)
	if err != nil {
		t.Fatalf("a P-256 peer could not dial out: %v", err)
	}

	if !strings.HasPrefix(body, serverID.Fingerprint()) {
		t.Errorf("the server saw %q, want %s", body, serverID.Fingerprint())
	}
}

// TestPinForMatchesTheCertificate ties the two halves of the pin together: what
// a trust record's SSH public key hashes to has to be what the certificate on
// the wire hashes to, or nothing would ever match.
func TestPinForMatchesTheCertificate(t *testing.T) {
	for _, id := range []*identity.Identity{
		newIdentity(t, "ed25519"),
		newP256Identity(t, "p256"),
	} {
		expected, err := transport.PinFor(id.PublicKey())
		if err != nil {
			t.Fatalf("pin the public key: %v", err)
		}

		var reached bool

		_, address := serve(t, transport.ServerOptions{
			Identity: id,
			Handler:  echoHandler(&reached),
		})

		client, err := transport.NewClient(transport.ClientOptions{
			Identity: newIdentity(t, "caller"),
		})
		if err != nil {
			t.Fatalf("create the client: %v", err)
		}

		if _, err := get(client, address); err != nil {
			t.Fatalf("call the peer: %v", err)
		}

		if peer := client.Peer(); !peer.Pin.Equal(expected) {
			t.Errorf("the handshake pinned %s, the public key pins %s",
				peer.Pin, expected)
		}
	}
}

// TestDisconnectDropsLiveConnections is what makes revocation immediate rather
// than eventual.
func TestDisconnectDropsLiveConnections(t *testing.T) {
	serverID := newIdentity(t, "desktop")
	clientID := newIdentity(t, "headless")

	var reached bool

	server, address := serve(t, transport.ServerOptions{
		Identity: serverID,
		Handler:  echoHandler(&reached),
	})

	client, err := transport.NewClient(transport.ClientOptions{
		Identity: clientID,
		Expect:   serverID.PublicKey(),
	})
	if err != nil {
		t.Fatalf("create the client: %v", err)
	}

	if _, err := get(client, address); err != nil {
		t.Fatalf("call the peer: %v", err)
	}

	if dropped := server.Disconnect(clientID.Fingerprint()); dropped != 1 {
		t.Fatalf("dropped %d connections, want 1", dropped)
	}

	// Nothing is left holding the door open. The client can of course dial
	// again — severing the connection is not the authorization decision, it is
	// what stops a revoked peer keeping one it already had.
	if dropped := server.Disconnect(clientID.Fingerprint()); dropped != 0 {
		t.Errorf("%d connections survived the disconnect", dropped)
	}
}

// TestBindPolicyKeepsThePublicInternetOptIn covers decision H.
func TestBindPolicyKeepsThePublicInternetOptIn(t *testing.T) {
	private, err := transport.ResolveBindAddresses("", false)
	if err != nil {
		t.Fatalf("resolve the default bind: %v", err)
	}

	if len(private) == 0 {
		t.Fatal("the default bind resolved to nothing")
	}

	for _, address := range private {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatalf("the default bind produced %q: %v", address, err)
		}

		if port != "7373" {
			t.Errorf("the default bind used port %q", port)
		}

		ip := net.ParseIP(host)
		if ip == nil {
			t.Fatalf("the default bind produced the non-address %q", host)
		}

		if !transport.IsLocalIP(ip) {
			t.Errorf("the default bind included the public address %s", host)
		}

		if ip.IsUnspecified() {
			t.Errorf("the default bind included the wildcard %s", host)
		}
	}

	// Loopback comes last, because a peer on another machine cannot use it.
	if len(private) > 1 {
		last := private[len(private)-1]

		host, _, _ := net.SplitHostPort(last)
		if !net.ParseIP(host).IsLoopback() {
			t.Errorf("the default bind ends with %q rather than loopback", last)
		}
	}

	cases := []struct {
		spec  string
		allow bool
		ok    bool
		want  string
	}{
		{spec: "0.0.0.0:7373", allow: false, ok: false},
		{spec: "0.0.0.0:7373", allow: true, ok: true, want: "0.0.0.0:7373"},
		{spec: "[::]:7373", allow: false, ok: false},
		{spec: "8.8.8.8:7373", allow: false, ok: false},
		{spec: "8.8.8.8:7373", allow: true, ok: true, want: "8.8.8.8:7373"},
		{spec: "127.0.0.1:9000", allow: false, ok: true, want: "127.0.0.1:9000"},
		{spec: "10.1.2.3", allow: false, ok: true, want: "10.1.2.3:7373"},
		{spec: "100.101.102.103:1", allow: false, ok: true, want: "100.101.102.103:1"},
		{spec: "9000", allow: true, ok: true, want: ":9000"},
	}

	for _, tc := range cases {
		got, err := transport.ResolveBindAddresses(tc.spec, tc.allow)

		if tc.ok && err != nil {
			t.Errorf("%q (public=%v): %v", tc.spec, tc.allow, err)

			continue
		}

		if !tc.ok {
			if err == nil {
				t.Errorf("%q (public=%v) was allowed, resolving to %v",
					tc.spec, tc.allow, got)
			} else if !errors.Is(err, transport.ErrPublicBind) {
				t.Errorf("%q (public=%v) failed with %v, want a public-bind refusal",
					tc.spec, tc.allow, err)
			}

			continue
		}

		if tc.want != "" && (len(got) != 1 || got[0] != tc.want) {
			t.Errorf("%q (public=%v) resolved to %v, want [%s]",
				tc.spec, tc.allow, got, tc.want)
		}
	}
}

// TestTailnetAddressesAreLocal records that a tailnet counts as private for the
// bind policy, which is what decision H means by "tailnet by default".
func TestTailnetAddressesAreLocal(t *testing.T) {
	cases := []struct {
		address string
		tailnet bool
		local   bool
	}{
		{address: "100.64.0.1", tailnet: true, local: true},
		{address: "100.127.255.254", tailnet: true, local: true},
		{address: "fd7a:115c:a1e0::1", tailnet: true, local: true},
		{address: "100.128.0.1", tailnet: false, local: false},
		{address: "192.168.1.4", tailnet: false, local: true},
		{address: "fd00::1", tailnet: false, local: true},
		{address: "127.0.0.1", tailnet: false, local: true},
		{address: "8.8.8.8", tailnet: false, local: false},
		{address: "2001:4860:4860::8888", tailnet: false, local: false},
	}

	for _, tc := range cases {
		ip := net.ParseIP(tc.address)
		if ip == nil {
			t.Fatalf("unparseable test address %q", tc.address)
		}

		if got := transport.IsTailnetIP(ip); got != tc.tailnet {
			t.Errorf("IsTailnetIP(%s) = %v", tc.address, got)
		}

		if got := transport.IsLocalIP(ip); got != tc.local {
			t.Errorf("IsLocalIP(%s) = %v", tc.address, got)
		}
	}
}
