package sshprobe_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/hugowetterberg/ladulas/internal/sshprobe"
)

// The property the whole command rests on: the probe learns which key the
// server would accept, and learns it without signing anything.
//
// The "without signing" half is not incidental. If the probe signed, it would
// go to the agent, and the agent would raise the approval prompt this command
// exists to ask for in advance — the feature would prompt in order to avoid
// prompting. The server here fails the test if a signature ever arrives.
func TestProbeFindsTheAcceptedKeyWithoutSigning(t *testing.T) {
	accepted := generateKey(t)
	other := generateKey(t)

	server := startServer(t, accepted.PublicKey())

	agent := startAgent(t, other, accepted)

	result, err := sshprobe.ProbeWith(
		t.Context(), agent, server.config(t), "test-host", 5*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	if got := ssh.FingerprintSHA256(result.PublicKey); got !=
		ssh.FingerprintSHA256(accepted.PublicKey()) {
		t.Errorf("the probe picked %s, want the key the server accepts", got)
	}

	if result.Username != "hugo" {
		t.Errorf("username %q, want hugo", result.Username)
	}

	if got := ssh.FingerprintSHA256(result.HostKey); got !=
		ssh.FingerprintSHA256(server.hostKey.PublicKey()) {
		t.Errorf("host key %s, want the server's", got)
	}

	if server.signatures() != 0 {
		t.Errorf("the probe produced %d signatures; it must produce none",
			server.signatures())
	}
}

// An unknown host is refused rather than shown to somebody to decide about. The
// fingerprint learned here becomes the scope of a promise, so guessing at one
// would let a machine in the middle name itself as a grant's destination.
func TestProbeRefusesAHostThatIsNotInKnownHosts(t *testing.T) {
	key := generateKey(t)
	server := startServer(t, key.PublicKey())
	agent := startAgent(t, key)

	cfg := server.config(t)
	cfg.KnownHostsFiles = []string{emptyKnownHosts(t)}

	_, err := sshprobe.ProbeWith(
		t.Context(), agent, cfg, "test-host", 5*time.Second)
	if err == nil {
		t.Fatal("an unknown host was accepted")
	}

	if !strings.Contains(err.Error(), "known_hosts") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// A server that accepts none of our keys is an answer, not a crash: a promise
// would be about a login that cannot succeed anyway, and the message has to say
// so rather than reporting a connection problem.
func TestProbeSaysWhenNoKeyIsAccepted(t *testing.T) {
	server := startServer(t, generateKey(t).PublicKey())
	agent := startAgent(t, generateKey(t))

	_, err := sshprobe.ProbeWith(
		t.Context(), agent, server.config(t), "test-host", 5*time.Second)
	if !errors.Is(err, sshprobe.ErrNoAcceptedKey) {
		t.Fatalf("probe: %v, want ErrNoAcceptedKey", err)
	}
}

// testServer is an ssh server that accepts exactly one public key and counts
// the signatures it is offered.
type testServer struct {
	listener net.Listener
	hostKey  ssh.Signer
	config2  *ssh.ServerConfig

	mu    sync.Mutex
	signs int
}

// addHostKey gives the server a second host key, so that a test can check which
// of them the client's preference order settles on.
func (s *testServer) addHostKey(key ssh.Signer) {
	s.config2.AddHostKey(key)
}

// knownHostsWith writes a known_hosts holding several keys for this host, which
// is the ordinary state for a server offering more than one type.
func (s *testServer) knownHostsWith(
	t *testing.T, keys ...ssh.PublicKey,
) string {
	t.Helper()

	host, port, err := net.SplitHostPort(s.listener.Addr().String())
	if err != nil {
		t.Fatalf("split the listener address: %v", err)
	}

	path := filepath.Join(t.TempDir(), "known_hosts")
	names := []string{knownhosts.Normalize(net.JoinHostPort(host, port))}

	var body strings.Builder

	for _, key := range keys {
		body.WriteString(knownhosts.Line(names, key))
		body.WriteString("\n")
	}

	if err := os.WriteFile(path, []byte(body.String()), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	return path
}

func (s *testServer) signatures() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.signs
}

func (s *testServer) config(t *testing.T) sshprobe.Config {
	t.Helper()

	host, port, err := net.SplitHostPort(s.listener.Addr().String())
	if err != nil {
		t.Fatalf("split the listener address: %v", err)
	}

	return sshprobe.Config{
		User:            "hugo",
		HostName:        host,
		Port:            port,
		KnownHostsFiles: []string{s.knownHosts(t, host, port)},
	}
}

func (s *testServer) knownHosts(t *testing.T, host, port string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line(
		[]string{knownhosts.Normalize(net.JoinHostPort(host, port))},
		s.hostKey.PublicKey())

	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	return path
}

func startServer(t *testing.T, accept ssh.PublicKey) *testServer {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	t.Cleanup(func() {
		_ = listener.Close()
	})

	server := &testServer{listener: listener, hostKey: generateKey(t)}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(
			_ ssh.ConnMetadata, key ssh.PublicKey,
		) (*ssh.Permissions, error) {
			// x/crypto's server calls this for the query form and again for a
			// real signature, and only the second has verified one — which is
			// exactly the distinction the probe relies on. Counting every call
			// past the query is how this test notices a probe that signs.
			if ssh.FingerprintSHA256(key) != ssh.FingerprintSHA256(accept) {
				return nil, errors.New("not that key")
			}

			return &ssh.Permissions{}, nil
		},
		AuthLogCallback: func(_ ssh.ConnMetadata, method string, err error) {
			if method == "publickey" && err == nil {
				server.mu.Lock()
				server.signs++
				server.mu.Unlock()
			}
		},
	}

	config.AddHostKey(server.hostKey)
	server.config2 = config

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer conn.Close()

				sc, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}

				defer sc.Close()

				go ssh.DiscardRequests(reqs)

				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "nothing to do here")
				}
			}()
		}
	}()

	return server
}

// startAgent serves a real SSH agent holding these keys, because the probe
// reads its identities over the agent protocol and a stub would skip the part
// that has gone wrong before.
func startAgent(t *testing.T, keys ...ssh.Signer) string {
	t.Helper()

	keyring := sshagent.NewKeyring()

	for _, key := range keys {
		if err := keyring.Add(sshagent.AddedKey{
			PrivateKey: signerPrivate(t, key),
		}); err != nil {
			t.Fatalf("add a key to the keyring: %v", err)
		}
	}

	socket := filepath.Join(t.TempDir(), "agent.sock")

	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen on the agent socket: %v", err)
	}

	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer conn.Close()

				_ = sshagent.ServeAgent(keyring, conn)
			}()
		}
	}()

	return socket
}

// generated keeps the private half beside the signer, since ssh.Signer does not
// hand it back and the agent keyring wants it.
var generated sync.Map

func generateKey(t *testing.T) ssh.Signer {
	t.Helper()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("make a signer: %v", err)
	}

	generated.Store(ssh.FingerprintSHA256(signer.PublicKey()), private)

	return signer
}

func signerPrivate(t *testing.T, signer ssh.Signer) ed25519.PrivateKey {
	t.Helper()

	value, ok := generated.Load(ssh.FingerprintSHA256(signer.PublicKey()))
	if !ok {
		t.Fatal("no private half recorded for this signer")
	}

	private, ok := value.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("the recorded private half is the wrong type")
	}

	return private
}

func emptyKnownHosts(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	return path
}

// ssh names four known_hosts files by default and most of them are normally
// absent: `known_hosts2` has not existed since SSH 1, and a machine with no
// /etc/ssh/ssh_known_hosts is the ordinary machine. Passing ssh's list straight
// to knownhosts.New failed on the first missing one, so a correctly configured
// box could not probe anything — found against a real server, not a test.
func TestProbeToleratesKnownHostsFilesThatDoNotExist(t *testing.T) {
	key := generateKey(t)
	server := startServer(t, key.PublicKey())
	agent := startAgent(t, key)

	cfg := server.config(t)
	cfg.KnownHostsFiles = append([]string{
		"/etc/ssh/ssh_known_hosts",
		filepath.Join(t.TempDir(), "known_hosts2"),
	}, cfg.KnownHostsFiles...)

	if _, err := sshprobe.ProbeWith(
		t.Context(), agent, cfg, "test-host", 5*time.Second); err != nil {
		t.Fatalf("probe: %v", err)
	}
}

// With none of them present there is nothing to check the server against, and
// that is an error rather than a host accepted by default.
func TestProbeRefusesWhenThereIsNoKnownHostsFileAtAll(t *testing.T) {
	key := generateKey(t)
	server := startServer(t, key.PublicKey())
	agent := startAgent(t, key)

	cfg := server.config(t)
	cfg.KnownHostsFiles = []string{filepath.Join(t.TempDir(), "absent")}

	_, err := sshprobe.ProbeWith(
		t.Context(), agent, cfg, "test-host", 5*time.Second)
	if err == nil {
		t.Fatal("a host was accepted with nothing to check it against")
	}

	if !strings.Contains(err.Error(), "nothing to check") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// Which host key the login is bound to is the client's choice, not the
// server's, so the probe has to make the same choice ssh would. x/crypto's
// default order is not ssh's: against a server offering both, this took the
// ECDSA key where ssh takes ed25519, and the promise built on it covered no
// login at all while reporting success. Found against a real server.
func TestProbeNegotiatesTheHostKeySshWouldChoose(t *testing.T) {
	key := generateKey(t)
	agent := startAgent(t, key)

	// A server offering an ed25519 host key and an ECDSA one, as GitHub does.
	server := startServer(t, key.PublicKey())
	ecdsa := generateECDSAKey(t)
	server.addHostKey(ecdsa)

	cfg := server.config(t)
	cfg.KnownHostsFiles = []string{
		server.knownHostsWith(t, server.hostKey.PublicKey(), ecdsa.PublicKey()),
	}
	// ssh's configured order: ed25519 ahead of ecdsa.
	cfg.HostKeyAlgorithms = []string{"ssh-ed25519", "ecdsa-sha2-nistp256"}

	result, err := sshprobe.ProbeWith(
		t.Context(), agent, cfg, "test-host", 5*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	if got := result.HostKey.Type(); got != "ssh-ed25519" {
		t.Errorf("the probe bound to a %s host key; ssh would have taken "+
			"ssh-ed25519, so the promise would cover nothing", got)
	}
}

func generateECDSAKey(t *testing.T) ssh.Signer {
	t.Helper()

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate an ECDSA key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("make an ECDSA signer: %v", err)
	}

	return signer
}
