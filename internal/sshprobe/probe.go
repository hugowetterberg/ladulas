// Package sshprobe finds out what a login to a server would look like, without
// making one.
//
// A promise made ahead of a login has to be scoped to exactly what that login
// will derive — the same key, the same user name, the same host key — because
// the grant is matched on strict equality of all three (pkg/approval.covers).
// A promise built from a guess is not a weaker promise, it is one that silently
// covers nothing: the login prompts anyway and the grant sits in the list until
// it expires, looking like it should have worked.
//
// Two of those facts cannot be guessed from this side. The user name comes out
// of ssh's own configuration resolution, which has Match blocks and per-host
// overrides in it. The key is whichever identity the *server* accepts, which is
// a fact about the server's authorized_keys and not about us — with three keys
// in the agent, picking the wrong one is the ordinary case rather than the
// unlucky one.
//
// So this asks. It costs a TCP connection and a key exchange, and nothing is
// signed: RFC 4252 §7 lets a client offer a public key with has_signature
// false, and the server answers SSH_MSG_USERAUTH_PK_OK if that key would be
// accepted. That is what ssh itself does before it asks an agent for anything,
// and it is why an approval prompt does not go up while this runs.
package sshprobe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Result is what a login to the destination would be made of.
type Result struct {
	// PublicKey is the identity the server said it would accept.
	PublicKey ssh.PublicKey
	// Username is the user the login would authenticate as.
	Username string
	// HostKey is the server's host key, already checked against known_hosts.
	HostKey ssh.PublicKey
	// Label is what to call the destination on a card: what the user typed,
	// which is also what they will recognise.
	Label string
	// Address is the host:port actually dialled, for the error messages.
	Address string
}

// Config is ssh's own answer to "what would you do with this destination".
type Config struct {
	User            string
	HostName        string
	Port            string
	KnownHostsFiles []string
	// HostKeyAlgorithms is ssh's configured preference order. It matters more
	// than it looks: a server offers several host keys and the *client's* order
	// decides which one the login ends up bound to, so a probe that negotiates
	// a different one from ssh learns a fingerprint no login will ever present.
	HostKeyAlgorithms []string
}

// ErrNoAcceptedKey is returned when the server refused every identity the agent
// offers. It is not a failure of the probe: it is the answer, and it means a
// promise would be about a login that cannot succeed anyway.
var ErrNoAcceptedKey = errors.New(
	"the server accepted none of the keys the agent offers")

// errAccepted aborts the handshake the moment the server has told us what we
// came to find out. It travels back out of ssh.Dial wrapped in the client's own
// error, which is why the caller matches on it with errors.Is rather than on
// what Dial says.
var errAccepted = errors.New("sshprobe: key accepted")

// ResolveConfig asks ssh what it would do with this destination, rather than
// reading ~/.ssh/config here.
//
// `ssh -G` runs the whole resolution — Match blocks, Host patterns, includes,
// the system file, the defaults — and prints the result. Reimplementing any of
// that would mean a promise scoped to a user name ssh does not agree with, and
// the failure would be invisible: the grant would simply never match.
func ResolveConfig(ctx context.Context, destination string) (Config, error) {
	out, err := exec.CommandContext(
		ctx, "ssh", "-G", destination).Output() //nolint:gosec // the destination is the user's own argument
	if err != nil {
		return Config{}, fmt.Errorf(
			"ask ssh how it would connect to %s: %w", destination, err)
	}

	cfg := Config{Port: "22"}

	for line := range strings.Lines(string(out)) {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}

		switch key {
		case "user":
			cfg.User = value
		case "hostname":
			cfg.HostName = value
		case "port":
			cfg.Port = value
		case "hostkeyalgorithms":
			cfg.HostKeyAlgorithms = strings.Split(value, ",")
		case "userknownhostsfile", "globalknownhostsfile":
			cfg.KnownHostsFiles = append(
				cfg.KnownHostsFiles, strings.Fields(value)...)
		}
	}

	if cfg.HostName == "" {
		return Config{}, fmt.Errorf(
			"ssh resolved no hostname for %s", destination)
	}

	if cfg.User == "" {
		return Config{}, fmt.Errorf(
			"ssh resolved no user name for %s", destination)
	}

	return cfg, nil
}

// Probe connects to the destination and returns what a login would look like.
//
// The host key is verified against the known_hosts files ssh would use, and an
// unknown host is refused rather than shown to somebody to decide on. That is
// the whole security of this: the fingerprint learned here becomes the scope of
// a promise, so a probe that accepted any host key would let a machine in the
// middle name itself as the destination of a grant. Refusing costs a real ssh
// login first, which is a step somebody takes once per host and which puts the
// fingerprint in front of them at the moment ssh is designed to.
func Probe(
	ctx context.Context, agentSocket, destination string, timeout time.Duration,
) (*Result, error) {
	cfg, err := ResolveConfig(ctx, destination)
	if err != nil {
		return nil, err
	}

	return ProbeWith(ctx, agentSocket, cfg, destination, timeout)
}

// ProbeWith is Probe with the configuration already resolved. It is the seam a
// test uses, because `ssh -G` reads the machine's own configuration and a test
// that went through it would be testing this box.
func ProbeWith(
	ctx context.Context,
	agentSocket string,
	cfg Config,
	label string,
	timeout time.Duration,
) (*Result, error) {
	identities, err := agentIdentities(agentSocket)
	if err != nil {
		return nil, err
	}

	if len(identities) == 0 {
		return nil, errors.New(
			"the agent offers no keys, so there is nothing a login could use")
	}

	// ssh names four known_hosts files by default and expects most of them to
	// be missing — `known_hosts2` has not existed since SSH 1, and a machine
	// with no /etc/ssh/ssh_known_hosts is the ordinary machine. knownhosts.New
	// fails on the first one it cannot open, so passing ssh's list straight
	// through refuses every host on a box that is configured correctly.
	present := existingFiles(cfg.KnownHostsFiles)
	if len(present) == 0 {
		return nil, fmt.Errorf(
			"none of the known_hosts files ssh would read exist (%s), so "+
				"there is nothing to check the server's key against",
			strings.Join(cfg.KnownHostsFiles, ", "))
	}

	hostKeys, err := knownhosts.New(present...)
	if err != nil {
		return nil, fmt.Errorf("read the known_hosts files: %w", err)
	}

	address := net.JoinHostPort(cfg.HostName, cfg.Port)

	var (
		accepted ssh.PublicKey
		hostKey  ssh.PublicKey
	)

	signers := make([]ssh.Signer, 0, len(identities))

	for _, id := range identities {
		signers = append(signers, &probeSigner{
			pub: id,
			onSign: func(pub ssh.PublicKey) {
				accepted = pub
			},
		})
	}

	// Which host key the login ends up bound to is the *client's* choice, not
	// the server's: a server offers several and the client's preference order
	// picks one. x/crypto's default order is not ssh's, so without this the
	// probe learns a fingerprint no real login will ever present — against
	// GitHub it took the ECDSA key where ssh takes ed25519, and the promise
	// that came out of it covered nothing. That is the exact failure this whole
	// command exists to avoid, and it was invisible: everything reported
	// success.
	//
	// The order offered is ssh's configured one, narrowed to the types
	// known_hosts actually holds for this host. Narrowing is what makes the two
	// agree — it is OpenSSH's own `order_hostkeyalgs`, which hoists the types it
	// has entries for — and it is safe here because a host with no entry is
	// refused a few lines above either way.
	algorithms := hostKeyAlgorithms(hostKeys, cfg.HostKeyAlgorithms, address)

	client, err := dial(ctx, address, timeout, &ssh.ClientConfig{
		User:              cfg.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyAlgorithms: algorithms,
		HostKeyCallback: func(
			hostname string, remote net.Addr, key ssh.PublicKey,
		) error {
			// Recorded before the check rather than after, so that a refusal can
			// name the fingerprint it refused — which is the one thing somebody
			// looking at an unknown-host error needs.
			hostKey = key

			return hostKeys(hostname, remote, key)
		},
		Timeout: timeout,
	})
	if client != nil {
		// Only reachable if the server accepted a login with no signature at
		// all, which no server does. Closed rather than left to the garbage
		// collector, because this one is a real authenticated connection.
		_ = client.Close()
	}

	switch {
	case accepted != nil && errors.Is(err, errAccepted):
		return &Result{
			PublicKey: accepted,
			Username:  cfg.User,
			HostKey:   hostKey,
			Label:     label,
			Address:   address,
		}, nil
	case err == nil:
		return nil, errors.New(
			"the server authenticated the connection without a signature, " +
				"which is not something to make a promise about")
	}

	return nil, probeError(err, hostKey, address)
}

// probeError turns what the ssh client says into what the person running this
// needs to do about it.
func probeError(err error, hostKey ssh.PublicKey, address string) error {
	var keyErr *knownhosts.KeyError

	if errors.As(err, &keyErr) {
		if len(keyErr.Want) == 0 {
			return fmt.Errorf(
				"%s is not in known_hosts, and its key is %s.\n"+
					"A promise is scoped to the host key learned here, so this "+
					"will not guess at one. Log in with ssh once — it will ask "+
					"you about this fingerprint — and run this again",
				address, fingerprint(hostKey))
		}

		return fmt.Errorf(
			"the host key for %s does not match known_hosts: it offered %s. "+
				"This is what ssh would refuse, and for the same reason",
			address, fingerprint(hostKey))
	}

	// x/crypto reports every exhausted method the same way, and by this point
	// the interesting case is the ordinary one: no key of ours is in the
	// server's authorized_keys.
	if strings.Contains(err.Error(), "unable to authenticate") {
		return fmt.Errorf("%w (%s)", ErrNoAcceptedKey, address)
	}

	return fmt.Errorf("probe %s: %w", address, err)
}

func fingerprint(key ssh.PublicKey) string {
	if key == nil {
		return "unknown"
	}

	return ssh.FingerprintSHA256(key)
}

// dial makes the connection cancellable, which ssh.Dial on its own is not.
func dial(
	ctx context.Context, address string, timeout time.Duration,
	config *ssh.ClientConfig,
) (*ssh.Client, error) {
	dialer := net.Dialer{Timeout: timeout}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", address, err)
	}

	client, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()

		return nil, err
	}

	return ssh.NewClient(client, chans, reqs), nil
}

// agentIdentities reads the public halves the agent advertises. It is a List
// and nothing else: asking the agent for signers would give us signers that
// really sign, and the first one used would raise the approval prompt this
// command exists to ask for in advance.
func agentIdentities(socket string) ([]ssh.PublicKey, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connect to the agent at %s: %w", socket, err)
	}

	defer conn.Close()

	keys, err := sshagent.NewClient(conn).List()
	if err != nil {
		return nil, fmt.Errorf("list the agent's keys: %w", err)
	}

	out := make([]ssh.PublicKey, 0, len(keys))
	for _, key := range keys {
		out = append(out, key)
	}

	return out, nil
}

// probeSigner offers a public key and refuses to sign with it.
//
// x/crypto calls Sign only after the server has answered SSH_MSG_USERAUTH_PK_OK
// for that key, so Sign being reached at all is the server saying yes — and
// returning an error from it both records the answer and stops the handshake
// before anything is signed. That ordering is the whole trick, and it is worth
// knowing that it is x/crypto's ordering rather than a rule of the protocol: a
// client is permitted to skip the query and sign straight away, and one that
// did would need this written differently.
type probeSigner struct {
	pub    ssh.PublicKey
	onSign func(ssh.PublicKey)
}

var (
	_ ssh.Signer          = (*probeSigner)(nil)
	_ ssh.AlgorithmSigner = (*probeSigner)(nil)
)

func (p *probeSigner) PublicKey() ssh.PublicKey {
	return p.pub
}

func (p *probeSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	p.onSign(p.pub)

	return nil, errAccepted
}

// SignWithAlgorithm makes this an AlgorithmSigner, which matters for RSA:
// without it x/crypto offers an RSA key as "ssh-rsa", every server built this
// decade refuses that, and the probe would report the key as unaccepted when
// the real ssh — which does negotiate rsa-sha2-512 — logs in with it happily.
func (p *probeSigner) SignWithAlgorithm(
	io.Reader, []byte, string,
) (*ssh.Signature, error) {
	p.onSign(p.pub)

	return nil, errAccepted
}

// existingFiles keeps the known_hosts files that are actually there. An
// unreadable one is kept rather than skipped: that is a permissions problem
// worth an error, where a missing one is ssh's normal state.
func existingFiles(paths []string) []string {
	var out []string

	for _, path := range paths {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}

		out = append(out, path)
	}

	return out
}

// hostKeyAlgorithms is ssh's preference order narrowed to the host key types
// known_hosts holds for this address.
//
// Returning nil leaves x/crypto's own default in place, which is the right
// fallback for a host we know nothing about — the connection is going to be
// refused by the callback anyway, and a refusal that names the key it saw is
// more use than a negotiation failure that names none.
func hostKeyAlgorithms(
	callback ssh.HostKeyCallback, configured []string, address string,
) []string {
	known := knownHostKeyTypes(callback, address)
	if len(known) == 0 || len(configured) == 0 {
		return nil
	}

	var out []string

	for _, algorithm := range configured {
		if slices.Contains(known, algorithm) {
			out = append(out, algorithm)
		}
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

// knownHostKeyTypes asks the known_hosts callback what it holds for a host, by
// offering it a key it cannot match and reading the answer out of the
// complaint: a KeyError for a host that *is* known lists the keys it wanted
// instead. x/crypto has no accessor for this as of v0.54.0.
//
// The probe key is freshly generated so that it cannot collide with a real
// entry. An unknown host produces a KeyError with nothing in Want, which is
// reported as "no known types" and falls back to the default order.
func knownHostKeyTypes(callback ssh.HostKeyCallback, address string) []string {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}

	probe, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		return nil
	}

	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		addr = &net.TCPAddr{}
	}

	err = callback(address, addr, probe)

	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		return nil
	}

	types := make([]string, 0, len(keyErr.Want))

	for _, want := range keyErr.Want {
		if algorithm := want.Key.Type(); !slices.Contains(types, algorithm) {
			types = append(types, algorithm)
		}
	}

	return types
}
