package agent

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// KnownHosts turns a host key into something a human recognises.
//
// This is a reverse lookup — key to host names — which is the opposite of what
// known_hosts is normally used for, so the file is parsed directly rather than
// through x/crypto's HostKeyCallback machinery. Hashed entries (|1|salt|hash)
// cannot be reversed, so a key that only appears hashed is reported as known
// with no name, which is still worth saying in a prompt.
type KnownHosts struct {
	paths []string

	mu      sync.Mutex
	loaded  time.Time
	entries map[string][]string
	hashed  map[string]bool
}

// DefaultKnownHostsPaths are the files OpenSSH reads by default.
func DefaultKnownHostsPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	return []string{
		home + "/.ssh/known_hosts",
		home + "/.ssh/known_hosts2",
	}
}

// NewKnownHosts reads the given known_hosts files, reloading them when they
// change.
func NewKnownHosts(paths ...string) *KnownHosts {
	return &KnownHosts{paths: paths}
}

// reloadInterval bounds how often the files are re-read. Host keys change
// rarely and a stale name in a prompt is harmless; a re-parse per SSH
// connection is not.
const reloadInterval = 30 * time.Second

// Annotate fills in what known_hosts knows about a host key.
func (k *KnownHosts) Annotate(hostKey *ladulasv1.HostKey) {
	if k == nil || hostKey == nil {
		return
	}

	k.load()

	k.mu.Lock()
	defer k.mu.Unlock()

	// The conversion is written out at each lookup rather than kept in a
	// variable, which reads worse and allocates less: indexing a map with
	// `string(b)` is the one case the compiler is allowed to skip the copy for,
	// and it cannot do that for a string somebody named first.
	if names, ok := k.entries[string(hostKey.GetBlob())]; ok {
		hostKey.Known = true
		hostKey.KnownHostsNames = names

		return
	}

	if k.hashed[string(hostKey.GetBlob())] {
		hostKey.Known = true
	}
}

func (k *KnownHosts) load() {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.entries != nil && time.Since(k.loaded) < reloadInterval {
		return
	}

	entries := map[string][]string{}
	hashed := map[string]bool{}

	for _, path := range k.paths {
		body, err := os.ReadFile(path) //nolint:gosec // the path is configuration
		if err != nil {
			continue
		}

		parseKnownHosts(body, entries, hashed)
	}

	k.entries = entries
	k.hashed = hashed
	k.loaded = time.Now()
}

func parseKnownHosts(body []byte, entries map[string][]string, hashed map[string]bool) {
	rest := body

	for len(rest) > 0 {
		marker, hosts, pubKey, _, remainder, err := ssh.ParseKnownHosts(rest)
		if err != nil {
			// A single unparseable line should not cost us the rest of the file,
			// but ParseKnownHosts does not tell us where it stopped, so there is
			// nothing to do but give up on what remains.
			return
		}

		rest = remainder

		// @revoked and @cert-authority entries are not "this host has this key".
		if marker != "" {
			continue
		}

		blob := string(pubKey.Marshal())

		for _, host := range hosts {
			if strings.HasPrefix(host, "|1|") {
				hashed[blob] = true

				continue
			}

			entries[blob] = appendUnique(entries[blob], host)
		}
	}
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}

	return append(list, value)
}

// hostKeyMessage builds the wire representation of a host key, annotated from
// known_hosts.
func (k *KnownHosts) hostKeyMessage(pub ssh.PublicKey) *ladulasv1.HostKey {
	hostKey := &ladulasv1.HostKey{
		Blob:        pub.Marshal(),
		Algorithm:   pub.Type(),
		Fingerprint: ssh.FingerprintSHA256(pub),
	}

	k.Annotate(hostKey)

	return hostKey
}

// DisplayName is what a prompt should call a destination: the first
// known_hosts name if there is one, and the fingerprint otherwise.
func DisplayName(hostKey *ladulasv1.HostKey) string {
	if hostKey == nil {
		return "unknown destination"
	}

	if names := hostKey.GetKnownHostsNames(); len(names) > 0 {
		return names[0]
	}

	if hostKey.GetKnown() {
		return fmt.Sprintf("a known host (%s)", hostKey.GetFingerprint())
	}

	return fmt.Sprintf("unknown host (%s)", hostKey.GetFingerprint())
}
