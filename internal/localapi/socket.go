// Package localapi is the connect-go service an instance serves to the machine
// it runs on, over a unix socket (docs/architecture.md §5, §8).
//
// It exists so that ladulas-sign can hand over a whole commit object rather
// than a digest, which is what makes a rich git prompt possible. The transport
// is deliberately the same shape as the peer channel: the same protobuf schema,
// the same connect-go layer, a unix socket instead of pinned TLS. When M4 moves
// signing to a remote key holder, the request that crosses the network is the
// one that crosses this socket today.
package localapi

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// SocketEnv is the environment variable that overrides the socket path, so
// that ladulas-sign finds a daemon started with a non-default one.
const SocketEnv = "LADULAS_SOCK"

// DefaultSocketPath is where the local service listens: next to the agent
// socket, in the user's runtime directory.
func DefaultSocketPath() string {
	if path := os.Getenv(SocketEnv); path != "" {
		return path
	}

	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "ladulas", "control.sock")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "ladulas", "control.sock")
	}

	return filepath.Join(home, ".ladulas", "control.sock")
}

// listen creates the socket with the permissions that are the whole of its
// access control: a 0700 directory holding a 0600 socket, plus the peer uid
// check in guardListener. A process that can open it can already open the agent
// socket beside it, so there is nothing a token would add.
func listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}

	if err := clearStaleSocket(path); err != nil {
		return nil, err
	}

	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()

		return nil, fmt.Errorf("restrict socket permissions: %w", err)
	}

	return listener, nil
}

// clearStaleSocket removes a socket a crashed process left behind, but never
// one a live instance is using.
func clearStaleSocket(path string) error {
	info, err := os.Stat(path)

	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("inspect socket path: %w", err)
	case info.Mode()&os.ModeSocket == 0:
		return fmt.Errorf("%s exists and is not a socket", path)
	}

	conn, dialErr := net.Dial("unix", path)
	if dialErr == nil {
		_ = conn.Close()

		return fmt.Errorf("an instance is already listening on %s", path)
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	return nil
}
