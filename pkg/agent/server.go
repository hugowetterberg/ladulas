package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/hugowetterberg/ladulas/pkg/peercred"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Options configures the agent server.
type Options struct {
	// SocketPath is the unix socket to listen on. Defaults to
	// DefaultSocketPath().
	SocketPath string
	// Keys is the store to offer keys from.
	Keys KeyStore
	// Approver decides every sign request.
	Approver Approver
	// Remote is the keys paired holders offer, and the way to have one used.
	// Optional.
	Remote RemoteKeys
	// KnownHosts turns host keys into names. Optional.
	KnownHosts *KnownHosts
	// Identity describes this instance as a requester. Optional.
	Identity func() *ladulasv1.RequesterInfo
	// OnSigned is called after a signature was actually produced, for the audit
	// log. Optional.
	OnSigned func(req *ladulasv1.ApprovalRequest, key *ladulasv1.KeyRef)
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Server accepts agent connections and serves one connAgent per connection.
type Server struct {
	socketPath string
	keys       KeyStore
	approver   Approver
	remote     RemoteKeys
	knownHosts *KnownHosts
	identityFn func() *ladulasv1.RequesterInfo
	onSigned   func(*ladulasv1.ApprovalRequest, *ladulasv1.KeyRef)
	log        *slog.Logger

	// ctx is cancelled when the server is shutting down, and is what an
	// in-flight signature waits on. It is created in New so that connection
	// handlers can read it without synchronising against Serve.
	ctx    context.Context
	cancel context.CancelFunc

	// mu guards the listener, which Listen writes and Close reads.
	mu       sync.Mutex
	listener net.Listener

	wg        sync.WaitGroup
	closeOnce sync.Once
}

// DefaultSocketPath is where the agent listens unless told otherwise:
// $XDG_RUNTIME_DIR/ladulas/agent.sock, falling back to a directory under the
// user's home when there is no runtime directory.
func DefaultSocketPath() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "ladulas", "agent.sock")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "ladulas", "agent.sock")
	}

	return filepath.Join(home, ".ladulas", "agent.sock")
}

// New creates a server. It does not listen; call Listen.
func New(opts Options) (*Server, error) {
	if opts.Keys == nil {
		return nil, errors.New("agent: no key store")
	}

	if opts.Approver == nil {
		return nil, errors.New("agent: no approver")
	}

	socketPath := opts.SocketPath
	if socketPath == "" {
		socketPath = DefaultSocketPath()
	}

	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	knownHosts := opts.KnownHosts
	if knownHosts == nil {
		knownHosts = NewKnownHosts(DefaultKnownHostsPaths()...)
	}

	identityFn := opts.Identity
	if identityFn == nil {
		identityFn = func() *ladulasv1.RequesterInfo {
			return &ladulasv1.RequesterInfo{Local: true}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		socketPath: socketPath,
		keys:       opts.Keys,
		approver:   opts.Approver,
		remote:     opts.Remote,
		knownHosts: knownHosts,
		identityFn: identityFn,
		onSigned:   opts.OnSigned,
		log:        log,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// SocketPath returns the path the agent listens on, which is what
// SSH_AUTH_SOCK should be set to.
func (s *Server) SocketPath() string {
	return s.socketPath
}

// Listen creates the socket. It is separate from Serve so that a caller can
// export SSH_AUTH_SOCK before anything tries to use it.
func (s *Server) Listen() error {
	dir := filepath.Dir(s.socketPath)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}

	// A socket left behind by a crashed process would make Listen fail, but
	// removing one that a live agent is using would hijack it. Probe first.
	if err := s.clearStaleSocket(); err != nil {
		return err
	}

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.socketPath, err)
	}

	if err := os.Chmod(s.socketPath, 0o600); err != nil {
		_ = listener.Close()

		return fmt.Errorf("restrict socket permissions: %w", err)
	}

	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()

	return nil
}

func (s *Server) clearStaleSocket() error {
	info, err := os.Stat(s.socketPath)

	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("inspect socket path: %w", err)
	case info.Mode()&os.ModeSocket == 0:
		return fmt.Errorf("%s exists and is not a socket", s.socketPath)
	}

	conn, dialErr := net.Dial("unix", s.socketPath)
	if dialErr == nil {
		_ = conn.Close()

		return fmt.Errorf("an agent is already listening on %s", s.socketPath)
	}

	if err := os.Remove(s.socketPath); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	return nil
}

// Serve accepts connections until the context is cancelled or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	listener := s.currentListener()

	if listener == nil {
		if err := s.Listen(); err != nil {
			return err
		}

		listener = s.currentListener()
	}

	// The caller's context is linked to the server's rather than replacing it,
	// so nothing has to write s.ctx after construction.
	stop := context.AfterFunc(ctx, s.cancel)
	defer stop()

	go func() {
		<-s.ctx.Done()

		_ = listener.Close()
	}()

	s.log.Info("ssh agent listening", "socket", s.socketPath)

	err := s.acceptLoop(listener)

	// Connections in flight get to finish; a signature the user has already
	// approved should not be lost to a shutdown.
	s.wg.Wait()

	if s.shuttingDown(err) {
		return nil
	}

	return err
}

func (s *Server) currentListener() net.Listener {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.listener
}

func (s *Server) acceptLoop(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.shuttingDown(err) {
				return err
			}

			// A transient accept failure — out of file descriptors, say — is
			// not a reason to stop being an agent.
			s.log.Warn("accept failed", "error", err.Error())

			continue
		}

		s.wg.Add(1)

		go func() {
			defer s.wg.Done()

			s.handle(conn)
		}()
	}
}

// shuttingDown reports whether an accept error is the listener being closed on
// purpose rather than something going wrong.
func (s *Server) shuttingDown(err error) bool {
	return s.ctx.Err() != nil || errors.Is(err, net.ErrClosed)
}

func (s *Server) handle(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	peer, err := peercred.Process(conn)
	if err != nil {
		s.log.Debug("could not read peer credentials", "error", err.Error())
	}

	c := &connAgent{server: s, peer: peer}

	// ServeAgent returns when the connection closes, which is an ordinary EOF
	// rather than a problem — and it never returns nil, because the only way
	// out of its loop is a read that failed. So what is sorted here is which
	// kind of ending it was; the `err != nil` that used to be in front of this
	// was a comparison that could not be false, which is what staticcheck's
	// SA4023 is for. The value is handed to the logger rather than its
	// Error(), so that a future version of x/crypto returning nil is a line
	// reading <nil> instead of a panic in the accept loop.
	if err := sshagent.ServeAgent(c, conn); !errors.Is(err, io.EOF) {
		s.log.Debug("agent connection ended", "error", err)
	}
}

// Close stops serving and removes the socket.
//
// The socket is only removed when this server is the one that created it. A
// short-lived CLI command constructs a Server it never listens on — and must
// not take the running daemon's socket away when it exits.
func (s *Server) Close() error {
	var err error

	s.closeOnce.Do(func() {
		s.cancel()

		listener := s.currentListener()
		if listener == nil {
			return
		}

		err = listener.Close()

		if removeErr := os.Remove(s.socketPath); removeErr != nil &&
			!errors.Is(removeErr, os.ErrNotExist) {
			s.log.Debug("could not remove socket", "error", removeErr.Error())
		}
	})

	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close listener: %w", err)
	}

	return nil
}

func (s *Server) requesterInfo() *ladulasv1.RequesterInfo {
	info := s.identityFn()
	if info == nil {
		info = &ladulasv1.RequesterInfo{}
	}

	return info
}

func (s *Server) signed(req *ladulasv1.ApprovalRequest, key *ladulasv1.KeyRef) {
	s.log.Info("signed", slogAttrs(req)...)

	if s.onSigned != nil {
		s.onSigned(req, key)
	}
}
