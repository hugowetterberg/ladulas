package localapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	"github.com/hugowetterberg/ladulas/pkg/peercred"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// maxRequestBytes caps a submission. A commit object is tiny; the diff that
// travels with it is what has any size, and gitctx caps that at a megabyte
// before it is sent. Eight leaves room for the encoding and for nothing else.
const maxRequestBytes = 8 << 20

// KeyStore is the subset of the encrypted store the local service needs. It is
// the same shape the agent uses, and the vault satisfies both.
type KeyStore interface {
	KeyRefs() []*ladulasv1.KeyRef
	Signer(fingerprint string) (ssh.Signer, *storepb.StoredKey, error)
}

// Approver decides requests. The approval engine implements it.
type Approver interface {
	SubmitSigned(
		ctx context.Context, req *ladulasv1.ApprovalRequest,
	) (*ladulasv1.ApprovalResponse, *ladulasv1.SignedApproval, error)
}

// RemoteKeys is the keys that live on paired holders, and the way to have one
// used (§3). The same seam the agent has, for the same reason: ladulas-sign on
// a keyless box should get a rich prompt on somebody else's screen rather than
// a fallback to ssh-keygen and a key that is not there either.
type RemoteKeys interface {
	RemoteKeyRefs() []*ladulasv1.KeyRef
	// RefreshKeys asks the holders again, for the moment a key was granted a
	// second ago and the cached answer is out of date.
	RefreshKeys(ctx context.Context)
	// BorrowedKey finds a key a paired holder has offered at some point, so
	// that a commit signed with a key on a sleeping phone fails saying whose
	// phone it is (decision N).
	BorrowedKey(blob []byte) (*ladulasv1.KeyRef, bool)
	RemoteSign(
		ctx context.Context,
		req *ladulasv1.ApprovalRequest,
		payload []byte,
		wrapSSHSIG bool,
	) (*ladulasv1.RemoteSignResponse, error)
}

// Options configures the server.
type Options struct {
	// SocketPath defaults to DefaultSocketPath().
	SocketPath string
	// Keys is the store to sign with.
	Keys KeyStore
	// Approver decides every request.
	Approver Approver
	// Remote is the keys paired holders offer, and the way to have one used.
	// Optional.
	Remote RemoteKeys
	// Identity describes this instance as a requester. Optional.
	Identity func() *ladulasv1.RequesterInfo
	// OnSigned records that a signature was produced, for the audit log.
	OnSigned func(req *ladulasv1.ApprovalRequest, key *ladulasv1.KeyRef)
	// Control is the peer and pairing surface the command line drives. Optional:
	// an instance with peering switched off does not mount it, and the command
	// line says so rather than failing at a call.
	Control ladulasv1connect.ControlServiceHandler
	// AllowUID is the uid allowed to connect. Zero value means the uid this
	// process runs as, which is what anything but a test wants.
	AllowUID *uint32
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Server serves the local connect-go services.
type Server struct {
	socketPath string
	keys       KeyStore
	approver   Approver
	remote     RemoteKeys
	identityFn func() *ladulasv1.RequesterInfo
	onSigned   func(*ladulasv1.ApprovalRequest, *ladulasv1.KeyRef)
	control    ladulasv1connect.ControlServiceHandler
	allowUID   uint32
	log        *slog.Logger

	mu       sync.Mutex
	listener net.Listener
	http     *http.Server

	closeOnce sync.Once
}

// New creates a server. It does not listen; call Listen.
func New(opts Options) (*Server, error) {
	if opts.Keys == nil {
		return nil, errors.New("localapi: no key store")
	}

	if opts.Approver == nil {
		return nil, errors.New("localapi: no approver")
	}

	socketPath := opts.SocketPath
	if socketPath == "" {
		socketPath = DefaultSocketPath()
	}

	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	identityFn := opts.Identity
	if identityFn == nil {
		identityFn = func() *ladulasv1.RequesterInfo {
			return &ladulasv1.RequesterInfo{Local: true}
		}
	}

	allowUID := uint32(os.Getuid()) //nolint:gosec // a uid fits a uint32 by definition
	if opts.AllowUID != nil {
		allowUID = *opts.AllowUID
	}

	return &Server{
		socketPath: socketPath,
		keys:       opts.Keys,
		approver:   opts.Approver,
		remote:     opts.Remote,
		identityFn: identityFn,
		onSigned:   opts.OnSigned,
		control:    opts.Control,
		allowUID:   allowUID,
		log:        log,
	}, nil
}

// SocketPath is the path the service listens on.
func (s *Server) SocketPath() string {
	return s.socketPath
}

// Listen creates the socket.
func (s *Server) Listen() error {
	listener, err := listen(s.socketPath)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()

	return nil
}

// Handler builds the HTTP handler the service is served over. It is exported
// because it is also what a test — and, later, an embedder — can serve however
// it likes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	path, handler := ladulasv1connect.NewSigningServiceHandler(
		&signingService{server: s},
		connect.WithReadMaxBytes(maxRequestBytes))

	mux.Handle(path, handler)

	if s.control != nil {
		controlPath, controlHandler := ladulasv1connect.NewControlServiceHandler(
			s.control, connect.WithReadMaxBytes(maxRequestBytes))

		mux.Handle(controlPath, controlHandler)
	}

	return mux
}

// Serve accepts connections until the context is done or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	listener := s.listener
	s.mu.Unlock()

	if listener == nil {
		if err := s.Listen(); err != nil {
			return err
		}

		s.mu.Lock()
		listener = s.listener
		s.mu.Unlock()
	}

	server := &http.Server{
		Handler: s.Handler(),
		// The request body arrives in one go; the long wait is the approval,
		// which happens after the handler has read everything.
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return withPeer(ctx, c)
		},
	}

	s.mu.Lock()
	s.http = server
	s.mu.Unlock()

	stop := context.AfterFunc(ctx, func() {
		_ = s.Close()
	})
	defer stop()

	s.log.Info("local signing service listening", "socket", s.socketPath)

	err := server.Serve(&guardListener{
		Listener: listener,
		allowUID: s.allowUID,
		log:      s.log,
	})
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("serve the local signing service: %w", err)
	}

	return nil
}

// Close stops serving and removes the socket.
func (s *Server) Close() error {
	var err error

	s.closeOnce.Do(func() {
		s.mu.Lock()
		server := s.http
		listener := s.listener
		s.mu.Unlock()

		if server != nil {
			err = server.Close()
		} else if listener != nil {
			err = listener.Close()
		}

		if listener == nil {
			return
		}

		if removeErr := os.Remove(s.socketPath); removeErr != nil &&
			!errors.Is(removeErr, os.ErrNotExist) {
			s.log.Debug("could not remove the socket", "error", removeErr.Error())
		}
	})

	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close the local signing service: %w", err)
	}

	return nil
}

// signingService implements ladulasv1connect.SigningServiceHandler.
type signingService struct {
	ladulasv1connect.UnimplementedSigningServiceHandler

	server *Server
}

// SignPayload is §5's design detail in code: the caller sends the raw message,
// this side builds the SSHSIG wrapper, and the approver therefore has the whole
// commit object rather than the digest an agent would see.
func (s *signingService) SignPayload(
	ctx context.Context, req *connect.Request[ladulasv1.SignPayloadRequest],
) (*connect.Response[ladulasv1.SignPayloadResponse], error) {
	msg := req.Msg

	if len(msg.GetPayload()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("nothing to sign"))
	}

	namespace := msg.GetNamespace()
	if namespace == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("no SSHSIG namespace"))
	}

	key, local, err := s.server.findKey(ctx, msg.GetPublicKey())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	blob, err := sshsig.SigningBlobFor(namespace, msg.GetHashAlgorithm(), msg.GetPayload())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	approvalRequest := s.server.buildRequest(ctx, msg, key, blob)

	if !local {
		return s.signRemotely(ctx, msg, approvalRequest, key)
	}

	resp, signed, err := s.server.approver.SubmitSigned(ctx, approvalRequest)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("approval: %w", err))
	}

	out := &ladulasv1.SignPayloadResponse{
		RequestId: approvalRequest.GetRequestId(),
		Approved:  resp.GetDecision() == ladulasv1.Decision_DECISION_APPROVE,
		Source:    resp.GetSource(),
		Reason:    resp.GetReason(),
		Approval:  signed,
	}

	if !out.GetApproved() {
		return connect.NewResponse(out), nil
	}

	signer, _, err := s.server.keys.Signer(key.GetFingerprint())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("load key: %w", err))
	}

	inner, err := sshsig.SignBlob(signer, blob)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	signature := &sshsig.Signature{
		PublicKey:     signer.PublicKey(),
		Namespace:     namespace,
		HashAlgorithm: sshsig.NormaliseHash(msg.GetHashAlgorithm()),
		Signature:     inner,
	}

	out.ArmoredSignature = signature.Armored()

	s.server.signed(approvalRequest, key)

	return connect.NewResponse(out), nil
}

// signRemotely has the key's holder produce the signature (§3).
//
// The raw payload crosses the channel and the holder builds the SSHSIG wrapper
// itself, which is the same shape as the local path and for the same reason:
// the approver should have the commit object rather than a digest, and should
// derive it from the bytes it is about to sign (§5). The armour is assembled
// here because the holder returns the inner signature and this side already
// knows the key, the namespace and the hash it asked for.
func (s *signingService) signRemotely(
	ctx context.Context,
	msg *ladulasv1.SignPayloadRequest,
	req *ladulasv1.ApprovalRequest,
	key *ladulasv1.KeyRef,
) (*connect.Response[ladulasv1.SignPayloadResponse], error) {
	resp, err := s.server.remote.RemoteSign(ctx, req, msg.GetPayload(), true)
	if err != nil {
		return nil, connect.NewError(remoteSignCode(s.server.remote, key),
			fmt.Errorf("remote signing: %w", err))
	}

	decision, _, err := identity.VerifyApproval(resp.GetApproval())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("remote signing: %w", err))
	}

	out := &ladulasv1.SignPayloadResponse{
		RequestId: req.GetRequestId(),
		Approved:  decision.GetDecision() == ladulasv1.Decision_DECISION_APPROVE,
		Source:    decision.GetSource(),
		Reason:    decision.GetReason(),
		Approval:  resp.GetApproval(),
	}

	if !out.GetApproved() {
		return connect.NewResponse(out), nil
	}

	pub, err := ssh.ParsePublicKey(key.GetPublicKey())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("parse the borrowed key: %w", err))
	}

	var inner ssh.Signature

	if err := ssh.Unmarshal(resp.GetSignature(), &inner); err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("remote signing: parse the signature: %w", err))
	}

	signature := &sshsig.Signature{
		PublicKey:     pub,
		Namespace:     msg.GetNamespace(),
		HashAlgorithm: sshsig.NormaliseHash(msg.GetHashAlgorithm()),
		Signature:     &inner,
	}

	out.ArmoredSignature = signature.Armored()

	s.server.signed(req, key)

	return connect.NewResponse(out), nil
}

// remoteSignCode decides whether ladulas-sign should fall back to ssh-keygen
// when a borrowed signature could not be had.
//
// Unavailable means "there may be another way to this key", and for a key this
// instance has never heard of that is true: a real agent may well hold it, and
// that fallback is what §5 promises. For a key a paired holder is known to have
// it is false and actively misleading — the private half is in somebody else's
// store or somebody else's Secure Enclave, ssh-keygen cannot reach it either,
// and handing over buries the one sentence worth reading under whatever
// ssh-keygen says about a socket (decision N).
func remoteSignCode(remote RemoteKeys, key *ladulasv1.KeyRef) connect.Code {
	if _, known := remote.BorrowedKey(key.GetPublicKey()); known {
		return connect.CodeFailedPrecondition
	}

	return connect.CodeUnavailable
}

// findKey resolves the key a caller named, and says whether it is one this
// instance can sign with itself.
func (s *Server) findKey(
	ctx context.Context, blob []byte,
) (*ladulasv1.KeyRef, bool, error) {
	if len(blob) == 0 {
		return nil, false, errors.New("no key was named")
	}

	// KeyRefs leaves out disabled keys, so a key that is in the store but
	// switched off looks the same as one that was never there. That is the
	// right answer: the caller falls back to ssh-keygen either way.
	for _, ref := range s.keys.KeyRefs() {
		if bytes.Equal(ref.GetPublicKey(), blob) {
			return ref, true, nil
		}
	}

	if s.remote != nil {
		if ref := findRemote(s.remote.RemoteKeyRefs(), blob); ref != nil {
			return ref, false, nil
		}

		// A key granted on the holder a moment ago is not in the cache yet, and
		// this is the moment it matters.
		s.remote.RefreshKeys(ctx)

		if ref := findRemote(s.remote.RemoteKeyRefs(), blob); ref != nil {
			return ref, false, nil
		}

		// Remembered but not reachable: hand the reference on so the signing
		// attempt says whose machine has the key (decision N).
		if ref, ok := s.remote.BorrowedKey(blob); ok {
			return ref, false, nil
		}
	}

	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, false, errors.New("the key is not one this instance holds")
	}

	return nil, false, fmt.Errorf(
		"no key %s here or on a paired instance", ssh.FingerprintSHA256(pub))
}

func findRemote(refs []*ladulasv1.KeyRef, blob []byte) *ladulasv1.KeyRef {
	for _, ref := range refs {
		if bytes.Equal(ref.GetPublicKey(), blob) {
			return ref
		}
	}

	return nil
}

// buildRequest turns a submission into an approval request.
//
// The git context arrives from the caller, and the one field this side takes
// away from it is the object: it is set from the payload rather than trusted,
// so that the check in the engine compares the bytes being signed against
// themselves and not against a claim (§5).
func (s *Server) buildRequest(
	ctx context.Context,
	msg *ladulasv1.SignPayloadRequest,
	key *ladulasv1.KeyRef,
	blob []byte,
) *ladulasv1.ApprovalRequest {
	digest, _ := sshsig.Hash(msg.GetHashAlgorithm(), msg.GetPayload())
	payloadDigest := sha256.Sum256(blob)

	kind := ladulasv1.RequestKind_REQUEST_KIND_SSHSIG
	if msg.GetNamespace() == sshsig.GitNamespace {
		kind = ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN
	}

	git := msg.GetGitContext()

	if kind == ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN {
		if git == nil {
			git = &ladulasv1.GitContext{}
		}

		git.Object = msg.GetPayload()
	} else {
		// A signature in some other namespace is not a git object and must not
		// be dressed up as one.
		git = nil
	}

	requester := s.requesterInfo()
	requester.Local = true
	requester.Process = peerFrom(ctx)

	return &ladulasv1.ApprovalRequest{
		RequestId:     identity.NewRequestID(),
		CreatedAt:     timestamppb.Now(),
		Requester:     requester,
		Kind:          kind,
		Key:           key,
		Timeout:       msg.GetTimeout(),
		PayloadSha256: payloadDigest[:],
		Operation: &ladulasv1.ApprovalRequest_Sshsig{
			Sshsig: &ladulasv1.SshsigRequest{
				Namespace:     msg.GetNamespace(),
				HashAlgorithm: sshsig.NormaliseHash(msg.GetHashAlgorithm()),
				MessageDigest: digest,
				GitContext:    git,
			},
		},
	}
}

func (s *Server) requesterInfo() *ladulasv1.RequesterInfo {
	info := s.identityFn()
	if info == nil {
		info = &ladulasv1.RequesterInfo{}
	}

	return info
}

func (s *Server) signed(req *ladulasv1.ApprovalRequest, key *ladulasv1.KeyRef) {
	s.log.Info("signed",
		"request_id", req.GetRequestId(),
		"kind", req.GetKind().String(),
		"key", key.GetLabel())

	if s.onSigned != nil {
		s.onSigned(req, key)
	}
}

// guardListener drops connections from another user before a single protocol
// byte is read. The socket permissions already say the same thing; this is the
// check that still holds when a directory has been left open by accident.
type guardListener struct {
	net.Listener

	allowUID uint32
	log      *slog.Logger
}

func (l *guardListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err //nolint:wrapcheck // http.Server inspects this error
		}

		proc, err := peercred.Process(conn)
		if err != nil {
			// Without peer credentials there is nothing to check against, and
			// the socket permissions are the whole of the access control.
			l.log.Debug("could not read peer credentials", "error", err.Error())

			return conn, nil
		}

		if proc.GetUid() == l.allowUID {
			return &peerConn{Conn: conn, process: proc}, nil
		}

		l.log.Warn("refused a local connection from another user",
			"uid", proc.GetUid(), "pid", proc.GetPid())

		_ = conn.Close()
	}
}

// peerConn carries the peer credentials from Accept to the request context.
type peerConn struct {
	net.Conn

	process *ladulasv1.ClientProcess
}

type peerContextKey struct{}

func withPeer(ctx context.Context, conn net.Conn) context.Context {
	pc, ok := conn.(*peerConn)
	if !ok {
		return ctx
	}

	return context.WithValue(ctx, peerContextKey{}, pc.process)
}

func peerFrom(ctx context.Context) *ladulasv1.ClientProcess {
	process, _ := ctx.Value(peerContextKey{}).(*ladulasv1.ClientProcess)

	return process
}
