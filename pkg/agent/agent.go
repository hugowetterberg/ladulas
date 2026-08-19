// Package agent is the SSH agent Ladulås presents to ssh, git and everything
// else that speaks the agent protocol (docs/architecture.md §4).
//
// It implements agent.ExtendedAgent rather than agent.Agent: SignWithFlags is
// required, because a plain Agent silently drops the SSH_AGENT_RSA_SHA2_*
// flags and breaks RSA keys, and Extension is how session-bind@openssh.com
// arrives. One agent instance is created per accepted socket connection, which
// is what makes the session-bind list per-connection state.
//
// Nothing here decides anything. Every sign request becomes an
// ApprovalRequest and goes to an Approver; the agent's job is to classify the
// request honestly and attach the context that makes the prompt worth reading.
package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// ErrMutationNotSupported is returned for every request that would change the
// agent's key set. Key management goes through Ladulås itself (§4).
var ErrMutationNotSupported = errors.New(
	"ladulas: the agent does not accept key management requests; use ladulas keys")

// ErrDenied is returned when a request was not approved. The text reaches the
// user through ssh's "agent refused operation".
var ErrDenied = errors.New("ladulas: request denied")

// Approver decides whether an operation may proceed. The approval engine
// implements it; the agent knows nothing about policies, prompts or peers.
type Approver interface {
	Submit(
		ctx context.Context, req *ladulasv1.ApprovalRequest,
	) (*ladulasv1.ApprovalResponse, error)
}

// KeyStore is the subset of the encrypted store the agent uses.
type KeyStore interface {
	// KeyRefs returns the public halves of the keys to offer.
	KeyRefs() []*ladulasv1.KeyRef
	// Signer returns a signer for a key, by fingerprint.
	Signer(fingerprint string) (ssh.Signer, *storepb.StoredKey, error)
}

// RemoteKeys is the keys that live on paired key holders, and the way to have
// one of them used (§3).
//
// It is what makes a completely keyless instance useful: the agent offers the
// holders' keys as though they were its own, and a sign request for one is
// carried to the machine that has it. Optional — an instance with peering
// switched off has none, and then the agent is exactly what M1 shipped.
type RemoteKeys interface {
	// RemoteKeyRefs returns the keys paired holders offer this instance.
	RemoteKeyRefs() []*ladulasv1.KeyRef
	// RefreshKeys asks the holders again, for the moment a key was granted a
	// second ago and the cached answer is out of date.
	RefreshKeys(ctx context.Context)
	// BorrowedKey finds a key a paired holder has offered at some point,
	// whether or not that holder can be reached now (decision N).
	//
	// It exists so that a request naming a key on a sleeping phone fails saying
	// so, rather than with "no such key" — which is simply untrue, and sends
	// somebody looking for a key that is exactly where they left it.
	BorrowedKey(blob []byte) (*ladulasv1.KeyRef, bool)
	// RemoteSign asks the holder of the request's key to produce the signature.
	// It is the holder that decides: this instance holds no key and has no
	// authority over one (§8).
	RemoteSign(
		ctx context.Context,
		req *ladulasv1.ApprovalRequest,
		payload []byte,
		wrapSSHSIG bool,
	) (*ladulasv1.RemoteSignResponse, error)
}

// connAgent serves one agent socket connection.
type connAgent struct {
	server *Server
	peer   *ladulasv1.ClientProcess

	mu    sync.Mutex
	binds bindings
}

var _ sshagent.ExtendedAgent = (*connAgent)(nil)

// List answers SSH_AGENTC_REQUEST_IDENTITIES with this instance's own keys and
// the ones its paired holders offer (§3).
//
// A key held here wins over a key of the same fingerprint offered by a peer,
// which is the sensible way round: signing locally needs nobody else to be
// awake. ssh sees one list and cannot tell the difference, which is the point.
//
// What is left out is a key whose holder has said it does not belong in an
// identity list (decision T). It can still be signed with; ssh is simply not
// handed it and told to try, because ssh tries everything it is handed and the
// server allows six attempts.
func (c *connAgent) List() ([]*sshagent.Key, error) {
	refs := c.server.advertised()

	out := make([]*sshagent.Key, 0, len(refs))

	for _, ref := range refs {
		out = append(out, &sshagent.Key{
			Format:  ref.GetAlgorithm(),
			Blob:    ref.GetPublicKey(),
			Comment: keyComment(ref),
		})
	}

	return out, nil
}

func keyComment(ref *ladulasv1.KeyRef) string {
	if c := ref.GetComment(); c != "" {
		return c
	}

	return ref.GetLabel()
}

// Sign implements agent.Agent. ServeAgent prefers SignWithFlags when the agent
// is an ExtendedAgent, so this is only reached by in-process callers.
func (c *connAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return c.SignWithFlags(key, data, 0)
}

// SignWithFlags is the whole point of the agent: classify, ask, and only then
// sign.
func (c *connAgent) SignWithFlags(
	key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags,
) (*ssh.Signature, error) {
	ref, local, err := c.findKey(key)
	if err != nil {
		return nil, err
	}

	req := c.buildRequest(ref, data, flags)

	ctx, cancel := context.WithCancel(c.server.ctx)
	defer cancel()

	if !local {
		return c.signRemotely(ctx, req, data, ref)
	}

	resp, err := c.server.approver.Submit(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("approval: %w", err)
	}

	if resp.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		reason := resp.GetReason()
		if reason == "" {
			reason = resp.GetSource().String()
		}

		return nil, fmt.Errorf("%w: %s", ErrDenied, reason)
	}

	signer, _, err := c.server.keys.Signer(ref.GetFingerprint())
	if err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}

	sig, err := signWithAlgorithm(signer, data, req.GetSignatureAlgorithm())
	if err != nil {
		return nil, err
	}

	c.server.signed(req, ref)

	return sig, nil
}

// signRemotely has the key's holder produce the signature.
//
// The request is not put to this instance's approval engine first. The holder
// runs the whole decision — the hard rules, its policy, its grants, its human —
// and asking here as well would put the same operation in front of two people
// and let the wrong one settle it (§8). What comes back is already checked
// against the paired identity and the bytes that were sent, so all that is left
// is to tell ssh yes or no.
func (c *connAgent) signRemotely(
	ctx context.Context,
	req *ladulasv1.ApprovalRequest,
	data []byte,
	ref *ladulasv1.KeyRef,
) (*ssh.Signature, error) {
	resp, err := c.server.remote.RemoteSign(ctx, req, data, false)
	if err != nil {
		return nil, fmt.Errorf("remote signing: %w", err)
	}

	decision, _, err := identity.VerifyApproval(resp.GetApproval())
	if err != nil {
		return nil, fmt.Errorf("remote signing: %w", err)
	}

	if decision.GetDecision() != ladulasv1.Decision_DECISION_APPROVE {
		reason := decision.GetReason()
		if reason == "" {
			reason = decision.GetSource().String()
		}

		return nil, fmt.Errorf("%w: %s", ErrDenied, reason)
	}

	var sig ssh.Signature

	if err := ssh.Unmarshal(resp.GetSignature(), &sig); err != nil {
		return nil, fmt.Errorf("remote signing: parse the signature: %w", err)
	}

	c.server.signed(req, ref)

	return &sig, nil
}

// allKeys is the store's keys followed by the ones paired holders offer, with
// anything already held here left out of the second list.
func (s *Server) allKeys() []*ladulasv1.KeyRef {
	local := s.keys.KeyRefs()

	if s.remote == nil {
		return local
	}

	out := make([]*ladulasv1.KeyRef, 0, len(local))
	out = append(out, local...)

	for _, ref := range s.remote.RemoteKeyRefs() {
		if !holdsKey(local, ref.GetPublicKey()) {
			out = append(out, ref)
		}
	}

	return out
}

// advertised is allKeys minus the ones their holder does not want handed to ssh
// (decision T).
//
// It is applied here rather than in the store or on the channel, because this is
// the only place the setting means anything: everything else that resolves a key
// resolves it by name or by blob, and would be broken by a filter rather than
// improved by one.
func (s *Server) advertised() []*ladulasv1.KeyRef {
	refs := s.allKeys()

	out := make([]*ladulasv1.KeyRef, 0, len(refs))

	for _, ref := range refs {
		if keystore.RefAgentUse(ref) {
			out = append(out, ref)
		}
	}

	return out
}

func findRemote(refs []*ladulasv1.KeyRef, blob []byte) *ladulasv1.KeyRef {
	for _, ref := range refs {
		if bytes.Equal(ref.GetPublicKey(), blob) {
			return ref
		}
	}

	return nil
}

func holdsKey(refs []*ladulasv1.KeyRef, blob []byte) bool {
	for _, ref := range refs {
		if bytes.Equal(ref.GetPublicKey(), blob) {
			return true
		}
	}

	return false
}

// findKey resolves the public key in a request, and says whether it is one this
// instance can sign with itself.
func (c *connAgent) findKey(key ssh.PublicKey) (*ladulasv1.KeyRef, bool, error) {
	blob := key.Marshal()

	for _, ref := range c.server.keys.KeyRefs() {
		if bytes.Equal(ref.GetPublicKey(), blob) {
			return ref, true, nil
		}
	}

	if c.server.remote != nil {
		if ref := findRemote(c.server.remote.RemoteKeyRefs(), blob); ref != nil {
			return ref, false, nil
		}

		// A key granted on the holder a moment ago is not in the cache yet, and
		// this is the moment it matters.
		c.server.remote.RefreshKeys(c.server.ctx)

		if ref := findRemote(c.server.remote.RemoteKeyRefs(), blob); ref != nil {
			return ref, false, nil
		}

		// Nobody is offering it right now, but this instance may well know
		// whose it is. Handing the remembered reference on means the attempt
		// fails naming the machine that has it (decision N) instead of claiming
		// the key does not exist.
		if ref, ok := c.server.remote.BorrowedKey(blob); ok {
			return ref, false, nil
		}
	}

	return nil, false, fmt.Errorf("ladulas: no key %s here or on a paired instance",
		ssh.FingerprintSHA256(key))
}

// buildRequest turns a sign request into an ApprovalRequest, attaching whatever
// the connection knows about where it is going.
func (c *connAgent) buildRequest(
	ref *ladulasv1.KeyRef, data []byte, flags sshagent.SignatureFlags,
) *ladulasv1.ApprovalRequest {
	class := Classify(data)
	digest := sha256.Sum256(data)

	req := &ladulasv1.ApprovalRequest{
		RequestId:          identity.NewRequestID(),
		CreatedAt:          timestamppb.Now(),
		Requester:          c.requesterInfo(),
		Kind:               class.Kind,
		Key:                ref,
		SignatureFlags:     uint32(flags),
		SignatureAlgorithm: algorithmForFlags(ref.GetAlgorithm(), flags),
		PayloadSha256:      digest[:],
	}

	switch {
	case class.SSHAuth != nil:
		c.attachSessionContext(class.SSHAuth)

		req.Operation = &ladulasv1.ApprovalRequest_SshAuth{SshAuth: class.SSHAuth}
	case class.Sshsig != nil:
		req.Operation = &ladulasv1.ApprovalRequest_Sshsig{Sshsig: class.Sshsig}
	default:
		req.Operation = &ladulasv1.ApprovalRequest_OpaqueSign{OpaqueSign: class.Opaque}
	}

	return req
}

// attachSessionContext correlates the request against the connection's
// session-bind list, and names the destination (§4).
//
// Two things can say where a login is going, and they are not equal. The payload
// of a hostbound request carries the server's host key inside the bytes being
// signed; a session binding carries one beside them. Both are verified, so the
// difference matters only to an approver somewhere else — which is exactly who
// asks — so the payload's host key wins when there is one, and the binding
// answers when there is not.
func (c *connAgent) attachSessionContext(auth *ladulasv1.SshAuthRequest) {
	c.mu.Lock()
	bind := c.binds.context(auth.GetSessionId())
	c.mu.Unlock()

	auth.BindingChain = bind.chain
	auth.Forwarded = bind.forwarded
	auth.ForwardedHops = bind.hops
	auth.Bound = bind.binding != nil

	// This machine is the one with a known_hosts file, so it is the one that can
	// turn a host key into a name — for the payload's key as much as a binding's.
	if host := auth.GetPayloadDestination(); host != nil {
		c.server.knownHosts.Annotate(host)

		auth.Destination = host
		auth.DestinationLabel = DisplayName(host)

		return
	}

	if bind.binding == nil {
		// A pre-8.9 client, something that is not OpenSSH, or anything
		// pretending to be one: no binding and no host key in the payload.
		// Policy decides what to do with these; the default is to prompt,
		// marked as an unknown destination.
		auth.DestinationLabel = "unknown destination"

		return
	}

	auth.Destination = bind.binding.GetHostKey()
	auth.DestinationLabel = DisplayName(bind.binding.GetHostKey())
}

func (c *connAgent) requesterInfo() *ladulasv1.RequesterInfo {
	info := c.server.requesterInfo()
	info.Local = true
	info.Process = c.peer

	return info
}

// Extension receives session-bind@openssh.com (§4).
func (c *connAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != SessionBindExtension {
		return nil, sshagent.ErrExtensionUnsupported
	}

	pub, sessionID, isForwarding, err := parseSessionBind(contents)
	if err != nil {
		c.server.log.Warn("rejected a session binding",
			"error", err.Error())

		return nil, fmt.Errorf("session-bind: %w", err)
	}

	binding := &ladulasv1.SessionBinding{
		HostKey:           c.server.knownHosts.hostKeyMessage(pub),
		SessionId:         sessionID,
		IsForwarding:      isForwarding,
		SignatureVerified: true,
	}

	c.mu.Lock()
	err = c.binds.add(binding)
	c.mu.Unlock()

	if err != nil {
		return nil, fmt.Errorf("session-bind: %w", err)
	}

	c.server.log.Debug("bound agent connection to a session",
		"host_key", binding.GetHostKey().GetFingerprint(),
		"destination", DisplayName(binding.GetHostKey()),
		"is_forwarding", isForwarding,
		"hop", binding.GetHop())

	// An empty response is SSH_AGENT_SUCCESS.
	return nil, nil
}

// Add refuses to add keys. Key management goes through Ladulås (§4).
func (c *connAgent) Add(sshagent.AddedKey) error {
	return ErrMutationNotSupported
}

// Remove refuses to remove keys.
func (c *connAgent) Remove(ssh.PublicKey) error {
	return ErrMutationNotSupported
}

// RemoveAll refuses to remove keys.
func (c *connAgent) RemoveAll() error {
	return ErrMutationNotSupported
}

// Lock is not supported; the store's own lock state is not the agent's to
// change.
func (c *connAgent) Lock([]byte) error {
	return ErrMutationNotSupported
}

// Unlock is not supported.
func (c *connAgent) Unlock([]byte) error {
	return ErrMutationNotSupported
}

// Signers refuses to hand out signers. Handing a caller an ssh.Signer would
// hand it the ability to sign without asking, which is the one thing this
// agent exists to prevent. ServeAgent never calls it.
func (c *connAgent) Signers() ([]ssh.Signer, error) {
	return nil, errors.New(
		"ladulas: the agent does not expose signers; every signature needs approval")
}

// algorithmForFlags resolves the SSH_AGENT_RSA_SHA2_* flags to a signature
// algorithm. The flags are meaningless for anything but RSA, and OpenSSH
// ignores them there, so an empty string means "the key's own algorithm".
func algorithmForFlags(keyAlgorithm string, flags sshagent.SignatureFlags) string {
	if keyAlgorithm != ssh.KeyAlgoRSA {
		return ""
	}

	switch {
	case flags&sshagent.SignatureFlagRsaSha512 != 0:
		return ssh.KeyAlgoRSASHA512
	case flags&sshagent.SignatureFlagRsaSha256 != 0:
		return ssh.KeyAlgoRSASHA256
	default:
		return ""
	}
}

func signWithAlgorithm(
	signer ssh.Signer, data []byte, algorithm string,
) (*ssh.Signature, error) {
	if algorithm == "" {
		sig, err := signer.Sign(rand.Reader, data)
		if err != nil {
			return nil, fmt.Errorf("sign: %w", err)
		}

		return sig, nil
	}

	as, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf(
			"ladulas: key does not support the requested algorithm %s", algorithm)
	}

	sig, err := as.SignWithAlgorithm(rand.Reader, data, algorithm)
	if err != nil {
		return nil, fmt.Errorf("sign with %s: %w", algorithm, err)
	}

	return sig, nil
}

// slogAttrs logs a request consistently wherever it is mentioned.
func slogAttrs(req *ladulasv1.ApprovalRequest) []any {
	return []any{
		"request_id", req.GetRequestId(),
		"kind", req.GetKind().String(),
		"key", req.GetKey().GetLabel(),
	}
}
