package agent

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
)

// sshsigMagic is the preamble of an SSHSIG signing payload. It is six raw bytes
// with no length prefix, which is what makes classification unambiguous: an
// RFC 4252 §7 auth blob starts with a length-prefixed session identifier, and
// no plausible session identifier length has "SSHS" as its big-endian encoding
// (that would be a 1.4 GB session ID).
const sshsigMagic = sshsig.Magic

// gitNamespace is the SSHSIG namespace git uses for commit and tag signatures.
const gitNamespace = sshsig.GitNamespace

// msgUserauthRequest is SSH_MSG_USERAUTH_REQUEST, the message type embedded in
// the blob a client asks the agent to sign during public key authentication.
const msgUserauthRequest = 50

// The two authentication methods an agent is asked to sign for.
//
// MethodHostbound is OpenSSH's own, documented in its PROTOCOL file: the same
// blob as RFC 4252 §7 with the server's host key appended, negotiated whenever
// both ends support it. Both ends have since 8.9, so it is not the exotic case
// — it is what ssh sends to nearly every server, and treating it as unknown is
// treating ordinary public key authentication as unknown.
//
// The extra field is the whole reason OpenSSH added the method, and it is worth
// more here than anywhere: it binds the signature to the server it is for, so an
// approver on the far side of a peer channel can tell where a login is going
// from the bytes rather than from what the requesting machine says about them
// (§4, §15).
const (
	MethodPublicKey = "publickey"
	MethodHostbound = "publickey-hostbound-v00@openssh.com"
)

// maxOpaquePrefix caps how much of an unclassifiable payload is kept for the
// audit log.
const maxOpaquePrefix = 64

// Classification is the result of parsing a sign request payload. Exactly one
// of the operation fields is set, and Kind says which.
type Classification struct {
	Kind    ladulasv1.RequestKind
	SSHAuth *ladulasv1.SshAuthRequest
	Sshsig  *ladulasv1.SshsigRequest
	Opaque  *ladulasv1.OpaqueSignRequest
}

// Classify decides what a sign request is asking for (docs/architecture.md
// §4).
//
// A payload is either an SSHSIG blob or a public key authentication blob, in
// either of the two methods ssh uses for one. Anything else classifies as
// opaque, and opaque requests are denied unconditionally — that is a hard rule
// policy cannot override, so the parsing here is deliberately strict: partial
// parses and trailing bytes both fall through to opaque.
//
// The strictness is right and its cost is real: an authentication method this
// does not know is an ssh login that fails with "agent refused operation", which
// says nothing about why. The audit entry does — it names the method — and that
// is the only reason the hostbound method was anything but a mystery.
func Classify(payload []byte) Classification {
	if sig, err := parseSshsig(payload); err == nil {
		kind := ladulasv1.RequestKind_REQUEST_KIND_SSHSIG
		if sig.GetNamespace() == gitNamespace {
			kind = ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN
		}

		return Classification{Kind: kind, Sshsig: sig}
	} else if !errors.Is(err, errNotSshsig) {
		return opaque(payload, fmt.Sprintf("malformed SSHSIG payload: %v", err))
	}

	auth, err := parseAuthBlob(payload)
	if err != nil {
		return opaque(payload, fmt.Sprintf("not an SSH authentication blob: %v", err))
	}

	return Classification{
		Kind:    ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH,
		SSHAuth: auth,
	}
}

// errNotSshsig distinguishes "this is not an SSHSIG payload at all" from "this
// claims to be one and is broken". The second case is worth reporting rather
// than silently trying to read it as an auth blob.
var errNotSshsig = errors.New("no SSHSIG preamble")

// parseSshsig reads the blob ssh-keygen -Y sign hands to the agent:
//
//	byte[6]  "SSHSIG"
//	string   namespace
//	string   reserved
//	string   hash_algorithm
//	string   H(message)
func parseSshsig(payload []byte) (*ladulasv1.SshsigRequest, error) {
	if len(payload) < len(sshsigMagic) || string(payload[:len(sshsigMagic)]) != sshsigMagic {
		return nil, errNotSshsig
	}

	r := &reader{buf: payload[len(sshsigMagic):]}

	namespace, err := r.text()
	if err != nil {
		return nil, fmt.Errorf("namespace: %w", err)
	}

	if _, err := r.stringValue(); err != nil {
		return nil, fmt.Errorf("reserved: %w", err)
	}

	hashAlgorithm, err := r.text()
	if err != nil {
		return nil, fmt.Errorf("hash algorithm: %w", err)
	}

	digest, err := r.stringValue()
	if err != nil {
		return nil, fmt.Errorf("message digest: %w", err)
	}

	if !r.empty() {
		return nil, fmt.Errorf("%d trailing bytes", r.remaining())
	}

	if namespace == "" {
		return nil, errors.New("empty namespace")
	}

	return &ladulasv1.SshsigRequest{
		Namespace:     namespace,
		HashAlgorithm: hashAlgorithm,
		MessageDigest: append([]byte(nil), digest...),
	}, nil
}

// parseAuthBlob reads the public key authentication blob:
//
//	string    session identifier
//	byte      SSH_MSG_USERAUTH_REQUEST
//	string    user name
//	string    service name
//	string    "publickey" | "publickey-hostbound-v00@openssh.com"
//	boolean   TRUE
//	string    public key algorithm
//	string    public key blob
//	string    server host key          (hostbound only)
func parseAuthBlob(payload []byte) (*ladulasv1.SshAuthRequest, error) {
	r := &reader{buf: payload}

	sessionID, err := r.stringValue()
	if err != nil {
		return nil, fmt.Errorf("session identifier: %w", err)
	}

	if len(sessionID) == 0 {
		return nil, errors.New("empty session identifier")
	}

	msgType, err := r.byteValue()
	if err != nil {
		return nil, fmt.Errorf("message type: %w", err)
	}

	if msgType != msgUserauthRequest {
		return nil, fmt.Errorf(
			"message type %d, want SSH_MSG_USERAUTH_REQUEST (%d)",
			msgType, msgUserauthRequest)
	}

	username, err := r.text()
	if err != nil {
		return nil, fmt.Errorf("user name: %w", err)
	}

	service, err := r.text()
	if err != nil {
		return nil, fmt.Errorf("service name: %w", err)
	}

	method, err := r.text()
	if err != nil {
		return nil, fmt.Errorf("method name: %w", err)
	}

	if method != MethodPublicKey && method != MethodHostbound {
		return nil, fmt.Errorf("method %q, want %s or %s",
			method, MethodPublicKey, MethodHostbound)
	}

	hasSignature, err := r.boolValue()
	if err != nil {
		return nil, fmt.Errorf("signature flag: %w", err)
	}

	if !hasSignature {
		// A query probe is never signed, so the agent should not be seeing one.
		return nil, errors.New("signature flag is false")
	}

	if _, err := r.stringValue(); err != nil {
		return nil, fmt.Errorf("public key algorithm: %w", err)
	}

	if _, err := r.stringValue(); err != nil {
		return nil, fmt.Errorf("public key blob: %w", err)
	}

	auth := &ladulasv1.SshAuthRequest{
		Username:  username,
		Service:   service,
		Method:    method,
		SessionId: append([]byte(nil), sessionID...),
	}

	if method == MethodHostbound {
		hostKey, err := r.stringValue()
		if err != nil {
			return nil, fmt.Errorf("server host key: %w", err)
		}

		pub, err := ssh.ParsePublicKey(hostKey)
		if err != nil {
			return nil, fmt.Errorf("server host key: %w", err)
		}

		// No known_hosts here: this is a pure parse, and it runs on the machine
		// holding the key as well as on the one asking. The names are filled in
		// where there is a file to read them from.
		auth.PayloadDestination = &ladulasv1.HostKey{
			Blob:        pub.Marshal(),
			Algorithm:   pub.Type(),
			Fingerprint: ssh.FingerprintSHA256(pub),
		}
	}

	if !r.empty() {
		return nil, fmt.Errorf("%d trailing bytes", r.remaining())
	}

	return auth, nil
}

func opaque(payload []byte, reason string) Classification {
	sum := sha256.Sum256(payload)

	prefix := payload
	if len(prefix) > maxOpaquePrefix {
		prefix = prefix[:maxOpaquePrefix]
	}

	return Classification{
		Kind: ladulasv1.RequestKind_REQUEST_KIND_OPAQUE_SIGN,
		Opaque: &ladulasv1.OpaqueSignRequest{
			PayloadLength: uint32(len(payload)),
			PayloadSha256: sum[:],
			Reason:        reason,
			Prefix:        append([]byte(nil), prefix...),
		},
	}
}
