package agent

import (
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// SessionBindExtension is the extension name OpenSSH ≥ 8.9 clients use to tell
// the agent where they are connecting.
const SessionBindExtension = "session-bind@openssh.com"

// maxBindings caps the per-connection binding list. A legitimate client sends
// one bind per hop; a hostile one on a forwarded socket could otherwise grow
// the list without bound.
const maxBindings = 32

// parseSessionBind reads the extension payload:
//
//	string  hostkey
//	string  session identifier
//	string  signature
//	bool    is_forwarding
//
// The signature is the server's, over the session identifier, made with the
// host key — which is what makes the destination in a prompt evidence rather
// than a claim. A binding whose signature does not verify is rejected outright:
// accepting it would let anything that can talk to the socket assert an
// arbitrary destination.
func parseSessionBind(contents []byte) (pub ssh.PublicKey, sessionID []byte, isForwarding bool, err error) {
	r := &reader{buf: contents}

	hostKeyBlob, err := r.stringValue()
	if err != nil {
		return nil, nil, false, fmt.Errorf("host key: %w", err)
	}

	sessionID, err = r.stringValue()
	if err != nil {
		return nil, nil, false, fmt.Errorf("session identifier: %w", err)
	}

	signature, err := r.stringValue()
	if err != nil {
		return nil, nil, false, fmt.Errorf("signature: %w", err)
	}

	isForwarding, err = r.boolValue()
	if err != nil {
		return nil, nil, false, fmt.Errorf("is_forwarding: %w", err)
	}

	if !r.empty() {
		return nil, nil, false, fmt.Errorf("%d trailing bytes", r.remaining())
	}

	if len(sessionID) == 0 {
		return nil, nil, false, errors.New("empty session identifier")
	}

	pub, err = ssh.ParsePublicKey(hostKeyBlob)
	if err != nil {
		return nil, nil, false, fmt.Errorf("parse host key: %w", err)
	}

	var sig ssh.Signature

	if err := ssh.Unmarshal(signature, &sig); err != nil {
		return nil, nil, false, fmt.Errorf("parse signature: %w", err)
	}

	if err := pub.Verify(sessionID, &sig); err != nil {
		return nil, nil, false, fmt.Errorf(
			"host key signature over the session identifier does not verify: %w", err)
	}

	return pub, sessionID, isForwarding, nil
}

// bindings is the ordered session-bind list for one agent connection.
//
// Order matters: hop 0 is the connection the client made itself, and every
// further bind is a forwarded hop (§4). Correlating an auth blob's session
// identifier against the list is what tells us which host a signature is for,
// and whether the request reached us through somebody else's machine.
type bindings struct {
	list []*ladulasv1.SessionBinding
}

func (b *bindings) add(binding *ladulasv1.SessionBinding) error {
	if len(b.list) >= maxBindings {
		return fmt.Errorf("more than %d session bindings on one connection", maxBindings)
	}

	binding.Hop = int32(len(b.list))
	b.list = append(b.list, binding)

	return nil
}

// bindContext is what the binding list can say about one authentication
// request.
type bindContext struct {
	// binding is the entry whose session identifier the request carried, or nil
	// when the request could not be tied to any of them.
	binding *ladulasv1.SessionBinding
	// forwarded is set when the request reached us through at least one agent
	// forwarding hop. Such requests always prompt, whatever the policy says,
	// because a hostile remote host holding the forwarded socket can send
	// arbitrary well-formed requests (§4).
	forwarded bool
	// hops counts the forwarding hops between us and the destination.
	hops int32
	// chain is the whole ordered list, for display.
	chain []*ladulasv1.SessionBinding
}

// context correlates an auth blob's session identifier against the binding
// list.
//
// The list is ordered outermost first: entry 0 is the connection this agent
// socket belongs to, and OpenSSH marks it is_forwarding when the socket is
// itself a forwarded one. Further entries are hops the client added as it
// chained onward, so everything up to and including the matched entry
// contributes to whether the request is forwarded.
func (b *bindings) context(sessionID []byte) bindContext {
	out := bindContext{chain: b.snapshot()}

	for _, binding := range b.list {
		if binding.GetIsForwarding() {
			out.forwarded = true
			out.hops++
		}

		if sessionID != nil && bytes.Equal(binding.GetSessionId(), sessionID) {
			out.binding = binding

			return out
		}
	}

	// No match. Everything the connection knows about still counts towards
	// "this arrived through a forwarded socket".
	return out
}

// snapshot copies the binding list for inclusion in a request.
func (b *bindings) snapshot() []*ladulasv1.SessionBinding {
	if len(b.list) == 0 {
		return nil
	}

	out := make([]*ladulasv1.SessionBinding, len(b.list))
	copy(out, b.list)

	return out
}
