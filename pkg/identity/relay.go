package identity

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// relaySigningPrefix domain-separates a call to the wake-up relay from
// everything else the identity key signs (§11).
//
// It matters more here than anywhere else, because this is the only signature
// an instance produces for a party it does not trust. A relay is handed a
// signature over bytes it chose the shape of; without the prefix, a relay that
// wanted one could hand back a call whose serialization also parses as an
// approval and keep the signature.
const relaySigningPrefix = "ladulas-relay-v1\x00"

// RelayClockSkew is how far a relay call's timestamp may be from the relay's own
// clock. It is the replay window, and it is short because nothing about a wake-up
// is worth queueing: a call that arrives late is one whose request has almost
// certainly been answered or given up on.
const RelayClockSkew = 5 * time.Minute

// SignRelayCall produces the artifact the relay verifies.
func (i *Identity) SignRelayCall(
	call *ladulasv1.RelayCall,
) (*ladulasv1.SignedRelayCall, error) {
	if call == nil {
		return nil, errors.New("nil relay call")
	}

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(call)
	if err != nil {
		return nil, fmt.Errorf("marshal relay call: %w", err)
	}

	sig, err := i.signer.Sign(rand.Reader, relayInput(body))
	if err != nil {
		return nil, fmt.Errorf("sign relay call: %w", err)
	}

	return &ladulasv1.SignedRelayCall{
		Call:               body,
		PublicKey:          i.signer.PublicKey().Marshal(),
		SignatureAlgorithm: sig.Format,
		Signature:          ssh.Marshal(sig),
	}, nil
}

// VerifyRelayCall checks the signature and returns what it covers, together with
// the key that made it.
//
// The key is returned rather than checked against anything, because the relay
// has nothing to check it against: it does not know which instances are paired
// with which and is deliberately never told (§11). What it does with the key is
// bind an instance id to the first one that claimed it, and count.
func VerifyRelayCall(
	src *ladulasv1.SignedRelayCall,
) (*ladulasv1.RelayCall, ssh.PublicKey, error) {
	if src == nil {
		return nil, nil, errors.New("nil relay call")
	}

	pub, err := ssh.ParsePublicKey(src.GetPublicKey())
	if err != nil {
		return nil, nil, fmt.Errorf("parse caller public key: %w", err)
	}

	var sig ssh.Signature

	if err := ssh.Unmarshal(src.GetSignature(), &sig); err != nil {
		return nil, nil, fmt.Errorf("parse signature: %w", err)
	}

	if err := pub.Verify(relayInput(src.GetCall()), &sig); err != nil {
		return nil, nil, fmt.Errorf("verify relay call signature: %w", err)
	}

	var call ladulasv1.RelayCall

	if err := proto.Unmarshal(src.GetCall(), &call); err != nil {
		return nil, nil, fmt.Errorf("unmarshal relay call: %w", err)
	}

	return &call, pub, nil
}

// NewRelayCall stamps a call with the two fields that bound replay, so that no
// caller has to remember to.
func NewRelayCall(instanceID string) *ladulasv1.RelayCall {
	return &ladulasv1.RelayCall{
		IssuedAt:   timestamppb.Now(),
		Nonce:      NewRequestID(),
		InstanceId: instanceID,
	}
}

func relayInput(body []byte) []byte {
	return prefixed(relaySigningPrefix, body)
}
