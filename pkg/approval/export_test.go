package approval

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// DelegationForTest builds what an approver would hand over for a request, so
// that the requester-side tests match against a real scope rather than one
// hand-written beside the code that derives it — which is exactly the sort of
// copy that goes on passing after the derivation changes.
func DelegationForTest(
	approver *identity.Identity,
	msg *ladulasv1.ApprovalRequest,
	requesterFingerprint string,
	ttl time.Duration,
) *ladulasv1.Delegation {
	now := time.Now()
	scope := scopeFor(msg)

	return &ladulasv1.Delegation{
		DelegationId:         identity.NewRequestID(),
		Scope:                scope,
		CreatedAt:            timestamppb.New(now),
		ExpiresAt:            timestamppb.New(now.Add(ttl)),
		Description:          DescribeScope(scope, GrantSubject(msg), ttl),
		ApproverFingerprint:  approver.Fingerprint(),
		ApproverName:         approver.Name(),
		RequesterFingerprint: requesterFingerprint,
	}
}
