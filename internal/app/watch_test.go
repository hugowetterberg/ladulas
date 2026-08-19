package app

import (
	"errors"
	"testing"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// A front end that has gone away is sent nothing, and the point of the test is
// that "nothing" is checked before the stream is touched rather than after.
//
// The stream here is nil, which is a harsher version of what the real one
// becomes: an RPC handler that has returned leaves behind an `http.response`
// whose buffered writer went back to a pool, so a send lands on a nil pointer
// inside net/http instead of returning an error. That crashed the daemon —
// taking the agent socket, the peer links and the unlocked store with it —
// because a front end was killed while a prompt was on its way to it. If the
// guard in send is removed, this test does not fail politely; it panics, which
// is the right amount of noise for what it is protecting.
func TestSendingToAFrontEndThatHasGone(t *testing.T) {
	t.Parallel()

	approver := &socketApprover{id: "desktop", stream: nil}

	approver.finish()

	err := approver.send(&ladulasv1.ApprovalPrompt{
		Kind: ladulasv1.ApprovalPromptKind_APPROVAL_PROMPT_KIND_ATTACHED,
	})

	if !errors.Is(err, errFrontEndGone) {
		t.Fatalf("sending to a detached front end returned %v", err)
	}
}

// And it is the same answer whichever kind of event it is, because they all go
// through the one door: the prompt, the withdrawal the engine sends when
// somebody else answered, and the announcement of a decision made without
// asking. The withdrawal is the one that crashed — it is sent from the context's
// own branch, precisely when the reason for the context finishing is that the
// stream is gone.
func TestEveryKindOfSendIsRefusedAfterTheStreamStops(t *testing.T) {
	t.Parallel()

	kinds := []ladulasv1.ApprovalPromptKind{
		ladulasv1.ApprovalPromptKind_APPROVAL_PROMPT_KIND_PROMPT,
		ladulasv1.ApprovalPromptKind_APPROVAL_PROMPT_KIND_WITHDRAWN,
		ladulasv1.ApprovalPromptKind_APPROVAL_PROMPT_KIND_DECIDED,
	}

	for _, kind := range kinds {
		approver := &socketApprover{id: "desktop", stream: nil}
		approver.finish()

		if err := approver.send(&ladulasv1.ApprovalPrompt{Kind: kind}); err == nil {
			t.Errorf("a %s went out to a front end that is not there", kind)
		}
	}
}
