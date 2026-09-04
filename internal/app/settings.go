package app

import (
	"fmt"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The settings a surface may change. Today that is the signing budget and
// nothing else (§9, §12).
//
// It is deliberately not "edit the policy over the socket". The policy document
// decides what is approved without asking, and a screen that could write rules
// would put an auto-approve rule one mis-click from every process running as
// this user. What is here is one number that decides how long somebody has to
// answer, which cannot approve anything by itself.

// SignTimeout is the signing budget in force, and where it is written down.
//
// In force rather than on disk: an instance that has been running since before
// somebody edited policy.json is deciding by what it loaded, and a screen that
// showed the file would be describing a state the daemon is not in.
func (a *App) SignTimeout() time.Duration {
	if current := a.currentCore(); current != nil {
		return current.engine.Policy().Timeout(
			ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN)
	}

	// Sealed: there is no engine to ask, and the file is the best account of
	// what the next unlock will run with. A policy that cannot be read at all
	// falls back the way LoadPolicy does, because the daemon would too.
	policy, err := approval.LoadPolicy(a.Config.PolicyPath())
	if err != nil {
		return approval.DefaultSignTimeout
	}

	return policy.Timeout(ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN)
}

// MaxGrantTTL is the longest promise this instance makes, read the way
// SignTimeout is: from the engine in force, or from the file while sealed.
func (a *App) MaxGrantTTL() time.Duration {
	if current := a.currentCore(); current != nil {
		return current.engine.Policy().MaxGrantTTL()
	}

	policy, err := approval.LoadPolicy(a.Config.PolicyPath())
	if err != nil {
		return approval.DefaultGrantTTLs[len(approval.DefaultGrantTTLs)-1]
	}

	return policy.MaxGrantTTL()
}

// SetSignTimeout writes the budget to the policy document and puts it into
// effect, with no reload and no restart.
//
// The document is re-read before it is written, rather than the running
// policy's copy being saved over it. The two differ exactly when somebody has
// hand-edited the file since it was loaded, and of the two ways to resolve
// that, adopting what is on disk is the one that does not throw away work
// somebody did in an editor. So changing the timeout from a surface also picks
// up an edit that was waiting for a reload, which is worth knowing and is a
// great deal better than silently reverting it.
//
// Requests already waiting are not moved. Their deadlines were set when they
// arrived (§9), and a clock that jumps under somebody reading a diff is a clock
// that cannot be trusted for the one thing it is for.
func (a *App) SetSignTimeout(d time.Duration) error {
	policy, err := approval.LoadPolicy(a.Config.PolicyPath())
	if err != nil {
		return fmt.Errorf("read the policy: %w", err)
	}

	if err := policy.SetSignTimeout(d); err != nil {
		return err
	}

	if err := policy.Save(a.Config.PolicyPath()); err != nil {
		return fmt.Errorf("write the policy: %w", err)
	}

	if current := a.currentCore(); current != nil {
		current.engine.SetPolicy(policy)
	}

	a.LogLifecycle(fmt.Sprintf("signing requests now wait up to %s",
		approval.HumanDuration(d)))

	return nil
}
