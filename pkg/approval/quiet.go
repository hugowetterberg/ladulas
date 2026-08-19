package approval

import "time"

// QuietUntil is the wake-up milestone's one question of the engine (§20, M9):
// until when would a request from this requester be answered here without asking
// anybody?
//
// The answer is the latest expiry among the live grants scoped to that
// requester, and it is used for exactly one thing — deciding whether a wake-up
// should be a silent background push or a visible alert. Nothing is authorized
// by it and nothing is skipped because of it: the request still arrives, still
// goes through the whole decision, and still reaches a human if the grant turns
// out not to cover it after all.
//
// Delegated grants are excluded, and that is not an oversight. A delegated grant
// is applied by the requester itself (decision P), so a request it covers never
// travels here at all — counting one would be promising to answer quietly for
// requests that will never be sent.
func (e *Engine) QuietUntil(requesterFingerprint string) time.Time {
	if e.grants == nil || requesterFingerprint == "" {
		return time.Time{}
	}

	grants, err := e.grants.Grants()
	if err != nil {
		e.log.Error("could not read grants", "error", err.Error())

		return time.Time{}
	}

	now := e.now()

	var latest time.Time

	for _, grant := range grants {
		if grant.GetDelegated() {
			continue
		}

		if grant.GetScope().GetRequesterInstanceId() != requesterFingerprint {
			continue
		}

		expires := grant.GetExpiresAt().AsTime()
		if !expires.After(now) {
			continue
		}

		if expires.After(latest) {
			latest = expires
		}
	}

	return latest
}
