# A peer that cannot approve vetoes every request

**Fixed:** 2026-08-19, as decisions AC and AD. The engine takes a peer's
`NO_APPROVER` off the answer path and onto the failure path — first
*decision* wins, and that is not one (§2, §9) — and the direction a pairing
grants is now one answer given on the side displaying the code, so the
pairing that made this reachable is harder to create by accident (§7). The
third question below, excluding such a peer from `eligible` up front, was
turned down: it needs the peer to keep advertising something that changes
when a laptop lid closes, and the rule above is needed for the gap either
way.

**Found:** 2026-08-19, on `guppy`, signing a git commit.
**Severity:** signing and ssh authentication are dead on the affected
instance until the peer is unpaired. Every request is denied; no local
approver is ever given the chance to answer.
**Areas:** `pkg/approval/engine.go` (`prompt`, `eligible`), §2 "First
response wins", §9.

## Signal

Every `git commit` fails immediately — not after a wait — with

```
error: ladulas-sign: the signature was refused: pietro: no approver is available to answer
fatal: failed to write commit object
```

and the daemon logs, for each attempt:

```
level=DEBUG msg="a poll was open, so no wake-up was sent" peer=SHA256:qXY… request_id=24hevrdogmyjz4ab
level=INFO  msg=decided request_id=24hevrdogmyjz4ab kind=REQUEST_KIND_GIT_SIGN \
            decision=DECISION_DENY source=DECISION_SOURCE_NO_APPROVER approver=pietro \
            reason="pietro: no approver is available to answer"
```

The tell that this is not the ordinary headless `no_approver` described in
`docs/ops.md` under "A signature hangs and then times out": there **is** a
local approver here. The desktop answered fine the day before, and the
denial names a peer and carries a reason string prefixed with that peer's
name — the denial was made *on pietro* and shipped back.

What changed in between was a pairing, nothing else:

```
Aug 18 21:38:04  decided … decision=DECISION_APPROVE source=DECISION_SOURCE_USER \
                 approver=guppy reason="approved at the desktop for anywhere on guppy, for 1 hour"
Aug 19 05:00:34  msg="linked to a peer" peer=pietro address=pietro:7373
Aug 19 17:39:51  decided … decision=DECISION_DENY source=DECISION_SOURCE_NO_APPROVER approver=pietro
```

## Mechanism

`Engine.prompt` fans a request out to every eligible approver and takes the
first answer, cancelling the rest — §2, and `engine.go`:

```go
case r := <-results:
	// Cancelling here is what tells the other approvers to drop their
	// prompts: first response wins.
	cancel()

	return e.answerToResponse(req, r.handler, r.answer)
```

On the requester, `eligible(OriginLocal)` returns the local prompt *and*
the `RemoteHandler` for the peer, and both are asked concurrently. The peer
receives the request over its open poll (`pkg/peer/inbox.go`, "a poll was
open, so no wake-up was sent") and runs `prompt` itself. There, two rules
meet:

* a request that arrived from a peer is not passed on to another peer, so
  the remote handlers are filtered out of `eligible` (`engine.go`, "passing
  one on would make this instance a relay for somebody else's decision");
* the peer has no local human approver of its own.

So on the peer `len(handlers) == 0`, and it returns, immediately:

```go
return deny(
	ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER, reason), nil
```

That travels back to the requester as a perfectly well-formed **answer**.
It is instant, because nothing was asked of anybody, so it always beats a
desktop prompt that is waiting on a human to look at a window. First
response wins, `cancel()` fires, and the desktop prompt is torn down —
usually before it has been read.

The result is that pairing an instance which cannot approve does not add a
second way to get approval, it removes the first one. It is a veto, and it
is a race the local human cannot win.

## Why the existing failure path is the shape of the fix

`prompt` already distinguishes an answer from an absence of one. Handlers
that error go to a `failures` channel, and the request is only denied when
every one of them has gone:

```go
case <-failures:
	failed++

	// Every approver that could have answered has gone. […]
	if failed == len(handlers) {
		return deny(ladulasv1.DecisionSource_DECISION_SOURCE_NO_APPROVER,
			"no approver could be reached"), nil
	}
```

`NO_APPROVER` from a peer belongs on that path. It is the peer saying "ask
somebody else", which is a report about the peer's own state, not a
decision about the request. Treating it as a decision is what lets it win a
race it should not be in.

Worth deciding at the same time:

* Whether `TIMEOUT` from a peer deserves the same treatment. Probably not —
  the peer's timeout may be shorter than the requester's, but somebody was
  at least asked.
* Whether a `RemoteHandler` whose peer has no approver should be excluded
  from `eligible` up front rather than raced and discarded. Cheaper, but it
  needs the peer to advertise the fact, and decision T already has
  machinery for a peer announcing what it can do.
* Whether this wants a new decision in §19 — `AC`, the table having run
  through `Z` into `AA` and `AB` — since §2 states "first response wins"
  flatly and this qualifies it: first *decision* wins, and `NO_APPROVER` is
  not one.

## Reproducing

Pair a second instance that has no approver registered — no GUI, no console
— and leave it polling. Then ask for anything requiring approval on the
first instance. `internal/integration/delegation_test.go` already builds
the two halves this needs; `TestADelegatedGrantOutlivesItsApprover` takes
its approver away *after* a grant exists, which is the case decision P
covers and is why it passes. The case here is a peer that never had one,
with no grant in play.

Expected once fixed: the local desktop prompt opens and stays open, and the
peer's inability to answer changes nothing about the outcome.

## Workaround

Commit with `--no-gpg-sign`, or unpair the peer. Retrying does not help:
the denial is instant and deterministic.
