# Observability

Every metric the daemon and the relay export, and what a change in one
means. The definition of most of them is in the name; what is worth
writing down is which direction is bad, what is routinely non-zero, and
what the number should be read against.

| Document | What it settles |
|---|---|
| [`README.md`](../README.md) | What the repository holds, how to build and run it, every configuration flag, and what is still missing. |
| [`docs/architecture.md`](architecture.md) | How the service is built: roles, process model, subsystems, protocol, and the decisions behind them. |
| [`docs/ops.md`](ops.md) | Running it: dependencies, ports, bootstrap order, failure modes and what to do about each. |
| **`docs/observability.md`** (this) | Every metric the daemon and the relay export, and what a change in one means. |

What this document does **not** cover: what to do when a number has moved,
which is [ops.md](ops.md)'s failure-mode catalogue — every failure mode
there names its signal, and this is where that signal is defined.

**Both ports are unauthenticated and neither carries an identifier.** No
fingerprint, no request id, no instance id, no key label, no payload. The
metrics surface is the least protected one an instance has and the one
whose output is written down and kept, so everything that could name a
person, a machine or a request stays in the audit log
([architecture §14](architecture.md#14-management-surface-the-control-socket-and-cli)).
That is a constraint on what can ever be added here, not just a
description of what is here now: a label whose values come from the store
is a label that does not get added.

## Where the numbers come from

All collectors are declared in one place, `internal/observe`, and
registered through a registry the debug server owns — never a package-level
variable, never the default registry. The two server binaries are the only
things in the tree that link a Prometheus client at all; `approval`, `peer`
and `relay` expose a function field or a small interface and know nothing
about metrics, which is what keeps the library out of the phone's gomobile
build ([architecture §18](architecture.md#18-the-library-boundary)).

Three sets are the library's rather than this repository's, registered on
both binaries and documented by upstream: `go_*` (the Go runtime
collector), `process_*` (open file descriptors, resident memory, CPU, and
`process_start_time_seconds`), and `go_build_info`. They are worth having
here for one reason beyond the usual: `process_start_time_seconds` is how
a counter reset is told apart from a quiet period, and the daemon restarts
more often than a server does — it is a user unit, so it goes down with the
session.

**The daemon's port is off unless an address is named for it, and the
relay's is on loopback by default.** Neither is a default an operator
should leave alone without reading
[ops.md](ops.md#endpoints-and-ports) — the reasoning is in
[architecture §14](architecture.md#14-management-surface-the-control-socket-and-cli).

## Approval — the daemon

The pair to watch is `ladulas_approval_requests_total` against
`ladulas_approval_decisions_total{decision="approve"}`. Requests that
arrive and are never approved are the shape of every interesting failure
here: an approver that is not there, a policy that is denying more than
its author meant, a phone that nobody is picking up.

* **`ladulas_approval_requests_total{origin,kind}`** — requests that
  reached the engine. `origin` is `local` for something on this machine
  (ssh, `ladulas-sign`) and `peer` for a paired instance asking this one to
  decide or to sign; `kind` is the request kind — `ssh_auth`, `git_sign`,
  `sshsig`, `key_list`, `pairing`, `opaque_sign`. A rise in
  `{origin="peer"}` is somebody else's machine using a key that lives here,
  which is either the point of the pairing or the first sign that a
  requester has been taken.
* **`ladulas_approval_decisions_total{origin,decision,source}`** — the
  answers. `source` is what decided, and it is the label that carries the
  information: `user` is a person who answered a prompt, `policy` and
  `grant` are answers given in advance, `hard_rule` is something no policy
  can override
  ([architecture §9](architecture.md#9-approval-engine-and-policies)), and
  `timeout`, `no_approver` and `cancelled` are requests that reached nobody.
  Every request produces exactly one decision, so decisions lagging
  requests over a window means requests are still open, not that they were
  lost.
* **`{source="no_approver"}` rising is the one that needs an operator.**
  It means the engine had a request and nowhere to send it: a headless box
  whose only approver has been revoked or is unreachable, or a desktop that
  is soft-locked with no peer paired. Nothing retries it into working.
* **`{source="hard_rule"}` is never routine.** It is an unclassifiable
  payload, a forwarded-agent request, or a git context that does not
  describe the commit it would sign — the last of which is the compromised
  requester of
  [architecture §16](architecture.md#16-security-considerations). One is
  worth reading the audit log over; a stream of them is worth acting on.
* **`ladulas_approval_wait_seconds{origin}`** — from a request arriving to
  it being decided, computed from the timestamps on the audit entry rather
  than from a stopwatch, so it is the same number the log shows. The long
  tail is a person walking back to their desk and is not a fault. What it
  is useful for is the other end: a p50 in milliseconds means grants and
  policy are doing the work, and a p50 in tens of seconds means somebody is
  answering nearly every signature by hand, which is how approval fatigue
  starts ([architecture §16](architecture.md#16-security-considerations)).
  The buckets run to 3600s because that is the signing budget
  ([architecture §9](architecture.md#9-approval-engine-and-policies),
  decision AJ), so a request that ran the clock out lands in the top bucket
  rather than past every bucket there is. They stopped at 300s while the
  budget was five minutes, and had to move with it. `ssh_auth` has about two
  minutes before sshd gives up on the login regardless, so its p99 living
  anywhere near the top of this histogram is a different fault from a
  signature's.
* **`ladulas_signatures_total`** — signatures actually produced with a key
  held here. It trails approvals, and the gap is real rather than an error:
  a request can be approved and then never signed, which is what a
  requester that gave up looks like. Approvals with no signatures following
  them is the interesting direction.
* **`ladulas_audit_entries_total{event}`** — every line written to the
  audit log, by event: `request`, `decision`, `signature`, `grant`,
  `lifecycle`, `key_transfer`, `error`. The counters above are derived from
  the same stream, so this is both a superset and the way to see the events
  that have no counter of their own. **`{event="key_transfer"}` is the one
  to alert on** — a portable key left or arrived at this machine
  ([decision S](architecture.md#10-keys-and-key-storage)), which is rare,
  deliberate, and the thing somebody wants to know about immediately if it
  was not them. `lifecycle` covers unlocking, sealing, key imports and the
  daemon starting.

## State gauges — the daemon

These are read off the running instance at scrape time rather than kept in
step with it, so they answer for the moment they were asked and there is no
mirror to go stale. Reading them takes the instance's read lock and
touches no disk; they are as cheap as the scrape interval makes them.

* **`ladulas_lock_state{state}`** — 1 for the current state and 0 for the
  other three (`sealed`, `unlocked`, `locked`, `uninitialized`). Every
  state is emitted rather than only the current one, so that "sealed"
  cannot be confused with "the daemon stopped answering" — the second is
  the metric disappearing, and it is a different problem.
  [Architecture §10](architecture.md#10-keys-and-key-storage) is what the
  four mean; `sealed` after a restart is the design rather than an
  incident, and `sealed` an hour later means nobody has unlocked it and
  nothing on that machine can sign.
* **`ladulas_lock_state_since_timestamp_seconds`** — when it entered that
  state. The useful reading is `time() - ` this while sealed, which is how
  long the box has been unable to sign.
* **`ladulas_keys`, `ladulas_grants`, `ladulas_key_offers`** — this
  instance's own keys, live TTL grants, and keys a peer has handed over
  that are waiting for somebody to accept or refuse
  ([decision S](architecture.md#10-keys-and-key-storage)). A non-zero
  `key_offers` needs a person: nothing else will ever mention it on a box
  nobody is sitting at, and it stays until it is answered.
* **`ladulas_endorsements{state}`** — promises other holders of a key have
  made about a machine
  ([decision AG](architecture.md#9-approval-engine-and-policies)), by what
  this instance does with them. `live` is the one to watch: it is this
  instance signing for a paired machine **without asking anybody**, which is
  the number that answers "is this box auto-signing, and under whose
  promise" on a machine nobody is sitting at. `carried` is a copy it
  presents when it borrows and never acts on, and is the ordinary state on a
  keyless requester. `inert` is one it holds and will not apply, which is
  usually a pairing revoked since the promise was made. A `live` count that
  is not zero and that nobody expected is what `ladulas endorsements list`
  is for.
* **`ladulas_borrowed_keys{state}`** — keys that live on a paired peer, by
  whether they can be used right now: `usable`, `unreachable`, or
  `held_here` for one this instance also holds its own copy of.
  **`unreachable` is the ordinary state of a key on a phone in a pocket and
  is not a fault** ([decision N](architecture.md#10-keys-and-key-storage));
  what is worth watching is `usable` falling to zero on a machine that has
  no keys of its own, because that box can no longer sign anything.
* **`ladulas_peers{state}`** — paired peers by whether a link is up
  (`online`/`offline`). A desktop peer that is `offline` for long is a
  fault; a phone is `offline` nearly always by construction, since it never
  listens and dials only when somebody opens the app
  ([architecture §3](architecture.md#3-system-overview)). The gauge cannot
  tell you which kind a peer is — it has no identifying label and will not
  get one — so read it against how many of the pairings are phones.
* **`ladulas_pending_pairings`** — pairings waiting for somebody to answer.
  **Every non-zero value needs a person, and nothing will time it out**: a
  pairing does not expire, and the command that raised it is usually long
  gone ([decision M](architecture.md#7-identity-pairing-and-trust)).
* **`ladulas_peer_listeners`** — how many addresses the peer channel is
  bound to. Zero means no peer can reach this instance at all, which is
  either peering switched off deliberately or a sealed store — the identity
  key that authenticates the channel lives inside the store, so a sealed
  instance cannot listen.

**The store gauges are absent rather than zero while the store is sealed.**
`keys`, `grants`, `key_offers`, and everything from the peer node, are only
emitted when there is a store open to read them from. "No keys" and "cannot
say" are different answers, and a dashboard that read the second as the
first would show every machine losing all its keys every time it was
sealed. Alert on `ladulas_lock_state{state="sealed"}` instead, and treat
absent gauges as its consequence.

## Wake-ups — the relay

The pair to watch is `ladulas_relay_wakeups_total{outcome="delivered"}`
against everything else that outcome label can be. Only `delivered` means a
notification went out; the rest are all reasons one did not, and each of
them is a different problem.

* **`ladulas_relay_wakeups_total{style,outcome}`** — `style` is `alert` (a
  banner asking for a person) or `silent` (a background wake for something
  a grant will answer). The outcomes:
  * `delivered` — a push was accepted by the platform. This is the number
    the service exists to produce.
  * `throttled` — paced against the per-instance limit, five seconds for
    alerts and sixty for silent wakes. Occasional throttling is the
    mechanism working during a burst of commits. Sustained throttling on
    one instance is the leaked-instance-id case
    ([architecture §11](architecture.md#11-wake-ups-and-push-all-optional)):
    the harm is bounded to a banner, and the relay cannot tell you which
    instance without a label it will not have.
  * `unknown` — no device has ever registered that instance id, or the
    registration has been dropped. A requester that keeps producing this is
    knocking at a door that was never there.
  * `unregistered` — the platform says the token is dead; the registration
    is dropped as this is counted, and the requester drops the route when
    it reads the answer. **A spike here is a phone that was reinstalled or
    restored**, and it should be followed by a registration within minutes
    of somebody next opening the app. If it is not, the phone is not coming
    back on its own.
* **`ladulas_relay_registrations_total{platform}`** — registrations
  accepted. It rises on installs, reinstalls and token rotations, and not
  on use, so on a relay serving one person it is close to flat: on guppy it
  has one device registered and the counter moves a handful of times a
  year. A registration that is refused because the instance id belongs to
  another identity does not appear here — it is a `permission_denied` in
  the RPC counter below, which is where the abuse case shows up.
* **`ladulas_relay_pushes_total{platform,outcome}`** — the call to APNs
  itself, by what it answered: `sent`, `unregistered`, or `failed`. `failed`
  is the one that is nobody's fault but yours to fix — a signing key Apple
  no longer accepts, the wrong host for the token's environment, or APNs
  being down. Wake-ups with `outcome="delivered"` and pushes with
  `outcome="sent"` should track each other exactly; they are two counts of
  the same event kept apart because one is the answer given to the
  requester and the other is what the platform said.
* **`ladulas_relay_push_duration_seconds{platform}`** — time waiting for
  APNs, which is the only thing this service waits for. It answers the
  question a slow relay always raises: whether the slowness is Apple's. A
  p99 in the tens of milliseconds is ordinary; seconds mean APNs is
  struggling or the host's egress is.
* **`ladulas_relay_devices`** — registrations held, read from the store at
  scrape time. It is the whole of this service's state, so **a drop to zero
  that nobody caused is a state file that went missing**, and every phone
  will re-register only when its app is next opened.

## RPC — the relay

* **`ladulas_relay_rpc_requests_total{procedure,code}`** — every call
  served, by procedure (`ladulas.v1.RelayService/Register`, `/Wake`) and
  connect status code. This is where calls that never reached a wake-up
  outcome are counted, which makes it the companion to every counter above:
  `unauthenticated` is a signature that did not verify or a clock too far
  from the relay's, `permission_denied` is an instance id claimed by a
  second identity, `unavailable` is a push that failed, and
  `invalid_argument` is a malformed call.
* **`unauthenticated` on an open port is background noise, not an
  incident.** The relay is reachable by anything on the tailnet and the
  signature check is the gate; what is worth reading is the ratio, since
  the requesters that matter never produce one except when a clock has
  drifted.
* **`ladulas_relay_rpc_duration_seconds{procedure}`** — time in the
  handler. `Wake` includes the push, so it should sit just above
  `push_duration_seconds`; a gap between them is time spent in the store or
  the throttle rather than at Apple.

## Conventions

* **A labelled counter does not exist until it has counted something.**
  `ladulas_relay_wakeups_total{outcome="unregistered"}` is absent on a relay
  where no token has ever died, which is not the same as zero and will
  break an alert written as `== 0`. Use `absent()` deliberately, or compare
  rates.
* **Counters reset when the process restarts**, and the daemon is a user
  unit that goes down with the session. Read them as rates, and use
  `process_start_time_seconds` to tell a restart from a quiet week.
* **A gauge that is absent is a statement.** The daemon emits nothing it
  would have to guess at: the store gauges disappear while sealed and the
  peer gauges disappear when peering is off, in both cases because there is
  no honest number to report.
* **Unbounded values never become labels.** Fingerprints, instance ids,
  request ids, key labels, peer names and file paths are all things this
  process knows and none of them appear here — partly for cardinality and
  mostly because of what the port is
  ([architecture §14](architecture.md#14-management-surface-the-control-socket-and-cli)).
  Enum-derived labels fall back to `other` for a value this build has no
  name for, so a peer running a newer schema cannot invent a time series.
* **Nothing here is a leader-only metric**, because nothing in Ladulås
  elects a leader. Every number is about the one process that produced it.
