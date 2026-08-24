# Ladulås — operations

For somebody running an instance, or working out why one is not signing
anything. It assumes the reader is at a terminal on the machine, or has
SSH to it, and that they are the account the instance belongs to — that is
the whole of the authority model
([architecture §14](architecture.md#14-management-surface-the-control-socket-and-cli)).

| Document | What it settles |
|---|---|
| [`README.md`](../README.md) | What the repository holds, how to build and run it, every configuration flag, and what is still missing. |
| [`docs/architecture.md`](architecture.md) | How the service is built: roles, process model, subsystems, protocol, and the decisions behind them. |
| **`docs/ops.md`** (this) | Running it: dependencies, ports, bootstrap order, failure modes and what to do about each. |
| [`docs/observability.md`](observability.md) | Every metric the daemon and the relay export, and what a change in one means. |

What this document does **not** cover: why anything is built the way it is
(architecture), or what an individual metric means (observability) — each
failure mode below names its signal, and observability defines it.

> **There is no cluster and no deployment pipeline for the daemon.** It is
> a systemd **user** unit on a laptop or a headless box, one process per
> logged-in account, installed with `go install`. "Operations" here means
> one person's machines. The relay is the only piece that is a service in
> the ordinary sense, and there is exactly one of it.

## What the service is

An instance is two halves that fail separately, and knowing which half is
broken is most of the triage:

* **The outer half** — the agent socket, the control socket, the audit log
  and the lock state. It exists from the moment the process starts and does
  not need the store. A daemon in this state answers `ladulas status` and
  `ladulas unlock`, lists no keys, and signs nothing.
* **The inner half** — the vault, the approval engine, the project cache
  and the peer channel. It is built by unsealing and destroyed by sealing.

**A sealed instance is not a broken instance.** It is the state every
daemon comes up in unless the keychain is enrolled, and the fix is a person
typing a passphrase. Almost everything below that looks like a failure is
this, and `ladulas status` says so in one line.

## Components

| Repository path | What it is to us |
|---|---|
| `cmd/ladulasd` | The daemon. What runs under `ladulas.service`. |
| `cmd/ladulas` | The management CLI, and — in a build with `-tags gui` — the desktop application, `ladulas gui`. Both are clients of a running daemon; neither opens the store (decision Z). |
| `cmd/ladulas-sign` | The git signer, run by git as `gpg.ssh.program`. Not a service. |
| `cmd/ladulas-relay` | The wake-up relay. One instance, on guppy, on the tailnet. |
| `pkg/` | The seventeen packages a mobile core binds against, which is why they are not `internal/` (§18, §21). |

## Deployment shape

| Role | Configuration | Runs |
|---|---|---|
| Desktop instance | `contrib/ladulas.service`. `LADULAS_UNLOCK=ask-password`, suspend and session-lock triggers on | One per logged-in account, `~/go/bin/ladulasd` |
| Desktop application | `contrib/ladulas.desktop`, started at login by the session's autostart and attached to the daemon over the control socket. Not a unit | Zero or one per session, `~/go/bin/ladulas gui` |
| Headless instance | `contrib/ladulas.service` with `LADULAS_CONSOLE=off`; approvals come from a paired peer | One per account on the box |
| Relay | `~/.local/bin/ladulas-relay` under a user unit bound to guppy's tailnet address, APNs key through systemd `LoadCredential=` | Exactly one |

**There is one unit on a desktop too, and the window is not it.** Until
decision Z there were two — `ladulas.service` and `ladulas-tray.service` —
and they were alternatives rather than companions, because the tray was an
instance in its own right and the two fought over the agent socket: the
second to start lost it and exited saying an agent was already listening, an
error naming the socket rather than the mistake. They declared `Conflicts=`
on each other so systemd refused first. Both are gone: the desktop
application holds no keys and serves no socket, so it starts from a
`.desktop` entry beside the daemon rather than instead of it, in any order,
as many times as somebody clicks it.

### Installed from a package rather than `go install`

Two things move. The binaries are at `/usr/bin` instead of `~/go/bin`, which
is what the packaged units' `ExecStart` says — `package()` rewrites the
`%h/go/bin` that `contrib/ladulas.service` carries for the `make install`
case. And the units themselves come from `/usr/lib/systemd/user/` rather than
`~/.config/systemd/user/`, so a hand-copied unit from an earlier install
**shadows the packaged one and keeps pointing at `~/go/bin`**: an upgrade
then changes nothing, and the running daemon is whatever was last
`go install`ed. `systemctl --user cat ladulas` says which file is in force,
and that is the check when a packaged upgrade appears to have done nothing.

The same crossing runs the other way when you want the tree on a box the
package owns: `ExecStart` is `/usr/bin/ladulasd`, so installing into
`~/go/bin` and restarting brings the packaged binary back up and changes
nothing. `make install-dropin` writes a drop-in overriding `ExecStart` to
the installed `ladulasd`, and `make uninstall-dropin` removes it;
`systemctl --user show ladulas.service -p ExecStart --value` resolves the
unit and every drop-in together, which `cat` does not.

The packaged `contrib/ladulas-relay.service` is generic — site values in
`~/.config/ladulas-relay/env`, the `.p8` at
`~/.config/ladulas-relay/apns.p8`. The relay running on guppy predates it and
has its address and key ids in the unit body; the row above still describes
that one.

**Replicas are not a thing here, and adding one would break the store.**
The store document is held whole in memory and rewritten whole on every
change, with no lock and no compare-and-swap, so a second process opening
it can silently discard everything the first has learned
([decision L](architecture.md#14-management-surface-the-control-socket-and-cli)).
One process owns `store.age`; every other path to it goes through the
control socket.

The relay is not replicable either, for a smaller reason: its state is a
JSON file it rewrites, and two of them would each hold half the devices.

## Runtime dependencies

| Dependency | Needed for | What happens without it |
|---|---|---|
| A person with the passphrase | Unsealing after every restart | The daemon serves, lists no keys and signs nothing, until somebody runs `ladulas unlock` |
| logind over D-Bus | Lock on suspend and session lock | The daemon starts and says so; the store stays unlocked through a suspend, which is the security posture silently weakened |
| Secret Service keyring | Only if `ladulas keyring enrol` was run | Falls back to the passphrase, which is the default posture anyway ([decision I](architecture.md#10-keys-and-key-storage)) |
| A reachable paired peer | Approving on a keyless or headless box | Requests reach nobody and time out; `source="no_approver"` |
| The tailnet (or any IP path) | Peer links, and reaching the relay | Peers go offline; the phone can neither collect nor be woken. Nothing is lost — requests wait as long as the requester does |
| The relay + APNs | Waking a phone that is not already polling | Approvals degrade to poll-on-open. **ssh authentication does not degrade** — it needs the wake-up, so a phone-held key stops being advertised |
| `git` on PATH | `ladulas-sign` collecting commit context | The signer still signs; the prompt loses the diff and the branch |

**Truly required: the daemon's own store, and a person to unlock it.**
Everything else in that table degrades to something the design already
calls a normal state.

## Endpoints and ports

| Endpoint | Default | What is on it |
|---|---|---|
| Agent socket | `$XDG_RUNTIME_DIR/ladulas/agent.sock` | The SSH agent. `SSH_AUTH_SOCK` points here. 0600 in a 0700 directory, plus a peer-uid check |
| Control socket | `$XDG_RUNTIME_DIR/ladulas/control.sock` | `SigningService` (`ladulas-sign`) and `ControlService` (the CLI). Same gate |
| Peer channel | TCP 7373, private and tailnet addresses only | Pinned-TLS connect RPCs from paired instances. Public binds need `--peer-listen-public` |
| Daemon debug | **off** | Prometheus metrics and pprof, when `LADULAS_DEBUG_ADDR` names an address |
| Relay API | TCP 8443 (guppy's tailnet address) | `RelayService`, cleartext HTTP/2 by design — WireGuard is the transport security |
| Relay debug | `127.0.0.1:8444` | Prometheus metrics and pprof |

**Nothing authenticates the debug ports.** A heap profile of an unlocked
daemon is a copy of a heap that holds the store key, and the relay's holds
a push key and a device list; the address they are bound to is the whole of
the protection, and a non-loopback bind is logged as the widening it is.

## Data flows

### 1. Signing with a key that is here

```
ssh / git ──▶ agent or control socket (uid-checked)
                │  parse: SSHSIG, or RFC 4252 §7 / hostbound blob (§4)
                ▼
          approval engine ── hard rules ─▶ deny, audited
                │           ── policy / TTL grant ─▶ approve, notified
                ▼
          fan out to eligible approvers: local prompt, paired peers
                │  first response wins, everyone else cancelled
                ▼
          sign with the vault's key ──▶ audit: decision, then signature
```

The weight is in the fan-out and the timeout. An SSH login has about two
minutes before sshd gives up regardless of what the policy says; a git
signature has minutes to spare because git waits happily. A request that
reaches no approver is not an error until it times out — it sits, which is
why `pending` and `no_approver` are different signals.

### 2. Signing with a key that is on a phone

```
ssh ──▶ agent ──▶ key resolves to a borrowed key (decision N/T)
                    │
                    ├─ holder polling? ──▶ hand it down the open poll
                    │
                    └─ no poll ──▶ park in the inbox
                                     │
                                     ▼
                              relay ──▶ APNs ──▶ phone
                                     │
                       phone opens/wakes, FetchPending ◀────┘
                                     │
                       holder's own engine decides and signs
                                     │
                       AnswerPending ─▶ signature ─▶ ssh
```

**The wake-up is load-bearing on this path and only this one.** Everything
else degrades to poll-on-open; an ssh login cannot, because of
`LoginGraceTime`. That is why a holder with no wake-up route is not
advertised in the agent's identity list at all
([decision T](architecture.md#19-decisions-resolved-2026-08-08-extended-2026-08-09)).

### 3. Waking a phone

```
requester ──(signed RelayCall, https or tailnet http)──▶ ladulas-relay
                                                            │
                                             devices.json lookup by
                                             opaque instance id
                                                            │
                                                            ▼
                                              APNs (api.push.apple.com)
                                                            │
                                                   empty payload,
                                              one of two fixed sentences
                                                            ▼
                                                          phone
```

The relay is never told a request, a fingerprint or a peer. What it can
learn from a full read of its database is which devices exist and roughly
how often somebody signs something. A dead token answers
`WAKE_OUTCOME_UNREGISTERED`, the registration is dropped as that is
counted, and the requester drops the route — which is the half of token
rotation that works while the phone is in a drawer.

## Where state lives

| Store | Path | Authoritative for |
|---|---|---|
| The encrypted store | `~/.local/share/ladulas/store.age` | Keys, identity key, trust records, pending pairings, grants, wake-up routes, borrowed-key cache |
| The audit log | `~/.local/share/ladulas/audit.jsonl` | Every request, decision, signature and transfer. Outlives the store's key deliberately |
| The policy | `~/.config/ladulas/policy.json` | Auto-approve, deny and prompt rules. Re-read on SIGHUP and on `Reload` |
| Project pages | `~/.local/share/ladulas/projects/` | What this instance has read of peers' projects. Sealed with the same key; a cache, discardable |
| Relay registrations | `%S/ladulas-relay/devices.json` | Device tokens by opaque instance id. The whole of the relay's state |

The store is a plain age file with scrypt passphrase recipients, so
`age`/`rage` plus the passphrase opens a backup of it with no Ladulås
involved. That is the recovery path of last resort and it is deliberate.

## Bootstrap order

1. **`go install ./cmd/ladulasd ./cmd/ladulas`**, then
   `systemctl --user enable --now ladulas.service`. Order does not matter
   here any more: a daemon with no store comes up uninitialised and serving
   rather than exiting, which used to be a restart loop under
   `Restart=on-failure`.
2. **`ladulas init`** — creates the store, the identity key and the default
   policy through the running daemon, and leaves it unlocked. Asks for the
   passphrase twice.
3. **`ladulas keys generate <name>`** — or `keys import`. Add the public
   half wherever it needs to go; nothing does that for you.
4. **`ladulas pair --listen --intent <approver|requester|mutual>`** on the
   machine displaying the code and **`ladulas pair <host:port> --code
   <code>`** on the other, then **`ladulas pairings approve`** if the
   confirmation outlived the command. The intent is required and settles
   both sides; the joining side has no direction flag of its own
   ([decision AD](architecture.md#7-identity-pairing-and-trust)). Pairing
   grants directions, never keys.
5. **`ladulas peers allow <peer> --approve --key <label>`** (or
   `--all-keys`) — the separate decision that lends a key. Its flags
   describe the state wanted, so anything left out is withdrawn. A pairing
   that skipped this is correct and useless, which is
   [M12's discovery](architecture.md#20-milestones).
6. **`export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/ladulas/agent.sock`**, and set
   `gpg.ssh.program`/`user.signingkey` for signing.

Out of order, the failures are quiet rather than loud: a pairing with no
key allowed announces an empty key list, and an agent socket exported
before `init` lists nothing.

## Failure modes

### Every ssh login is refused, with `agent refused operation`

ssh says nothing useful about why; the audit log does. Historically this
was **the request classifying as opaque**: OpenSSH ≥ 8.9 authenticates with
`publickey-hostbound-v00@openssh.com` rather than `publickey`, and an agent
that knows only the RFC 4252 blob denies the real one by hard rule, before
anybody is asked. It cost most of a debugging session in M12 and the fix is
in; what is left is the shape of the symptom.

**Signal:** `ladulas_approval_decisions_total{source="hard_rule"}` rising
with every login, and an audit entry naming the method.
**Action:** read `ladulas audit`. A hard-rule denial names what it refused.
If it is a classification failure against a client nobody has tested,
that is a bug in `pkg/agent/classify.go` rather than a configuration
problem.

### The agent lists nothing and nothing can sign

**Signal:** `ladulas_lock_state{state="sealed"} 1`, or `ladulas status`
saying `sealed`. The store gauges are absent rather than zero.
**Action:** `ladulas unlock`. If a `systemd-ask-password` prompt is
standing in somebody else's session, `status` says so — either answers, and
whichever wins withdraws the other. After a reboot this is the expected
state, not an incident.

### A signature hangs and then times out

**Signal:** `ladulas_approval_decisions_total{source="timeout"}` or
`{source="no_approver"}`; `ladulas_peers{state="online"}` at zero on a box
that has no local approver.
**Action:** on a headless box, check that a peer is paired and reachable —
`ladulas status` lists both. `no_approver` means the engine had nowhere to
send it at all: nothing retries that into working, and on a machine whose
only approver is a phone it means the phone has no route and is not
polling.

**Not to be confused with the denial that names a peer.** Until 2026-08-19
a refusal reading `<peer>: no approver is available to answer` was a
different failure wearing the same source: the peer had answered, instantly,
to say it had nobody to ask, and that answer won the fan-out against the
local prompt before anybody could look at it. Every signature on the machine
failed at once and deterministically, and unpairing the peer was the only
cure. It is fixed — a peer's `no_approver` is a report and not a decision
([decision AC](architecture.md#9-approval-engine-and-policies)) — so the
tell is worth keeping: a `no_approver` denial that carries a peer's name
and arrives instantly rather than after a wait is this, and means the
binary predates the fix.

### A key that is on the phone is missing from `ssh-add -l`

This is usually correct behaviour rather than a fault, and there are three
different reasons for it.

**Signal:** `ladulas_borrowed_keys{state="unreachable"}` non-zero, or the
key absent from `ladulas keys list` entirely.
**Action:** `ladulas keys list` shows borrowed keys whether or not the
holder is there, with a last-seen — that is the surface that can tell the
truth, because the agent protocol has no way to say "present but
unavailable". Then, in order: the holder may not have announced a wake-up
route (notifications off — the key is deliberately not advertised), the
key may have its agent-offer setting off (still signs when named), or the
peer may never have been allowed the key.

### The phone is never woken

**Signal:** `ladulas_relay_wakeups_total{outcome="unknown"}` rising, or
`{outcome="unregistered"}`, or `ladulas_relay_devices` at zero.
**Action:** an entry in the relay's `devices.json` is the fastest way to
tell the phone's half from the daemon's. An entry there means the phone
reached the relay, so a missing push is the requester's problem — a stale
daemon, or a route never announced. No entry means the phone has not
registered, which needs somebody to open the app.

**Do not reach for a collapse id to tidy up a burst of pushes.** It does
not merge notifications, it makes each push *replace* the last, and iOS
updates an unread one without alerting again — so the first wake-up gets
through and every one after it is swallowed, while every log on the sending
side reports success. It cost most of a day, and it was settled in a minute
by sending three pushes six seconds apart and counting banners.

### A pairing never completes

**Signal:** `ladulas_pending_pairings` non-zero and staying there.
**Action:** it needs a person, and nothing will time it out. `ladulas
pairings list` is where one is found; `approve`, `reject` or `withdraw`
ends it. A sealed instance can neither list nor answer one, because pending
pairings live in the store — that is a stated cost, not a bug.

### The CLI says nothing is listening, but the daemon is running

**Action:** compare the socket paths. `ladulas status` prints the ones it
is looking at; the unit sets `LADULAS_AGENT_SOCK` and `LADULAS_SOCK`
explicitly, and a shell without them looks in `$XDG_RUNTIME_DIR/ladulas/`.
A daemon belonging to another account is invisible on purpose.

### The desktop window says "Nothing is running", or no prompt appears on screen

The desktop application is a client of the daemon (decision Z), so there are
two processes and either can be missing. The tray label is the first
signal — "Ladulås" means attached, "Ladulås — not attached" means it is
retrying every two seconds and no prompt is going to appear there.

**Action:** `systemctl --user status ladulas` for the daemon, and
`pgrep -af "ladulas gui"` for the window. Starting the daemon is enough; the
front end attaches on its own without being restarted. If both are running
and the label still says not attached, they are looking at different
sockets — the unit sets `LADULAS_SOCK` explicitly and a desktop session
started from a menu entry does not, so `ladulas status` and the unit's
environment are what to compare.

A prompt that appears nowhere at all, with the daemon up and the window
attached, is the ordinary sealed store: nothing can sign, and the window shows
the passphrase panel in place of its screens until it is unlocked — which it
opens itself, once, the moment it attaches to a sealed instance.

### The daemon died and the store is sealed again

```
panic: runtime error: invalid memory address or nil pointer dereference
bufio.(*Writer).Flush(...)
net/http.(*response).Flush(...)
connectrpc.com/connect.(*ServerStream[...]).Send(...)
…/internal/app.(*socketApprover).send(...)
…/internal/app.(*socketApprover).Decide(...)
```

The agent stops, every paired instance drops, the unit restarts and the store
comes up sealed — so the first thing anybody notices is that signing has stopped
and a passphrase is being asked for again.

**Cause.** A prompt was sent to a front end whose RPC handler had already
returned. The stream belongs to that handler and dies with it, and what is left
is an `http.response` whose buffered writer has gone back to a pool, so the write
dereferences nil inside net/http and takes the process down. Unregistering the
approver was not enough on its own: the engine has already taken its list of
approvers by the time it prompts. It was reached by killing `ladulas gui` while a
prompt was on its way to it — which is an ordinary thing for a front end to do,
including crashing.

`internal/app.socketApprover` now refuses to send once the handler has stopped,
and the handler waits for any send already under way before returning. A front
end that goes away takes its own approver with it and nothing else, which is what
decision Z always claimed.

**Action:** if this signature appears again, it is a send that got past that
guard — the stack says which kind of event — and the daemon needs `ladulas
unlock` after the restart either way. `journalctl --user -u ladulas -n 60` has
the trace; `restart counter is at N` in the unit's log says how often it has
happened.

### The desktop application is running and does nothing at all

The tray icon is there, `pgrep -af "ladulas gui"` finds the process, the label
says `Ladulås` — and every item on the menu does nothing, no window opens, and
no approval prompt appears again for as long as it runs. Signing does not fail
loudly: each request sits until the requester's timeout, so what a person sees
is `git commit` hanging and then giving up, with a desktop application that
looks like it is running. Choosing `Quit` does nothing either, which is the
quickest way to tell this apart from anything else.

**Two different causes have produced exactly this**, and both are fixed;
if it happens again, tell them apart before doing anything else.

*The loop on the wrong goroutine.* Wails compares every main-thread dispatch
against the thread its own `init` locked, so a GTK loop started from any other
goroutine deadlocks the first time a main-thread callback makes another
main-thread call — which is what `App.cleanup` does, and both closing the last
window and choosing Quit go through it (§12, decision AA). `application.Run`
is called from `gui.Run` itself now, and `DisableQuitOnLastWindowClosed` is set
besides. **Look at what `Run` is called from.**

*A second copy of the application.* Two GApplications with the same id make the
second a remote instance: its `activate` never fires, so it can never create a
window, while its tray icon appears and its menu does nothing. Starting the
menu entry while one was already running was enough. It is prevented now — a
second launch raises the first one's window and exits — but an *old* binary
started alongside a new one still does it, and the giveaway is in the log:

```
Gtk-CRITICAL **: gtk_window_present: assertion 'GTK_IS_WINDOW (window)' failed
```

**Action:** `ps -eo pid,args | grep "ladulas gui"` — and grep for the absolute
path as well as the bare name, because a `.desktop` entry runs
`/usr/bin/ladulas gui` and `pkill -f "^ladulas gui"` does not match that.

**Action:** `pkill -f "ladulas gui"` and start it again — `ladulas gui`, or the
menu entry. Nothing is lost: the daemon holds the keys, the agent and the
engine (decision Z), a front end that goes away only takes that approver with
it, and a request that was waiting on it is refused rather than left. Then
compare what is running against the tree, the way the section below says: this
is exactly the class of symptom that looks like a bug in the feature and is a
build from before it.

### The desktop application starts but no tray icon appears

```
Failed to register: Timeout was reached
systray error: failed to register: The name is not activatable
```

The icon is a **StatusNotifierItem**, and this session has no
StatusNotifierWatcher on its bus to show one. That is the ordinary state for
i3, sway's bar, polybar and most others: their tray is XEmbed, which is a
different protocol, and only GNOME (with an extension), KDE and a few panels
own an SNI watcher. `busctl --user list | grep -i statusnotifier` says which —
an `org.kde.StatusNotifierWatcher` or `org.x.StatusNotifierWatcher` that is
present rather than `(activatable)` is a session that can show the icon.

**What is lost is the menu and the attached/not-attached label, and nothing
else.** Approval prompts are windows, and windows do not need a tray, so the
machine goes on signing. `ladulas status`, `ladulas unlock` and `ladulas lock`
are the same verbs the menu would have called.

**Action:** run something that owns the watcher name. On i3 with its XEmbed
tray, `snixembed` bridges the two — `pacman -S snixembed`, then
`exec --no-startup-id snixembed &` in the i3 config beside the bar, which
needs `tray_output` set (it is). The desktop application logs a warning of its
own saying this, so a bare D-Bus error is not the only thing to go on.

### The change that was tested is not the change that is running

The daemon runs from `~/go/bin`, so a build that compiles and passes tests
is still not a build that is running. **Compare the binary's mtime against
the process start time before believing a symptom** — "the feature does
nothing" and "the feature is not running" look identical from the outside.
`make install && systemctl --user restart ladulas.service`, and then unlock
it again. The desktop application is a second process running from the same
directory, so a change to it needs the window restarted as well — the
daemon's restart does not carry it, and an attached front end from the old
build reattaches to the new daemon perfectly happily.

## What to watch, in order

1. **`ladulas_lock_state{state="sealed"}`, with
   `time() - ladulas_lock_state_since_timestamp_seconds`.** A sealed box
   signs nothing. Everything else on this list is downstream of it.
2. **`ladulas_approval_decisions_total{source="no_approver"}` and
   `{source="timeout"}`.** Requests that reached nobody. Nothing retries
   them, and on a headless box this is the failure that looks like a hung
   terminal.
3. **`ladulas_audit_entries_total{event="key_transfer"}`.** Key material
   arrived or left. Rare, deliberate, and the thing to know about
   immediately if it was not you.
4. **`ladulas_relay_wakeups_total{outcome!="delivered"}` and
   `ladulas_relay_pushes_total{outcome="failed"}`.** The phone is not being
   woken; approvals still work by poll-on-open, ssh with a phone-held key
   does not.
5. **`ladulas_approval_decisions_total{source="hard_rule"}`.** Never
   routine: an unclassifiable payload, a forwarded-agent request, or a git
   context that does not match the commit it would sign.

## Common operations

* **Unlock a machine reached over SSH.** `ladulas unlock` — it reads the
  passphrase without echoing and sends it over the uid-checked socket.
  `--stdin` exists for scripts and for a shell with no tty.
* **Suspend approval here without losing remote signing.** `ladulas lock`.
  The key stays in memory and paired approvers go on answering; `ladulas
  lock --seal` wipes it and needs the passphrase to come back.
* **Wait for a machine somebody has to unlock.** `ladulas wait unsealed`
  blocks until it is, and exits 0. It is a long poll, not a loop.
* **Pick up a policy or store change without a restart.** `systemctl --user
  reload ladulas.service`, or SIGHUP. Key and grant changes made through
  the CLI need neither — they land in the document the daemon is serving.
* **Read what happened.** `ladulas audit -n 50`. The metrics say a decision
  was made; this says which and to whom.
* **Keep `main` compiling.** A consumer of `pkg/` builds against a
  pseudo-version of this branch and not against a release, so a change it
  needs is a change pushed to `main` (§21).

## Security

* **Inbound, local:** both unix sockets are 0600 in a 0700 directory with a
  peer-uid check. Possession of the account is the whole authority; the
  store passphrase is not a management credential and does not gate
  `status`.
* **Inbound, network:** the peer channel's unauthenticated surface is the
  TLS handshake. An identity that is neither paired, nor arriving at an
  open pairing window, nor half way through a written-down pairing gets a
  handshake and a refusal. The relay's is the signature check on every
  call, and a clock more than the allowed skew from its own is refused.
* **Outbound credentials:** the APNs `.p8` reaches the relay through
  systemd `LoadCredential=` and is never in the unit's environment. The
  daemon has no outbound credentials at all — a peer is authenticated by
  the identity key in its own store.
* **Not a write path:** the metrics and pprof ports are GETs and change
  nothing, which is not the same as harmless — a heap profile of an
  unlocked daemon contains the store key. Bind them where only the machine
  can reach them.
* **Secrets that exist:** the store passphrase (never on a command line,
  never logged, wiped after the KEK is derived), the DEK (in memory only
  while unsealed, or in the keychain if enrolled), and the relay's signing
  key. `ttrun.env` and unit files hold references, never values.

## Not in place yet

* **The relay's unit file is not in the repository.** The one on guppy sets
  the tailnet listen address, the APNs topic, key id and team id, and
  `LoadCredential=` for the `.p8`. `contrib/` has the daemon's unit only,
  so a second relay would be assembled from this document rather than
  installed.
* **No alerting exists.** The metrics are there and nothing scrapes them on
  a schedule; the watch list above is a description of what an operator
  should look at, not of something that pages anybody.
* **Socket activation is designed and unbuilt** ([architecture
  §13](architecture.md#13-platform-notes)), so the agent socket exists from
  start-up rather than on first connection.
* **Log aggregation is `journalctl --user -u ladulas.service`.** There is
  nowhere central for the audit logs of several machines to be read
  together, and the audit log deliberately stays on the machine that wrote
  it.
