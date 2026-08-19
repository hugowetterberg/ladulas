# Ladulås

## The documents, and which question each one answers

| Document | Ask it |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Why anything is the way it is. **The design authority** — when the code and it disagree, it wins unless there is a concrete reason, and then the reason gets written down there. |
| [`docs/ops.md`](docs/ops.md) | What is broken and what to do about it: ports, bootstrap order, failure modes, the watch list. |
| [`docs/observability.md`](docs/observability.md) | What a metric means. |
| [`README.md`](README.md) | Build commands, every configuration flag, what is missing. |

**Read the relevant section before changing behaviour it describes**, and
**update the documents in the same commit as the change** — including
deleting the paragraph that described the old behaviour, which is the half
that gets forgotten. When behaviour is reversed, leave the history: what
the old shape was, what it cost, and what must not be reintroduced.
Prohibitions without their history read as taste and get overridden.

`make docs` checks that the four still link to each other; it runs as part
of `make test`.

**Architecture section numbers and decision letters are stable
identifiers.** Code comments cite them — `§10` in over a hundred of them,
`decision P` in fifty. Sections get corrected and extended; they are never
renumbered, and a decision letter is never reused. A new decision takes the
next free letter and goes in the table at the end of §19 with a dated
heading.

## The daemon on this machine is not the tree

Hugo's own instance runs as a systemd **user** unit from `~/go/bin`, so a
change that builds and tests is still not a change that is running. After
touching anything in `cmd/ladulasd`, `pkg/peer`, `pkg/approval`
or the store, reinstall and restart before concluding anything about live
behaviour:

```
make install
systemctl --user restart ladulas.service
```

**`make install`, not `go install`** — this machine has GTK 4 and
`webkitgtk-6.0`, so `ladulas` here is always built with the desktop
application in it (`-tags gui`, the Makefile's default `GUI_TAGS`). A
binary installed without it is a binary whose `gui` command refuses to run,
and the difference is invisible until somebody asks for a window.

`ladulas status` is the check. Compare the binary's mtime against the
process start time before believing a symptom — "the feature does nothing"
and "the feature is not running" look identical from the outside.

**The desktop application is a second process** (decision Z): `ladulas gui`
is a client of the daemon, started from a `.desktop` entry rather than a
unit, so restarting `ladulas.service` does not carry a change to it. After
touching `internal/gui` or `internal/frontend`, kill and restart the window
too — `pkill -f "ladulas gui"` and start it again — and say which of the two
a symptom is in before changing anything.

**Reinstall and restart without asking.** When a change touches the daemon
or the CLI, install it and restart the unit as part of the work — do not
stop to ask whether now is a good time, and do not hand the restart back as
a step for Hugo to run.

## Unlocking after a restart

The store comes up **sealed**: `LADULAS_UNLOCK=ask-password` and login
unlock is not enrolled, so the daemon has no key and the SSH agent offers
nothing until somebody unlocks it. Ask Hugo, which is the only part that
needs him — and do not wait for the `systemd-ask-password` prompt.

**Ask him to run it with the `!` prefix** (`! ladulas unlock`) so it runs in
the session and its output lands in the conversation. The passphrase is his
to type and must never be asked for, stored, or passed on a command line.
`--stdin` exists for scripts and for a shell with no tty; it is not a way
around that.

`ladulas lock` suspends approval here while leaving paired approvers able to
answer, and `ladulas lock --seal` wipes the key. Plain `lock` is not a way
to test sealed-state behaviour.

## The relay on this machine

`ladulas-relay.service`, a user unit bound to guppy's tailnet address,
running from `~/.local/bin`. Its shape and failure modes are
[ops.md](docs/ops.md#3-waking-a-phone); what matters when debugging a
missing push is that `~/.local/state/ladulas-relay/devices.json` is the
fastest way to tell the phone's half from the daemon's — an entry there
means the phone reached the relay, so a missing push is the requester's
problem.

`contrib/ladulas-relay.service` exists but **is not the unit that is
running**: it is the generic one the Arch packages install, taking its
address and key ids from `~/.config/ladulas-relay/env`. The live one has
those written into the unit body and lives only in
`~/.config/systemd/user/`. So do not read `contrib/` as a description of
guppy — `systemctl --user cat ladulas-relay` is that.

## Toolchain

`golangci-lint run` must be clean and `go test ./...` must pass. Protobuf is
regenerated only through `make generate` (buf), never protoc by hand.

**`main` has to stay green, and that is not a slogan here.** A consumer of
`pkg/` builds against a pseudo-version of this branch rather than against
a release, so a commit that does not compile is a commit nobody can build
anything from.

Metrics go in `internal/observe` and nowhere else: the packages that produce
the numbers expose a function field or a small interface, which is what
keeps a Prometheus client out of the phone's gomobile build. Never a
package-level collector, never `promauto`, never the default registry.

## `pkg/` is bound by something this repository cannot compile

Exported signatures in `pkg/` have to stay `gomobile`-bindable: a
parameter or result that is a map, a slice of structs, an interface or an
unexported type is one `gomobile` cannot bind, and it compiles perfectly
here, passes `go test ./...` here, and fails where it is bound. Nothing in
this tree catches it. So when a change to `pkg/` widens an exported
signature, **say so** rather than reporting it green.

`internal/` is exempt — nothing outside the module can reach it. §21 has
the rest of what nothing here checks, and decision AB is why `pkg/` is
public at all.

## Commits

Messages start with a lowercase letter and read as prose: a short evocative
subject, then a body saying what the change turned out to be and why the
alternative was rejected. No Co-Authored-By trailer. Work lands on `main`
directly — no feature branches until there is a real release.
