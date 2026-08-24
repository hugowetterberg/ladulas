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

## Nothing here describes a particular machine

**This file is committed, and Ladulås runs on more than one box** — which
is the whole point of it, a laptop approving for a headless box approving
for a phone. So a paragraph here that says "this machine" is a paragraph
that is wrong on every machine but one, and it will be read on all of
them. Unit paths, drop-ins, which package is installed, which webkit is
present, which host the relay is on: **none of that goes in this file.**
It goes in `CLAUDE.local.md`, which is untracked, is loaded after this file
on the box it is written on, and is the right place for "the daemon here
runs from …". Facts about a deployment that outlive one machine's setup
belong in [ops.md](docs/ops.md).

This is written down because it went the other way for a while: this file
carried a section describing Hugo's own box, and it drifted — it named the
wrong package and claimed a GTK 4 webkit the box did not have, so the
build it prescribed could not run there at all. A machine description in a
shared file is not merely misplaced, it is unverifiable by anyone standing
anywhere else, and it goes stale silently.

## The daemon you are debugging is not the tree

Ladulås is usually **installed** on the machine it is developed on, so the
running daemon and the checkout are two different things and a change is
not live until you have shown that it is.

**Check what is actually running before believing anything about live
behaviour.** `systemctl --user cat ladulas.service` is the one that
answers it: which unit file is in force — a package's in
`/usr/lib/systemd/user/`, a hand-copied one in `~/.config/systemd/user/`,
plus any drop-in — and which binary its `ExecStart` names. ops.md's
[installed from a package rather than `go install`](docs/ops.md#installed-from-a-package-rather-than-go-install)
has the ways those get crossed. `ladulas status` is the other half, and
note that `ladulas` on `$PATH` may not be the binary the daemon is —
compare mtimes against the process start time before believing a symptom.
"The feature does nothing", "the feature is not running" and "the feature
is not installed where the unit looks" are indistinguishable from outside.

**Which build command is right depends on the box.** `make install`
defaults to `GUI_TAGS=gui`, which is Wails' GTK 4 and wants
`webkitgtk-6.0`; a GTK 3 box needs `make GUI_TAGS=gui,gtk3 install` and a
headless one wants `make install-headless`. Getting it wrong is not a
partial install — `make install` builds `ladulas` first, so a missing
webkit fails in `pkg-config` and installs **nothing**, including
`ladulasd`, which needs no GUI and would have built fine. README's
[packages table](README.md) is which is which.

**Where a package owns the unit**, `ExecStart` names `/usr/bin/ladulasd`
and installing into `$GOPATH/bin` changes nothing that runs.
`make install-dropin` overrides `ExecStart` to the installed binary and
`make uninstall-dropin` takes it back out. Neither restarts the service:
that is deliberate, because a restart seals the store and somebody has to
unlock it again.

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

But **say what that did and did not do.** If the unit's `ExecStart` names a
binary you did not just write to, the restart brought that one back up and
the change is sitting unused wherever you installed it. Reporting "the
change is running" after that sequence is the specific wrong claim to
avoid; check, rather than assume the two paths agree.

## Unlocking after a restart

Restarting the daemon **takes the keys away**: unless login unlock is
enrolled, the store comes back **sealed** under
`LADULAS_UNLOCK=ask-password`, so the daemon has no key and the SSH agent
offers nothing until somebody unlocks it. An instance that was unlocked
before a deployment is not after it.

Unlocking is the part that needs Hugo. Do not wait on the
`systemd-ask-password` prompt — **ask him to run it with the `!` prefix**
(`! ladulas unlock`) so it runs in the session and its output lands in the
conversation. The passphrase is his to type and must never be asked for,
stored, or passed on a command line. `--stdin` exists for scripts and for a
shell with no tty; it is not a way around that.

`ladulas lock` suspends approval at that instance while leaving paired
approvers able to answer, and `ladulas lock --seal` wipes the key. Plain
`lock` is not a way to test sealed-state behaviour.

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
