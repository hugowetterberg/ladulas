# Ladulås

Ladulås replaces 1Password's SSH agent and git commit signing with a
distributed approval system. It takes over the agent socket and
`gpg.ssh.program` on a machine, and every signature it makes is approved —
by a prompt on that machine, by a policy or a time-boxed grant made
earlier, or by a paired instance somewhere else. The name is apt: Magnus
Ladulås put a lock on the barn.

The part that is not an ordinary agent is the "somewhere else". Instances
pair with each other over any IP path, and approval travels between them:
a headless box with no keys of its own lists the keys its paired phone
holds and asks the phone to sign; a desktop reached over SSH while its
screen is locked keeps working because the phone in your pocket is what
answers. Keys never move as a side effect of being used — the holder makes
the signature — and there is **no mandatory infrastructure**: peers connect
directly, and the optional push relay only ever says "something is
pending".

The rich prompt is the other half. `ladulas-sign` replaces `ssh-keygen` as
git's signing program, so what you approve is the commit message, the
repository, the branch and the diff rather than a hash; an SSH login shows
the destination host read out of the bytes being signed. A requester can
publish its repositories' documentation to its approvers, so somebody being
asked to sign for a machine they are not sitting at can read what the
project is.

## Documentation

| Document | What it settles |
|---|---|
| **`README.md`** (this) | What the repository holds, how to build and run it, every configuration flag, and what is still missing. |
| [`docs/architecture.md`](docs/architecture.md) | How the service is built: roles, process model, subsystems, protocol, and the decisions behind them. The design authority. |
| [`docs/ops.md`](docs/ops.md) | Running it: dependencies, ports, bootstrap order, failure modes and what to do about each. |
| [`docs/observability.md`](docs/observability.md) | Every metric the daemon and the relay export, and what a change in one means. |

The architecture document's section numbers (`§10`) and decision letters
(`decision P`) are **stable identifiers cited from code comments** — over a
thousand citations across the tree. Sections are corrected and extended;
they are not renumbered.

The links between these documents are checked by `go test ./docs/`, which
runs as part of `make test`: a relative link that does not resolve, or an
`#anchor` that no heading produces, fails the build.

## Repository layout

```
cmd/
  ladulas/        desktop application and management CLI (one binary)
  ladulasd/       the headless daemon
  ladulas-sign/   git's signing program: rich commit prompts
  ladulas-relay/  the optional wake-up relay (APNs)
pkg/              what a mobile core binds against, and so what is
                  public: an import path anybody can name, with no
                  compatibility promise attached to it (§18, §21)
  agent/          SSH agent server, request classification, session-bind
  apns/           APNs client: ES256 JWTs from a .p8
  approval/       engine, policies, grants, prompts, audit log
  avatar/         the picture drawn beside a fingerprint (decoration)
  bridge/         the one http.Handler every GUI host serves
  gitctx/         commit object parsing and diff collection
  hardware/       the seam to a platform's secure element
  identity/       instance keys, fingerprints, signed artifacts
  keystore/       the age-encrypted store, DEK wrapping, portable keys
  peer/           links, inbox, pairing, borrowed keys, wake-ups
  peercred/       the uid check, and the session a request came from
  project/        project publishing, browsing and the read-page cache
  protocol/       generated protobuf and connect-go services
  relay/          the wake-up relay service, and its client
  sshsig/         SSHSIG wrapping
  storepb/        the store document's protobuf types
  transport/      pinned-TLS listener and dialer, bind policy
  trust/          pairing codes, trust records, directions
internal/         the desktop's and the daemon's own halves, which no phone
                  reaches and nothing outside this repository may import
  app/            the assembly: store, engine, sockets, lock states
  branding/       the app icon; icon-1024.png here is the master
  command/        the shared command tree of ladulas and ladulasd
  frontend/       the desktop's half: a viewer host that is a socket client
  gui/            the Wails shell: tray, windows, notifications (tag: gui)
  integration/    cross-package tests: two instances, an agent, a signer
  localapi/       the control socket: SigningService and ControlService
  logind/         suspend and session-lock triggers over D-Bus
  observe/        metrics and pprof: the only package that links Prometheus
  signcli/        the ssh-keygen -Y CLI contract ladulas-sign implements
  testutil/       instances a test can start
  tui/            the terminal shell: the same front end, drawn with keys
proto/            the schema those are generated from
viewer/           the shared HTML/JS bundle: cards, diff, markdown, and the
                  desktop shell (sidebar and screens; decision AA)
contrib/          the systemd user units and the desktop entry
docs/             architecture, ops, observability
```

`pkg/` is the whole of the public surface. A mobile core built out of this
module binds those packages, which is why they are not `internal/` and why
nothing in them is promised — §21 is that seam, and what it means for a
change made on this side of it.

## Build and development

Go 1.26 or later. `buf` is the only tool that has to be installed
separately; the protoc plugins are `go tool` entries in `go.mod`.

| Command | What it does |
|---|---|
| `make` | `generate lint test` — what CI runs |
| `make tools` | Installs `buf` |
| `make build` | Builds every binary into a scratch directory, never the tree |
| `make gui` | Builds `ladulas` with the desktop application (`GUI_TAGS=gui,gtk3` for GTK 3) |
| `make install` | `go install`s the desktop binary, the daemon and the signer |
| `make install-headless` | The same three with no desktop application in any of them, for a box with no display or no webkit |
| `make install-dropin` | Points an already-installed `ladulas.service` at the `ladulasd` in `$GOPATH/bin`. `make uninstall-dropin` takes it back out |
| `make lint` | `golangci-lint run`, which must be clean. CI pins **v2.13.0**; a local copy that is older will pass things the release job fails |
| `make test` | `go test ./...` |
| `make generate` | `buf lint`, `buf generate`, `go mod tidy` — the only way protobuf is regenerated |
| `make viewer` | The checks that keep the viewer bundle self-contained |

Two rules that are not obvious from the target list. **Protobuf is
regenerated only through `make generate`** — the toolchain runs in Docker
and `protoc` is never run by hand. And **`main` has to stay green**, which
is a heavier obligation here than it looks: a consumer builds against a
pseudo-version of this branch rather than against a release, so a commit
that does not compile is a commit nobody can build anything from.

There is no phone target here, and nothing in the tree compiles against
gomobile — which is also the only check `pkg/` does not get. Gomobile
takes strings, signed integers, booleans, `[]byte`, errors and types
declared in the bound package, so a change that widens an exported
signature past that list compiles perfectly, passes `make test`, and then
fails to bind. §21 has the rest of what nothing here checks.

## Running a local instance

The daemon comes up **sealed**, or **uninitialised** if there is no store,
and serves either way — that is what makes a box reached over SSH able to
say what is wrong with it.

```
make install
cp contrib/ladulas.service ~/.config/systemd/user/
systemctl --user enable --now ladulas.service

ladulas status          # says uninitialised, and what to do about it
ladulas init            # creates the store; asks for a passphrase twice
ladulas keys generate work
ladulas keys list
```

Then point ssh and git at it:

```
make install-env        # SSH_AUTH_SOCK, from the next login onwards
git config --global gpg.format ssh
git config --global gpg.ssh.program ladulas-sign
git config --global user.signingkey "key::$(ladulas keys public work)"

ladulas doctor          # says whether any of that did not take
```

`make install-env` puts `contrib/50-ladulas-agent.conf` in
`~/.config/environment.d/`, which the systemd user manager reads at
startup — so the GUI, every user unit and every terminal opened from the
desktop get the variable without a line in anybody's shell rc. It takes
effect at the **next login**; for this one, and for sessions systemd did
not start (an `ssh` into the box, a bare TTY), add it to your shell rc:

```
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/ladulas/agent.sock
```

**`SSH_AUTH_SOCK` is contended**, and the interesting failure is not that
it is unset but that it is set to somebody else's agent: GnuPG's
`gpg-agent-ssh.socket`, 1Password and Secretive all want it, whichever
writes last wins, and the symptom is a key list from the wrong agent rather
than an error. `ladulas doctor` names which agent has it.

On a box with no display, or with a webkit that `GUI_TAGS` does not match,
use **`make install-headless`** instead of `make install` — the package
table under [Installing a release](#installing-a-release) says which webkit
each build wants. It installs the same three commands and only `ladulas
gui` refuses to run.

Without the unit, `ladulasd run` in a terminal does the same thing and
approves at the terminal. With a piece missing: no `ladulas-sign` and git
still signs through the agent with a poorer prompt; no logind and the
automatic locks are off and say so; no peer paired and everything still
works locally, which is the single-machine 1Password replacement.

### Answering in a terminal

```
ladulas tui
```

`ladulas tui` attaches to the running daemon as an approver and draws the
card the desktop window draws — the commit, who is asking, which key, and
the diff a file at a time — with the same answers under it, including
"approve for a while". It is a client of the daemon like `ladulas gui`
(decision AK), so it opens no store and holds no key, and quitting takes
only this approver away: anything still waiting goes on waiting for the
window, the phone or whoever else can answer.

`enter` and `a` approve once, `w` opens the promise, `d` denies, and `?` lists
the rest. It needs a terminal to draw on and says so if it is given a pipe.

**The change is three screens.** The card is the facts and the list of files;
`f` opens that list, where typing narrows it to the file you are looking for;
and `enter` there reads one file's change on a screen of its own. `n` and `p`
step straight from one file to the next without the list, and `r` asks the
requesting machine for the rest of a diff that was cut short.

`enter` is the answer **only on the card** — in a change it closes the change,
because a signature is not something to approve by reflex while scrolling
through code. The letters still answer from anywhere, being deliberate.

With nothing waiting it says how long the next request will wait for an
answer, and — on a sealed or locked store — that nothing is going to be asked
of it at all, which is the state where an empty screen would otherwise be
reassuring and wrong.

It is not the same thing as `ladulasd run`'s terminal prompt: that one is
inside the daemon, on the daemon's own stdin, and offers a yes, a no and four
fixed lengths. Both may be attached at once, and the log tells them apart as
`console` and `terminal`.

**It picks up what is already waiting**, so starting it because something is
stuck is the point rather than too late (decision AL): a `git commit` that has
been hanging for twenty minutes comes up on the first screen, with its own
clock rather than one that starts when you look at it.

**And it can open the store.** `u` on a sealed or locked instance gives a
passphrase field, which matters because a terminal is often the only surface in
front of you: an `ssh` session on a box whose window you cannot see. On an
instance that enrolled "unlock at login", `enter` with nothing typed uses the
keychain. `q` does not quit while the field is up — a passphrase may contain a
q — so `esc` first.

### Running the tree on a box that has the package installed

Where a package owns the unit, `ExecStart` is `/usr/bin/ladulasd`, so
installing into `$GOPATH/bin` and restarting changes nothing that is
running. **`make install-dropin`** writes a systemd drop-in that overrides
`ExecStart` to the installed `ladulasd` and reloads the daemon:

```
make install-headless install-dropin
systemctl --user restart ladulas.service
```

`make uninstall-dropin` removes it and hands the service back to whatever
its unit names. Neither target restarts anything — that stays a separate
step, because restarting seals the store (§10, §14) and somebody has to
unlock it again. `systemctl --user show ladulas.service -p ExecStart
--value` is how to check which binary is actually in force.

### Pairing a second instance

```
ladulas pair --listen --intent approver      # displays a code, waits
ladulas pair host:7373 --code <that code>    # on the other instance
ladulas pairings list                        # if the confirmation outlived
                                             # the command that raised it
ladulas peers allow <peer> --approve --key work
```

**The side displaying the code says what the pairing is for**, and that
settles both records (decision AD): `--intent approver` for a machine that
will approve for this one, `--intent requester` for one this machine
approves for, `--intent mutual` for both. The other side declares nothing
and is shown the sentence on its confirmation. It is required, because the
alternative was two independent guesses that routinely disagreed; changing
it later means removing the peer and pairing again. On a desktop the same
question, the same code and a QR are the **Add a machine** screen in the
window.

Pairing grants **directions**, never keys; `peers allow` is the separate
decision that lends one, and its flags describe the state wanted rather
than a change to make — anything left out is withdrawn. A pairing that
skipped it is correct and useless.

### Where the peer channel listens

```
ladulas listen                          # what is bound, what peers dial,
                                        # and what was passed over
ladulas listen set 192.168.1.5 auto     # this address as well as the policy's
ladulas listen set off                  # stop listening; still dials out
ladulas listen clear                    # forget the setting
```

With nobody having said, the automatic policy takes **one tier** of
addresses: the machine's tailnet addresses if it has any, otherwise its
other private ones, otherwise loopback — having skipped every interface
that is up but not running, and every interface whose name belongs to a
container runtime or a virtual machine (decision AH). On a desktop with
Docker and libvirt on it that is the difference between two listeners and
fourteen, eleven of which no peer could reach.

What peers are told to dial is a second list, printed as **Peers dial**. A
tailnet address is advertised under its node name first —
`horatio.tailnet.ts.net:7373` before `100.74.235.31:7373` — which is what
the other machine records and shows; loopback is advertised only by an
instance that has nothing else. **A trust record keeps the addresses a peer
advertised when it paired**, and nothing refreshes it, so pruning a list
here does not tidy up a peer that already has the old one — the dialling
side skips the addresses that turn out to be its own, and re-pairing is what
replaces the list.

`ladulas listen set` remembers the change in the store and rebinds at once;
if the new addresses cannot be bound the previous ones come back and it says
so. It cannot lock you out of the CLI, which reaches the daemon over a unix
socket, only out of peering.

### Asking for permission before the login needs it

```
ladulas ssh-grant git@github.com          # blocks until somebody answers
ladulas ssh-grant bastion --for 2h        # a length to suggest to the approver
```

An SSH login runs on the far server's clock: sshd closes the connection
after `LoginGraceTime`, typically two minutes, so an approval that has to
reach a phone has about ninety seconds to be noticed and answered. That is
fine at a keyboard and hopeless in a pocket, and it is not a number this
side can raise.

`ssh-grant` asks the same question with nothing waiting on it, so the
answer gets the signing budget — an hour by default — and what it produces
is an ordinary grant that the logins afterwards fall under. Use it before
a `git push` or a batch of logins that would otherwise each ask.

It connects to the destination first, and prints what it found:

```
Asking git@github.com what a login would look like…
  Server    github.com:22
  User      git
  Key       SHA256:bgle/IWUw6RDTxbiZ9Zik+ApYrxUMqk+I7ubmJOCqsU
  Host key  SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s
```

Nothing is signed by that: it offers each key the agent holds without a
signature, which is what ssh does to find out the same thing, and the
server says which one it would accept. The connection is necessary because
a promise is matched on strict equality against what the login derives — a
scope built from a guess covers nothing, and looks like it should have.

The destination is written the way ssh takes it, and **ssh's own
configuration decides what it means**: `Host`/`Match` blocks, `User`,
`Port` and `IdentityFile` are all resolved by `ssh -G`.

Two things to know:

* **Run it in the shell that will do the work.** The promise is scoped to
  the session it was asked from, so a grant taken in one terminal does not
  cover a `git push` in another. Approve with the Machine reach on the card
  if that is what you want.
* **The host must be in `known_hosts`.** An unknown host is refused rather
  than guessed at — the fingerprint learned here becomes the scope of the
  promise. Log in with `ssh` once, which is the moment designed for looking
  at a fingerprint, and run it again.

The card has no plain Approve on it: there is nothing to sign, so the
answer is a length or a denial. The exit status is the answer — 0 granted
or already covered, 1 refused or unanswered — so a script can use it.

### The standing permissions, from both ends

```
ladulas grants list             # promises this instance made, and to whom
ladulas grants extend <id> 2h   # give one more time, counted from now
ladulas grants revoke <id>      # take one back
ladulas delegations list        # promises made about this instance, by whom
ladulas endorsements list       # promises about a key that other holders made
ladulas endorsements retract <id>          # take one back, tell every holder
ladulas endorsements retract --key <fp>    # take back everything about a key
```

A third list because there is a third thing (decision AG). A **portable key
can be held by several machines** (decision S), and a promise one holder
makes about a requester is honoured by all of them: the requester carries
the signed statement and presents it wherever it borrows, so the promise
works with the machine that made it asleep. `endorsements list` is what this
instance is signing under, and it shows the copies it merely carries and the
ones it will not act on too, with the reason — because a promise nobody can
see is a promise nobody can take back.

**Any holder of the key may retract**, including one that did not make the
promise, and retracting says which holders were told and which were not.
The ones that were not are still honouring it: a retraction is a delivery,
it gossips between holders, and the promise runs out on its own whether or
not anybody gets through.

Two lists rather than one for the first two, because they are two things
(decision P): a
grant is this instance's own promise and can be taken back here, and a
delegation is somebody else's promise about this instance, which it
applies itself and can only let run out. Ending one of those early is the
approver's `grants revoke`, and the listing names who to ask.

`extend` counts from now rather than adding to what is left, and is
bounded by the longest promise this instance makes — so it tops one back
up and never reaches past what "approve for a while" could have. A promise
that was handed to another machine is re-signed and delivered before the
record here moves; if that machine cannot be reached, nothing is extended
and the command says so.

### Resetting

Everything an instance is lives in three places:
`~/.local/share/ladulas/` (store, audit log, project pages),
`~/.config/ladulas/policy.json`, and `$XDG_RUNTIME_DIR/ladulas/` (the
sockets). Stop the unit, remove the first two, and the next `ladulas init`
is a new instance with a new identity — every peer will see a stranger.

## Installing a release

A release is a **tag**, and the tag is the whole version: nothing in the tree
records which tag points at a commit, so pushing one is what tells goreleaser
what to build and what to stamp into the binaries.

```
git tag -a v1.2.3 -m 'what changed'
git push origin v1.2.3
```

`.github/workflows/release.yml` then tests, lints, checks that the desktop
application still compiles under both GTK tag sets, builds linux/amd64 and linux/arm64, and
commits the Arch packaging into
[`ladulas-aur`](https://github.com/hugowetterberg/ladulas-aur) as one commit.
`ladulas version` in any of the binaries says what a build is; a build made
without those ldflags — `go install ./cmd/ladulasd`, which is what a
development machine runs — says `0.0.0-dev` and the commit it came from,
`.dirty` included.

That last step needs two things that live outside this repository, and
neither of them fails until a tag has already been pushed and the GitHub
release already published — the packaging commit is the last step, so what
a missing prerequisite produces is a red run over a release that exists and
installs:

* the **`hugowetterberg/ladulas-aur` repository**, which has to exist and
  be initialised with at least one commit. `actions/checkout` asks for the
  default branch name before it clones anything, so an absent repository
  and an empty one both surface as `Not Found` against the repositories
  API, which reads like a permissions problem and is not one.
* the **`AUR_REPO_KEY` secret**: an SSH private key whose public half is a
  deploy key on that repository *with write access*. Read-only is enough to
  clone and gets all the way to `git push` before failing.

Re-running the workflow over the same tag is the fix once both exist —
`workflow_dispatch` takes the tag as an input for exactly this, and the
packaging step is a no-op when it is already current, so nothing is
double-committed.

Three Arch packages come out of it, all installing the same four binaries, all
owning `/usr/bin/ladulas` because that one binary is both the desktop
application and the management CLI (§12, §14), and therefore all
**conflicting with each other**:

| Package | Built | The desktop application |
|---|---|---|
| `ladulas` | From source by `makepkg` | GTK 4 and `webkitgtk-6.0` — Wails' default |
| `ladulas-gtk3` | From source by `makepkg` | GTK 3 and `webkit2gtk-4.1` |
| `ladulas-headless-bin` | Prebuilt, downloaded | **None.** CGO off, no dependencies at all, and no desktop entry |

The GTK packages are built on the installing machine rather than shipped as
binaries on purpose: a webview cross-compiled on a CI runner links whatever webkit
soname that distribution shipped, which is how a package installs cleanly and
then refuses to start. Compiling against the machine's own libraries is the
answer and costs only Go, because the generated protobuf is committed — no
`buf`, no Docker.

The prebuilt package was `ladulas-bin` up to and including v0.0.1, and the
rename is not cosmetic. `-bin` on the AUR means *the same package, already
compiled*, and this one was not that — it was the only one of the three with no
window in it. Said alone, the suffix advertised how the package was built when
the thing that actually differs is what you get, so somebody reaching for
`ladulas-bin` to skip a compile got a package with no `ladulas gui` in it and
nothing in the name to warn them. `headless` is that warning; `-bin` is still
there and still true, now qualifying `headless` rather than standing for the
whole difference. It is also not removable — goreleaser appends `-bin` to any
`aurs` name that lacks it, with no setting to disable that.

Making `-bin` mean what it looked like it meant — a prebuilt package *with* the
GTK 4 window, so it and `ladulas` install the same thing — is the
cross-compiled webview two paragraphs up, and it fails later and worse than a
misleading name: pacman's dependency check passes, the package installs, and
the failure waits for the first `ladulas gui`. It needs the release job to
build inside an Arch container so the sonames are Arch's, which does not exist
yet.

All three are `makepkg -si` and nothing else: the release assets are reachable
over plain HTTPS, which is all a `PKGBUILD` needs. The licence is **MIT**, in
[`LICENSE`](LICENSE), which every package names and installs.

What is still left before any of this can go to the AUR is in that repository's
[README](https://github.com/hugowetterberg/ladulas-aur#becoming-a-real-aur-repository):
three AUR remotes, an account with a key on it, and a `.SRCINFO` worth reading
before the first push.

### The units, and the desktop entry

The packages install two user units to `/usr/lib/systemd/user/`, and one
desktop entry.

```
systemctl --user enable --now ladulas          # the instance: agent and engine
systemctl --user enable --now ladulas-relay    # the optional wake-up relay
```

**The same unit runs on a desktop.** The desktop application is not a unit and
not an instance: it is a client of the daemon over the control socket
(decision Z), so it is started by `contrib/ladulas.desktop` — installed both
into `/usr/share/applications`, where it is a menu entry, and into
`/etc/xdg/autostart`, where a session starts it at login. Either order works,
and neither can take the other down.

There used to be a `ladulas-tray.service` alongside, running a desktop
application that opened the store itself. It and `ladulas.service` were
alternatives rather than companions — both took over the agent socket, so the
second to start lost it and exited complaining about the socket rather than
about the mistake — and it was enabled into `graphical-session.target`, which
most sessions never reach, so it sat enabled and never started, reported as
`inactive` with no error. Both problems are gone with it.

`contrib/` holds the units, and they are the packaged ones — with one
substitution. `contrib/ladulas.service` names `%h/go/bin/ladulasd`, which is
right for `make install` and wrong for a package, so `package()` rewrites it to
`/usr/bin`.

**A package also has to install the icon.** `contrib/ladulas.desktop` says
`Icon=ladulas`, which is a name in the icon theme rather than a path, so
`package()` needs the sizes under
`/usr/share/icons/hicolor/<size>x<size>/apps/ladulas.png`, scaled from
`internal/branding/icon-1024.png` the way
`make install-desktop` does it for `$HOME`. Without them the entry has no icon
and the window has none either — see "The icon, and the menu entry" below for
why that file is the only mechanism there is.

**Refreshing the caches those feed is pacman's job, and the packages leave it
alone.** `update-desktop-database.hook` fires on
`usr/share/applications/*.desktop` and `gtk-update-icon-cache.hook` on
`usr/share/icons/*/`, both after the transaction and on install, upgrade and
remove alike, so the entry and the icon are live without an `install=`
scriptlet. Those hooks come from `desktop-file-utils` and
`gtk-update-icon-cache`, which are hard dependencies of both `gtk3` and `gtk4`
— so a machine that can install either GTK package has them, and a scriptlet
running the same two commands would only rebuild both caches a second time.
`make install-desktop` does run them, because it writes under `$HOME` where no
hook is watching. `ladulas-headless-bin` installs neither file and so needs
neither refresh.

## The desktop application

`ladulas gui` puts a tray icon on the bar and nothing else on screen. Two kinds
of window come out of it (decision AA).

**One application window**, opened by clicking the tray icon or its `Open
Ladulås` item, and reused: asking for it again brings back the one that is open.
It is the phone's app in a window — a sidebar with Home, Keys, Activity and
Documents, one entry per paired machine below them, and Settings at the bottom
where the phone has "This phone". Home is what is waiting for an answer, the
machines and the promises still running; Settings is this instance's own
fingerprint, where its files are, how long a signing request waits, and the
lock, seal and reload verbs. A sealed store shows the passphrase panel in place
of the screens, and the window opens itself once when it attaches to an
instance that is sealed.

**What a screen can do is an icon in its title bar** (decision AF), and a sheet
opens behind it: **+** on Keys makes a key, and the **cog** on a paired machine
holds the pairing's fingerprint, addresses and key access, and the button that
ends it. What a screen *is* stays in the pane.

**How long a signing request waits** is on Settings under Approvals, and
`Change` opens a sheet with the length on a clock and the lengths worth one tap,
the default among them (decision AJ). It is a sheet rather than a box on the
screen for the reason every form here is one: the pane repaints every four
seconds and a repaint empties a field somebody is halfway through. The number
goes into `policy.json` and into effect at once, with no restart and no reload;
requests already waiting keep the length they started with.

**A key another machine handed this one** — `ladulas keys send` at that end
(decision S) — waits on the Keys screen and is counted beside `Keys` in the
sidebar. Accepting it is a sheet: the fingerprint to compare with the sending
machine, the name it takes here, and what each answer costs. Accepting puts the
private half in this store, where it signs like any other key; refusing keeps
nothing, and the sender is not told and still holds it. `ladulas keys offers`,
`keys accept` and `keys refuse` are the same thing at a terminal.

**A popup per request**, small, centred and above the others, the way 1Password
and OpenSnitch ask. Only one is on screen at a time: the rest queue, and the
closing of the one in front starts the next, so a burst of signatures is never a
stack of overlapping always-on-top windows. Closing a popup without answering is
a refusal. What is waiting is also listed on Home, which is where a popup that
was closed by accident is answered from.

Closing the window does not quit — the tray is the application, and `Quit` is on
its menu. Starting it a second time does not make a second application either:
the running one raises its window and the new process exits, which is what a
menu entry clicked while it is already running should do.

### The icon, and the menu entry

`internal/branding/icon-1024.png` is the master — the one drawing anybody makes
by hand — and it reaches the desktop by two different routes, because GTK 4 has
only one of them.

The **tray** icon is bytes: `internal/branding` embeds a downscale of the master
and the tray is handed it at startup. `make icons` regenerates that copy after
the app icon changes, and the package's test fails until it is run, which is what
makes keeping a copy safe.

`internal/branding/icon-1024.png` is the master, because the Linux packages need
the drawing whatever else is ever built from it. The test in that package catches
a stale `tray-128.png`, since both are in this repository; **a copy of the master
kept anywhere else is compared by nothing here**, and going out of date silently
is what such a copy does.

The **window** icon, and the one a launcher shows, cannot be set from the
program at all: GTK 4 removed every API that takes an icon as bytes, and Wails'
own backend says so where its `setIcon` used to do something. What draws it is
the desktop entry's `Icon=ladulas`, resolved against the icon theme — so it
needs the icon installed under that name, and it needs the process's `WM_CLASS`
to match the entry's name for a window manager to connect the two
(`LinuxOptions.ProgramName`, also `ladulas`).

For a tree installed with `make install` rather than from a package:

```
make install-desktop      # the menu entry and every icon theme size
make install-autostart    # and start it at login, like the packages do
make uninstall-autostart
```

Both write only under `$HOME` and need no root. Autostart is a separate target
on purpose: installing binaries is a build step and starting something at
somebody's login is a decision.

### On a tiling window manager

The popup is an ordinary window as far as the window manager is concerned, so i3
and its relatives tile it. **There is no window role to match on**:
`WM_WINDOW_ROLE` was a GTK 3 property, GTK 4 dropped `gtk_window_set_role`
entirely, and Wails exposes nothing else that would set it — nor a per-window
`WM_CLASS`, which comes from the process name and so is `ladulas` for every
window it opens. What tells the two apart is the title: a popup is always
`Ladulås — <what is being asked>` and the application window is exactly
`Ladulås`. In i3:

```
for_window [class="ladulas" title="^Ladulås — "] floating enable
```

That floats the prompts at the size they ask for and leaves the application
window tiled.

## The relay

`ladulas-relay` is optional and nothing depends on it: an instance with no
relay, or one whose relay is down, approves exactly as it did before — the
phone finds the request when it is next opened. What it buys is that the
phone is opened sooner.

Every credential is configuration; there is no key, key id, team id or
topic compiled in, because self-hosting means running this against your own
Apple project.

```
APNS_KEY_FILE=AuthKey_XXXX.p8 APNS_KEY_ID=… APNS_TEAM_ID=… \
  APNS_TOPIC=nu.wetterberg.ladulas ladulas-relay
```

## Configuration reference

### Both binaries: locations and the peer channel

| Flag | Environment | Default | What it does |
|---|---|---|---|
| `--data-dir` | `LADULAS_DATA_DIR` | `$XDG_DATA_HOME/ladulas` | The encrypted store, the audit log and the project pages |
| `--config-dir` | `LADULAS_CONFIG_DIR` | `$XDG_CONFIG_HOME/ladulas` | The policy document |
| `--socket` | `LADULAS_AGENT_SOCK` | `$XDG_RUNTIME_DIR/ladulas/agent.sock` | Where the SSH agent listens. `SSH_AUTH_SOCK` points here |
| `--control-socket` | `LADULAS_SOCK` | `$XDG_RUNTIME_DIR/ladulas/control.sock` | The signing and control services. The CLI and `ladulas-sign` both find the instance here |
| `--no-keyring` | `LADULAS_NO_KEYRING` | off | Ignore the platform keychain entirely, so an instance that enrolled "unlock at login" can still be started without it |
| `--peer-listen` | `LADULAS_PEER_LISTEN` | port 7373 on one tier of addresses — see `ladulas listen` | A port, a `host:port`, a comma-separated list of either, `auto`, or `off`. Set, it **overrides** what `ladulas listen set` stored, which is what makes it the way back into a machine whose stored address no longer exists |
| `--peer-listen-public` | `LADULAS_PEER_LISTEN_PUBLIC` | off | Allow binding addresses reachable from outside. The channel does not trust the network either way; this exists so it never happens by accident |
| `--log-level` | `LADULAS_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

### Running an instance: `ladulasd run` and `ladulas agent`

Both name what they start. `ladulasd` alone is the daemon,
because a unit starts it with nothing to pass; `ladulas` alone prints the
usage and starts nothing, which is why `contrib/ladulas.desktop` runs
`ladulas gui` (decision Y). The verb is `gui` and not `tray` because the
tray icon is one of the things it draws.

`ladulas gui` takes no flags of its own beyond the global `--control-socket`:
it is a client of a daemon (decision Z), so the automatic locks and the debug
listener below are the daemon's and the passphrase dialog is the desktop's
answer to `--unlock`.

| Flag | Environment | Default | What it does |
|---|---|---|---|
| `--unlock` | `LADULAS_UNLOCK` | `auto` | How the passphrase is asked for once the daemon is up: `auto` uses the terminal when there is one and `systemd-ask-password` otherwise, `terminal` and `ask-password` force one, `none` waits for `ladulas unlock`. The store is sealed and the daemon serving either way — the asking always comes after the listening |
| `--console` | `LADULAS_CONSOLE` | `auto` | Whether to approve at the terminal. `auto` follows whether stdin is one; `off` leaves approvals to paired peers. Registering a terminal approver on a unit whose stdin is `/dev/null` would advertise a prompt that cannot be shown |
| `--debug-listen` | `LADULAS_DEBUG_ADDR` | **off** | Address for Prometheus metrics and pprof. Off unless set, because this is one daemon per account — a default port is one two users fight over — and because a heap profile of an unlocked instance contains the store key |

### Automatic locks

Each takes `lock` (suspend approval here, keys stay usable by a paired
approver), `seal` (wipe the store key; the passphrase is needed to come
back) or `off`.

| Flag | Environment | Default | What it does |
|---|---|---|---|
| `--on-suspend` | `LADULAS_ON_SUSPEND` | `lock` | What happens when the machine suspends. `seal` takes a logind inhibitor so the key is gone before the machine goes down — the answer to a stolen sleeping laptop, at the cost of a passphrase on every wake |
| `--on-session-lock` | `LADULAS_ON_SESSION_LOCK` | `lock` | What happens when the session locks. `lock` rather than `seal` is deliberate: a desktop reached over SSH must keep signing while its screen is locked, which is the 1Password failure this project exists to fix |
| `--idle-lock` | `LADULAS_IDLE_LOCK` | off | Lock after this long with nothing decided |
| `--idle-lock-action` | `LADULAS_IDLE_LOCK_ACTION` | `lock` | What the idle timeout does |

### `ladulas-sign`

`ssh-keygen` owns the flag namespace, so everything git's signing program can
be told is told through the environment.

| Environment | Default | What it does |
|---|---|---|
| `LADULAS_SOCK` | `$XDG_RUNTIME_DIR/ladulas/control.sock` | The instance to sign through |
| `LADULAS_SIGN_TIMEOUT` | the instance's own budget, an hour | How long to wait for an approval, as a Go duration: `30m`, `2h`. Set, it overrides the instance's for this signature only |
| `LADULAS_SIGN_NO_DIFF` | off | Set to anything to skip collecting the diff, for a repository where `git diff` is too slow to want on every commit |
| `LADULAS_SIGN_DIFF_BYTES` | — | Cap on the collected diff, in bytes |
| `LADULAS_SSH_KEYGEN` | `ssh-keygen` on `$PATH` | The program the command lines this one does not answer are handed to |

The hour is the instance's setting rather than this program's: `ladulas policy
show` prints it, the desktop's Settings screen changes it, and it lands in
`policy.json` as `signTimeout` (architecture §9, decision AJ). It is meant to
be long — a request that gives up costs the commit, and the person answering
may be in another room. SSH authentication keeps its own much shorter budget,
because the server at the other end is counting too. `ladulas ssh-grant` is
how a login gets the long budget anyway: asked before there is a handshake,
there is nothing at the other end to count (architecture §9, decision AO).

### `ladulas ssh-grant`

| Flag | Default | What it does |
|---|---|---|
| `--for` | — | A promise length to suggest. It joins the lengths the card offers as one tap; the approver still chooses, and a length past what this instance promises is dropped rather than trimmed |
| `--probe-timeout` | `15s` | How long to give the connection that works out what the login would look like |
| `--quiet` | off | Say nothing, and answer with the exit status alone |

The wait for an answer is the instance's signing budget and is not a flag
here: it is one number, set in one place, for the reason decision AJ gives.

### `ladulas-relay`

| Flag | Environment | Default | What it does |
|---|---|---|---|
| `--listen` | `LISTEN_ADDR` | `:8443` | Where the relay serves. Cleartext HTTP/1 and HTTP/2 — it expects to sit behind TLS termination, or on a tailnet, where WireGuard is the transport security |
| `--state` | `STATE_FILE` | `devices.json` | The device registrations, which are the whole of its state |
| `--debug-listen` | `DEBUG_ADDR` | `127.0.0.1:8444` | Prometheus metrics and pprof. On by default here because this is one process on a host somebody operates — but loopback, because its heap holds a push key and a device list |
| `--apns-host` | `APNS_HOST` | production | The production host, because TestFlight builds carry production tokens and the sandbox host answers `BadDeviceToken` for every one of them — which looks exactly like a bug in this service |
| `--apns-topic` | `APNS_TOPIC` | — | The app's bundle identifier |
| `--apns-key-id` | `APNS_KEY_ID` | — | The key id of the `.p8` |
| `--apns-team-id` | `APNS_TEAM_ID` | — | The Apple Developer team id |
| `--apns-key` | `APNS_KEY` | — | The signing key itself, in PEM. Preferred to a path, so the key never reaches a disk |
| `--apns-key-file` | `APNS_KEY_FILE` | — | Path to the `.p8`, when it is on one. What systemd `LoadCredential=` produces |

A relay that came up without a key would answer every wake-up with a
failure, which reads to everybody upstream as the phone being unreachable —
so it refuses to start instead.

## Pending work

**Android (M10).** The one milestone with no code written for it: a Kotlin
shell, Keystore P-256 keys, and the opt-in foreground-service live
connection that makes an Android phone a real-time approver with no
infrastructure at all. The core is already bound for gomobile and the
keystore decides per key rather than per platform, so what is missing is
the shell rather than the design.

**Windows and macOS.** Designed and unbuilt. Windows needs the named-pipe
agent (`\\.\pipe\openssh-ssh-agent`, the takeover 1Password does) and DPAPI
for the DEK; macOS needs nothing platform-specific written but has never
been run, because there is no Apple hardware here.

**A request made in the first moments after pairing can be refused for no
better reason than timing.** Pairing writes the trust record; the link that
carries a request to the peer is built afterwards, by the reconciliation
that follows — new link, register the remote approver with the engine, ping
(§7). A request submitted in that gap is not queued or delayed but denied
outright, with *"no approver is available to answer"*, because the engine's
fan-out answers immediately when it has no handlers rather than waiting for
one to appear (§9).

Answering at once is deliberate and worth keeping: it is what makes an
approver that is switched off fail in seconds instead of hanging for the
request's whole timeout. So the fix is not "wait for a handler" but a
bounded grace, taken only when a peer is paired-and-may-approve and its
link is still coming up — and getting that bound wrong turns the good
failure back into the hang. That is a decision to take on its own.

It surfaced as a test flake rather than a report: every test that paired and
then immediately submitted was racing it, at a few percent under load. That
half is fixed — `pair()` in the peer tests now waits for the link to report
online — which means the race is no longer *visible* in CI while still being
there in the product. Reproduce it by submitting inside the gap; do not
expect the suite to catch it.

**Socket activation.** The unit starts the daemon directly, so the agent
socket exists from start-up rather than on first connection.

**Hash-chaining the audit log.** Tamper evidence today comes from the
approver's signature over each decision, which cannot be forged without the
identity key. Chaining the log itself is deferred, and will be an added
field rather than a new format.

**Nothing scrapes the metrics.** The daemon's port is off by default and
the relay's is on loopback; there is no Prometheus, no dashboard and no
alerting. [`docs/ops.md`](docs/ops.md#what-to-watch-in-order) describes
what an operator should watch, not something that pages anybody.

**The packaged relay unit is not the one running on guppy.** `contrib/` now
holds a generic `ladulas-relay.service` — site values in an
`EnvironmentFile`, the `.p8` at a conventional path — because a package has
to ship something enableable. The instance that is actually running predates
it and has its addresses and key ids written into the unit itself, so
[`docs/ops.md`](docs/ops.md#deployment-shape) is still what describes what is
deployed. The two will drift; the packaged one is the one that gets
maintained.
