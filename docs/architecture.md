# Architecture

How Ladulås is built and why it is built that way: the roles instances
play, the process model, every subsystem in the order content moves
through it, the protocol surface, and the record of what was decided and
what was rejected. **This is the design authority — when the code and this
document disagree, the document wins unless there is a concrete reason,
and then the reason gets written down here.**

Ladulås replaces 1Password's SSH agent and git commit signing with a
distributed approval system: desktops and phones approve — and when the
key lives elsewhere, remotely perform — signing operations for each other,
over any network the instances can reach each other on. The name is apt:
Magnus Ladulås put a lock on the barn.

| Document | What it settles |
|---|---|
| [`README.md`](../README.md) | What the repository holds, how to build and run it, every configuration flag, and what is still missing. |
| **`docs/architecture.md`** (this) | How the service is built: roles, process model, subsystems, protocol, and the decisions behind them. |
| [`docs/ops.md`](ops.md) | Running it: dependencies, ports, bootstrap order, failure modes and what to do about each. |
| [`docs/observability.md`](observability.md) | Every metric the daemon and the relay export, and what a change in one means. |

What this document does **not** cover: how to build the tree or configure
an instance (README), what to do when something is broken (ops), or what
any individual metric means (observability). It covers what the things
those documents talk about *are*.

**The section numbers and decision letters are stable identifiers, not an
outline.** Code comments cite them — `§10` appears in over a hundred of
them, `decision P` in fifty — because the reason a thing is the way it is
belongs next to the thing and does not fit in a comment. Sections may
grow, be corrected, or be marked stale; they are not renumbered, and a
decision letter is never reused. New material goes in the section it
belongs to, or takes the next free number.

Sections marked **Decision** keep the option space that was considered,
because the rejected options are the reasoning; §19 is the index of what
was resolved and when. A decision that was later reversed is recorded
where the current behaviour is described, as history, so that the current
reading comes first and the prohibition arrives with the argument that
earned it.

## 1. Problem and goals

1Password currently owns the SSH agent socket and git signing. Its approval
prompt is a local GUI, which makes it impossible to approve operations on a
machine you are not sitting at — a headless box, or a desktop reached over
SSH while away from it.

Goals:

* A desktop application that takes over the SSH agent and git signing roles
  from 1Password, with a local graphical approval prompt.
* The same application able to run headless — and completely keyless — with
  approval and signing delegated to remote peers.
* An Android (later iOS) app that approves, and can itself hold keys and
  sign.
* Desktop-to-desktop approval as well as mobile-to-desktop.
* Rich approval context everywhere: commit message, diff, and repo details
  on desktop *and* mobile, plus browsable project documentation published
  by requesters ahead of time.
* **No mandatory infrastructure.** Instances connect peer-to-peer over any
  IP network. Tailscale and push notifications are optional enhancements;
  nobody is forced to route through infrastructure hosted by the author or
  anyone else.
* A Go library that lets custom applications participate in the approval
  flow.

Non-goals (at least initially):

* GPG signing. Git is configured with `gpg.format=ssh` everywhere; one
  agent protocol covers both SSH auth and commit signing.
* FIDO/sk-* keys, PIV/smartcard passthrough.
* NAT traversal. Ladulås does no hole punching and runs no relays; peers
  must be directly reachable, and when they aren't, that is what VPNs
  (Tailscale, WireGuard, …) are for. Krypton died and took every pairing
  with it because its data path ran through the company's AWS account;
  Ladulås's data path is always a direct connection between peers.

## 2. Settled decisions

From the initial discussion:

* **SSH signing only** — no GPG surface.
* **Real remote signing** — when the key lives on the approver, the
  signature is computed there; private keys never move between instances
  as a side effect of using them. The one way key material travels is a
  portable key handed over on purpose, which is a transfer and not a
  signature (decision S, §10).
* **Phones are full peers** — they can hold keys and sign, not just
  approve. Consequence (§10): phone-resident SSH keys are
  `ecdsa-sha2-nistp256`, because Apple's Secure Enclave and Android
  StrongBox only do P-256.
* **Any network, no required infrastructure** — peers connect directly to
  configured hosts over whatever IP path exists. Tailscale is an optional
  hardening/reachability layer (§7), used because it's there, never
  required.
* **Push is optional** — a content-free wake-up optimization (§11) with a
  zero-infrastructure baseline (live connections, poll-on-open, Android
  foreground service). No hosted component is ever load-bearing.
* **Policies + prompt** — per-key/per-peer rules (auto-approve, TTL
  grants), everything audited.
* **First decision wins** — requests fan out to all eligible approvers;
  the first approve/deny settles it and other prompts are cancelled. A peer
  reporting that it has nobody to ask is not one of those, and does not
  settle anything (decision AC, §9).
* **iOS first** (the Apple developer account is in place; everything
  builds Mac-less on macOS CI runners), Android later on the same core.
* **A rich signer binary** — `ladulas-sign` replaces `ssh-keygen` as
  `gpg.ssh.program`, so git approval prompts show the commit message, repo,
  and diff (§5).
* **The rich viewer runs on mobile too** — one shared webview-hosted
  viewer bundle across desktop and mobile (§12).
* **Project publishing** — requesters can proactively publish a project's
  markdown documentation to approvers, browsable from the approval UI
  (§6).

## 3. System overview

### Roles

Every instance is the same protocol peer; behaviour differs by
configuration, not by kind:

* **Requester** — an instance where an SSH auth or git signing operation
  originates. May hold the relevant key locally (needs approval only) or
  not (needs remote signing).
* **Approver** — an instance trusted to approve a requester's operations.
  Approval direction is chosen per pairing: mutual or unidirectional.
* **Key holder** — an instance that holds a private key and is willing to
  sign with it for paired requesters. Approving and holding keys usually
  coincide, but a keyless GUI instance that only approves is valid, as is
  a headless key holder that requires a third instance's approval to use
  its keys.

A headless requester can be completely keyless: its agent lists keys that
live on its paired key holders and forwards sign requests to them.

### Components

* **The core library** — `internal/*`, implementing identity, trust store,
  transport, protocol, approval engine, agent server and key store. Every
  binary below is a consumer of it, which is what keeps the API honest; a
  mobile core is a consumer too, through its gomobile shell (§12).
* **`ladulasd`** — the daemon, and **the instance**: the SSH agent, the
  control socket, the approval engine, the peer channel and the store key.
  What runs under a systemd user unit on a desktop as well as on a
  headless box, since decision Z made the desktop a client of it rather
  than a second one.
* **`ladulas`** — the desktop application *and* the management CLI in one
  binary, a client of a running instance either way (decision Z).
  `ladulas gui` is the desktop application — the tray icon, the queued
  prompt popups and one application window with a sidebar in it
  (decision AA) — and needs a build that has a GUI in it
  (`-tags gui`, Wails v3); it holds no keys, serves no agent and draws
  what the daemon tells it over the control socket. `ladulas agent` is the
  one verb that still *is* an instance: the same daemon with a terminal
  for a prompt, for a box with no systemd. Every other verb is a thin
  client of the same socket (§14), and with no verb at all it prints the
  usage and starts nothing (decision Y). The two are one binary because
  the CLI and the GUI are peers rather than primary and afterthought.
* **`ladulas-sign`** — `ssh-keygen -Y sign` CLI-compatible signer binary
  for rich git signing prompts (§5).
* **`ladulas-relay`** — the optional wake-up relay: platform push
  credentials and device tokens keyed by opaque instance ids, sending
  "something is pending" and nothing else (§11). Nothing depends on it.
* **Ladulås mobile** — iOS today (a SwiftUI shell over the gomobile core),
  Android with M10. Approval prompts, key generation in hardware, remote
  signing, project doc browsing.
* **Shared viewer bundle** — one HTML/JS bundle, `viewer/`. On the desktop
  it renders request cards, the commit/diff viewer and the project doc
  browser; on the phone it keeps the two panes that are documents and the
  shell draws the rest (§12, decisions O and R).

### Process model

What the daemon starts, in the order it starts it. Everything here is one
process: there is no supervisor, no leader election and no work queue,
because an instance serves one account on one machine.

* **The outer half exists from start-up** and does not depend on the store:
  the audit log, the agent socket, the control socket, and the lock state
  itself. This is what makes a sealed instance answerable (§10, §14).
* **`App.Serve` binds the agent socket, then the peer listener, then the
  control socket, and only then marks the instance ready** — one goroutine
  per socket, and the ready signal is what anything unsealing at start
  waits for. The order is load-bearing: a peer listener that binds after
  the control socket would let something ask where this instance can be
  reached and get an answer that was about to change.
* **One goroutine per accepted connection**, on all three sockets. An SSH
  agent connection is served for its lifetime because the session-bind list
  is per connection (§4).
* **The passphrase prompt runs in a goroutine of its own** and races the
  control socket deliberately; whichever unseals the store first withdraws
  the other (§14).
* **The peer node adds three kinds of goroutine** when the store is
  unsealed and peering is on: the listener, one link per paired peer that
  can be dialled — each holding a presence stream open and reconnecting on
  a backoff that starts at a second and stops doubling at a minute — and
  the convergence loop, which is what makes a pairing resumable and a
  queued key handover eventually delivered.
* **The lock-trigger watcher** is a goroutine over logind's system bus
  (suspend, session lock) plus an idle timer where one is configured, and
  it is what turns those events into soft locks or seals (§10, decision J).
* **The debug listener** is one more goroutine when an address was named
  for it, and it is the only one that can fail without the instance
  noticing (§14).

**Sealing destroys the inner half rather than flagging it.** The engine,
the vault, the project cache and the peer node — links, listener and
convergence loop with them — are built by unsealing and dropped by
sealing, which is what makes "the DEK is not in memory" a statement about
the process rather than a hope. The sockets and the audit log outlive it.

The relay's process model is one sentence: an HTTP server, a debug server,
and no background work at all. It holds its device registrations in memory
behind a mutex and rewrites one file when they change.

### Connectivity model

Peers connect directly to each other, addressed as `host:port` (DNS names
fine), over any IP path — LAN, VPN, tailnet, or the open internet. The
app-level channel (§8) provides mutual authentication and end-to-end
encryption, so the network is never trusted, whatever it is.

Desktops listen and accept peer connections. **Phones never listen** —
they always dial out, triggered by a wake-up push (optional), by the user
opening the app, or on Android by a persistent foreground-service
connection. This sidesteps iOS's prohibition on background listeners
entirely and makes the phone story identical on both platforms:

```
requester desktop ──(optional wake-up: relay ▸ FCM/APNs/UnifiedPush)──▶ phone
       ▲                                                                 │
       └────────────── phone dials requester directly ◀─────────────────┘
```

When the approver is a desktop, or a phone that already has a live
connection (foreground app or foreground service), the request goes
directly over the existing channel and no wake-up is involved (Home
Assistant's "local push" model).

M6 made the consequence explicit rather than implied. A requester fans a
request out to every approver it has, and there are two ways of reaching
one: dial it, or hold it until it comes. Which one a peer gets is decided
by whether it advertised an address at pairing time, and a phone never
does, because it never listens. So a phone gets an **inbox** — the
request waits at the requester for exactly as long as somebody is blocked
on the answer, the phone collects it when the app opens, and posts back
the same signed artifact a dialled approver would have streamed. Nothing
is stored and nothing outlives the request: a phone that opens the app an
hour later finds an empty inbox rather than a commit nobody is making any
more.

## 4. SSH agent integration

Verified mechanics (against git master, openssh-portable, and
`golang.org/x/crypto` v0.54.0):

* The agent implements `agent.ExtendedAgent` — `SignWithFlags` is required
  (a plain `agent.Agent` silently drops the `SSH_AGENT_RSA_SHA2_*` flags,
  breaking RSA), and `Extension` is how `session-bind@openssh.com` arrives.
  Served with `agent.ServeAgent` per accepted connection.
* Sockets: unix socket + `SSH_AUTH_SOCK` on Linux/macOS. On Windows, claim
  the named pipe `\\.\pipe\openssh-ssh-agent` (via `Microsoft/go-winio`),
  exactly as 1Password does — Win32-OpenSSH finds it with zero config; the
  built-in "OpenSSH Authentication Agent" service must be disabled.
  git-for-windows users set `core.sshCommand` to Windows OpenSSH (same
  documented setup as 1Password's).
* **Git signing needs no signer binary to function**: with
  `user.signingkey` set to a literal public key (`key::…`), git runs
  `ssh-keygen -Y sign -n git -U -f <tmp-pubkey> <payload>`, and `-U` makes
  ssh-keygen sign via the agent. A pure agent covers commit signing;
  `ladulas-sign` (§5) is an enrichment, not a requirement.
* **Request classification is unambiguous.** A git/SSHSIG signing payload
  starts with the raw bytes `SSHSIG` (then namespace `"git"`, hash
  algorithm, and the message *digest*); an SSH auth payload is the
  RFC 4252 §7 blob (session ID, `SSH_MSG_USERAUTH_REQUEST`, username,
  service). Anything that parses as neither is denied by default.
* **There are two authentication methods, and the second is the usual one.**
  RFC 4252 §7 names the method `publickey`; OpenSSH ≥ 8.9 negotiates
  `publickey-hostbound-v00@openssh.com` whenever the server also has it,
  which in practice is nearly every server — GitHub included. The blob is
  identical with the **server's host key appended** (documented in
  OpenSSH's own `PROTOCOL`). An agent that knows only `publickey`
  classifies ordinary logins as opaque and denies them, and the symptom is
  `sign_and_send_pubkey: … agent refused operation` — which says nothing
  about why. Dogfooding found it that way; the audit entry naming the
  method is what turned it into a sentence.

  The extra field is worth more here than in OpenSSH. It puts the
  destination **inside the bytes being signed**, so it is not something
  the requesting machine says about a request — which makes it the one
  piece of §5's context that needs no "the approver's UI marks this as the
  requester's word". A key holder deciding a borrowed login parses the
  host key out of the payload itself, and a requester whose claimed
  destination is a different key is refused rather than shown to somebody
  (§15). The known_hosts *name* is still the requester's word, because
  known_hosts is on the requesting machine; it is only ever displayed
  beside a fingerprint that has been checked against the payload.
* **SSH auth prompts get host context from the payload first, and from
  `session-bind@openssh.com` otherwise**:
  OpenSSH ≥ 8.9 clients send the server's host key, session ID, and the
  server's signature over it before requesting identities — verifiable, and
  matchable against `known_hosts` for a display name. The agent keeps an
  ordered binding list per connection (forwarded hops arrive as additional
  binds with `is_forwarding=true`) and correlates auth-blob session IDs
  against it. Non-OpenSSH or older clients never bind; policy decides how
  to treat unbound sign requests (default: prompt, marked "unknown
  destination"). A binding is verified but travels *beside* the payload,
  which is why the hostbound host key wins when there is one: the
  difference is invisible on the machine that made the connection and is
  the whole question on a phone deciding for it. The binding list stays the
  path — it is what says a request came through a forwarded hop — and it is
  what answers when the payload names nothing.
* **Forwarded-agent requests always prompt**, regardless of auto-approve
  policies (Bitwarden's rule, and the right one: a hostile remote host
  holding the forwarded socket can send arbitrary well-formed requests).
* Mutation requests (`Add`/`Remove`/`Lock`/…) fail; key management goes
  through Ladulås itself. Optionally (ssh-tpm-agent's pattern) proxy
  unknown keys to another agent socket for coexistence during migration.
* **The identity list is what can sign, not what exists** (decision N).
  Keys borrowed from a paired holder are advertised only while that holder
  is reachable and still offering them. Every other surface — `ladulas
  keys list`, the viewer — lists them whether or not the holder is there,
  because a person looking for a key wants to know where it is; the agent
  protocol has no way to say "this one is unavailable", and ssh would
  spend one of the server's `MaxAuthTries` on it and fail with a sentence
  about authentication rather than about a phone. A *sign* request naming
  a borrowed key is still answered, and fails naming the holder (§8) —
  that path resolves a key by blob and does not go through the list.
* **A key is advertised because its holder says it may be** (decision T).
  The list is not everything that can sign either. Every key carries one
  setting for whether it belongs in an agent's identity list, kept where
  the key is and travelling with the public half to whoever borrows it. A
  key with it off is still a key: it signs when something names it,
  `user.signingkey` and `ssh -i` included, and no permission changed. It
  is simply not one of the identities ssh is handed and told to try in
  turn — which is worth having because ssh does try them all, and a phone
  lending four keys can put the interesting one after the server's
  `MaxAuthTries` has run out.
* **Reachable includes wakeable** (decision T). A phone holds keys and
  never listens, so "advertised while the holder is reachable" would have
  meant "never" for the holder that most needed it. A holder that collects
  counts as reachable when something will tell it there is something to
  do: a poll it is holding open, or a wake-up route it has announced
  (§11). The signature that follows is parked and pushed exactly as an
  approval is (§8). An ssh login is the one operation here with somebody
  else's clock on it — sshd closes the connection after `LoginGraceTime`,
  two minutes by default — so for authentication the wake-up is the
  mechanism rather than an optimization on poll-on-open, and a holder with
  no route is not advertised at all.

An SSH auth prompt can therefore say:

> **SSH login** as `hugo` to `bastion.example.net`
> (host key `SHA256:…`, matched known_hosts entry; via 1 forwarded hop)
> using key `work-ed25519` — requested by `builder` (headless)

A plain-agent git signing prompt can only say "sign git object
`sha512:…` with key X" — the agent sees a digest, not the commit. Hence:

## 5. `ladulas-sign`: rich git signing prompts

`ladulas-sign` implements the `ssh-keygen -Y sign` CLI contract
(`-Y sign -n git -f <keyfile> [-U] <payload-file>`, write `<payload>.sig`)
and is configured as `gpg.ssh.program`. Unlike `ssh-keygen` it talks to the
local Ladulås instance directly and attaches context:

* **From the payload file**: git hands the signer the *full commit or tag
  object* — tree, parents, author, committer, timestamps, and the complete
  message. Parsed and attached, not hashed away.
* **From the environment**: the signer runs inside the repo, so it collects
  the repo path, `origin` URL, branch, and a diffstat
  (`git diff <parent> <tree>`), with the full diff available on demand when
  the approval UI asks for it (capped; large diffs truncate with a note).

The approval prompt for a commit then shows repo, branch, author, message,
and diffstat, with drill-down to the diff on the approving device — desktop
or phone, same viewer (§12). Fallback remains stock
`ssh-keygen -Y sign -U` against the agent socket on machines where only
`SSH_AUTH_SOCK` is configured — same keys, poorer prompt.

**Hand-over is for the command lines git builds, and only those**
(decision AI). Every one of them names an operation with `-Y` — `sign` when
git wants a signature, `find-principals` and `verify` when it is checking
one — so anything reaching this program without a `-Y` was typed by a
person, and passing it on is the wrong reflex: `ssh-keygen` with no
operation flag *generates a key*. `ladulas-sign -h` therefore opened a
prompt to write a new private key into `~/.ssh` instead of saying what the
program was, and `-help`, which getopt reads as `-h -e -l -p`, opened one
to change the passphrase on an existing key. A command line with no `-Y`
now gets the usage: exit 0 when it is a help request, exit 1 and a sentence
naming what was refused otherwise. Everything git constructs is untouched.

Design detail: `ladulas-sign` submits the *raw payload* plus context; the
signing instance recomputes the SSHSIG wrapper itself. The context is
display metadata, and the approver's UI marks it as such — the payload is
what gets signed; the context rides along unverified (it originates on the
requesting machine, which is exactly the machine we distrust when it's
headless). Mitigation: the approver independently verifies that the
context's claimed commit matches the payload it is about to sign (it has
the full object, so message/author shown are provably what is signed; only
repo/branch/diff remain requester-asserted, and are labelled so in the UI).

## 6. Project publishing and doc browsing

Approving for a headless box is easier when you know what the project is.
A requester **marks a project as published to its paired approvers**, and
an approver can browse that project's documentation — from the peer it
belongs to, or from the card asking it to sign something in it.

Publishing is a **state, not an action** (decision Q, §19): marking a
project published sends nothing. An approver that wants to read one lists
the directories a page at a time, searches them by filename, and fetches
the files it opens — keeping those, so what has been read once stays
readable with no signal. A project nobody has opened is not readable
offline, which is the price of never shipping a tree.

Published per project:

* identity: a name, the path on the requester, the `origin` URL, and the
  branch/HEAD it was last read at;
* the files of the project's working directory, browsable. Markdown is
  what the viewer renders today and the listing is deliberately not
  limited to it — what can be *shown* is a separate question from what can
  be *listed*, and the answer to the first will grow. Symlinks are never
  followed, and per-file, per-page and per-project caps bound both what an
  approver has to store and what a single call can be made to return.

**What of markdown is understood is a security boundary, not a feature
list.** Headings, paragraphs, fenced and indented code, quotes, lists, pipe
tables, rules, and inline emphasis, code spans and links — parsed in Go into
typed blocks, because a renderer with no parser in it has very little to get
wrong (§12, §16). Tables are in because the documents this exists for are
full of them: a README says what a flag does in a table, and a reader shown
the pipes instead is being asked to parse it themselves. Footnotes,
reference links and raw HTML are not interpreted and arrive as the text they
are, which is the right failure mode for a document viewer that must not
become a rendering engine.

A heading carries an anchor derived from its own text, and a link to one is
the only link in a published document that navigates nothing at all — the
page scrolls. Both halves are computed in Go, so every host lands on the
same heading for the same fragment, and a fragment naming no heading in that
document is demoted to text rather than drawn as a button that does nothing
when it is tapped. A fragment that travels with a path to another file is
that file's business and is checked when it is opened, which is also how it
survives the phone: it rides as its own parameter through the shell that
takes the link over (decision R), rather than as a URL fragment nobody
promised to hand on.

**Who says so is the browser, not the publisher** (decision R). Keeping
listing and showing apart is a property of the protocol and not an
instruction to draw every entry: a desktop window has room for a
greyed-out row with "not a kind this instance offers to read" beside it,
and a phone does not — there the same honesty is forty rows that do
nothing when tapped. So a browsing call may say it will only draw what it
can show (`only=readable` on a directory or a search), and the answer
drops what the publisher would refuse. Because paging belongs to the
publisher, filtering can empty a page that still has a token in it, so the
same call reads on until it has something or the directory ends — bounded,
because an unbounded walk of somebody else's repository is not a thing to
do on the strength of a query parameter. A caller that does not ask gets
the listing whole, which is what the shared bundle asks for.

**A folder that leads nowhere is answered by the publisher.** Filtering
files out leaves the folders that contain only files that were filtered
out, and an approver cannot tell which those are without a call per folder
and then a call per folder inside it — down a network, to find out whether
a row is worth drawing, and still wrong about a folder whose only document
is four levels down. So the entry for a directory carries
`nothing_readable`: the publisher walks its own disk, stops at the first
file it would serve, and says so. The field is stated the empty way round
and every uncertainty resolves to false — a walk that fails, a walk that
hits its cap, a publisher too old to have heard of it — because a browser
that hides on true then shows a folder it should not rather than hiding
every folder there is.

Signing requests reference the project they belong to — by an identifier both
ends derive from the origin URL and the repository path, so nothing has to be
carried — and an approval prompt links straight to the docs. The link is
offered whether or not anything of the project has been read, because
browsing is a pull and the machine that is asking for a signature is by
definition awake. Staleness is labelled against the commit the change is
built on, since the commit being signed has no identifier until the signature
exists: "2 pages read here on 9 Aug 14:03, at X, which is the commit this
change is built on", or "…; this change is built on Y". A project nothing has
been read of has nothing to be stale against, and says so.

**Decision F — publication model:**

* **F1 — snapshot push.** Publishing sends the doc set to approvers, who
  store it. Browsable offline (phone on the bus), survives the requester
  going away; can go stale.
* **F2 — live pull.** Approvers fetch tree and files from the requester
  on browse. Always current, nothing stored, but only works while the
  requester is reachable.
* **F3 — snapshot + live refresh (recommended).** Publish pushes a
  snapshot; when the requester is reachable, the viewer refreshes files
  on demand and shows what changed. Offline browsing and freshness both;
  the extra cost is a content-addressed manifest, which the staleness
  labelling wants anyway.

**Resolved: F3, snapshot + live refresh** — and then **superseded in part
by decision Q**, which keeps the live half and drops the snapshot. The
argument F3 won on was offline browsing; the argument it lost on is that
it paid for offline browsing by shipping every doc set to every approver
whether or not anybody would ever open one. Q keeps what an approver has
actually read, which is the same offline property for the pages that
have a reader.

Safety rails, independent of model: the doc server side canonicalizes
paths against the project root (symlinks resolved, `..` and absolute paths
rejected) so a compromised requester cannot use browsing to read arbitrary
files *from the requester* — and more importantly the approver treats all
of it as untrusted display content: rendered by the sandboxed markdown
renderer in the viewer (no scripts, no remote fetches, §12), with per-file
and per-project size caps. Published content is requester-asserted
context, not evidence, and the UI labels it as such.

## 7. Identity, pairing, and trust

### Instance identity

Every instance generates an identity keypair at first run, distinct from
any SSH keys it may hold:

* Desktop: ed25519.
* Mobile: P-256 in Android Keystore / Secure Enclave (hardware-resident,
  *not* biometric-gated — it authenticates the channel, and per-handshake
  biometrics would be unusable; the SSH keys are the biometric-gated ones).

The identity key authenticates the transport channel (§8) and is the
**sole mandatory trust layer** — everything below in "network-layer
hardening" is optional extra. Instances are identified in UIs by a
fingerprint (SHA-256, SSH-style base64) plus a human-assigned name.

A UI may also draw a **picture generated from the fingerprint**
(`pkg/avatar`, served by the bridge so every host draws the same
face for the same key), because forty-four base64 characters are exactly
what nobody compares and a peer whose face changed is a peer worth
looking at twice. It is **decoration, not security**: nothing about it is
checked or signed, and a face two keys share is a collision in a small
hash rather than in an identity key. The characters stay on screen beside
it, and the pairing confirmation still shows both fingerprints in full
(decision O, §19).

### Pairing (trust on first use)

Pairing establishes a mutual record: peer identity key, name, and the
**approval direction** — whether the other may approve for it, may request
approval from it, or both.

**The direction is one answer, given on the side displaying the code** —
decision AD. Somebody there says what the pairing is for, in the three
shapes there are: an approver for this instance, an instance to approve
for, or both. The side that uses the code declares nothing; it is shown
what was chosen, on its own confirmation, and either agrees to that pairing
or does not. What each side writes down is that one answer and its mirror,
because a peer that may ask us to approve is a peer we approve for.

It was two independent declarations until 2026-08-19, one per side, with
nothing making them agree — and the ordinary result was a pairing whose two
halves said different things, because the flag defaulted to "both" at each
end and nobody was ever shown what the other had chosen. The way that
failed is [`bugs/a-peer-that-cannot-approve-vetoes-every-request.md`](../bugs/a-peer-that-cannot-approve-vetoes-every-request.md):
an instance recorded "this machine may approve for me" about a box with no
approver at all, and every request it made was then answered by that box
saying it had nobody to ask (decision AC is the other half of that fix).
The direction is not a preference to be tuned afterwards, either —
**changing what a pairing is for means removing the peer and pairing
again**, which is a limit and is meant to be one: a direction that can be
widened later is a direction nobody has to think about now, and this is the
question a pairing exists to ask. `ladulas peers allow` still adjusts an
existing record, which is the escape hatch for somebody who knows exactly
what they are doing.

Key access is a third decision, taken separately: pairing grants directions,
never keys, and `ladulas peers allow --key <label>` (or `--all-keys`) is what
lends one. Its blast radius differs from either direction's — a peer that may
ask this instance to approve is not thereby allowed to borrow its keys — and
the all-keys flag exists because a list of everything held today silently fails
to cover a key generated tomorrow.

Flow: instance A says what the pairing is for and displays a pairing code
(and a QR — the Krypton pattern; the QR carries A's identity public key so
B can seal its response to it, making the visual channel the integrity
root). B connects to A's `host:port`, both sides display both fingerprints
and the same sentence about what the pairing does, and *each side's user
confirms on that side*. Trust records live in the encrypted local store
(§10) and are revocable unilaterally.

**The QR is drawn** since 2026-08-19 — decision AE. A desktop shows it
beside the typed code and the command line, on the same screen the intent
was chosen on; a headless box still prints the string and the `qrencode`
invocation, because a terminal is not somewhere Ladulås gets to choose the
pixels. It is one route on the bridge (`/api/v1/pairings/qr`), drawn from
`rsc.io/qr` and rendered to SVG here, and it is the one response the bridge
serves with `Cache-Control: no-store`: the string behind it is a secret
with five minutes to live.

**A pairing is in two halves that keep different time** (decision M). The
first half is the code: `trust.CodeValidity` (5 minutes), single use, five
wrong answers. That window is what bounds guessing a fifty-bit secret and
it is a security property; nothing about it is negotiable. What it buys is
the second half, and the second half has no clock on it at all — because
what remains is two people comparing two hashes on two screens, and a
person is not something an attacker can guess at ten thousand tries a
second.

So the moment the code is spent, **both sides write down a pending
pairing**: the session id, the peer's identity key and fingerprint, its
addresses, which side dialled, what this side would grant if its user
agrees, what the peer said it grants, and each side's answer so far. It
lives in the encrypted store beside the trust records, because who is
trying to pair with this machine is the same map they are. The cost is
real and is stated rather than worked around: **a sealed instance can
neither list nor answer a pending pairing**, exactly as it can neither
list a peer nor revoke one.

From there, three rules:

* **An answer is recorded here before anybody is told.** `pairings
  approve` writes it into the store and returns; telling the peer is a
  separate, retried, idempotent thing. An unreachable, asleep,
  backgrounded or restarting peer therefore costs a delay and nothing
  else.
* **Either side may drive the convergence.** `SettlePairing` carries the
  caller's answer and brings the callee's back, and either end may call it
  as often as it likes. This is not symmetry for its own sake: a phone
  advertises no address, so if only the dialler could report, a phone that
  went to sleep would strand the pairing for ever. A completed pairing
  goes on answering for the session it came out of — the session id is
  kept on the trust record — so a peer that never heard the last word gets
  it rather than being told the pairing is gone.
* **Nothing but a person ends a pairing.** No deadline denies one; a
  confirmation prompt is submitted to the engine with no timeout, and an
  engine that found nobody to ask leaves the pairing exactly where it was
  and tries again when an approver appears. The ways a pairing ends are:
  somebody says no, somebody withdraws it, or the two ends turn out to
  disagree about who they are talking to — a proof that does not match the
  code, an identity in a message that is not the one on the channel, a
  session id presented by an identity it does not belong to. Those are
  errors. Unreachable, asleep, backgrounded, restarted and slow are not.

**Withdrawal propagates by asking, not by remembering.** Calling a pairing
off removes it here and tells the peer if it happens to be reachable; a
peer that was not finds out the next time it asks, because an instance
with no record of a session says so and the side still holding one drops
it. The alternative — keeping a tombstone until it has been delivered —
was rejected for a specific reason rather than a general one: a phone has
no address, so a desktop could never deliver a tombstone to one at all,
and the side-that-holds-it-asks mechanism has to exist anyway. Having two
mechanisms where one covers every case is worse than the cost, which is
that a peer that was unreachable at the moment of the decision is told
"the other side has no record of this pairing" rather than "declined" or
"called off". The exact reason is delivered whenever the peer is reachable
at the time, which is most of the time and is never load-bearing.

**The pending set is bounded**, at one entry per peer identity and sixteen
in total. It is clutter control rather than a security boundary — every
entry is listed and any of them can be dismissed by hand — but it has to
be bounded by something. A second attempt from an identity that is already
pending replaces its entry, because that is one person retrying rather
than two questions; and since a code is single use, each new identity in
the set costs somebody a deliberate action at the machine displaying one.

The surfaces follow from all of this rather than being a separate
decision. `ladulas pairings list|approve|reject|withdraw` on the control
socket (§14), the same list and the same cards in the shared viewer on the
tray and the phone (§12), and `ladulas pair` reporting that the pairing is
recorded and giving the terminal back once its own user has answered —
because nothing is waiting on that terminal any more.

**Starting one is a surface too**, and was a command line and nothing else
until 2026-08-19 (§12). The window now asks the intent and displays the
code; the window holding a code is what holds the pairing window open, so
closing the screen takes the code off both.

What this replaces: a model in which nothing survived an unanswered
attempt. The pending record was in the memory of the process running the
call, the confirmation was a card on a deadline, and the dialling side
owed the listening side a report that had to land in the moment. Running
M6 on a phone found all three at once — the desktop's user approved, the
phone's card ran out, and both machines were left with nothing. The
narrow fixes for that (a budget per side, a report on a context of its
own, an error that distinguishes "unanswered" from "declined") were
correct and are still here; what they could not fix is that the pairing
had nowhere to live.

### What a peer's state says, and what it must not

Every surface that lists peers shows one word for reachability, and all of
them get it from `trust.DescribeState` — the desktop's pill, the STATE column
of `ladulas peers list`, the badge on the phone. It was three copies of the
same `switch` in three packages before that, which is how they drifted.

**"Not connected" and "not available" are different facts, and which one a
missing link means depends on who does the dialling.** A machine listens on
`host:port`, so this instance dials it: no link is a machine that is not
there, and `connecting` while it tries and `offline` once a dial has failed
are both honest. A phone listens to nothing at all. It reaches *us* — when
somebody opens the app, when a push wakes it, when it polls (§11) — so a
phone with no link is a phone in a pocket, which is the ordinary state of a
phone and says nothing whatever about whether it can be asked to sign. Its
keys are one notification away (decision T), and calling it `offline` claims
the opposite.

So a peer with no address in its record gets **when it was last here**
instead: `last seen 4m ago`, `connected` while it is holding a call open, and
`waiting to hear from it` when this instance has heard nothing yet. That is the
question somebody actually has in front of them — a phone seen a minute ago and
a phone seen in March want different things done — and it is the same
distinction decision N already draws for the keys such a peer holds, which are
listed whether or not their holder is reachable. It said `connecting` forever
before this, on a dial that was never going to succeed against a device that
does not listen.

The lack of an address is what tells the two apart, because it is what the
dialling is decided on: nothing can dial a peer whose record carries no address.

**Where the answer comes from for a device that dials in**, since none of the
dialling machinery ever hears from it: every call a peer makes goes through one
of the two authorisation chokepoints — `authorize` for a peer asking this
instance to approve, `publisherFor` for an approver collecting work or reading
documentation — and both record the contact (`peer.Node.saw`). A long poll for
parked requests also registers as a call *held open* (`peer.Node.holding`),
which is as connected as a device that does not listen ever gets, so a phone
with the app open reads as `connected` and one in a pocket reads as when it was
last used. Everything a phone does is one of those calls: collecting what is
parked for it, announcing the keys it holds, reading a page of a published
project.

It is in memory and not in the store. Presence is worth nothing after a restart
and stamping the encrypted store on every poll would be a write a second for a
fact that expires — which is also why the unknown case says `waiting to hear
from it` rather than "never": after a daemon restart, "never" would be a claim
about the phone when the truth is a claim about this instance. **A nil timestamp
is not a zero time**, either: `AsTime()` on an absent one gives the epoch, which
is how a phone nothing had heard from was reported as `last seen 20683 days
ago`.

A surface that wants to say more than the word has the fields to do it —
`PeerView.Dialable` and `PeerView.LastSeen` — and the desktop's peer screen uses
them to say, in a sentence, that a machine which reaches us is not a machine
that is missing.

### Optional network-layer hardening

Ladulås runs on any network; when it happens to be a tailnet, it can use
it (all of this is optional and auto-detected, never assumed). Two of the
three are still design rather than code, and are marked so — the `transport.Gate`
hook exists and admits everything until the WhoIs half is built:

* **Same-user gate** (*not yet built*): with a local tailscaled available,
  incoming connections could be checked via LocalAPI `WhoIs` and restricted
  to the same tailnet user's devices (Taildrop's rule) before any protocol
  bytes are processed. The gate seam is in place; the WhoIs lookup behind it
  is not, so today it admits every identity to the pairing surface and the
  app-level trust check is the whole of the door (§8, §15).
* **TOFU labelling** (*half built*): WhoIs node names would make pairing
  prompts confirmable — "new identity `SHA256:…` connecting from tailnet
  node `hugo-phone`" beats a bare fingerprint. That half needs the WhoIs
  lookup and is still design. The other half needs nothing: an instance can
  find its *own* node name by asking the resolver what its own tailnet
  address is called, and advertise that instead of the number, so the name is
  what the peer records and shows (§8, decision AH). Reverse DNS and a forward
  confirmation, no dependency, no daemon socket — and it is corroboration in
  the same sense as everything else here, because the identity key is what a
  pairing is checked against and an address list that has been lied to costs
  a failed connection rather than a wrong peer.
* **Bind policy** (built, decisions H and AH): the listener binds where the
  user says, and where nobody has said it chooses one tier of addresses
  rather than every address it can find. Binding to public interfaces is an
  explicit opt-in — listening on the open internet is supported (the channel
  doesn't trust the network), but it should never happen by accident.

App-level identity keys stay authoritative in all cases: a compromised
Tailscale control plane can insert a node that WhoIs vouches for, which is
exactly the attack the app-level TOFU layer survives. Trust decisions key
on the identity key; the tailnet `Node.StableID`, when present, is recorded
as a corroborating attribute only.

## 8. Transport — **Decision A**

The app-level channel provides end-to-end mutual auth bound to identity
keys and assumes nothing about the network underneath. **Resolved: A1
(pinned TLS) with connect-go as the RPC layer (Decision D).**

**Option A1 — TLS 1.3 with self-signed certs and pinned-SPKI TOFU
(recommended).** Each instance wraps its identity key in a self-signed
cert. Server side `RequireAnyClientCert`, client side
`InsecureSkipVerify: true`; both run a custom `VerifyPeerCertificate`
pinning the SHA-256 of the peer's `RawSubjectPublicKeyInfo` (SPKI, not the
cert — reissuing a cert around the same key doesn't change the identity;
Syncthing's mistake avoided). Stdlib crypto; works natively with both
ed25519 (desktop) and P-256 (mobile) identities — the deciding argument;
Syncthing-proven trust model; and HTTP-shaped, so the RPC layer (below)
comes for free.

**Option A2 — Noise_XX (`flynn/noise`).** Cryptographically the most
elegant TOFU handshake (static keys exchanged encrypted, neither side needs
prior knowledge). But: X25519 statics only — P-256 mobile identities don't
fit at all and ed25519 needs conversion tricks, so mobile hardware keys
would have to endorse a software Noise key; plus DIY framing, rekeying,
multiplexing, and RPC; small single-maintainer dependency, no public audit.

**Option A3 — SSH protocol as transport (`x/crypto/ssh`).** Best
out-of-box fingerprint UX (`ssh.FingerprintSHA256`) and built-in channels.
But client/server asymmetry fits symmetric peers badly, request payloads
are opaque bytes so a message schema is needed anyway, and it drags in
SSH's whole negotiation surface.

**RPC layer on A1: connect-go over the mutually-authenticated TLS.**
Protobuf-defined RPCs on plain `net/http` (the pinned `tls.Config` plugs
straight in), full streaming support for the long-lived
approval-subscription stream, and far lighter than grpc-go. Alternative:
hand-rolled length-prefixed framing — adequate at these message rates, but
buys nothing except owning correlation/cancellation/versioning ourselves.

**Reachability and discovery.** Peers are configured as `host:port`; only
listeners (desktops/headless boxes) need to be reachable — phones always
dial out. No NAT traversal is built in (§1 non-goals). Optional later:
mDNS announcement for LAN discovery during pairing, so the phone can find
`desktop.local` without typing an address. tsnet (an embedded Tailscale
node) stays available as an *option* for exotic embedders of the library,
but is not load-bearing — and embedding tsnet via gomobile on Android is
currently broken anyway (tailscale/tailscale#17311).

**What is bound and what is advertised are two lists** (decision AH). They
were one until 2026-08-21, and one list cannot be both: what a socket is
opened on is a fact about this machine, and what a peer is told to dial is
an instruction to another one.

The automatic policy picks **one tier**: the machine's tailnet addresses if
it has any, otherwise its other private addresses, otherwise loopback —
having first passed over every interface that is up but not running, and
every interface whose name belongs to a container runtime or a virtual
machine. It used to bind all of them at once. On a desktop with Docker and
libvirt installed that was fourteen listeners, eleven of which no peer could
reach, and the same fourteen addresses were handed to every peer that paired
with it.

What gets advertised is that list with two changes. A tailnet address is
advertised under its **node name** first — `horatio.tailnet.ts.net:7373`
before `100.74.235.31:7373` — which is the string a person recognises on the
other machine and is stable in a way the address is not; the address stays
behind it, because the name resolves only for a peer whose MagicDNS is on.
And loopback is advertised only by an instance that has nothing else, since
telling a peer on another machine to dial `127.0.0.1` is telling it to dial
itself.

Which it did, and the consequences were not confined to a wasted
connection. **An address that answers with our own identity is not an
impostor**: the dialler compares the pin it met against its own before it
compares it against the peer's, and an address that turns out to be this
machine is skipped rather than reported. And when every address fails, the
one reported is the **most informative** — a peer that answered as somebody
else over a connection that was refused, and a refusal over a name that would
not resolve — rather than the last one tried, which by construction is the
one nobody expected to work. All three of those are one bug's three parts,
written up in `bugs/an-identity-mismatch-that-was-a-loopback-address.md`: an
unreachable peer reported "the peer is not the expected identity", naming
fingerprints that did not match because one of them was ours, and the store
that was actually sealed went unmentioned. Do not report a peer's identity as
wrong on evidence gathered from a socket on this machine.

**The name is looked up when somebody asks, not when the channel binds.**
That is a correction rather than a refinement: it was resolved once, inside
the bind, and whatever the resolver said in that instant was what every
later reader got. Binding is the worst moment to ask. It happens seconds
after the daemon starts, which on a machine where NetworkManager and
tailscaled are still arguing over the tailnet link is exactly when MagicDNS
is not there — and the failure is silent by design, because the address is
the documented fallback. So an instance would come up advertising the
number, keep advertising it for as long as the channel stayed up, and a
pairing made in that window would write the number into the peer's trust
record for good, since nothing refreshes one. A convenience that degrades
under a transient fault is fine; one whose transient fault is written down
permanently is not.

Asking at the point of use makes it self-healing, and a small cache in
front of the resolver is what makes that affordable — five minutes for a
name that resolved, thirty seconds for one that did not, because a name is
stable and a failure is a question worth re-asking soon. Only the pairing
paths and `ladulas listen` ask; `ladulas status` and the window's poll
report what was **bound**, so nothing on a four-second timer touches a
resolver. A lookup that finds nothing logs once at `debug` rather than once
per question — the original bug went unnoticed because nothing said
anything at all, and a feature that degrades in silence is one discovered
by comparing two screens.

**A link is not up until the peer has said something.** The presence stream
is what tells this instance whether there is anybody to ask before it has
anything to ask, and it used to be treated as established the moment the
client returned it. It is not: connect hands back a stream as soon as the
request has been queued and keeps the transport error for the first
`Receive`, which its own comment on `CallServerStream` says outright. So a
laptop asleep with its lid shut was logged as "linked to a peer" every
twenty seconds, marked online, and sent the grant activity that a link
coming up hands over — and, worse, the loop over the peer's addresses never
advanced past its first entry, because the address that could not be reached
never reported that it could not be reached. The first heartbeat is free
evidence and costs nothing to wait for: `Watch`'s handler sends one before
it waits on its ticker, so a stream that yields nothing is a peer that is
not there.

**Failing over is rationed rather than free.** Once the loop works, a peer
that is merely asleep charges a dial timeout for every address in its trust
record — and a record written before decision AH holds every address the
peer could see, including its container runtime's, fourteen of them on an
ordinary desktop. So the address that last worked is tried alone for three
consecutive failures before the rest of the record gets a turn. A peer
coming back on the address it left on never reaches the sweep; one that has
genuinely moved is found inside the minute the backoff ceiling promises.
The call paths do not ration it — a signature somebody is waiting for tries
everything it has, because it is not on a timer and there is no next round.

The protocol (sketch — to be specified precisely in a follow-up):

* `Pair` — pairing handshake, direction declaration.
* `ListKeys` — keys a peer offers this requester (public halves +
  metadata), letting a keyless agent answer `SSH_AGENTC_REQUEST_IDENTITIES`.
* `AnnounceKeys` — the same list, sent the other way, by a holder that
  cannot be dialled. A phone is the side that can always dial, so it says
  what it offers rather than waiting to be asked, the way it already says
  where it can be woken (§11). The requester remembers it exactly as it
  remembers an answer to `ListKeys` (decision N).
* `RequestApproval` — typed request (ssh-auth | git-sign | key-list |
  pairing | admin) with the parsed context from §4/§5; streamed so the
  requester can cancel on first-response-wins.
* `RemoteSign` — payload + key ref; returns the signature. Implies an
  approval on the key holder per its own policy (§9). The key holder rebuilds
  the SSHSIG wrapper and re-classifies the payload itself, so the prompt it
  shows is a parse of the bytes it is about to sign rather than of the
  requester's account of them (§5). A holder that cannot be dialled is
  asked through the inbox instead: the same request is parked, the wake-up
  is sent, and the signature comes back on `AnswerPending` beside the
  decision — one road, two directions of dialling, and the holder's
  reconstruction and its engine are the same code either way.
* `FetchDiff` — the rest of a diff the caps cut short, asked of the requester
  about a request it currently has out to the asking peer, and only then.
* `PushProject` / `ListProjects` / `FetchProjectFile` / `DropProject` —
  project doc publishing and browsing (§6). The push goes to an approver; the
  listing and the fetch go the other way, from a browsing approver to the
  requester, so the two are authorized by the two halves of a pairing.
* `FetchPending` / `AnswerPending` — the inbox (§3, M6): an approver that
  cannot be dialled asks a requester what is waiting for it, and posts its
  decision back. Both are authorized by the same half of a pairing as
  `RequestApproval` and carry the same bytes and the same signed artifact;
  what differs is only which side dials. `FetchPending` takes a bounded
  wait, so a phone with the app open is a long poll rather than a
  refresh button. A parked request may also carry the payload to sign, and
  then the answer carries the signature: that is `RemoteSign` for a holder
  in a pocket, and nothing else about the inbox changes for it.
* `Ping/Presence` — liveness for the "skip the wake-up" fast path.

All requests carry a random request ID; responses are signed by the
approver's identity key so approvals are auditable artifacts, not just
channel messages.

## 9. Approval engine and policies

One engine serves both local prompts and remote requests; local GUI
approval is simply an approver that happens to share the process.

**Request lifecycle**: agent/signer produces a typed, parsed request →
policy evaluation → if a rule auto-approves (or auto-denies), done, logged
→ otherwise fan out to eligible approvers: local GUI if present (and the
store not locked, §10), connected peers with approval rights, wake-ups for
reachable-but-sleeping mobile approvers. First decision wins; everyone else gets a cancellation.

**How long a request waits, and why the two kinds differ** (decision AJ).
SSH authentication gets ~90 s, because it is not this instance's clock:
the far server's `LoginGraceTime` is typically 120 s, so a budget past that
is a login that fails after the person answered it. Signing gets **an
hour**, because nothing is counting at the other end — `ssh-keygen` and git
block happily — and the two costs are not symmetric. A request that waits
too long costs a terminal somebody has walked away from. One that gives up
too early costs the commit: git aborts, the work is repeated, and the
person answering is punished for having been in another room. It was five
minutes, which is long enough to walk to the kitchen and not long enough to
be in a meeting.

Two numbers elsewhere are the same number and move with it. A request
collected out of an inbox by a phone (§8) is capped at what the budget is,
having been capped at fifteen minutes against a five-minute budget where it
never bit; a shorter cap takes the prompt off the phone while the requester
is still waiting, which is the case the hour exists for. And the approval
wait histogram's last bucket is the budget, so a request that ran the clock
out is a bucket rather than an overflow ([observability.md](observability.md)).

**The budget is the one thing a surface may change.** `Settings` and
`SetSignTimeout` on the control socket read it and write it; the desktop
window's Settings screen and any other host draw it from the instance view,
with the bounds the instance will accept — at least 30 s, at most a day —
the way a grant offer carries its `max_ttl` (decision V). Writing it goes
through the daemon, which is the only process that touches the policy
document (decision L), and it re-reads the file before writing so that a
hand edit waiting for a reload is adopted rather than silently reverted.
Requests already waiting keep the budget they started under: a deadline is
set when a request arrives, and a clock that jumps under somebody reading a
diff is a clock that cannot be trusted for the one thing it is for.

**It is one field and not a policy editor, deliberately.** The policy
decides what is approved without asking anybody, so a settings screen that
could write rules would put an auto-approve rule one mis-click from every
process running as this user. A number that decides how long somebody has
to answer cannot approve anything by itself. Adding a second setting here
is deliberate work, and that is the point. The bounds are on the surfaces
rather than on the document: a hand-edited `policy.json` stays unbounded,
because somebody editing the file has said what they mean.

**An answer settles one card, and the others are withdrawn** (decision AM).
The engine cancels the losers the moment a decision arrives, and each
cancelled approver takes its own card off its own screen — which only
works if exactly one approver's `Decide` returns the answer. An answer
arriving on the control socket therefore names the *prompt* it answers and
not the request: a request id names the question and every card drawn for
it, so an answer under one was handed to every screen showing it, every
approver returned it, and nobody reached the branch that withdraws
anything. The desktop's popup went on asking after the terminal had
answered and the commit had been signed. An approver id is no
discriminator either — two terminals both call themselves `terminal` — so
the daemon mints a token per card, sends it with the prompt, and matches
the answer against it.

**The set of approvers is not fixed when the request goes out** (decision
AL). An approver that registers while a request is waiting is asked about
it too, and so is a local prompt the moment a soft lock is lifted from
one — because the question is the daemon's and a front end is a screen
that answers it, not a party whose standing depends on having been in the
room when it was asked. Attaching grants nothing: the socket's uid check
is the whole authority (§14), the deadline stays the request's, and the
answer is signed and logged the same either way.

What the old behaviour cost was the obvious thing: a signature blocking a
terminal could only be answered by something that was already running, so
`ssh` in and start a terminal approver and the screen was empty. It was
not a rule anybody wrote down — it was where the fan-out kept its count.
That count is the part to be careful with, and it now moves under a lock:
`prompt` denies with `NO_APPROVER` only once every approver **it has
asked** has gone, the tally is re-read each time round the loop, and a
request that has been settled takes no more joiners. Decision AC is the
bug that lived in exactly that arithmetic, which is why the same file says
so twice.

**A peer saying it has nobody to ask is not a decision** — decision AC. It
is a report about the peer, and it goes where an approver that could not be
reached goes: the request is denied only when every eligible approver has
gone that way, and until then the prompts that are up stay up. The
distinction is not academic. A peer runs this same engine, and a peer with
no approver of its own denies with `NO_APPROVER` the instant it is asked,
because nothing was asked of anybody — so under "first response wins" it
took the race against a desktop prompt waiting on a human, every time.
Pairing an instance that could not approve stopped being a second way to
get an answer and became a veto on the first, deterministically, for every
signature on the machine. That is
[`bugs/a-peer-that-cannot-approve-vetoes-every-request.md`](../bugs/a-peer-that-cannot-approve-vetoes-every-request.md),
and decision AD is the other half of the fix: a pairing like that is now
harder to create by accident.

Only `NO_APPROVER`, and only from a peer. A peer's timeout means somebody
was asked and did not answer, which is a fact about the request; a policy
denial, a hard rule and a human saying no are all decisions. An approval is
never discarded whatever it says about its source.

**A pairing confirmation is offered no promise.** "Approve for a while" is a
scope and a clock over signing with a key, and a pairing has no key, happens
once, and always prompts — so a grant over one could never be spent, and
the offer was three buttons and a clock under a question whose whole content
is "is this the machine on the other screen". The engine sizes the offer
from the policy for kinds that can carry one and sends none for the kinds
that cannot (pairing, and a key listing, which is the same shape of
nothing); an answer that asks for a promise anyway is answering a question
it was not shown, and gets none.

**A pairing confirmation has no timeout at all** (decision M). Every other
kind is waited for by something that cannot wait — a handshake with a grace
period, a git command holding a terminal — and giving up is the kindest thing
to do to it. A pairing confirmation is waited for by a record on disk, and
giving up on it throws away half of a decision two people are in the middle of
making. So it runs on its caller's context alone and ends when somebody answers
it, when another approver answers it first, or when it is withdrawn. An engine
that finds no eligible approver does not deny it either: the pairing stays
where it is, and the prompt goes up again when an approver appears (§7).

**Policy vocabulary** (converged from Krypton's 3-hour grants, Secretive's
temporary unlock, Tailscale's `checkPeriod`, `ssh-add -c`):

* per use — always prompt;
* TTL grant, scoped — "this key to this host for 3 h", "git signing in
  this repo for the rest of the day", granted from the prompt itself
  (a **Session** or **Machine** button, and then a clock);
* auto-approve **with notification** — silent allow, but the approver
  devices still show a passive notification (Secretive's pattern);
* deny rules — e.g. "this key never signs for forwarded connections".

Hard rules that policies cannot override: forwarded-agent requests always
prompt (§4); requests that parse as neither SSHSIG nor RFC 4252 are denied;
pairing changes always prompt.

**Where a TTL grant lives follows the key it is about** — decision P,
argued in full in §19:

* **The requester's own key**: the grant is *delegated*. The approver
  signs a scoped, expiring artifact naming both instances, the requester
  keeps it and applies it in its own engine, and nothing needs to be
  reachable while it runs. This is not a weakening — the daemon holding a
  local key can already sign without asking anybody, and the scope goes on
  binding the programs at the agent socket exactly as before.
* **A key in an approver's hardware** (§10, decision N): unchanged, and
  unchangeable. The private half never moves, so the holder makes every
  signature and a grant can only spare its user the reading, never the
  approving. On iOS it cannot even spare them the Face ID prompt, which
  the Secure Enclave demands per signature.

**Which of the two a request is, is the door it came through.** A peer
that asks only for a decision holds the key and will sign with it itself;
a peer that sends the bytes along has no copy and is borrowing (decision
T). Nothing else on a request tells them apart — the key, the requester
and the kind read the same either way — so the origin carries it:
`OriginPeer` for the first, `OriginPeerSigning` for the second, and a
promise is handed over for the first only.

It asked a different question until 2026-08-13, and got the wrong answer
for an ordinary case. The test was whether *this* instance held the key,
as a stand-in for whether the requester did — and a portable key handed
from a phone to a laptop (decision S) is held by **both**. So the phone
kept every promise it made about that key, and the laptop went on waking
it for permission to use a key already in its own store: an hour-long
grant that answered from the phone once per signature, lighting its screen
each time, which is the exact cost decision P exists to remove. **A key
being here says nothing about whether it is also there**, and the
holds-it test must not come back.

**A promise about a portable key several machines hold travels with the
key** — decision AG. Decision P has two branches and there is a third case
that falls through both. A portable key handed from a phone to a laptop
(decision S) is held by both; a machine that holds no copy and borrows it
can be delegated nothing, and "the private half never moves, so the holder
is in the loop per signature" is a statement about hardware keys and not
about this one. So the promise stayed on the machine that made it and every
borrowed signature woke that machine — the cost decision P exists to remove,
in the shape decision S created.

An **endorsement** is that promise written down so the other holders can act
on it: a holder's signed statement that one named requester may borrow one
named key, within a scope, until a time. It is honoured under two conditions
that do different work, and each closes a hole the other does not.

* **It is signed with the key it is about**, as an SSHSIG under the
  namespace `endorsement@ladulas`. That proves the issuer held the key, and
  it is what makes the mechanism safe rather than merely authenticated: a
  holder promising unattended use of a key promises nothing it could not do
  itself. Without it an approver holding no copy could write a standing
  cheque on somebody else's key.
* **It is signed with the issuing instance's identity key too**, and honoured
  only from a peer this instance would have taken a live approval from. The
  key signature alone proves that *some* holder wrote it and not which, and
  possession of a key is not the same thing as being trusted to decide — a
  key sold with an old laptop, or shared with a colleague, would otherwise
  commandeer every other holder's willingness to sign unattended.

Together they reduce the security argument to one sentence worth keeping in
view: **an endorsement can produce no outcome that a live conversation with
the same approver could not have produced.** What it removes is the round
trip, not the trust decision.

Three more checks are made where the promise is spent, and each answers a
way it could go wrong quietly. The requester is checked against **the
identity the channel authenticated**, never against anything in the message
— `signForPeer` has already replaced the requester field with it before the
engine sees the request — so a copy presented by anybody else names somebody
else and matches nothing. The scope is matched by the same strict `covers()`
a grant uses. And the promise is refused if it runs longer than **this
instance's own `grant_ttl_options` maximum**, which is the one bound nobody
else can raise: an issuer that wrote itself a month is refused by a holder
that tops out at eight hours, and the request raises an ordinary prompt.

**Which way each half travels is the design.** The endorsement goes back to
the requester with its answer and is presented to whichever holder it
borrows from next, because that is the only road that works when the issuer
and the acting holder have never been awake at the same time. The
**retraction** never travels that road — the requester is precisely the
party with no reason to stop presenting a promise — so it is pushed between
holders and gossiped onward by every instance that learns one, is honoured
from **any** holder of the key whatever the trust records say, and is
remembered until what it takes back would have expired anyway. Honouring a
retraction nobody wanted costs a prompt; ignoring one that was meant costs a
signature.

**And an endorsement is published as well as carried**, to every holder this
instance knows of — a peer that advertises the key (decision N), a peer it
was handed to, the peer it came from (decision S). Not because publishing is
what makes it work, but because a holder that was never told has a promise
it will honour and cannot see, and **a promise nobody can see is a promise
nobody can retract.** Which holders could not be told is written onto the
grant rather than smoothed over, for the reason a revocation nobody could
deliver is. What publishing cannot reach is a holder further down a chain of
handovers this instance was not part of, which is the honest limit of it and
the reason the requester carrying its own copy is the mechanism.

**A grant is made to whoever asked, and "whoever" is a session** — decision
U. A scope has always held the key, the kind, the destination and the
repository; it now also holds the session the request came from, so
"approve for an hour" is a promise to the editor or the terminal window
somebody was working in rather than to the whole machine. A promise made
where there is no session to name — a request that arrived from a peer,
which is every request with no local process behind it — covers what it
always covered, so a grant already in a store does not change meaning.

**How far it reaches and how long it runs are two questions, and the
approver answers both** — decision V. The prompt offers the two reaches,
worded as the promise they would make:

* **Session** — "this kitty window", "emacs". The scope decision U
  describes.
* **Machine** — "any session on guppy". The same scope with the session
  taken out of it, which is exactly what `covers()` has always read as "any
  session on that machine". Widening a promise therefore reuses the
  meaning grants had before decision U rather than adding a second one: a
  delegate running older code applies one correctly without being told
  anything new, and nothing on the wire changed.

  **It was worded "anywhere on guppy" and that is not to be reinstated.**
  The word named the one part of the scope that widening does *not* touch:
  the key, the kind, the repository, the destination host and the user name
  all stay pinned, and only the session is dropped. On a git signing prompt
  that reads as a promise about the machine when it is a promise about one
  working directory — a wider promise than the one being made, offered in
  words that describe a wider one still. What actually widens is who may
  spend it, so that is what the button says.

Then a length, on a clock, bounded by the longest length the policy
offers (`grant_ttl_options`, default 8 hours). The four fixed lengths are
still there as suggestions worth one tap, and are no longer the whole of
what may be agreed to. **An answer that says nothing about reach means the
session**, which is the narrower of the two — a surface that forgets to
send it promises less than it meant rather than more.

The bound is what a free length costs. A duration taken straight from a
caller would let anything that can reach the bridge mint a promise of its
own length, which is why the answer route used to accept only a length the
prompt had named; the bound is that rule as a maximum instead of a list.
A request past it is refused rather than quietly approved without the
promise — an answer that is not the answer somebody gave must not be the
one that gets acted on — and the request stays waiting, which is the state
it can still be answered from.

The console approver keeps the four lengths and the session, and has no
way to make the wider promise. Choosing a length on a clock and saying who
a promise is for are for a screen with a picker on it; a console that grew
a syntax for both would be asking somebody to spell out, in the dark, the
thing the wording is there to make plain.

The program at the socket is deliberately *not* what a grant binds to. It
is a helper: `ssh` for every login and `ladulas-sign` for every commit,
which reads the same whether the person is in an editor or a terminal. The
session tells them apart, and a session is also the harder thing to
counterfeit — a process cannot join one it is not descended from, where any
program can be at a given path. It is still context rather than
authorization (§16, `pkg/peercred`): what it bounds is accidents and
unrelated programs, not a daemon that lies about its own `/proc`. Neither
does any other grant.

**Part of a scope is the requester's word, and a promise takes it on trust
— decision X.** The provable/asserted split (§5) governs the *bytes being
signed*: the commit object is proven against the payload digest, a bound
login's host key is proven against the payload. It does not govern the fields
a scope *matches on*. A grant scoped to a repository pins
`git_context.repository_path`, which is the requesting machine's word and is
labelled "reported by the requester" on the card; a policy `approve` rule may
match on the same field, and on the destination label and the calling
executable, none of them proven. For a request from a peer borrowing a key
(`OriginPeerSigning`), those fields are entirely the borrower's to set.

This is not a hole so much as the shape of the concession. A scoped
auto-approve is a decision to trust that peer with that key for that class of
operation; against a *compromised* peer the repository narrowing never
constrained anything, because the peer picks the value — it only ever
constrained an honest one. The `session_id` in a scope is the precedent
already in the design (decision U): it too is the requester's word, kept as a
scope field for the pragmatic reason decision V records, not because it is
proven. So the fix is not to strike asserted fields from the scope — that
would take the scoped grant, which §16 names as an approval-fatigue
countermeasure, away with them — but to make the trust **explicit** where the
promise is made. On a manual prompt the asserted lines are already marked;
where the prompt offers "approve for a while" for a request from another
machine, the offer carries a note (`GrantOffer.Trust`) naming what the
promise would take on the peer's word, with the fuller account behind a
disclosure. A person weighs an asserted field once when approving; a timed
promise spends that judgement ahead of time, and the surface says so before
it is made rather than after. This is disclosure, not proof, and it is
deliberately so: the honest limit is §16's — a compromised requester at
approval time is defended only by the approver reading what is in front of
them, and a promise is that reading, made early.

The narrower relative was closed outright rather than disclosed, because it
had no fatigue trade-off to weigh: an SSH auth grant used to pin the
destination *label* (asserted) and to gate on the requester's `Bound` flag, so
a promise made to one labelled host could be spent on another wearing the same
label, and a hostbound login claiming to be unbound fell under an unbound
promise. It now pins `destination_fingerprint` — the host key proven inside the
signed payload — and ignores both the label and the `Bound` flag for matching
(`scopeFor`/`covers` in `pkg/approval/grants.go`); the label rides along
only for the promise sentence. A login whose payload names no host keeps an
empty destination, covered only by a grant equally without one, exactly as
before. The cost is that a pre-hostbound session-bind-only login, whose proof
is not in the signed bytes, now scopes as unbound rather than to its host — a
less specific promise, never a wider one. This is why the trust note stays
scoped to the repository: it is the one asserted scope field left, the
destination having become proven.

**A promise that is still running can be given more time** — `ladulas
grants extend <id> <duration>`, or the button above "Revoke this grant" on
the phone. It is the same promise afterwards: the same identifier, the
same scope, the same account of what it has covered, running until later.
The length is counted from now rather than added to what is left, which is
what somebody setting a clock means by it and what lets the ceiling on
making a promise be the ceiling on extending one — an extension can top a
promise back up to the longest this instance offers, and never past it.
The rendered sentence is re-rendered with it, which is why a grant
remembers who it was promised to: a row reading "for 15 minutes" on a
promise with three hours on it is exactly the quiet untruth this list
cannot afford.

**Extending one that was handed over is a delivery, and the order is the
mirror of revoking's.** The approver re-signs the delegation under the
same identifier with the later expiry, sends it to the machine holding it
— on the reconciliation call, where a re-issued delegation already
replaces the one held, ledger and all — and amends its own record only
once that has landed. A holder that cannot be reached means the extension
did not happen and says so. The two failures are opposite in shape and
both matter: an undelivered revocation leaves somebody signing who should
have stopped, and an undelivered extension would leave the approver's list
promising more than the machine acting on it will do. Both are a list that
lies; the order is what stops each of them. A promise the approver keeps
needs no delivery at all, because the machine that asks comes back for
every signature anyway.

**Both halves are listable, and from both ends.** A promise made here is a
grant — `ladulas grants list`, the status pane's "Live grants", the
phone's home screen — and it can be taken back here. A promise made about
this instance by somebody else is a delegation: `ladulas delegations
list`, its own section in the status pane and on the phone, naming who
made it, when it runs out, how much has been done under it and how much of
that its approver has not been told yet. There is no revoking one from the
holding side, which is the difference the two lists exist to show.

The listing was missing until 2026-08-13, and its absence was the sharp
edge of the same seam: `grants list` reads the promises this instance
made, held delegations live in another part of the store, so a machine
could self-approve signatures for an hour with nothing locally that even
named the permission it was using. A grant that never says what it did is
a grant nobody can audit; one that cannot say what it *is* is worse.

A requester that self-approved under a delegation **reports what it did**
when the two are next connected. Those entries are an account received
rather than a decision made, and are recorded as such: the surfaces group
them under the grant that allowed them, with a count on the grant and the
individual uses in its detail view, because a signature covered by a
standing permission is something the grant did rather than an event of
its own.

**Audit log**: every decision — who asked, what was shown, which rule or
which approver decided, the approver's signature over the response —
appended to a local log on both requester and approver. (Format: JSONL
first; signing chain/tamper-evidence is a later refinement.)

"What was shown" is the whole card and not only the request behind it,
because those are not the same thing. The request is in the log and the
prompt is a deterministic rendering of it, so most of a card can be drawn
again from what is written down — but the documentation panel (§6) is the
approving instance's own state at that moment, the pages it happened to hold
of the requester's project and the commit they were read at, and all of that
moves. So the host that drew a panel hands it back and the entry keeps it,
and a host that drew none records none. What follows is that **a decision
can be opened again**: the activity list is a way back to the card that was
answered, drawn by the renderer that drew it at the time, with the decision
and the log's own recorded prompt beside it — rather than a summary written
after the fact, which is what a record of what somebody was told must not
be.

## 10. Keys and key storage

### Where keys live

Keys do not move by themselves. Enrollment of a new device means
generating a new key there and adding its public half wherever it needs to
go (GitHub, `authorized_keys`, allowed-signers) — Secretive's stance, and
the only one compatible with hardware-resident keys. Different keys on
different instances is the normal state, not an edge case. Using a key
never moves it: that is what `RemoteSign` is for, and no amount of
convenience changes it.

The exception is deliberate and is named as such: a **portable** key is
one whose private half is bytes in a store rather than a handle into a
secure element, and bytes can be copied to another instance by somebody
who decides to (decision S, below).

* **Desktop SSH keys**: ed25519 (RSA supported for legacy). Stored
  encrypted at rest (below); usable locally with approval, or remotely by
  paired requesters via `RemoteSign`.
* **Mobile SSH keys**: `ecdsa-sha2-nistp256`, generated in the Secure
  Enclave (iOS) / Android Keystore with StrongBox where available, TEE
  fallback. **This is forced, not chosen**: Apple's Secure Enclave is
  P-256-only by documentation; StrongBox's KeyMint HAL explicitly excludes
  curve 25519; Android's TEE ed25519 (API 33+) is undocumented territory
  in combination with per-use biometric gating, while P-256 +
  `BiometricPrompt.CryptoObject` is the well-trodden path. P-256 is
  first-class everywhere it matters (OpenSSH since 5.7, GitHub auth and
  signing, `gpg.format=ssh`), and hardware-resident P-256 with the nonce
  handled inside the secure element beats software ed25519 for this threat
  model. Mobile signing keys are biometric-gated per use, which composes
  naturally with the approval prompt.
* **Portable keys**: ed25519 (RSA on import, for legacy), private half in
  the store, on every platform including the phone. They are the desktop
  key of the first bullet, and saying so is the whole of the design: a
  phone that holds one holds the same document a desktop does and signs
  the same way. What distinguishes them is what the word says — they can
  be handed to a paired peer (decision S).

### The keys somebody else holds — **decision N**

Keys never move, so an instance's useful key set is its own keys plus the
ones its paired holders lend it. **The public halves of the lent ones are
written down**, in the store, beside the trust records: label, algorithm,
fingerprint, comment, which peer holds it, and when that peer last
confirmed it. Public material only, and there is nothing else that could
go in — a key reference is a fingerprint, an algorithm, a public key blob,
a comment and a label. A cached entry can therefore never imply a
signature, and it changes nothing about §16's rule that the holder runs
the whole approval decision.

Why write anything down at all: M4 learned a holder's keys by asking, and
kept the answer only in the live link. That is exactly right for a desktop
pair, where "unreachable" is a fault, and wrong for a phone, where it is
the normal state — a phone advertises no address, dials only when its app
is in the foreground, and is therefore out of reach nearly always. The
result was that a paired phone's keys were absent from every listing
except during the seconds somebody had the app open, which reads as a key
that has been lost rather than a screen that is off.

The rules that make it a cache rather than a second source of truth:

* **A successful refresh is authoritative and replaces everything
  remembered about that peer**, so a key the holder has stopped lending
  disappears at the next refresh rather than lingering.
* **A holder that could not be asked has said nothing**, which is not the
  same answer as an empty list, and leaves what is remembered alone.
* **Revoking a peer drops its keys**, the same way it already drops the
  documentation it published (§7).
* **Availability is shown, never implied.** Every surface says which keys
  can be used right now and, for the rest, when the holder was last there
   — "held by iphone, last seen 4 hours ago". The one exception is the
  agent socket, which advertises only what can sign (§4).
* **A key this instance holds itself is not borrowed at all.** The same key
  in two stores is something decision S does on purpose — a portable key
  handed to a phone, or accepted from one — and from the moment the copy is
  here, the copy is what everything uses: it leaves the remote key set, so
  the agent lists one identity rather than two and both sign paths resolve
  it locally without anybody being asked. The reason is stronger than
  "local is faster". A signature made on the holder is the holder's
  decision every single time, per key and per use, whereas one made here
  can be covered by a standing delegation (decision P) — so reaching for
  the holder's copy would throw away the one mechanism that lets a phone
  stay in a pocket, and would wake it to do what this machine can already
  do. The row stays in every listing, saying the key is held in both
  places and counted apart from the ones that need a holder, because
  "which machines have this key" is the question a listing answers and the
  one somebody asks after losing a device. **A disabled local copy stops
  being the answer**, and the holder's is borrowed again: what "held here"
  means is a key this instance can sign with, `KeyRefs` is what says so,
  and a key switched off here is not one — the fall back to the machine
  that will still use it is the useful reading of a key that is off on one
  of the two machines that have it.

**A signature asked of an unreachable holder fails immediately**, saying
which machine has the key and when it was last reachable. There is no new
budget and no retry: the link's state is already known, so the answer
arrives before anything has been asked of anybody, and the reconnection
backoff (§8) is what brings the holder back. It is not a denial and does
not read like one — nobody was asked — and it is not handed to `ssh-keygen`
either, because the private half is in another machine's store and falling
back could only bury the sentence worth reading (§5).

### Encryption at rest (desktop)

A random data-encryption key (DEK) encrypts the store (SSH private keys,
identity key, trust records) — age with scrypt passphrase recipients
(§19). The DEK is wrapped by, in order of preference:

1. **a passphrase** (scrypt-derived KEK) — the primary interactive unlock
   on desktops, established at `ladulas init`, and the recovery path
   everywhere;
2. **the platform keychain** — Secret Service/keyring on Linux, macOS
   login keychain, Windows DPAPI/Credential Manager — as an explicit
   per-instance opt-down ("unlock at login"), and the pragmatic choice
   for headless boxes that have a keyring daemon.

Passphrase-primary is a decision (2026-08-09), not an accident of
implementation order. The keychain is *enough* for at-rest protection: a
stolen powered-off disk needs the login password, and full-disk
encryption usually covers that case twice over. What it does not resist,
on Linux and Windows, is the running session: the Secret Service has no
per-app ACL, so any process under the same uid can read every keyring
secret with one D-Bus call — silent DEK theft, keys exfiltrated forever.
Ladulås's main gate is the approval engine — every key *use* is prompted
or policied regardless of how the store was unlocked — so what the
cold-start passphrase defends is specifically **silent key theft**: it
turns "dump the keyring, walk away with the keys" into "beat the approval
UI per signature, or persist and keylog." It also decouples the store
from the strength of the login password, and it is what makes
seal-on-sleep (below) meaningful. Cost accepted: one passphrase per boot,
and the agent is dead after a reboot until someone unlocks. Enrolling the
keychain removes both the cost and the protection; that trade is the
user's to make, per instance.

Both wrappings can coexist (keychain for daily unlock, passphrase as
recovery). A headless keyless instance stores only its identity key and
trust records — still encrypted, still sealed at boot (§14 covers how it
gets unlocked).

In the implementation the ordering above is not a preference but a rule
about who writes what. `ladulas init` refuses without a passphrase and
never touches the keychain; enrolling is `ladulas keyring enrol`, which
copies the DEK into the keychain and is the only thing that ever puts it
there. Opening prefers the keychain, because an entry only exists on an
instance that asked for one. What "wipes the input" can honestly mean is
worth stating too: the passphrase travels as bytes rather than as a
string so that the buffer can be cleared once the KEK is derived, which
clears this process's copy and not the ones scrypt and age make
internally, nor a page that has already been swapped.

### Lock states (desktop and headless)

The daemon is always running; what varies is how much of the store is
live. Four states:

* **Uninitialised** — there is no store. The daemon starts anyway and
  serves anyway: the control socket answers `Status` and `Initialize`,
  and nothing else, because there is nothing to read and no identity key
  to sign anything with. `ladulas init` is a client of that RPC (§14),
  which is what makes the daemon the only process that ever creates a
  store as well as the only one that ever writes to it. Initialising
  leaves the instance unlocked and serving in the same process, so
  nothing is restarted. A daemon that refused to start here would be one
  that could not be asked what was wrong with it — and, under a unit with
  `Restart=on-failure`, one that spins until somebody notices.
* **Sealed** — the DEK is dropped, and the private material the store held is
  zeroed on the way down as far as it can be reached (`Vault.Wipe`, M5): the
  PEM-armoured keys, the identity key, and any portable keys queued or waiting
  to be accepted. What zeroing cannot reach is stated where it is done — age
  keeps the DEK's scalar in an unexported field, and a parsed signer holds its
  own copy — so "the DEK is not in memory" is true of the recognisable copies
  and left to the collector for the rest, rather than an absolute. The boot
  state, unless the keychain is enrolled. Almost nothing works: the control
  socket serves
  `Status` and `Unlock`, the agent socket lists no keys and declines to
  sign, and the peer listener is down — the identity key lives in the
  store, so a sealed instance cannot even authenticate the channel.
  Unsealing: the GUI passphrase dialog, `ladulas unlock` over the control
  socket, `systemd-ask-password` at service start (§14), or the keychain
  where enrolled.
* **Unlocked** — normal operation.
* **Locked** (soft lock) — the DEK stays in memory; what is suspended is
  **local approval authority**. The local GUI/console prompt leaves the
  eligible-approver set (§9), so every request that needs a decision goes
  to remote approvers — the phone — or waits. Grants and auto-approve
  policies still fire (with their passive notifications): they are the
  approver's prior promise, made while unlocked, same reasoning as
  approver-side grants (§19). Keys remain usable *when a remote approval
  arrives*, which is the point: §1's "desktop reached over SSH while away
  from it" must keep working while the screen is locked. Sealing on lock
  instead would recreate exactly the 1Password failure this project
  exists to fix.

The states are two halves of an instance rather than a flag on one. The
sockets, the audit log and the lock state exist from the moment the
daemon starts; everything that needs the DEK — the engine that signs
decisions with the identity key, the trust records, the peer node — is
built by unsealing and destroyed by sealing, so "the DEK is not in
memory" is a fact about the process. Approvers register with the
instance rather than with an engine, so a front end that attached to a
sealed store is an approver the moment there is one — which is the
ordinary desktop start, since the window that draws the passphrase dialog
is the one that just attached (decision Z). Uninitialised is the
same halving one step earlier: the outer half is all there is, and
`Initialize` builds the inner half the way unsealing does, from a store
it has just made rather than from one it has just opened.

What a soft lock removes is precisely the handlers that draw on a screen
here: the desktop window and the terminal prompt. The window being in
another process changes nothing — the distinction the engine draws is
"answered by somebody who is here", not "answered in this process", so an
attached front end is `LocalPrompt` exactly as the in-process tray was
(decision Z). Handlers that are neither
that nor a paired peer — the session `ladulas pair` registers while it
runs — keep answering, because what authorizes those is possession of the
unix account rather than the state of the store (§14).

Default triggers (each configurable to `lock`, `seal`, or `off`):
system suspend and session lock soft-lock the store (logind
`PrepareForSleep` and the session's `LockedHint` on Linux); an idle
timeout is available but off by default; `ladulas lock [--seal]` always
works. Choosing `seal` for suspend takes a logind inhibitor so the seal
runs *before* the machine sleeps — the hardening against cold-boot/DMA
attacks on a stolen suspended laptop, at the cost of a passphrase on
every wake and no remote signing while asleep-then-locked. What the
inhibitor buys is only as good as what the seal removes, which is why the
seal zeroes the recognisable key material rather than only dropping its
references (M5); the residue it cannot reach is age's own scalar and the
parsed signers, left to the collector. Unlocking from
soft lock re-prompts for the passphrase (keychain-enrolled instances
re-unlock via the keychain — there the lock is a deliberateness gate, not
a cryptographic one). All transitions are audited, which is why the log
outlives the store rather than living inside it.

Unlocking the session does not unlock the store: the store passphrase is
a separate thing to know, and a screen that has been unlocked is not
evidence that it was.

### Mobile secure storage and unlock

The keys themselves live in Keystore/Secure Enclave (non-exportable), so
there is no DEK-wrapped key store to protect — remaining state (identity
key handle, trust records, audit log, published project snapshots) is
encrypted with a Keystore-resident key (EncryptedSharedPreferences-
equivalent / iOS Keychain with `WhenUnlockedThisDeviceOnly`).

App unlock is the 1Password model: opening the app (and returning to it
after a background timeout) requires biometrics — the store key is
gated by user authentication (`BiometricPrompt.CryptoObject` /
`kSecAccessControlBiometryCurrentSet`) — with the store passphrase as the
fallback when biometrics fail or enrollment changes invalidate the
hardware key, and with that passphrase unlock re-enrolling the keychain so
biometrics come back (below). This is UI/state gating; the SSH keys are separately
biometric-gated **per use** (§10 above), and that per-signature prompt is
unaffected by app-unlock state.

What M6 found is that none of it needed a mechanism of its own. A phone's
store is the same age-encrypted document a desktop's is, wrapped the same
two ways: a scrypt passphrase, and the platform keychain. The difference
is entirely in the access control the keychain item carries —
`WhenUnlockedThisDeviceOnly` plus `.biometryCurrentSet` — which makes
*reading* it the Face ID prompt, makes a re-enrolled face invalidate it,
and makes a restored backup arrive without it. So "unlock with Face ID"
is an unlock with no passphrase, "unlock with the passphrase" is an
unlock with one, and the fallback §10 asks for is what happens when the
first fails. Note that this is the opposite trade from decision I on the
desktop: there the keychain is same-uid-readable by anything in the
session and enrolling gives protection up, here the item is bound to this
app, this device and the current biometric set, so enrolling is what
creates the gate.

**A passphrase unlock re-enrols the keychain**, and that is the half of
the fallback that was described above and not built. `.biometryCurrentSet`
invalidates the item on any change to the enrolled biometrics — an
alternate appearance added, a face re-enrolled, some restores — and that
invalidation is the property worth having and is kept. What was missing is
that nothing ever wrote a new item afterwards, so the first biometric
change turned Face ID off permanently and left the passphrase as the only
way in for the life of the install. Now every unlock that used the
passphrase writes the data encryption key back under a fresh access
control, on both the sealed path and the soft-lock one. The passphrase is
what authorizes it: it is the credential that proves the person unlocking
may hand the key back to the platform. A failure to write it — a device
with no biometrics enrolled at all cannot be given an item like this — is
logged and nothing else, because the store is open, which is what was
asked for.

This is deliberately the opposite of the desktop's rule again. There
enrolling is a deliberate act with a command of its own (decision I), and
nothing re-enrols by itself; here the enrolled state is the intended one,
and `Create` already writes the item without being asked.

**And the name the item is filed under is a constant, since 2026-08-14.**
It used to be derived from the store's directory, which is right on a
desktop — several stores on one machine are told apart by where they are,
and that is somewhere they stay — and wrong on a phone, where the store
lives inside the app's data container and that path carries a UUID Apple
declines to promise is stable across launches and updates. The name was
recomputed from it on every launch, so when the path moved the write and
the read stopped agreeing: the store files moved with the container and
were found, the keychain lookup missed, `errSecItemNotFound` was reported
as "there is no entry", and the gate fell through to the passphrase
**without so much as a Face ID prompt**. The passphrase unlock then
re-enrolled under the new path and biometrics worked again — until the
next move. What that looks like from the outside is an app that always
wants the passphrase after an update, and it hid behind the fact that
falling through quietly is the correct behaviour when there really is no
entry.

`keystore.Options.KeyringName` is the fix, and the mobile core passes a
fixed value for it. **Never derive this name from a path on a platform
that does not promise its paths.** Nothing needs to be in it to tell
stores apart: the shell's keychain item is already scoped to the app by
its service attribute, and a phone has one store. The desktop passes
nothing and keeps the path-derived name, which is the behaviour decision I
describes and is not a bug there.

Two consequences. An install from before the fix has its key under the old
path-derived name, so it wants the passphrase once and then re-enrols
under the constant and stays fixed — the one-time cost of the rename, paid
by the mechanism that was already there for a re-enrolled face. And
enrolling under an explicit name deletes any entry under the path-derived
one, because that is a copy of the store key nothing will ever read again;
best effort by nature, since an entry left under a path the store has
already moved away from cannot be named at all from where it now is.

**The lesson is the general one and worth keeping.** A credential and the
thing it opens have to agree on a name, and a name assembled from the
environment is a name that can be assembled differently next time. It is
also why this had no test for so long: behaviour cannot see it — sealing
and unlocking passes either way, because a directory does not move inside
one test run. The test asserts on the name.

**And the probe does not look at the protected item at all.** It reads a
second keychain item written beside the store key — a marker holding no
secret and carrying no access control — and that indirection is the whole
design: **this probe must be incapable of raising a prompt, not merely
unlikely to.** Two builds shipped getting that wrong in opposite
directions, both by asking the platform to look carefully at a protected
item:

* `kSecUseAuthenticationUISkip` does not mean "look without
  authenticating". It means *omit from the results any item that would
  require authentication*, which is this item and only this item — so the
  probe answered "there is nothing here" about a perfectly good entry, on
  every launch, and the gate went to the passphrase without ever trying a
  face.
* Asking for the item's attributes instead raised the sheet. Since the lock
  state is part of the instance view the app re-reads every few seconds,
  that was a biometric prompt twenty times a minute and a Dynamic Island
  that never stopped moving.

A marker has no such subtlety to get wrong: there is nothing protected to
authenticate against, so there is nothing to suppress. It carries exactly
the contract the probe always claimed — "there is something to try" and not
"it will work" — because an item invalidated by a re-enrolled face leaves
the marker behind and fails on the first read, which is what the passphrase
is for. The two are written and deleted together, and a marker that will
not write takes the store key back out with it: a key with no marker is a
biometric unlock nothing offers, and a marker with no key is a Face ID
button that cannot work. **An install from before the marker existed wants
its passphrase once more**, and the re-enrolment writes both.

**And the answer is only asked for when it can be used.** It is wanted so
that a *gate* can decide what to offer, and an unlocked store has no gate —
`LockView.KeyringEnrolled` is documented as meaningful only when the state
is not "unlocked", and the phone leaves it alone otherwise. That is the
other half of what made the prompt-per-poll so visible: the question was
being asked continuously in the one state where nothing reads the answer.
**A cheap probe is not a reason to ask a question whose answer cannot be
used** — and this one was on a timer, which is where "cheap" stopped being
true the moment the implementation changed underneath it.

**A typed passphrase is checked, and is not something the keychain gets to
answer instead of.**
Unwrapping tried the keychain first whatever the caller was holding, and
returned as soon as it answered. On an instance whose entry works — which
after one passphrase unlock is every phone — that meant the store was
already open before anything looked at what had been typed, so **the gate
accepted any passphrase at all.** Hugo found it by entering nonsense.

What was and was not at stake, stated precisely, because the difference
matters for how alarmed to be. Nothing opened that should not have: the
credential that actually did the unwrapping was the keychain entry, whose
read is the Face ID prompt, so getting in still took a face or the right
passphrase and never neither. There was no path from "no credential" to
"open". What was broken is a different thing and not a smaller one — **a
gate that asks a question and ignores the answer is lying about what is
guarding the store**, and on the surface whose entire job is to be
trustworthy about that. A person who mistypes their passphrase and is let
in learns that the passphrase does not matter, and they are right to
conclude it, and they are wrong about the store.

The cause was a lost distinction. "Here is a passphrase, check it" and
"here is permission to ask for one if you need it" both arrived as a
`PassphraseFunc`, so by the time the store had them they were the same
thing, and the keychain-first order — correct for the second — was applied
to the first. `Options.GivenPassphrase` carries the credential and
`Options.Passphrase` stays the prompt: given one, the keychain is not
consulted at all and a wrong passphrase is `ErrWrongPassphrase` even when a
face would have opened it a moment earlier. The daemon's startup keeps
reaching for the keychain first, which is decision I and is what enrolling
bought; a test asserts it never prompts on an enrolled machine, because
"fix" the ordering there and unlock-at-login is gone.

**The two never collapse back into one type.** A credential and permission
to ask for one are not the same value, and any future field that means "the
user supplied this" must be visibly not the field that means "you may
prompt".

**And the gate asks rather than asserting.** Whether there is a
biometric unlock to offer is a question for the keychain, answered with a
probe that skips authentication rather than a read — a read is the Face ID
sheet, and the gate asks every time it draws. What a probe can honestly
say is that there is an item to try, not that the item still works; an
invalidated one may well still be sitting there and fail on the first
read, which is what the passphrase and the re-enrolment behind it are for.
A gate that claimed Face ID was available when the item had gone is how
somebody concludes that Face ID is broken rather than that it needs
setting up again.

**Both gates obey that, since 2026-08-14.** It was written here as a rule
and only the webview panel followed it; the native screen the phone
actually unlocks on (§12, decision R) asserted instead. It opened with a
prominent "Unlock with Face ID" while `onAppear` fired the same unlock the
button did, so the daily way in was a sheet that came up on its own and
the button under it was a control that had already been pressed — and on
an install with nothing enrolled it was a button that could only ever
fail. **A standing biometric button does not come back.** What the screen
needs is not a way to start Face ID, which arriving already does, but a
way *back* after a sheet is dismissed, since without one the only retry
is killing the app. That is a different control with a different label,
and it appears only once an attempt has been answered.
`Core.BiometricsEnrolled` is the probe, exported for this and reaching the
same `keystore.Enrolled` the panel's `keyringEnrolled` does.

**What a gate says when it does not open, and where the chain went.**
Every failure on the unlock path is logged whole and answered with one
sentence, which the surface shows verbatim rather than prefixing. What
this replaced is worth keeping written down, because each of these was on
a lock screen: a mistyped passphrase said "could not unlock: decrypt
wrapped key: no identity matched any of the recipients", and a dismissed
Face ID sheet said "could not unlock: keychain unavailable: read the
keychain: read the keychain: read the store key: OSStatus -128" — four
layers of internals, one of them printed twice, to report that somebody
had tapped Cancel. `keystore.ErrWrongPassphrase` is the sentinel that was
missing under the first, and the mobile core's unlock error is where the
translation happens. **A gate does not concatenate.** The person reading
it is trying to get in, not debugging the store, and the layers belong in
the log where the two readers are not the same person.

The split with the shell is the interesting half. Two states Go cannot
tell apart need different words and different buttons — a Face ID sheet
somebody dismissed and a face the platform refused — because the
difference is not in the error, it is in the `OSStatus` the shell is
holding and an error crosses the gomobile boundary as a string. So the
keychain implementation classifies its own reads and the gate reads the
classification, rather than either side parsing sentences back out of the
other. A dismissed sheet is then not worded as a failure at all, and does
not turn the screen red: it is a person deciding not to just now.

The private halves are the part that is genuinely different. A phone's
store document holds no key material at all: the identity key and every
SSH key are handles the Secure Enclave knows them by, and the public
halves. A signature is a call into the platform, which is where the
per-use prompt happens, and Go finds out only whether one came back — a
dismissed prompt is an ordinary refusal.

The one piece of "remaining state" that is not sealed with the data
encryption key is the audit log, on both platforms and for the same
reason: locking is a transition worth recording, and a log that went away
with the key could not record it. On iOS what protects it is the app
container — a file no other app can read, encrypted at rest by Data
Protection — rather than the store's own key.

### Portable keys — **decision S**

The paragraph above says a phone's store holds no key material, and that
stops being true here. **A portable key is a key whose private half is in
the store**: generated there, or imported from an OpenSSH private key
somebody pasted in, protected by the same age encryption as everything
else around it and by nothing else. Every instance can hold them; on a
desktop it is the only kind there is, and on a phone it sits beside the
enclave keys rather than replacing them.

Why a phone should have them at all, given that the enclave is right
there. Three keys cannot be enclave keys, and they are ordinary: one that
already exists — a 1Password export, a key some far end has been told
about and will not be told about again (§15); one that has to outlive the
device, because a key only this phone can use dies with the phone and
`ecdsa-sha2-nistp256` in a broken screen is an afternoon of rotation; and
one somebody wants on both the laptop and the phone on purpose. The
enclave's promise is exactly that its keys cannot do any of that. So the
choice is not between a strong key and a weak one, it is between a
portable key held here and the same key held in a password manager, and
this is the project that exists because of where the second one leads.

Nothing in the store had to change to hold them. `Vault` already decides
per key rather than per instance: a key with a handle is a call into the
platform, and a key without one is bytes it parses, in the same function
(§18). A portable key on a phone is a key with no handle, so listing,
signing, removing, lending to a peer over `RemoteSign` and the agent's
view of it are all the code the desktop has been running since M1. The
mobile-only part is the two ends: a way to make one, and the gate below.

**The per-use gate is LocalAuthentication, and it is an app's promise
rather than the enclave's.** §10 says mobile signing keys prompt per use,
and that must not quietly stop being true for the keys that need it most.
An enclave key gets the prompt for free because the signature happens
behind it; a portable key's bytes are already in the process, so the
prompt is something Ladulås chooses to ask for and could choose not to.
It is asked anyway, before every portable-key signature, because the
alternative is a phone whose keys behave differently depending on a
property the person holding it cannot see. The honest statement of what
it buys: someone who has the unlocked phone in their hands cannot sign
with it without a face, and someone who has the app's memory has the key
and was never going to be stopped by a prompt. It goes through a seam of
its own — the core calls out to the shell the way it calls out to the
enclave — because the decision is the platform's to draw and the reason
string is worth choosing per signature.

**Handing one over is a transfer, and the design treats it as the most
dangerous thing in the system.** The private half travels inside the
existing pinned-TLS peer channel, which is direct, has no relay in it and
has both ends authenticated by their identity keys — the same channel
that already carries a signature about to be made. Sealing it a second
time to the recipient's identity key was considered and rejected as
defence against nothing that exists in the topology; if store-and-forward
ever appears, that is when the envelope earns itself. Four rules around
it, each answering a way this could go wrong quietly:

* **The sender re-enters the store passphrase**, immediately before the
  send. The store is already open, so this unlocks nothing — it is a
  deliberateness gate and is meant to be, the same credential that
  authorizes handing the key back to the platform on a passphrase unlock
  (above). Face ID is not offered here; the point is the pause.
* **The recipient accepts explicitly.** An arriving key waits as a pending
  item and does not enter the store until somebody at that end says yes,
  because key material appearing unasked in a store is precisely the
  surprise the rest of this design refuses to allow, and because a paired
  peer may well be a machine nobody is sitting at. Saying yes is
  `ladulas keys accept`, and — since 2026-08-19 — the Keys screen of the
  desktop window, where the offer is a count on the sidebar, a row above
  the keys and a sheet with the fingerprint to compare in it (decision AF).
  It was the command line alone for a milestone, on the one surface whose
  premise is that somebody is sitting in front of it: the desktop could be
  *sent* a key and had nowhere to answer, which reads from the outside as a
  send that did nothing.
* **Both ends audit it**, with the peer, the label, the fingerprint and
  the time — the sender at the send and the recipient at the acceptance.
* **The sender keeps the key and writes down where it went.** A transfer
  is a copy: a move that half-failed would be the worst outcome on offer,
  and after this the key exists in two places whatever the sender thinks,
  so the store says so on the key.

What cannot be built is the undo. A sent key is sent; the only remedy is
rotation at the far ends, which is the same remedy as for a leaked key,
because that is what it now is. The UI says this in as many words at the
moment of sending rather than in a document nobody has open.

## 11. Wake-ups and push (all optional)

The baseline works with zero infrastructure: approvers with a live
connection get requests instantly; the mobile app polls on open (Duo's
fallback, always present); and Android can hold a persistent connection
from a foreground service, making the phone a real-time approver whenever
it can reach the requester. Push is an optimization layered on top, never
a dependency — losing every wake-up channel degrades to poll-on-open,
never breaks pairing (the Krypton lesson).

**A poll that is open announces what it finds.** The fast path below — a
requester with a poll already open sends the request down it and no
wake-up at all — leaves a request arriving with nobody told about it, so
the app raises a **local notification** for one its own poll brought in
while the app was in the background. It is better informed than a push
could be: the side raising it is holding the request, so it says which key
and what for, where a wake-up carries no payload and can only say "ask
your requesters". It is withdrawn when the request stops waiting, however
it stopped — a banner for something already decided invites somebody to
go and decide it twice.

**The window this covers is small, and saying so is the point.** iOS
suspends a backgrounded app within seconds and the long poll dies with it,
so "resident but backgrounded" is a brief state rather than the state a
phone spends its day in. What is left is the seconds before suspension,
and the app being woken by a silent push for a request that then turns out
to need a human after all — where the banner beats the alert push behind
it by the length of the grace window. It is emphatically **not** a
substitute for push: with wake-ups off and the app suspended, nothing
arrives to be announced, because nothing is polling.

The state test is `background`, not "not foreground". A launch passes
through an inactive state on its way to the front and the startup poll
collects everything that was waiting, so testing for "not active"
announces every pending request at the moment somebody opens the app to
look at it.

**Delivery is idempotent per request id**, on the collecting side. A poll
is answered out of what the requester has parked, and the approver's
answer travels back the other way; the two cross. A response computed
before the answer landed arrives after it, carrying a request that has
just been settled — a scheduling hiccup on a LAN, a whole round trip over
a relay, which is the phone-on-4G case this exists for. So the collecting
side remembers what it decided for as long as the requester said it would
wait, and a request id gets exactly one decision from it. A poll that
offers a request it has already answered is a delivery that did not
arrive, and is answered by sending the same signed decision again rather
than by asking anybody a second time. Without that rule the symptom is the
one that matters: being asked to approve the same commit twice.

The same asymmetry has a second consequence. A requester with something
parked answers a poll immediately, so while a card is on somebody's screen
the long poll is not long at all; the loop waits a beat before asking a
requester that has nothing for it but the request it is already dealing
with, which is the difference between one call a second and as many as the
link will carry.

**Resolved (Decision G): two opt-in modes get built** on top of the
always-present poll-on-open baseline — the publisher-hosted relay, and the
Android foreground-service live connection (a user-toggleable "stay
connected" mode: real-time approvals with zero infrastructure, at the cost
of a persistent notification and some battery; arrives with the Android
milestone). UnifiedPush stays documented as a deferred option.

Wake-up options, all opt-in:

* **Publisher-hosted relay** (FCM/APNs). A tiny Go service holding
  platform push credentials and device tokens keyed by opaque instance
  IDs; requesters authenticate with identity-key-signed requests and say
  "wake instance X". **Payloads are empty** — no request data, not even
  encrypted, leaves the peer connection. Honest constraint: FCM/APNs
  tokens are bound to the app's Firebase/Apple project, so any relay that
  serves the store-distributed app must hold the publisher's platform
  credentials — the same reason Bitwarden's self-hosted servers proxy
  through push.bitwarden.com. Self-hosting this relay therefore means
  building the app yourself with your own Firebase project/Apple keys;
  supported — relay URL and credentials are configuration, nothing is
  hardcoded — but not the mainstream path.

  A requester dials the relay over **https, or in cleartext over a
  tailnet** — the two shapes where the wake-up is confidential and the far
  end is authenticated before a packet arrives. The second is not a
  weakening of the first: a private relay on a tailnet is already inside
  WireGuard, and putting TLS in front of it would buy a certificate to
  renew rather than a secret kept better. It matters because the URL is
  chosen by a paired approver and dialled by the requester, so what is
  refused here is what keeps an announcement from turning a headless box
  into a way to reach its network. The test is a suffix or an address
  range and never a name that has to be resolved, so there is no window
  between deciding and dialling.
* **UnifiedPush / ntfy** (Android): fully self-hostable wake-ups with no
  Google dependency and no publisher infrastructure — the app registers
  with any UnifiedPush distributor and hands the requester an endpoint URL
  to POST to. The natural choice for the self-hosting audience.
* **None**: poll-on-open, plus the Android foreground service. iOS without
  APNs is open-app-to-approve (iOS forbids persistent background sockets;
  this is an OS constraint, not a design choice).

Platform notes: Android pushes are high-priority data-only FCM messages →
notification with **Approve/Deny action buttons** where the context fits,
full UI on tap (deep-Doze delivery is historically flaky; poll-on-open
covers it). iOS uses visible alert pushes ("Signing request pending — tap
to review"); `content-available` background pushes are explicitly
throttled and wrong for this. APNs requires the Apple Developer Program
($99/yr) — needed for the iOS app anyway.

**No `apns-collapse-id`**, and the reason is a trap worth leaving a sign
on. Collapsing looks obviously right here: several requests parked in a
minute are one event to the person holding the phone, and one banner
carrying the same fixed sentence seems strictly kinder than three. But a
collapse id does not merge notifications, it makes each push **replace**
the previous one, and iOS updates a notification still sitting unread
without alerting again — no banner, no sound. The result is that the
first wake-up gets through and every one after it is swallowed for as
long as the first goes untouched, which presents as "push worked once and
then never again" while every log on the sending side correctly reports
success. It cost most of a day; it was settled in a minute by sending
three pushes six seconds apart and counting banners, which is the way to
settle anything about somebody else's notification system.

The collapse would only be worth its cost if the replacement said
something the original did not, and it cannot: the payload is a constant,
because nothing about the request may leave the peer connection. What is
left is one alert per request, which is what was wanted in the first
place.

Desktop approvers need no wake-ups: they listen.

**What M9 built.** The relay is `cmd/ladulas-relay`: APNs token
authentication with a `.p8`, an ES256 JWT per connection, the host and
every credential configuration. It knows three things about a device — an
opaque identifier the device minted, a platform token, and the public
half of the identity key that first claimed the identifier — and is never
told a request, a fingerprint or a peer.

**One bit was added to that, deliberately, by decision S.** A wake-up now
carries a *subject*, and it decides which of two fixed sentences the relay
sends: somebody is waiting for a signature, or somebody is handing over a
key (§10). It is an enumeration written in this repository rather than
anything a caller composes, so what the relay can say is still a list and
never a message. What it costs is exactly one bit about the event — the
relay knew when, and now knows which of two kinds — and what it buys is a
phone that is not lied to. The alternative was a notification saying
"Signing request pending" when a key was waiting, which is the kind of
small dishonesty that teaches somebody to stop reading notifications. A
relay that predates the subject sends the sentence it always sent.

Registration binds the
identifier to that key, so nobody can point somebody else's identifier at
their own device. **Waking binds nothing**: the relay has no directory to
check a caller against and deliberately never acquires one, so the
identifier is the whole of the authorization and the signature is what
makes an abusive caller countable rather than anonymous. Stated plainly,
because it is the one place this design trades a property away: somebody
who learns an identifier can make a phone show "Signing request pending"
as often as the relay's throttle allows, and the phone opens, polls,
finds nothing, and closes.

**The knock is decided where the inbox already knew.** Parking a request
releases whatever long poll is waiting for that peer; if there was one,
the request travels down a line that is already open and nothing is spent
on a wake-up — the fast path this section already described, which turned
out to be a return value rather than a presence check. Only when nobody
was polling is the relay called.

**A requester will only dial an `https` relay, or a loopback one.** A
paired approver announcing a URL is a paired approver choosing an address
the daemon will make requests to, and a headless box on a network with
interesting things on it should not become a way to reach them. The
refusal is an answer rather than a dropped message, so the phone can say
"that machine will not wake me" instead of waiting to notice that nothing
ever arrives.

**On iOS the notification has no Approve and Deny.** The context does not
fit, in the specific sense this section means: the payload does not say
which request it is about, and answering needs the store, which needs its
data encryption key, which is behind Face ID — and a notification action
cannot raise a biometric prompt. Two buttons that both end at the same
sheet are one button with extra steps, and one of them would be a Deny
people learn to tap without reading. The actions are **Review**, which
opens the app, and **Not now**, which clears the banner and decides
nothing.

**Where opening the app lands is decided by how much is waiting.** One
request waiting and the app opens on that request: whatever the
notification said, that is what it was about, and leaving somebody to find
it on the home screen is answering a question they have already asked. Two
or more and it opens on the home screen, because guessing between them
means picking the screen somebody is about to approve on; none, and the
home screen is where the answer to "what happened to it" is. This is the
one thing in the app that navigates without being a tap on what it
navigates to, and it is not an exception to M6's rule that a request does
not open itself — that rule is about the phone taking over the screen
because a machine wanted something, and this is a person saying take me to
it. The tap waits for the first poll of an unlocked store before it
decides, and gives up on waiting after a few seconds: a wake-up that turns
out to be about nothing must not leave a phone that opens an unrelated
request an hour later.

## 12. GUI stacks — **Decisions B and C**

Research verdict up front: the original hope of one GUI stack across
desktop and mobile does not survive contact with push notifications and
hardware key storage. Pure-Go mobile toolkits either cannot do FCM at all
(Fyne — no mechanism to bundle the Firebase SDK, no path to a
`FirebaseMessagingService`) or hang the security-critical path on a
single-maintainer fork ecosystem (Gio + gio-plugins, pinned to old Gio
versions, needing a forked build tool). What *is* shared everywhere is one
level down (the core library) and one level up: the viewer.

### The desktop application is a client — **decision Z**

The window and the instance are two processes. `ladulas gui` holds a
`bridge.Session`, a tray icon and whatever windows are open; `ladulasd`
holds the store, the agent socket, the approval engine and the peer
channel. Prompts reach the screen over `ControlService.WatchApprovals` and
answers go back through `AnswerApproval` (§14). `internal/frontend` is the
half that is not a window — it builds the session's options out of control
socket calls and runs the stream — and `internal/gui` is Wails and nothing
else, which is what lets the seam be tested on a machine with no display.

It used to be one process. The desktop application opened `store.age`,
served the agent socket and ran the engine, which cost three things:

* **The two fought over the agent socket.** `ladulas.service` and
  `ladulas-tray.service` were alternatives declaring `Conflicts=` on each
  other, so a desktop chose between a tray and a daemon, and the second
  one started lost the socket and exited complaining about it.
* **A renderer bug was a key-theft bug.** The data encryption key and every
  portable private key sat in the same address space as webkit, rendering
  commit messages, filenames and diffs written by whoever asked for the
  signature. `PR_SET_DUMPABLE` and `LimitCORE=0` (§10) close the core dump
  and the ptrace, not a bug in the thing doing the parsing. A compromised
  front end can still *approve* — it is the approver, and §16 is honest
  about that — but it can no longer walk off with the keys.
* **Everything shared one lifetime.** A webkit crash took the SSH agent,
  the peer links and the unlocked store with it, and restarting the daemon
  meant restarting the window.

What it costs is stated where it is felt: a request in flight when the
front end dies loses that approver rather than surviving the restart —
whoever else could answer does, and the requester's own timeout applies;
**and a front end that dies must not be able to take the daemon with it**,
which for a while it could. The prompt goes out on the stream the
`WatchApprovals` handler holds, and that stream dies with the handler: sending
on it afterwards is not an error it reports but a write into an `http.response`
whose buffered writer has been recycled, which segfaults the process that owns
the agent socket and the store key. Unregistering the approver does not close
it, because the engine has already taken its list of approvers by the time it
prompts — so `socketApprover` refuses to send once the handler has stopped, and
the handler waits for a send already under way before it returns —
and the front end is one more thing to have running, which is why it
attaches on its own, retries forever, and says on the tray when it is not
attached. **It is started by a `.desktop` entry rather than by systemd**,
in `/usr/share/applications` and `/etc/xdg/autostart`: a GUI is an
application, and the unit it replaces was pulled in by
`graphical-session.target`, which most sessions never reach — so it sat
enabled and never started, reported as inactive with no error at all.

Rejected: serving the viewer's own JSON API over the control socket and
making the desktop a proxy in front of a webview. It is much the smaller
change — every option the session needs already exists in the daemon — and
it puts a second management surface on the socket, with its own way to
send a passphrase. That is what decision L exists to prevent, and §14's
claim that everything the GUI can do is a `ControlService` RPC is worth
more than the diff.

### The shared approval viewer

The rich request/context UI is **one HTML/JS bundle**: request cards, the
commit viewer (message, author, diffstat, full diff), and the project doc
browser with its sandboxed markdown renderer (§6). Desktop hosts it in
Wails' webview; Android will host it in a WebView inside the Compose
shell. The bundle is local content only — strict CSP, no network access,
no remote resources; data arrives through a small bridge API from the Go
core (desktop) or the shell (mobile). Native chrome — notifications,
biometric prompts, pairing QR scanning — stays native; the webview is the
document viewer, which is exactly what webviews are good at.

**On iOS the split moved** (decision O, §19). Everything that is chrome —
the tabs, the home screen, the peer list, the banners, and the approval
card itself — is SwiftUI, and the bundle keeps the two things that are
documents: the diff behind a commit and the markdown a paired instance
published. The bridge API did not change and neither did the seam; what
changed is how much of the page the shell draws for itself. The card
therefore exists twice, which is a cost, and §19 says what buys it.

**And then it moved once more, through the doc browser** (decision R,
§19). The project list, the directories, the filename search and the
provenance labelling are SwiftUI too, reading `/api/v1/projects/*`; the
bundle is opened one page at a time in a document-only mode, and a link
inside a page is handed back to the shell so that reading on is a screen
rather than a navigation inside a webview. What is left in the webview on
a phone is a diff and a document, which is the whole of what §12 ever
claimed a webview was for. Desktop hosts the browser as it always has.

**And the card itself learned what to lead with** (decision W, §19). Every
fact the core could render used to be on the approval card, in order, as
labelled rows: the destination and the user, then a SHA256 host key, then
the known-hosts verdict, then the binding, then the key, then its
fingerprint, then the program with its pid, then the session with its
number, then the walk up to it — and then the same list again underneath,
because the generic rendered details were drawn under every card as well
as inside it. On a phone that is two screens of text above the buttons,
most of it uncheckable: nobody compares forty-three base64 characters
against a memory, and a card that puts them in the way of the buttons
teaches the reader to skip the part above them too.

So the card leads with the four facts somebody holding a phone can
actually recognise as right or wrong — **what is being asked, on what, by
which program on which machine, and with which key** — and the
kind-specific card under it carries the verdicts rather than the material
they were reached from: "a host this machine has connected to before",
"not bound to this host", the provenance line on a commit. Everything else
is behind an (i) on the summary card, in the same idiom decision R gave
the doc browser: fingerprints, host keys, digests, algorithms, pids,
session numbers, the process chain, and a commit's tree, parents, extra
headers, committer and remote URL. **None of it is dropped**, and
reintroducing any of it to the
card is not the fix for wanting to read it — each is the answer to a
question asked afterwards ("which key was that", "was that host in
known_hosts", "what ran it"), and a prompt that could not answer those
would be asking for trust it had not earned (§5). The rendered detail list
is now drawn only for a kind with no card of its own, which is what it
always was for. Desktop is unchanged: a window has the room, and the same
JSON draws both.

The commit card is the same treatment applied to the one screen that had
the most to say. Its subject was drawn three times — on the summary card,
again in semibold on the commit card, and again as the first line of the
message under that — so the card now carries the message *body*, split off
in Go and sent as its own field. Splitting it on the rendering side would
be a viewer deciding where a subject ends, and §5 is that what is shown
beside a signature is parsed once, here. A commit that is only a subject
therefore shows no message block at all, which is most of them. What
stayed is what a person signing checks: the provenance line, the body, the
author, the repository and branch under their "the machine that asked
says" heading, and the diffstat with the way into the change.

**And the host's type, and none of its zoom.** A document in a webview
that pinches away from the navigation bar above it reads as an embedded
website rather than a screen of the app, so the two hosted panes do not
zoom — `user-scalable=no`, which WKWebView honours, and the pinch
recogniser disabled behind it. That is only defensible because what
pinching was for arrives another way: the panes take their type from
`-apple-system-body`, the system font at the reader's own Dynamic Type
size, which WebKit resolves against the setting itself and re-resolves
when it changes. Nothing crosses the bridge for it and there is nothing to
keep in step — and the document's own sizes are relative to it, so a
heading in a page whose body text is 28 points is still a heading. A host
that does not know the value keeps the fixed 14px it always had.

**The bundle follows the host's appearance.** It was written dark-only,
which is invisible on a desktop that is dark and looks like a fault on a
phone that is not: a light navigation bar above a black page, in an app
whose every other screen had turned light. So the palette is one set of
tokens declared twice, switched on `prefers-color-scheme`, with no colour
left as a literal anywhere else in the stylesheet — a webview inherits the
appearance from the shell that hosts it, so the same file follows a Wails
window and a SwiftUI one without either being asked. The two panes a
native shell pushes go further and paint no background at all: the surface
under them belongs to the screen around them, and letting it show through
is how the two are the same colour rather than nearly.

**A tap is never allowed to look like nothing.** Three separate things on
the phone made one look that way, and all three are now closed.

The one that mattered most was interactive glass inside a button. Every
row that is tappable — a waiting request, a paired machine, a live grant,
a published project — is a `Button` or a `NavigationLink` whose label
carries a glass panel, and that panel was asking for `.interactive()`.
Interactive glass follows the finger itself, which is exactly what makes
a plain view feel like a control; a row is not a plain view, and the
button wrapped around it was already following the same finger. Two
things watching one touch is one too many, and the touch is what got
lost: tapping a request that was waiting for an answer sometimes did
nothing at all. The press feedback now comes from a `ButtonStyle`, where
the thing that renders the press is also the thing that acts on it.
**Interactive glass does not go inside a button label**, on this app or
any shell that copies it — the rendering is worth less than the tap.

The first was the shell rebuilding itself on a timer. Everything the home
screen draws is re-read from the core every three seconds, which is what
keeps a countdown honest and notices a peer going offline — but the
answer was assigned to the published properties whether or not it
differed from the last one, and an assignment to a published property
invalidates every view holding the model, which here is every screen
there is. So the whole hierarchy was rebuilt under the reader's finger
several times a minute, and a row rebuilt mid-tap sometimes loses the
tap. It presented as "sometimes tapping a file or a request does
nothing", intermittent because it depended on where in the three seconds
the finger landed. The fix is to assign only what moved, which is why the
instance view is `Equatable`: nothing about the refresh interval changed,
only whether a poll that found nothing gets to redraw the app.

The second was a hosted pane with nothing in it. Reading a document is a
pull from the machine that publishes it (decision Q), so it takes as long
as that machine takes to wake up and answer, and the shell pushes the
screen for it immediately — correctly, because waiting on the network
before transitioning would be worse. But the bundle put nothing in the
DOM until the document arrived, so what filled that screen was the bare
`Loading…` that `index.html` ships, on the bundle's own background, and a
sleeping publisher left it there for seconds. So the reader now says it
is reading, and drops its background at the same moment rather than when
the document lands, which is the shell's surface from the first frame.
**A hosted pane that can wait says so before it starts waiting**, the way
the project list already did.

### The desktop is one window with a sidebar — **decision AA**

The window is the phone's app in a window. The phone has four tabs and puts
the paired machines on its home screen, because a tab bar holds four things;
a window has a side to put a list down, so the machines are *in* the sidebar,
one entry each with its own face and its own state dot, and "This phone"
becomes Settings at the bottom of it. Home, Keys, Activity and Documents are
the phone's tabs, over the same `/api/v1/instance` JSON, and a peer's entry
opens the screen `PeerDetailView` draws. `viewer/assets/shell.js` is the
sidebar and the routing, `screens.js` is one function per entry, and the
prompt card is `prompt.js` — shared with the popup, because a request being
answered under a signature must not be rendered two ways (§5).

**What it replaced, and why that had to go.** The desktop had three windows
and no application. `Status and recent activity…` opened one long scrolling
pane — identity, waiting requests, pairings, keys, borrowed keys, peers,
grants, delegations and recent activity, as tables, in that order, repainted
whole every five seconds. `Published documentation…` opened a second window
on the doc browser, `Unlock…` a third on the passphrase panel, and **every
click made a new one**: the menu item called `Window.NewWithOptions` each
time, so a few clicks left a pile of identical windows behind one tray icon,
each with a webview polling the daemon in it, and none of them was "the
Ladulås window". Nothing in the pane was wrong and none of it was findable:
the answer to "is that machine reachable" and the answer to "what did I
approve at lunchtime" were the same wall of `<table>`s, five sections apart.

**Requests are popups, and they queue.** A desktop asks the way 1Password
and OpenSnitch ask: a small window, centred, above the others, with one
request in it. Only one is on screen at a time — the rest wait, and the
closing of the one in front is what starts the next, so the answer to a
signature is never a stack of overlapping windows to be clicked through in
whatever order they happen to be layered. A queued request announces itself
on the tray label and nowhere else; nothing navigates on its own, which is
M6's rule (§12) and applies to a window that steals focus at least as much
as to a phone screen that flashes past. The window is still what the request
is answered in and closing it is still a refusal — and what is waiting is
also listed on Home, which is where a popup that was closed by accident, or
never seen, is answered from.

**The answer is pinned, and the change is folded.** Both halves of that are
the same complaint decision O made about the phone — a card whose buttons a
thumb reaches by scrolling — arriving on the desktop, where the card is
exactly as long as the commit it is showing. The approve, the deny and the
reach buttons sit in a footer stuck to the bottom of whatever is scrolling
the card, so answering never requires reading to the end first; sticky
rather than fixed, because `prompt.js` is drawn in two different scrolling
things and the footer belongs to the card in both. And every file in a diff
is collapsed, without exception. A file under forty lines used to open
itself on the reasoning that folding a three-line change helps nobody, and
the cost of that was a card whose length depended on the shape of the
change: a commit touching a dozen small files unrolled into a page nobody
asked for, and the list of *what was touched* — which is what an approver
reads first — stopped fitting on a screen. **Neither is a statement about
what an approver may see.** The whole diff is one click per file away and
the fetch for a truncated one is unchanged (§5); what moved is only which
of the two a card shows before being asked.

The trust note a timed promise carries (decision X) stays in the body
rather than riding along in the footer. It is prose to be read before
making a promise, not a control, and a footer that grows a paragraph is a
footer that eats the card it is pinned to — it is still the last thing
above the choices, which is the order that decision asked for.

**One window means one of it, and one application.** Two things had to be
said for that to hold, and both were bugs first. A window may not be asked
for before Wails has started: on GTK 4 the widget is created when the
application's `activate` signal fires, so a window created earlier is a
handle whose GTK window does not exist — every call on it is a `GTK-CRITICAL`
on stderr and nothing on screen, and the handle is indistinguishable from a
working one afterwards. That was not a startup race but the ordinary state of
a desktop here: a sealed store asks for the window the moment the front end
attaches (decision I), which is usually before Wails is up. So a request that
arrives too early is remembered and honoured on `ApplicationStarted`.

And the application is a single instance, because a second one is worse than
a duplicate. Two GApplications with the same id make the second a *remote*
instance: its `activate` never fires, so it can never create a window at all,
while its tray icon registers fine and its menu items do nothing — the same
silence as the deadlock above, from starting the menu entry while one was
already running. It also registers a second approver on the control socket, so
prompts arrive twice. A second launch now hands over: the running instance
raises its window and the new process exits.

**Two things the window can start rather than only watch**, since
2026-08-19: adding a machine, and making a key. Both were command lines and
nothing else, on a surface whose whole premise is that somebody is sitting
in front of it, and both are one call the daemon already served (§14).

*Add a machine* is a screen in two states and never both. First the
question decision AD says belongs on this side — what the pairing is for,
as three rows worded as what each does rather than as which flag it sets.
Then the invitation: the code, and the three ways into it, which are one
secret seen by three kinds of machine. A terminal types the command line;
another window pastes the full code, which carries the identity key and so
leaves that side nothing to compare by hand; a phone points a camera at the
QR (decision AE). The screen holds the pairing window open — the control
call that displays a code is a stream whose lifetime *is* the window's — so
leaving takes the code off both, and coming back shows the code already on
display rather than spending a second one. What arrives when the other
machine uses it is an ordinary approval card, drawn by the renderer that
draws every other one.

*Make a key* is a name, a comment and a button behind the **+** in the Keys
screen's title bar (decision AF), and generation only: importing one is a
file to pick and a passphrase to type into a webview, and `ladulas keys
import` is where both belong. It was a card on the screen, above the keys,
for one milestone, and that cost the Keys screen its place in the set the
poll may redraw — a name is typed a character at a time, any decision
anywhere changes the instance payload, and a repaint four seconds later
emptied the box. A sheet is outside the pane, so the screen is back in the
set and there is nothing under the poll to empty. **What must not come back
is a text field drawn into a screen the poll repaints**, whichever screen
grows one next.

*Accept a key* is the third, and it is the receiving half of decision S. A
portable key handed over by a paired machine waits in the store and is not
a key here until somebody at this end says so — and until 2026-08-19 the
only thing anywhere that could say so was `ladulas keys accept`, on the one
surface whose whole premise is that somebody is sitting in front of it. It
is now a count on the Keys entry in the sidebar, a row at the top of the
Keys screen and a section on Home, and answering one is a sheet: the
fingerprint to compare, who sent it, a name to give it here — the store
refuses a label it already holds, and the sender chose theirs on a machine
that could not know what is here — and what each answer costs. Accepting is
final in the sense the transfer already was; refusing keeps nothing, and
the sender is not told and still holds the key.

**Ending one is on the peer screen**, behind the cog in its title bar, and
it asks twice. The screen used to say, in as many words, that revoking was
`ladulas peers revoke` and that a window able to do it is a window a stray
click can unpair a machine from.
The premise was right and the conclusion was not: a machine somebody wants
rid of — a lost phone, a rebuilt laptop — is exactly the case where the
person is looking at the window and the terminal is the thing they have to
go and find. What answers the stray click is the second press. The first
turns the button into the sentence it would carry out, naming the machine;
only the second calls anything. It is the one action on any of these
screens that cannot be undone by doing it again — it drops the direction,
the borrowed keys, the promises made under the pairing and the connection
it is holding — and it is the only one that asks twice, which is what keeps
the asking meaningful.

It shares the cog with the pairing's own facts — the fingerprint the two
machines compared, which keys the peer may use, the addresses, when it was
last connected. Both were rows down the screen, under everything a peer is
*for*: the keys it lends and what it publishes. They are read once each, when
two fingerprints are being compared or somebody is working out why a machine
cannot be reached, and once ever, when a phone is lost — which is the
definition of what belongs behind a cog rather than in front of one
(decision AF).

**Three rules the sidebar screens follow, all three learned on the phone.**
A poll that found nothing new redraws nothing: the instance is re-read every
few seconds to keep a countdown honest, and a pane rebuilt under somebody's
cursor loses the click that was landing on it. A screen that has to ask
another machine says so before it starts asking — reading what a peer
publishes is a pull (decision Q) and a sleeping build box takes seconds to
answer. And the screens that fetched something of their own are not
repainted by the poll at all, because throwing away a document somebody is
three directories into, to show them the same document again, is the same
bug wearing a hat.

**The GTK loop runs on the goroutine that started the process, and two hangs
came of it not doing so.** Wails locks the goroutine that imported it to the
main OS thread — package `application`'s own `init` calls
`runtime.LockOSThread` — and remembers that thread. Every main-thread dispatch
checks against it, and `InvokeSync` made *from* the main thread runs its
function inline rather than queueing it, which is what makes it safe for one
main-thread callback to call another. Run the loop on any other goroutine and
that check is false forever: a nested dispatch queues a task and then waits
for a loop that is already inside the dispatch, and nothing runs again. Two
paths reach it, and both were live. **Closing the last window**: Wails
destroys the window on the main thread and, if it was the last, quits from
inside the same call — `unregisterWindow` → `linuxApp.destroy` →
`App.cleanup`, which dispatches. **Quit**: `App.Quit` *is*
`InvokeSync(impl.destroy)`, which reaches the same `cleanup` the same way, so
choosing Quit from the tray froze the application instead of ending it.

What either one looks like is nothing, which is the part worth remembering:
the process stays alive, the front end stays attached, the tray icon stays on
the bar, and every item on its menu does nothing at all. No window can open,
so **no approval can ever be shown again** — every request from then on waits
out its timeout unanswered, which is a failure closed rather than open, and
silent either way. It was reported as "it hangs if I close its window" and
then as Quit freezing.

So `application.Run` is called on the goroutine `main` handed to `runGUI`,
and the two things that used to be a `select` beside it — the run error and
the signal context — are a goroutine each.
`DisableQuitOnLastWindowClosed` is set on both platforms as well, and that is
a separate statement that is true on its own: a tray application has no
business quitting when its last window closes, because the tray is the
application. Quitting is what the Quit item is for. ops.md has both as a
failure mode with the way to recognise them.

### The terminal is a third shell — **decision AK**

`ladulas tui` is the desktop window's job done in a terminal: it attaches to
a running daemon as an approver, draws the card the window draws, and
answers over the same socket. It is a client and nothing more, exactly as
`ladulas gui` is (decision Z) — no store, no agent socket, no key.

**It is the seam decision Z left, used.** `internal/frontend` has said since
that decision that its host "supplies a `bridge.Presenter` and nothing else",
and that a different toolkit or a terminal could be written against it. The
terminal supplies one. Everything that decides anything is on the far side:
the watching and the answering are the front end's, the card is the
`RequestView` the bridge renders, the diff was parsed in Go, and the answer
goes through `POST /api/v1/requests/{id}/answer` like the webview's — which
is what keeps the bound on a promise, the audit entry naming what was on
screen, and the refusal of a request that has since been settled in one place
instead of two. Nothing in `internal/tui` parses a commit or knows what a
scope is. A second surface answering signing requests is a second chance to
disagree about what a commit says, and the only way not to take it is to
have nothing there that could disagree.

**It is not the console approver, and the distinction is the one pkg/approval
already wrote down.** `ConsoleHandler` lives inside the daemon, prompts on the
daemon's own stdin, and is what `ladulasd run` gives a box started
interactively; it offers a yes, a no and the four fixed lengths, because "a
console that grew a syntax for both would be asking somebody to spell out, in
the dark, the thing the wording is there to make plain". That sentence is
about a line-oriented prompt, and it still stands. This is a screen with a
picker on it, so it offers what the window offers: the reach and the length
of decision V, the trust note of decision X, and the diff a file at a time.
Both can be attached at once; they are two approvers with two names in the
log, `console` and `terminal`.

**And it says when nothing can arrive.** "Nothing is waiting" is not the
whole truth on a sealed instance, where nothing *can* wait — the agent
offers no keys, so a signature fails before it is a request — so a screen
sitting empty and reassuring while every commit on the machine was refused
would be wrong twice over. The lock state is on the idle screen in the
words every other surface uses, with the way out of it, which is the same
thing the window does by drawing the passphrase panel in place of its
screens (§10). A soft lock says the keys are still here and paired
approvers still answer; a state this build has no branch for says so rather
than guessing.

**What is in a terminal that is not in the window.** The answer keys are
drawn at the bottom whatever is scrolled where, which is the same rule the
window's pinned footer follows and for the same reason: on any commit worth
reading, an answer underneath the diff means scrolling past the whole change
before you can refuse it. The diff opens a file at a time on `enter` with a
focus ring the arrow keys walk, because there is no pointer to click a
disclosure with. The colours are the sixteen ANSI ones, so red and green are
whatever the terminal's owner has decided those are, and every coloured line
says in words what the colour says. And the log goes to stderr only when
stderr is not the screen: one INFO line about attaching is enough to put a
timestamp through the middle of a card.

**It picks up what is already waiting**, which it did not at first: the
engine settled the set of approvers when it fanned a request out, so a
terminal started while a signature was blocking somebody's shell showed an
empty screen. That was where the fan-out kept its count and not a rule about
who may answer, and it is decision AL. The card carries the request's own
timestamp rather than the moment this screen saw it, because "waiting 0s" on
something that has been on a desktop for forty minutes is wrong about the one
number somebody uses to decide whether to hurry.

**And it can open the store.** A terminal is often the only thing in front of
somebody — an `ssh` session on a box whose window they cannot see — so the
screen that says the store is sealed is the screen that unlocks it: `u`, a
field that draws dots, and the daemon's own sentence back when the passphrase
is wrong. What is typed is held as runes and zeroed when it is sent, the
encoded body is zeroed after the call, and neither goes near the log — this
program writes no log to the screen at all. An empty passphrase is not
refused, because on an instance that enrolled "unlock at login" it is the
whole of the answer and the daemon is the one that knows (decision I). `q`
does not quit while the field is up: a passphrase may contain a q.

### Decision B — mobile (**resolved: B1**)

**B1 — gomobile bind + native shells (recommended).** Go core compiled to
an xcframework consumed by a small SwiftUI app (later: .aar +
Kotlin/Jetpack Compose), hosting the shared viewer in a webview for all
rich content.
Push, Keystore/StrongBox with biometric-gated keys, key attestation,
foreground services, and notification action buttons are all boring
first-party platform features. This is the Tailscale pattern — they
shipped Gio-for-Android for four years and then rewrote exactly this way,
keeping Go for the engine. Boundary kept tiny (JSON/protobuf in `[]byte`,
callback interfaces), so the gomobile type restrictions don't bite. Cost:
a thin UI written twice, and Xcode-in-CI (later Gradle) in the toolchain —
thinner now that the viewer is shared web content.

**B2 — Gio + gio-plugins.** The only all-Go option that functions
end-to-end (FCM token, system notification, Keystore-backed storage via
`safedata`). Rejected as primary for the reasons above; also `safedata`
stores secrets but does not give hardware-resident *signing keys* or
biometric-gated key use, which §10 requires — and it has no WebView story
for the shared viewer.

### Decision C — desktop (**resolved: C1**)

**C1 — Wails v3 (recommended, matches your stated preference).** Beta as
of 2026-08 (beta.0 Aug 2, beta.5 Aug 7); desktop API declared stable.
Tray-first design — tray icon with rich menus and windows attached to the
tray — is exactly the shape of an approval agent. Frontend is HTML/JS in
the platform webview — which is now doubly motivated, since the shared
viewer bundle (§12) *is* web content and renders natively here. Risk: beta
software; mitigated by the GUI being a thin shell over the library.

**C2 — Fyne v2.8.** Pure Go, stable, no JS toolchain. Weaker tray story,
Material-look widgets — and the shared viewer would need an embedded
webview anyway (Fyne has none built in), eroding its "no web tech"
advantage. Fallback if Wails v3 beta misbehaves.

### iOS without a Mac

Every stack needs Apple hardware to build for iOS; the answer is a GitHub
Actions macOS runner + fastlane once the Apple developer account exists.
The gomobile-bind architecture extends most naturally (same Go core,
SwiftUI shell, WKWebView viewer, APNs, Secure Enclave). Nothing in the
design blocks on iOS.

M6 built it, and the shape decision B1 predicted held. The binding
surface is one `Core` object, three interfaces the shell implements —
the Secure Enclave, the Keychain, and the thing that puts a request on
screen — and JSON in `[]byte` for everything structured. The webview is
served by the same `http.Handler` the desktop hands Wails: a
`WKURLSchemeHandler` takes the method, the path and the body off a load
and hands them to the Go bridge, which is the seam M2 built and the test
that asserts the two produce the same bytes is what keeps it one bundle.

The shell is thin in the way that matters — it decides nothing — but it
is not identical to the desktop's. M6 wrote down one place: the unlock
screen is native rather than the shared bundle's unlock panel, because
both of its inputs are — the biometric sheet is the platform's, and a
passphrase field wants iOS password autofill. It calls the same core
unlock the panel would have, so what is duplicated is pixels rather than
logic.

Decision O turned that exception into the rule. The shell draws the tabs,
the home screen, the peers, the banners and the approval card, all from
the same JSON the bundle would have read, and the bundle keeps the diff
and the published markdown. "Thin" still means the same thing — the shell
decides nothing, verifies nothing and words nothing — but there is more of
it, and one card's worth of drawing now exists on both sides.

Running M6 on a real phone found the shell doing one thing it decides, and
therefore should not have been: deciding what was on screen. Presenting and
dismissing a request both ignored the identifier they were handed, so a
request settling anywhere took away whatever card was up; returning to the
app reset the webview to the status pane while the request behind the card
went on waiting; and `.inactive` was treated as the app leaving, which on iOS
a notification banner, Control Centre or the screen dimming is enough to
cause. The rule the shell follows now is the one that was meant all along:
what is drawn follows the set of requests the core is waiting on, that set is
read back from the core on every return to the foreground, and `.background`
is the only transition that means the app has gone. The status pane's list of
waiting requests opens the cards it names, which is what makes one that was
navigated away from reachable at all.

The gap M6 leaves is on the *requester's* side of pairing rather than the
phone's. The phone scans, and the string a QR carries is the full pairing
code that has existed since M3; what nothing yet does is draw one. A
headless box prints the code and the command to turn it into a QR
(`qrencode -t ansiutf8 …`); the tray could render one itself, but the
viewer bundle has no dependencies by policy and a QR encoder is either a
dependency or six hundred lines. That is a decision, not an oversight,
and it is open.

## 13. Platform notes

* **Linux desktop**: primary dev target, and the only one anything has been
  run on. Unix socket agent, Secret Service keyring, and a desktop
  application via Wails behind the `gui` build tag — a client of the
  daemon, started by a `.desktop` entry rather than a unit (decision Z).
* **Headless Linux**: `ladulasd`, under a systemd user unit
  (`contrib/ladulas.service`). Starts sealed — unlocked via
  `systemd-ask-password` at service start, `ladulas unlock` over the
  control socket (§14), or the keychain where a keyring daemon exists.
  Socket activation (the ssh-tpm-agent precedent) is **intent**: the unit
  starts the daemon directly today, which is why the agent socket exists
  from start-up rather than on first connection.
* **iOS**: built (M6, M11, M12) — SwiftUI shell over the gomobile core,
  Secure Enclave P-256 keys, portable keys beside them, APNs wake-ups.
* **macOS (intent)**: nothing platform-specific is written, and there is no
  Apple hardware here to run it on. The keychain wrapping and the unix
  socket agent should both work as they do on Linux; nobody has tried.
* **Windows (intent)**: named pipe takeover per §4 and DPAPI for the DEK
  are designed and unbuilt. The agent listens on unix sockets only, and
  `go-winio` is not a dependency.
* **Android (intent)**: M10. The core is already bound for gomobile and the
  keystore's per-key handle model is what a StrongBox key would use, so
  what is missing is the shell rather than the design.

## 14. Management surface: the control socket and CLI

Every instance serves a local API on unix sockets under
`$XDG_RUNTIME_DIR/ladulas/`, peer-uid-checked so only the owning account
can talk to it: the `SigningService` that `ladulas-sign` uses (§5), and a
`ControlService` that is the instance's **complete management surface**.
Everything administrative the GUI can do maps to a `ControlService` RPC,
and the `ladulas` CLI is a thin client of the same service — the GUI and
the CLI are peers, not primary and afterthought. This is what makes
headless instances first-class: a box with no display is managed by
SSHing in and running the CLI, at feature parity.

The surface (existing pieces from M2/M3 plus planned):

* `init` — create the store and the identity key on an instance that has
  neither. The one call besides `status` that an uninitialised instance
  answers;
* `status` — instance identity, lock state, connected peers;
* `unlock` / `lock [--seal]` — the passphrase travels over the
  uid-checked socket; the daemon derives the KEK and wipes the input.
  `unlock --stdin` reads it from a pipe instead of the terminal, which is
  a flag rather than a fallback so that a command whose input was
  redirected by accident asks rather than unlocking with whatever was
  there. `keyring enrol|forget|status` is the "unlock at login" opt-down
  of decision I, and says what it gives up before it does it — enrolling
  copies the DEK into the keychain, so it is the daemon's to do;
* pairing — `ladulas pair --listen --intent <approver|requester|mutual>`
  starts one and says what it is for, which settles both sides (decision
  AD); `ladulas pair <host:port> --code <code>` uses one and declares
  nothing. Either gives the terminal back once this side's user has
  answered. `ladulas pairings
  list|approve|reject|withdraw` is everything after that: a pairing does
  not expire and the command that raised it is usually gone, so the list
  is where one is found and answered. `ladulas pairings approve
  <fingerprint>` is the headless equivalent of clicking Confirm in the
  tray, and `withdraw` is the only way a pairing leaves the list without
  being answered. While sealed the verbs refuse rather than answering
  emptily, because pending pairings live in the store (§7);
* wait — hold until the store reaches a state, and exit 0 when it does.
  `unsealed` is either unlocked or soft-locked, which is the difference
  between the key being in memory and approval being available here (§10).
  It is a long poll rather than a loop for the reason the inbox is one: the
  daemon knows the moment the state changes, and anything asking every few
  seconds is a machine finding out late and saying so in a log nobody
  reads. What it is for is watching a machine that is waiting for a person
   — a script, a deploy, or an agent that has to stop and let somebody type
  a passphrase;
* peers — list, rename, revoke, and set directions/roles (`allow`);
* listen — `ladulas listen` says what the peer channel is bound to, what
  peers are told to dial, and every address the automatic policy passed over
  with the reason it did; `ladulas listen set <address...|auto|off>` changes
  it and `ladulas listen clear` forgets the change (decision AH). The setting
  is in the store, which puts it on this surface rather than in a unit file,
  and the change rebinds the channel rather than waiting for a restart — a
  management surface that needs a `systemctl restart` to finish a change is
  one the person reaching a box over SSH cannot use. A bind that fails puts
  the previous addresses back and says so, because the address somebody typed
  wrongly is the one they are reaching the machine through. `--peer-listen`
  on the daemon still wins over the stored setting, and the answer says so
  when it does: a stored address on an interface that has been renamed is
  exactly what needs a way back in. Answerable while sealed, where it reports
  what the policy would choose and why nothing is bound;
* keys — list, generate, import, remove, enable/disable, and the
  public half in `authorized_keys` form. `keys list` shows the keys
  paired instances lend this one under the keys it holds itself, with the
  machine each lives on and whether it can be used right now (decision N);
  `status` counts them the same way, "3 borrowed, 1 usable now". A lent key
  this instance holds a copy of says "held here too, signs locally" and is
  counted apart from both, because it is not waiting on anybody (§10). Each of
  this instance's own keys says whether it is in the secure element or
  portable, and a portable one that has been given away says so — under
  the table, by name, because "which of these are on somebody else's disk"
  is the question somebody asks after losing a machine and a column could
  only have answered it with a number;
* keys send, offers, accept, refuse — giving a portable key to a paired
  peer and answering one that has arrived (decision S). `send` prints what
  it is about to do, asks for the store passphrase, and says afterwards
  whether the key went out or is queued for a peer that was not there. The
  passphrase is typed at the terminal and checked in the daemon, which is
  the division every other passphrase already has: the terminal is what can
  ask a person, and the process holding the wrapping is the only thing that
  can say whether the answer was right. Refusing keeps nothing, so there is
  no list of keys this instance turned down;
* grants — list, revoke; policy — show, path;
* tui — attach as an approver and answer requests in this terminal
  (decision AK, §12). It is a client of a running daemon rather than a
  command that does something and exits, and it is on this surface rather
  than in the desktop binary alone: a headless box reached over SSH is
  precisely where a terminal that can read a diff and make a promise is
  worth having, and it needs no GUI toolchain to build;
* projects — publish, list, unpublish, auto. `unpublish` works in both
  directions: on one of this instance's own publications it withdraws the
  offer, and on one it has been reading it forgets the pages it kept. There
  is no `refresh`, because under decision Q there is nothing to refresh — a
  branch and a commit are re-read every time an approver lists a project,
  and a page is read from the machine that has it every time somebody
  opens it. `auto` is the setting instead: publish, automatically, any
  project this instance asks for a signature in, which is on by default.
  **The directory `publish` is given is resolved by the CLI, and the
  daemon refuses one that is not absolute.** A thin client passes what it
  was given through, but a path is the one argument it cannot: the two
  processes have different working directories — the daemon's is a
  systemd unit's — so `publish ../notes` resolved on the far side would
  quietly name some other directory, or nothing, while the person who
  typed it believed they had published the sibling of the project they
  were standing in;
* audit — tail the decision log.

**And the half a front end needs, which a command line does not**
(decision Z). The desktop application answers prompts over this socket
rather than from inside the daemon, so four things joined the surface:

* `WatchApprovals` — a server stream that *is* the registration. While it
  is open the caller is a local approver in the engine's fan-out, marked
  `LocalPrompt` like the tray window it replaces, so a soft lock takes it
  away for the same reason (§10). It carries the request as **the bytes
  the digest covers**, not as a message, so the card is drawn from the
  same material the signature commits to — the rule the peer channel
  follows, for the same reason (§8) — plus what may be promised, and it
  carries withdrawals and the announcements an auto-approved request still
  gets. Answers come back through `AnswerApproval`, a separate unary call
  rather than the other half of a bidirectional stream, so that an answer
  is an ordinary request with an ordinary error: "settled while you were
  reading it" is a code rather than a silence. The ceiling on a promise is
  checked again here — the front end draws the bound, it does not own it.
  **Opening the stream picks up whatever is still waiting** (decision AL), so
  restarting a front end, or starting one on a box where a signature is
  blocking somebody's shell, raises the cards that are still open. And an
  answer carries the prompt's token as well as the request id (decision AM):
  the prompt is the thing being answered, and the cards on the other screens
  are withdrawn rather than handed somebody else's answer;
* `FetchRequestDiff` — the deferred diff (§5) for a front end that has no
  connection to the requester. Only a request that is on a screen right
  now can be asked about, which is the peer channel's rule word for word;
* the doc browser — `ListPeerProjects`, `OpenPeerProject`,
  `ListPeerDirectory`, `SearchPeerProject`, `ReadPeerPage`. Both halves of
  an answer are the daemon's: what a peer publishes is read over the peer
  channel, and what has been read before is in a cache sealed with the
  store key. Every one of them says which half it came from (decision Q);
* `Reload`, because a menu item may not depend on being able to signal a
  process, and `Status` grew the instance's file locations — a front end
  started from a menu was not started with the unit's environment, so
  where the store is is the daemon's answer to give rather than a path the
  window guesses;
* `Settings` and `SetSignTimeout` — how long a signing request waits, read
  and written (§9, decision AJ). They are two calls rather than one policy
  editor on purpose: the document decides what is approved without asking,
  and a screen that could write rules would be an auto-approve rule one
  mis-click from every process running as this user. The write is bounded
  by the instance and answers with what a read would now say, so a screen
  redraws from the reply rather than polling to find out whether its own
  write took. Both are answered while the store is sealed, because the
  policy is a config file rather than store contents — and somebody who
  cannot sign yet is exactly the person asking how long the next request
  will wait.

The audit log stays a plain file read even from the front end, which is
the same exception it has always been, made once for the same reason.

**Authority model: possession of the unix account is the authority.**
The uid check is the whole gate — no admin password, no second authz
layer. Anyone with a shell as the user can already replace binaries and
sockets; pretending the CLI needs more auth than the shell it runs in
would be theater. The store passphrase is not a management credential
either: it unlocks key material, not the right to run `status`. While
sealed, the surface shrinks to what needs no store — `Status` and
`Unlock` — because trust records live inside the encrypted store (§10)
and there is nothing to list or mutate until the DEK is back. Before
there is a store at all it is `Status` and `Initialize`, for the same
reason one step earlier.

**One owner: the socket is the only way in** (decision L). `ladulasd`
opens `store.age`, and nothing else ever does — not the CLI, not the
desktop application, not `ladulas init`. There are no exceptions and no
`--offline` flag. The desktop application was the one standing exception
until decision Z took it away: it opened the store in its own process,
which is why L had to name it.

Three reasons, in the order they matter:

* **Nothing guards the file against two writers.** The store document is
  held whole in memory and rewritten whole on every change, with no lock
  and no compare-and-swap. Any second process that opens it while the
  daemon has it can silently discard everything the daemon has learned
  since. One owner removes that class of bug outright, and removes the
  locking protocol that would otherwise have to be designed, implemented
  and got right.
* **A fallback normalises the dangerous path.** It is why the `keys`
  verbs were written with only a direct-store path and no socket path at
  all — a defect that dogfooding found, not review — and why `grants
  list` and `grants revoke` had the same one after it: against a running,
  unlocked daemon they answered "a passphrase is needed but there is no
  terminal to ask on", which is the one answer a management command must
  never give. A rule with an escape hatch is a rule people write code
  against the wrong side of.
* **It costs nothing in security terms.** The authority model above
  makes the uid check the whole gate, so the socket is not a weaker path
  than the file; it is the same authority, exercised by the process that
  already holds the key.

What that buys, beyond the absence of a race: a read needs no passphrase,
because the daemon has already been given one — which is what makes
`ladulas keys list` work on a headless box over SSH. A write lands in the
document the daemon is serving from, so a generated key is offered by the
agent the moment it exists rather than at the next SIGHUP. And a daemon
that answers with a refusal — a sealed store — is an answer, which the
CLI passes on rather than working around by asking a person for a
passphrase nobody has given the daemon.

The recovery path when the daemon will not start is to run `ladulasd run`
in the foreground and read what it says. Failing that, the store is a
plain age file and `age`/`rage` plus the passphrase will open it. A
silent fallback is the dangerous part; an explicit flag could be added if
a real need appears, and adding one later is much easier than taking one
away.

**Creating the store is the daemon's too.** `ladulasd` starts with or
without a store: with none it comes up **uninitialised** (§10), serving
`Status` and `Initialize` and nothing else, and `ladulas init` is a
client of that RPC like every other verb. The passphrase travels over the
uid-checked socket exactly as `unlock`'s does and is wiped the same way;
the CLI's part is asking for it twice, because the CLI is the side with a
person in front of it. Afterwards the instance is unlocked and fully
serving in the same process — no restart between creating a store and
using it. This also removes a trap the unit file used to set: a daemon
that exited with "no store yet" under `Restart=on-failure` is a restart
loop, so enabling the unit before initialising was an ordering somebody
had to know about. There is no ordering now.

**Unlocking a unit that has no terminal.** `ladulasd run` starts sealed
and unseals deliberately: the keychain where one is enrolled, otherwise
the terminal if there is one, otherwise `systemd-ask-password`
(`--unlock=auto|terminal|ask-password|none`). Unprivileged, that writes
its request into `$XDG_RUNTIME_DIR/systemd/ask-password`, where
`systemd-tty-ask-password-agent --query` in an SSH session — or the
desktop's own agent — answers it. None of it is privileged, and none of
it is load-bearing: the daemon comes up either way, because a sealed
instance still answers `Status` and `Unlock`, and a daemon that refused
to start until somebody typed something would be a daemon that could not
be asked what was wrong with it.

**The asking comes after the listening.** The order is part of the
promise rather than an implementation detail: the daemon reaches its
sealed-but-serving state — both sockets open, `Status` and `Unlock`
answerable — and only then asks, however `--unlock` said to ask. Asking
first would make the prompt the only way in, so a box nobody answered
within the timeout would sit sealed with no control socket at all, and
`ladulas unlock` would be advice that could not be taken. The two routes
race deliberately and either may win: an unlock over the socket kills
the `systemd-ask-password` child still holding a prompt up, and an
answered prompt unseals a store the socket has not been asked about.
`Status` reports which prompt is standing while one is, since "sealed
with a question waiting in somebody's session" and "sealed with nothing
happening" want different things done about them.

**A verb that does not exist starts nothing, and `ladulas` on its own
starts nothing either — decision Y.** `ladulasd` alone is still the
daemon, because a unit starts it and has nothing to pass. `ladulas` alone
used to be the desktop application, or the terminal agent in a build with
no GUI in it, on the same argument about launchers; that is withdrawn, and
what it does now is print the usage.

Two things were wrong with it, and the second is why the rule is gone
rather than patched. The command-line library reaches the default command
for anything it could not match, so `ladulas pairings list`, before that
verb existed, started the desktop application, which printed a webkit
banner and then died saying an agent was already listening: a typo that
starts a GUI on a machine that may have no display, reported as a problem
with something else. Refusing positional arguments takes that away, and
the desktop application, the agent and the daemon all do — none of them
takes any, so a verb nobody has heard of gets the usage and a non-zero
exit like any other command line, and that half stands.

What refusing arguments could not fix is that the default was chosen by a
build tag. The same command line was the window here and the agent on a
box built without a GUI, so what `ladulas` did was a property of how the
binary was compiled rather than of what was typed — and the three Arch
packages ship both builds under that one name, so it was not even a
property of the machine. The binary is also the management CLI as much as
it is the application, so typing its name to find out what it does — the
thing a person does with an unfamiliar command — took over the agent
socket. The desktop application is worth exactly one word to say so, and
that word is **`gui`**: it draws a tray icon, but it also draws the
prompt, the status pane and the menus, and a verb named after one widget
read as though `ladulas tray` put an icon somewhere while something else
did the work. `gui` is what the build tag, the package and the make
target have always called it. `ladulas gui` is what `contrib/ladulas.desktop`
runs, and no future default command is worth sparing a launcher an
argument.

**Metrics and pprof are a port of their own, and the daemon's is off
until it is asked for.** Prometheus metrics and `net/http/pprof` are
served on a separate HTTP listener — `--debug-listen`, or
`LADULAS_DEBUG_ADDR` — rather than on any socket that does work. They are
unauthenticated by nature: a scrape is a GET, a heap profile is a GET, and
a password on either would be a password in a scrape configuration. What
keeps them private is the address they are bound to, which is a thing an
operator can only choose if it is a separate address. The daemon opens
none unless one is named, for two reasons that are both about it being one
process per logged-in account: a port in the default would be a port two
people on the same box fight over, and while the store is unlocked the
heap holds the data encryption key — a heap profile is a copy of the heap.
The relay defaults to `127.0.0.1:8444` instead, because it is one process
on a host somebody operates, and it says the same thing about its own
heap: what is in it is a push key and a device list. Either way a
non-loopback bind is logged as the widening it is.

What the ports carry is counts and states and nothing else. No
fingerprint, no request id, no instance id, no payload: the metrics
surface is the least protected one an instance has and the one whose
output is written down and kept, so the identifying detail stays in the
audit log, which is readable by the account that owns it and by nothing
else. The daemon's counts come from watching that log rather than from a
second seam in every subsystem — every request, decision, signature,
grant and key transfer already passes through it, so the instrumentation
is wherever the audit trail is by construction — and its gauges are read
off the instance at scrape time, so a sealed store reports no key count
rather than a key count of zero. Only the two server binaries link a
metrics library at all; the packages that produce the numbers expose a
seam and nothing more, so the phone, which links several of them through
gomobile, does not carry a Prometheus client for a scraper that will never
call it.

Which numbers there are, and what a change in each of them means, is
[`docs/observability.md`](observability.md); what to do about one that has
moved is [`docs/ops.md`](ops.md).

**Remote management is deliberately absent from the peer protocol.**
Managing a headless box from elsewhere means SSHing in and running the
CLI. SSH is already the authenticated, audited admin channel for that
machine — a second remote-admin authz system riding the peer channel
would double the trust surface for zero reach, since any box worth
managing is reachable over SSH by construction (it is running an SSH
agent). The `admin` request type stays reserved in the protocol (§8) in
case a real need appears — phones administering desktops, say — but it
is not designed until then.

## 15. Migration from 1Password

Per machine: disable the 1Password SSH agent, point `SSH_AUTH_SOCK` /
`IdentityAgent` at Ladulås, set `gpg.ssh.program = ladulas-sign` and
`user.signingkey = key::ssh-…`. Since 1Password keys are exportable,
either import them (they become desktop-resident Ladulås keys) or — better,
matching §10's philosophy — generate fresh per-device keys and rotate
GitHub/servers. Both paths supported; import eases transition, rotation is
the recommended end state. The agent's proxy-to-another-agent option (§4)
allows running both during migration.

## 16. Security considerations

Threat model sketch (to be expanded in its own document):

* **Compromised requester (the main threat)**: a hostile headless box can
  ask for signatures with false context, and publish misleading project
  docs. Mitigations: the approver independently parses the payload it
  signs (§5 — message/author are provable, repo/diff labelled as
  requester-asserted); published docs are labelled untrusted context and
  rendered sandboxed (§6); per-key/per-peer policy limits blast radius;
  audit logs on both ends; unbound/forwarded requests always prompt. One
  seam is that a policy `approve` rule or a TTL grant scopes on
  requester-asserted fields (repository, destination label, executable) — so
  a scoped auto-approve trusts the borrowing peer to describe them honestly
  for as long as it runs, and against a compromised peer that narrowing bound
  only an honest one. It is a disclosed concession, not a defended boundary
  (decision X): the note on the grant offer says what the promise takes on the
  peer's word, and the standing defence is the same as for any asserted field
  — the approver reading it, once at approval or once when the promise is
  made.
* **Hostile networks**: assumed by default — the pinned-TLS channel is the
  only trust anchor, so running over the open internet is safe in the
  cryptographic sense. The listener's unauthenticated surface is the TLS
  handshake itself; unpaired identities get no protocol access beyond the
  pairing endpoint, which rate-limits and always prompts. Public binds are
  explicit opt-in (§7) — supported, never accidental.
* **Compromised Tailscale control plane** (when Tailscale is used): outer
  layer only; app-level TOFU identities survive (§7). Tailnet Lock
  optional hardening.
* **Stolen phone**: enclave keys are hardware-resident and biometric-gated
  per use; revoke the pairing from any desktop and rotate the P-256 public
  keys out of GitHub/servers. A portable key on that phone (§10, decision
  S) is a different loss and a worse one: it is bytes under the store's
  data encryption key, so what stands between a thief and the key is the
  store passphrase or the keychain item's `WhenUnlockedThisDeviceOnly`
  plus current biometric set — device security, in other words, rather
  than a secure element. Its per-use prompt is the app's own and does not
  survive the app being taken apart. Treat a stolen phone that held a
  portable key as that key having leaked, and rotate it.
* **A portable key in transit**: the transfer is inside the pinned-TLS
  peer channel between two paired identities, so the wire is the same one
  the approval protocol already trusts. What the design defends beyond
  that is misdirection and inattention rather than interception — the
  passphrase on the sending side, the explicit acceptance on the receiving
  one, an audit entry at both ends. What it cannot defend is the decision
  itself: a key sent to the wrong peer is a key that must be rotated, and
  there is no revocation to reach for.
* **Stolen desktop / disk**: store encrypted; passphrase-wrapped DEK by
  default (keychain enrollment is an explicit opt-down, §10). The
  seal-on-sleep option wipes the DEK before suspend for the
  stolen-suspended-laptop / cold-boot case.
* **Session malware (same uid, the honest limit)**: with keychain
  auto-unlock it can read the DEK out of the Secret Service in one D-Bus
  call and exfiltrate keys silently; with the passphrase default it must
  instead go through the approval engine per signature — visible,
  audited — or persist long enough to keylog the passphrase. The
  cold-start passphrase buys detection opportunity, not immunity; full
  session compromise still loses eventually (§10).
* **Push relay compromise** (when used): learns device tokens, wake timing,
  which of two kinds of thing is waiting (§11, decision S), and — since every
  signed relay call carries the caller's identity public key on the wire, even
  though the honest relay discards it after checking the signature — which
  identity wakes which registered device, i.e. the pairing graph. It cannot
  forge (only miss) notifications, and no approval content or key material ever
  crosses it; poll-on-open bounds the missed-notification damage. The metadata
  leak is the reason the wake capability (the instance id) is deliberately not
  derived from the identity key, and it is priced in rather than defended.
* **Malicious published docs**: markdown is parsed in Go into typed blocks and
  rendered by a viewer with no parser in it, with no script execution, no
  remote fetches and capped sizes; the only links that survive are ones
  pointing at another file of the same project and ones pointing at a heading
  of the document being read, and both are buttons with no href, so a
  published document cannot navigate an approver's window anywhere. A
  heading's anchor is computed in Go from the heading's own text, and a
  fragment naming no heading in the document is demoted to text before it is
  drawn — so the second kind of link either scrolls the page it is on or is
  not a link, and there is no third thing it can do. Path canonicalization
  prevents the doc browser reading outside the project root, on the
  publishing side and again on the browsing one (§6).
* **Approval fatigue**: the real long-term risk. Rich context (§5),
  project docs for orientation (§6), scoped TTL grants instead of blanket
  auto-approves, notify-on-auto-approve, and decision X's disclosure of what a
  grant trusts are the countermeasures. Underneath them is a blunt ceiling:
  one peer may hold only so many decisions in flight at once
  (`maxDecisionsPerPeer`, M3), so a compromised requester cannot bury a real
  prompt under a flood of decoys or pour requests in until somebody taps
  approve to make them stop — past the cap it is told to back off.

Explicitly *not* defended: a fully compromised approver device (it holds
keys and approval authority by definition), and malware on the requester
with access to the user's session *at approval time* (it can race the
legitimate request — mitigated only by the approver reading the prompt).

## 17. Prior art notes

* **Krypton/Kryptonite** — phone-held SSH keys with per-op approval; QR
  pairing where the QR carries a public key and the response is sealed to
  it; time-boxed per-host grants; died with its hosted relay. Ladulås is
  roughly "Krypton without the mandatory relay".
* **Secretive** — Secure-Enclave-resident keys, per-key policy, temporary
  unlock, notify-even-when-not-asking, keys-never-move.
* **ssh-tpm-agent** — the Go agent skeleton: `ExtendedAgent` +
  `ServeAgent`, socket activation, proxy-through to a fallback agent.
* **Bitwarden SSH agent** — forwarded-requests-always-prompt; user
  complaints about context-free prompts validate §5; its push relay is the
  honest precedent for why FCM/APNs can't be fully self-hosted (§11).
* **Syncthing** — the pinned-cert TOFU trust model between symmetric
  peers over arbitrary networks.
* **Tailscale SSH check mode / Taildrop** — TTL'd re-auth grants as policy
  vocabulary; same-user restriction as an optional outer-layer pattern.
* **`ssh-add -c`** — the cautionary tale: context-free confirmation that
  OpenSSH itself calls "somewhat easy to phish".

## 18. The library boundary

The annotated tree lives in the [README](../README.md#repository-layout),
which is where somebody who has just cloned the repository looks; what
belongs here is the seam it is arranged around.

The boundary to "custom applications participating in the approval flow":
embed `identity` + `trust` + `transport` + `protocol`, implement an
`approval.Handler` (receive requests, return decisions) or submit requests
to an `approval.Engine` — both small interfaces. The daemon, the tray, the
CLI and the phone are themselves consumers of this API, which is what
keeps it honest, and `internal/app` is the assembly they share rather than
a fifth arrangement of the same parts.

**Seventeen packages are in `pkg/` and the promise has still not been
made.** The rule this violates is a good one: a package moves out of
`internal/` once something outside the module has embedded it *and* the
shape has stopped changing, because publishing an import path costs more
to take back than to delay. Only the first half of that condition is met
here. A `gomobile` bind surface reaches nearly every package in the tree
(decision AB, §21), so the choice was to publish them or to publish a
binary framework instead — and the packages were the cheaper of the two.

So the import paths are public and the API is not. **Nothing in `pkg/`
carries a compatibility promise**: it is renamed, narrowed and re-shaped
whenever a consumer is changed alongside it, which is most weeks. What
made the old rule right is unchanged — it is only that the cost is now
paid in one known place instead of avoided. A second, independent consumer
appearing is the event that should force this paragraph to be rewritten
into a real guarantee, and until then the seam described above —
`identity` + `trust` + `transport` + `protocol` plus an
`approval.Handler` — is the part worth depending on, being the part four
programs already do.

Two seams are worth knowing about because they are what keep a metrics
library, a GUI toolkit and a webview out of the phone's build: the bridge
(§12) is one `http.Handler` every host serves, and the counting seams
(§14) are function fields and small interfaces on the packages that
produce the numbers, implemented with Prometheus only in `internal/observe`
and only linked by the two server binaries.

## 19. Decisions (resolved 2026-08-08, extended 2026-08-09)

| # | Decision | Resolution |
|---|----------|------------|
| A | Peer channel | **TLS 1.3 pinned-SPKI TOFU** (over Noise_XX, SSH transport) |
| B | Mobile stack | **gomobile bind + Kotlin/Compose shell**, shared webview viewer (over Gio + gio-plugins) |
| C | Desktop stack | **Wails v3** — Fyne v2.8 remains the fallback if the beta misbehaves |
| D | RPC layer | **connect-go** (over hand-rolled framing) |
| E | 1Password key migration | **support import and fresh keys; recommend rotation** |
| F | Project publication model | **snapshot + live refresh** |
| G | Wake-up modes | **publisher-hosted FCM/APNs relay + opt-in Android foreground-service live connection**, on the always-present poll-on-open baseline; UnifiedPush deferred |
| H | Listener bind default | **private/tailnet by default, public interfaces opt-in** — which of them, and what gets advertised, is decision AH |

Added 2026-08-09:

| # | Decision | Resolution |
|---|----------|------------|
| I | Desktop cold-start unlock | **passphrase-primary**; keychain enrollment ("unlock at login") is an explicit per-instance opt-down. Rationale in §10: the approval engine gates use, the passphrase gates silent key theft — Linux/Windows keyrings are same-uid-readable |
| J | Auto-lock default | **soft-lock on suspend and session lock** (DEK retained, local approval authority suspended, remote approval keeps working); seal-on-sleep and idle timeout are config options. Mobile: biometric app unlock with passphrase fallback (1Password model) |
| K | Headless management | **the uid-checked control socket is the complete management surface**, the CLI a thin client of it; remote administration = SSH + CLI, never the peer channel (the protocol's `admin` type stays reserved, undesigned) |
| L | Who opens the store | **`ladulasd` and nothing else, with no exceptions** — the CLI and the GUI reach an instance only over the control socket, `ladulas init` included. Replaces the daemon-first/store-fallback rule; no `--offline` flag. Rationale in §14 |
| M | How long a pairing lasts | **the code expires and the pairing does not.** `trust.CodeValidity` keeps its five minutes, its single use and its five wrong answers; everything after the code has been proved is a pending pairing in the encrypted store on both sides, answered locally and reconciled with the peer whenever either can reach the other. Withdrawal propagates by the side that still holds an entry asking, not by a tombstone. Rationale in §7 |
| N | The keys paired peers offer | **remembered, in the store, public halves only.** What a holder offers is written down as it is learned — label, algorithm, fingerprint, comment, which peer, when it was last confirmed — so an unreachable holder's keys stay listed and legible instead of vanishing. A successful refresh replaces what is remembered about that peer; a holder that could not be asked leaves it alone; revoking a peer drops it. The agent socket advertises only what can sign; every surface a person reads shows the rest with its availability and its last-seen. Qualified by decision T on both halves of "what can sign": which keys their holder offers to an agent at all, and what reachable means for a holder that collects. Rationale in §10 |
| O | Where the phone's UI is drawn | **the shell draws, the webview keeps the documents.** On iOS the chrome and the approval card are SwiftUI reading the same `/api/v1` JSON the bundle reads; the diff behind a commit and published markdown stay in the shared bundle, which is what a webview is for. Accepted cost: the request card exists twice. Desktop and Android are unchanged. Deployment target rises to iOS 26 (Liquid Glass). Rationale in §12 |
| P | Where a TTL grant lives | **follow the key.** A grant over a key the requester holds is **delegated**: a signed, scoped, expiring artifact the requester applies itself, so "approve for an hour" works with the phone asleep. A grant over a key held in an approver's Secure Enclave cannot be delegated and is unchanged — the private half never moves, so the holder is in the loop per signature whatever anyone decided. Delegated use is **reported back** and shown grouped under the grant. Supersedes the 2026-08-08 "TTL grants live approver-side" resolution for the first case only. Which case a request is, is the door it came through — a peer asking for a decision holds the key, a peer sending the bytes does not — and *not* whether the approver holds a copy, which was the implementation until 2026-08-13 and kept every promise about a portable key both machines hold. Rationale in §9 |
| Q | How published projects reach an approver | **published is a state, and an approver pulls what it looks at.** A project is marked published on the requester and nothing is sent; an approver lists projects, browses directories with pagination and a filter, searches by filename, and fetches files on demand — keeping what it has actually opened, content-addressed, so a page it has read stays readable offline. Replaces the push half of decision F. A project nobody has opened is not readable offline, which is the price of never shipping a tree. Rationale in §6 |

Added 2026-08-11:

| # | Decision | Resolution |
|---|----------|------------|
| R | How far into the doc browser the shell draws | **the webview keeps one document, and nothing around it.** On iOS the project list, the directories, the filename search and the provenance are SwiftUI reading the same `/api/v1/projects/*` JSON, and the bundle is opened one page at a time in a document-only mode; a link inside a page is handed back to the shell and becomes a screen rather than a navigation inside the webview. Two things follow, both stated in §6: a listing is asked for with `only=readable`, so a phone is shown what it can open and the core reads on when filtering empties a page; and the repository's path, remote, branch and commit move behind an (i) rather than sitting above every reader. Extends decision O; desktop is unchanged and still draws the greyed-out row with its reason |
| S | Portable keys, and whether key material may travel | **a key whose private half is in the store is a key that can be handed over, once, on purpose.** Every instance can generate or import one, the phone included, where it sits beside the enclave keys rather than replacing them — a key that already exists, or has to outlive the device, cannot be an enclave key, and the alternative to holding it here is holding it in a password manager. Transfer is inside the pinned-TLS peer channel, with the store passphrase re-entered on the sending side, an explicit acceptance on the receiving side, an audit entry at both, and a record on the sender of where the key went. Portable-key signatures on mobile prompt through LocalAuthentication, which is the app's promise rather than the enclave's, and is stated as such. Qualifies the "private keys never move" half of §2: using a key still never moves it. Rationale in §10 |

Added 2026-08-12:

| # | Decision | Resolution |
|---|----------|------------|
| T | Which keys an agent offers, and whether a phone's are among them | **the holder decides per key, and a holder that can be woken counts as reachable.** Every key carries one setting for whether it belongs in an agent's identity list; it is kept beside the key, travels with the public half to whoever borrows it, and is advertising rather than permission — a key with it off signs whenever something names it. A holder that cannot be dialled announces what it offers instead of waiting to be asked, and its keys are advertised while it is polling or has a wake-up route, because the sign request that follows is parked and pushed like an approval. For ssh authentication that push is load-bearing rather than an optimization: sshd's `LoginGraceTime` gives the whole login about two minutes, so a holder with no route is not advertised at all. Qualifies decision N; rationale in §4 |
| U | What a prompt calls the asker, and what a timed approval covers | **the session, named after what runs it.** The program at the socket is a helper — `ssh`, `ladulas-sign` — and is the same one whoever ran it, so a prompt that named it said nothing and a grant scoped to it would be no narrower than one scoped to the machine. The session is the discriminator: an editor that spawns its own subprocesses is one session, a terminal window is another. A prompt shows the session's name and the walk up to it (`git ← zsh ← kitty`), and a grant is scoped to the session, so "approve for an hour" means Emacs, or this window, and not the box. A request with no local process behind it is unscoped exactly as before. Rejected: the calling executable, which does not distinguish the cases anybody cares about, and walking the tree to its root, which on a real desktop names the window manager or whatever launched the terminal. Rationale in §9 |

Added 2026-08-13:

| # | Decision | Resolution |
|---|----------|------------|
| V | How far a timed approval reaches, and how long it runs | **two questions, and the approver answers both.** The prompt offers the two reaches, worded as the promise they would make — the session the request came from (decision U), or the machine it came from — and then a length on a clock, bounded by the longest length the policy offers. The four fixed lengths remain as suggestions worth one tap and are no longer the whole of what may be agreed to. An answer that says nothing about reach means the session, which is the narrower. The machine-wide promise is a scope with the session taken out of it, which is the shape a promise made where there was no session to name has always had — so nothing on the wire changed, a delegate running older code applies one correctly, and no stored grant changes meaning. A length past the bound is refused rather than approved without its promise, and the request stays waiting. Rejected: four more ready-made buttons for the wider promise, which on a phone is eight paragraphs of hyphenated text where the decision should be; and an unbounded picker, which would let anything that can reach the bridge mint a promise of its own length. The console approver keeps the four lengths and the session. Rationale in §9 |
| W | What an approval card leads with | **the four facts a person can check: what is being asked, on what, by which program on which machine, and with which key.** The kind-specific card under it carries verdicts rather than the material they were reached from — "a host this machine has connected to before", "not bound to this host" — and everything else moves behind an (i) on the summary card: fingerprints, host keys, digests, algorithms, pids, session numbers, the process chain, and a commit's tree, parents, extra headers, committer and remote URL. Nothing is dropped, because each of those is the answer to a question asked after the fact; putting them back on the card is not the fix for wanting to read them. The generic rendered detail list is drawn only for a kind with no card of its own, having been drawn under every card and repeating it fact for fact. On the commit card the same rule removes a subject drawn three times: the card carries the message body, split off in Go so that no renderer decides where a subject ends, and a commit that is only a subject shows no message block at all. Extends decisions O and R, and the (i) is the same idiom R gave the doc browser. Desktop is unchanged. Rationale in §12 |

Added 2026-08-14:

| # | Decision | Resolution |
|---|----------|------------|
| X | That a grant's scope can rest on requester-asserted context, and what to do about it | **disclose the trust, do not strike the field.** A grant or a policy `approve` rule matches on the repository a commit claims, the destination it names and the calling executable — none of them proven the way the signed bytes are (§5), and for a borrowed-key request all of them the requester's word. Striking them would take the scoped grant, an approval-fatigue countermeasure (§16), away with them; and the concession is real anyway, since a scoped auto-approve already trusts that peer with that key for that class, and the narrowing only ever bound an honest peer. `session_id` in a scope is the same shape already accepted (decision U). So the resolution is transparency at the point the promise is made: where "approve for a while" is offered for a request from another machine, the offer carries a note naming what the promise would take on the peer's word, with the fuller account behind a disclosure — a person weighs an asserted field once when approving, and a timed promise spends that judgement ahead of time, so the surface says so first. Disclosure, not proof: the honest limit is §16's, a compromised requester at approval time defended only by the reading, and a promise is that reading made early. Separately resolved and closed outright, having no fatigue trade-off: an SSH auth grant now pins the host key proven in the signed payload (`destination_fingerprint`), not the asserted destination label or the requester's `Bound` flag. Rationale in §9 |

Added 2026-08-15:

| # | Decision | Resolution |
|---|----------|------------|
| Y | What `ladulas` with no arguments does | **prints the usage, and starts nothing.** It used to run a default command chosen by a build tag — the desktop application where the GUI was compiled in, the terminal agent where it was not — so the same command line did different things on two machines, and the three Arch packages ship both builds under the one name. The binary is the management CLI as much as it is the desktop application, so the reflex of typing a command's name to see what it does took over the agent socket instead of answering. `ladulas gui` and `ladulas agent` each say which one is wanted, and `contrib/ladulas.desktop` runs the former, so nothing that starts a program by itself loses anything. The verb is `gui` and not `tray`, renamed with the decision: the tray icon is one of the things the desktop application draws, alongside the prompt window, the status pane and the menus, and `gui` is what the build tag, the package and the make target already call it. `ladulasd` keeps its `run` default, where a unit is the only caller and there is one thing to start. Does not replace the refusal of positional arguments introduced with it: `NoArguments` still stands, because a default command remains where the parser sends what it could not match, and the root action gives an unknown verb the usage and a non-zero exit rather than the library's "No help topic for". Rationale in §14 |

Added 2026-08-15:

| # | Decision | Resolution |
|---|----------|------------|
| Z | Whether the desktop application is an instance | **it is a client, and the daemon is the instance.** `ladulas gui` opened the store, served the agent socket, ran the approval engine and held the data encryption key, with a window on top; so it collided with `ladulasd` over the agent socket — the two units declared `Conflicts=` and a desktop had to pick one — and a webkit crash took the SSH agent, the peer links and the unlocked store down with it. It now holds a `bridge.Session` and nothing else: prompts arrive on `ControlService.WatchApprovals`, answers go back through `AnswerApproval`, and the keys, the engine and the sockets stay in the one process that owns them, which is what decision L has always said and what the tray was the standing exception to. Three things follow. The store key and the portable private keys no longer share an address space with a browser engine rendering commit messages and diffs written by whoever asked for the signature — a renderer bug is no longer a key-exfiltration bug, though a compromised front end can still approve, because it is the approver. `systemctl --user restart ladulas` no longer takes the window with it, and the window no longer takes the agent with it; the front end reattaches on its own, and says on the tray while it is not attached. And the doc browser, the diff fetch and the reload had to become RPCs, because the front end has no store to read and no peer channel to ask down. What it costs: a request in flight when the front end dies loses that approver rather than surviving a restart, and the desktop is one more process to have running. **`ladulas-tray.service` is deleted with it** — a GUI is an application rather than a service, and the unit was pulled in by `graphical-session.target`, which most sessions never reach, so it sat enabled and never started with no error anywhere. `contrib/ladulas.desktop` replaces it, installed both as a menu entry and into `/etc/xdg/autostart`. Rejected: serving the viewer's own JSON API over the control socket and making the desktop a webview proxy, which is a smaller diff and a second management surface on the socket — the exact thing decision L exists to prevent. Rationale in §12 and §14 |

Added 2026-08-18:

| # | Decision | Resolution |
|---|----------|------------|
| AA | What the desktop application looks like | **one window with a sidebar, and requests as queued popups.** The letters A–Z are spent; this is the next one and the sequence carries on with two. The window is the phone's app in a window: Home, Keys, Activity and Documents are its tabs over the same `/api/v1/instance` JSON, the paired machines are entries in the sidebar rather than a list on the home screen — a side has room for them and a tab bar does not — and "This phone" becomes Settings at the bottom. It replaced three windows and no application: one long five-second-repainted pane of tables reached from a tray item, a second window for the doc browser, a third for the passphrase, and **a new window every time an item was clicked**, so a few clicks left a pile of identical windows each polling the daemon and none of them was "the Ladulås window". Requests stay windows and become popups that queue: one on screen at a time, centred, above the others, the next one starting when the one in front closes — because two overlapping always-on-top prompts is a decision made in whatever order the compositor happened to stack them. What is waiting is listed on Home too, which is where a popup closed by accident is answered from. Closing the window does not quit the application: the tray is the application, and `Quit` is on its menu. Both of those froze on GTK 4 until the loop was moved onto the goroutine that started the process — Wails compares every main-thread dispatch against the thread its own `init` locked, so a loop running anywhere else deadlocks the moment one main-thread call makes another, which is what both `App.cleanup` and `App.Quit` do. A live process with a tray icon whose every item does nothing, and no way for any approval to be shown again. Rationale in §12; the failure mode is in ops.md |

Added 2026-08-19:

| # | Decision | Resolution |
|---|----------|------------|
| AB | Whether the packages a mobile core binds are public | **they are, and nothing about them is promised.** A phone is a full Ladulås node — a keystore, an agent, an approval engine, a peer link and the viewer bundle — and not a client of one, so a `gomobile` bind surface reaches very nearly everything that is not the desktop. Seventeen packages are in `pkg/` rather than `internal/` for that reason alone, and not one of them carries a compatibility guarantee; the shell that binds them, and the version pin naming the commit it was built from, belong to the consumer, and this module depends on nothing of theirs. Rejected: building `Mobile.xcframework` here and publishing it as a versioned binary artifact, which would have kept every package `internal/`. It puts a macOS runner in the middle of this repository's release path, and it makes every change a consumer needs wait on a release of this module before anything can be built against it at all. Two things follow. Nothing here compiles the bind surface, so a change that breaks `gomobile`'s type rules is green here and fails where it is bound. And `pkg/` is a published import path, which §18 would rather it were not. Rationale in §21 |
| AC | What a peer's "nobody to ask" counts as | **a report, not a decision: first *decision* wins.** An answer of `NO_APPROVER` from a paired peer goes where an approver that could not be reached goes — the request is denied only once every eligible approver has gone that way, and the prompts that are up stay up. It qualifies §2's "first response wins", which was flat and wrong in one case that turned out to be ordinary: a peer runs this same engine, and one with no approver of its own answers instantly because nothing was asked of anybody, so it won every race against a desktop prompt waiting on a person. An instance paired to a box like that had every signature and every SSH login denied, deterministically, with the peer's name on the refusal — pairing had removed the only way to get an answer instead of adding a second one. Narrow deliberately: only `NO_APPROVER`, only from a peer, and never an approval. A peer's timeout means somebody was asked and did not answer; a policy denial, a hard rule and a human saying no are decisions and settle the request as they always did. Rejected: excluding a peer with no approver from the eligible set up front, which is cheaper but needs the peer to keep advertising a fact that changes when somebody closes a laptop lid, and would still need this rule for the moment in between. Rationale in §9; the report is in `bugs/` |
| AD | Who decides what a pairing is for | **the side displaying the code, once, for both sides.** `ladulas pair --listen --intent approver\|requester\|mutual` — an approver for this instance, an instance to approve for, or both — and the side that uses the code declares nothing: it is shown the sentence on its own confirmation and either agrees to that pairing or does not. Each record is that one answer and its mirror, because a peer that may ask us to approve is a peer we approve for. It replaces two independent declarations, one per side, each defaulting to "both", with nothing making them agree and neither side ever shown what the other had chosen — which is how an instance came to record "may approve for me" about a box with nobody at it and hand decision AC its veto. The intent is required rather than defaulted: guessing here is the thing being fixed. Changing what a pairing is for means removing the peer and pairing again, which is a limit and is meant to be one; `ladulas peers allow` still edits a record for somebody who knows exactly what they are doing. On the wire the joining side's direction fields are reserved rather than reused, and the answer it gets carries the intent it is agreeing to. Rationale in §7 |
| AE | Where the pairing QR comes from | **a Go dependency, drawn by the bridge.** `rsc.io/qr` encodes and this repository renders the matrix to SVG, served on `/api/v1/pairings/qr` the way `pkg/avatar` serves a face — so the viewer bundle keeps its no-dependencies rule, which its own tests assert, and the phone gets the picture for nothing by being the other host of the same handler. It settles open question 6, which had been "the viewer takes its first dependency, or somebody writes an encoder, or `qrencode` stays the documented step" since M3, with the phone able to read a QR nothing here could draw. `qrencode` stays the documented step for a headless box, where the terminal's pixels are not Ladulås's to choose. The one response the bridge serves `no-store`: the string behind the picture is a five-minute single-use secret. Rejected: writing the encoder, which is Reed–Solomon over GF(256) plus four tables to be got exactly right, against a dependency that is 700 lines, unchanged since 2015 and read in an afternoon |
| AF | Where a screen puts what it can start, and what it can take apart | **an icon in the pane's title bar, and a modal sheet behind it.** A screen in this window lists what is true; a form is neither a fact nor a list, and a screen that leads with one is a screen whose first line is not what somebody opened it for — the Keys pane greeted a reader with an empty text box above the keys they had come to look at, and the peer screen kept the pairing's own facts and the button that ends it below everything the peer is *for*. So: a **+** on Keys opens "make a new key", a **cog** on a machine opens the pairing and the way to end it, and both are `dialog` elements shown with `showModal`. Three things come with that and none of them is decoration. Escape closes a sheet and the window behind it is inert while one is up, neither of which this bundle has to implement. A sheet lives outside the pane, so the four-second poll cannot repaint a box somebody is typing into — which is what took the Keys screen out of the redrawn set when the form was on it, and what puts it back now the form is not (decision AA). And a sheet is thrown away when it closes, so reopening one starts again, which is the right answer for a form and would be the wrong one for a screen. The rule it sets: what a screen can *do* goes in the title bar, what a screen *is* stays in the pane, and a text field is never drawn into a screen the poll repaints. Rejected: a disclosure inside the pane, which is the same box on the same screen one click further away; and a route of its own per form, which the shell can carry — a fingerprint is base64 and the router takes everything after the first slash as the identifier, so `peer/<fp>/settings` is a peer named `<fp>/settings`. Extends decision AA; the sheets themselves are `ui.sheet` in the viewer bundle. Rationale in §12 |
| AG | Where a TTL grant lives when several machines hold the key | **it travels with the key, signed by it.** Decision P follows the key and has two branches; a portable key held by several instances (decision S) falls through both — the requester holds no copy so nothing is delegated, and the private half has very much moved so the hardware branch's reasoning does not apply. The promise stayed on the machine that made it and every borrowed signature woke it, which is the cost decision P exists to remove. An **endorsement** is a holder's signed statement that one named requester may borrow one named key within a scope until a time, and any other holder of that key honours it. Two signatures, each closing a hole the other does not: **the key's** (SSHSIG, namespace `endorsement@ladulas`) proves the issuer held the key, so the promise adds no authority — a holder promises only what it could do itself, and an approver holding no copy cannot write a cheque on somebody else's key; **the issuer's identity key's** says which holder, because the receiving side honours one only from a peer it would have taken a live approval from. Possession-only was rejected: a key sold with an old laptop, or shared with a colleague, would make every holder an approver for every other with nobody having decided it. The security argument is then one sentence — an endorsement can produce no outcome that a live conversation with the same approver could not have produced, and what it removes is the round trip rather than the trust decision. Three checks at the point of spending: the requester against the identity the channel authenticated and never against the message, the scope by the same `covers()` a grant uses, and the expiry against **this** instance's own `grant_ttl_options` maximum, which is a ceiling nobody else can raise. **The asymmetry is the design.** The promise travels with the requester, which is the only road that works when the issuer and the acting holder are never awake at once; the retraction never does — the requester is precisely the party with no reason to stop presenting one — so it is pushed and gossiped between holders, honoured from any holder of the key whatever the trust records say, and remembered until its target would have expired. Honouring a retraction nobody wanted costs a prompt; ignoring one that was meant costs a signature. And an endorsement is **published** to every holder this instance knows of as well as carried — not because publishing is what makes it work, but because a promise nobody was told about is one a holder will keep and cannot see, and a promise nobody can see is a promise nobody can retract; the holders that could not be told are named on the grant rather than smoothed over. Extends decision P and qualifies decision V's wording, which now has to say the promise reaches anywhere the key is held. Rationale in §9 |

Added 2026-08-21:

| # | Decision | Resolution |
|---|----------|------------|
| AH | Which addresses the peer channel binds, which it advertises, and who may change them | **one tier, chosen not swept; a name in front of a tailnet address; and a stored setting the control socket writes.** The automatic policy bound every private and tailnet address on the machine and loopback besides, and advertised the same list to every peer that paired. On a desktop with Docker and libvirt that is fourteen listeners, eleven of which nothing can reach, and fourteen addresses in every peer's trust record — of which the one that mattered was somewhere in the middle and the last one was the dialler's own loopback. It now takes the best tier present — tailnet, else other private, else loopback — after skipping interfaces that are up but not running (IFF_UP outlives a container runtime's bridge and IFF_RUNNING does not) and interfaces whose *name* belongs to a runtime or a hypervisor. The name test is a guess about a string and is admitted as one: `br-` with the hyphen is Docker's per-network bridge while a real `br0` is left alone, and every address passed over is reported with the rule that ate it, because a listener missing from where somebody expected it has to be a question with an answer. **Bind and advertise become two lists**, since what a socket was opened on is a fact about this machine and what a peer is told to dial is an instruction to another one: a tailnet address is advertised under its node name first, found by asking the resolver and confirming the answer forward, with the address behind it for a peer whose MagicDNS is off; and loopback is advertised only by an instance that has nothing else. Three related repairs on the dialling side, all from the same evening: an address answering with **our own** identity is an address on this machine and is skipped rather than reported as the peer being an impostor; the failure reported when every address fails is the most informative rather than the last, which was the worst by construction; and an identity mismatch prints a pin against a pin, having printed an SSH fingerprint against a pin, which reads as the two ends disagreeing about how to hash a key. Management is `ladulas listen`, keeping its setting in the store because the control socket is the whole management surface (decision K) and rebinding the channel on the spot, with the previous addresses restored if the new ones cannot be bound; `--peer-listen` still outranks it, deliberately, as the way back into a machine whose stored address no longer exists. Rejected: binding every tier and letting the dialler sort it out, which is what this replaced and what made a peer's stored list mostly unreachable; stripping loopback from the advertisement without the dialler's self check, which leaves every already-paired peer holding one; and reading the node name from tailscaled's LocalAPI, which is a dependency and a socket permission for a string the resolver already has. Qualifies decision H, whose "sensible default to decide" this is. Rationale in §8; the report is in `bugs/` |

Added 2026-08-25:

| # | Decision | Resolution |
|---|----------|------------|
| AI | What `ladulas-sign` does with a command line git did not build | **answers it, rather than passing it to `ssh-keygen`.** Everything not a `-Y sign` request was handed over unchanged, which is the promise §5 makes and is right for the ones git makes — `-Y find-principals` and `-Y verify` on every `git log --show-signature`. It is wrong for the ones a person makes, because `ssh-keygen` with no operation flag does not print usage: it *generates a key*. So `ladulas-sign -h` opened a prompt to write a new private key into `~/.ssh`, and `-help`, which getopt reads as `-h -e -l -p`, opened one to change the passphrase on an existing key — a program whose whole purpose is that no key is used without somebody approving it, offering to write one because somebody asked it what it was. The discriminator is `-Y` itself: every invocation git makes of `gpg.ssh.program` names an operation, verified against git 2.55 by logging the argv of both signing arrangements, the key file and the `key::` literal, through sign, `--show-signature` and `%GK`. Without one, the usage is printed — exit 0 for a help request, exit 1 and a sentence naming what was refused for anything else. Rejected: enumerating `ssh-keygen`'s action-selecting flags and refusing only the key-generating shapes, which is a list to keep in step with another project's getopt and misclassifies every flag OpenSSH adds after this is written; and intercepting `-h` alone, which leaves `-help` and `-v` opening the same prompts. What is given up is using `ladulas-sign` as a general `ssh-keygen` stand-in, which it never was — it is a `gpg.ssh.program`, and the fallback is still every command line git builds. Rationale in §5; the report is in `bugs/` |

Added 2026-09-01:

| # | Decision | Resolution |
|---|----------|------------|
| AJ | How long a signing request waits, and who may change it | **an hour, and one field on the control socket.** It was five minutes, and five minutes is the length that fails whenever the phone is in a pocket: long enough to walk to the kitchen, not long enough to be in a meeting or in another room. The two costs are not symmetric — a budget that is too long costs a terminal somebody has walked away from, and one that is too short costs the commit, because git aborts and the work is repeated and the person answering is punished for having been elsewhere. Nothing counts at the requester's end (`ssh-keygen` and git block happily), so the only clock is this one. SSH authentication keeps its ~90 s and must: sshd is counting, and a budget past `LoginGraceTime` is a login that fails after the person answered it. **Two numbers elsewhere are the same number** and moved with it — a request collected out of an inbox by a phone was capped at fifteen minutes, which never bit against five and would have been the shorter of the two against an hour, taking the prompt off the phone while the requester still waited; and the approval-wait histogram's last bucket was 300 s, so every request that ran the clock out would have piled into `+Inf` together. **The budget is also the one setting a surface may change**, through `Settings` and `SetSignTimeout` on the control socket: the desktop's Settings screen draws it from the instance view with the bounds the instance will accept (at least 30 s, at most a day, refused rather than trimmed), the daemon re-reads the document before writing so a hand edit waiting for a reload is adopted rather than reverted, and requests already waiting keep the budget they started under, because a clock that jumps under somebody reading a diff is not a clock. Rejected: a policy editor on the socket, which is what "let the screen change the policy" would grow into — the document decides what is approved *without asking*, so a screen that could write rules is an auto-approve rule one mis-click from every process running as this user, where a number deciding how long somebody has to answer cannot approve anything by itself. Also rejected: bounding the document. A hand-edited `policy.json` stays unbounded, because somebody editing the file has said what they mean. Rationale in §9 |
| AK | Whether a terminal can be a front end | **it is the third shell on the seam decision Z left.** `ladulas tui` attaches to a running daemon as an approver, draws the same `RequestView` the window draws, and answers through the same `POST /api/v1/requests/{id}/answer` — so the bound on a promise, the audit entry naming what was on screen, and the refusal of a request settled elsewhere all stay in one place. Nothing in `internal/tui` parses a commit or knows what a scope is; a second surface answering signing requests is a second chance to disagree about what a commit says, and having nothing there that could disagree is the only way not to take it. **It is not the console approver**, and the distinction is the one `pkg/approval` already wrote down: `ConsoleHandler` is inside the daemon on the daemon's stdin and offers a yes, a no and four fixed lengths, because a line-oriented prompt asked to express a reach and a clock is asking somebody to spell out in the dark the thing the wording exists to make plain. This is a screen with a picker on it, so it offers the whole of decision V, decision X's trust note, and the diff a file at a time. Both may be attached at once, as `console` and `terminal`. Three things a terminal decides for itself: the answer keys are drawn at the bottom whatever is scrolled where (the window's pinned-footer rule, for its reason — an answer underneath the diff means scrolling past the whole change before you can refuse it); the diff opens on `enter` with a focus ring the arrow keys walk, there being no pointer; and the palette is the sixteen ANSI colours, so red and green are whatever the terminal's owner decided, with every coloured line saying in words what the colour says. The log goes to stderr only when stderr is not the screen. The verb is `tui` rather than `approve` because answering is the first thing it does rather than the only thing it will do — the window it is modelled on grew a status pane, a key list and an activity log around this same seam. It also unlocks the store, because a terminal is often the only surface in front of somebody and a sealed instance is the state where an empty screen is most misleading. **It shipped unable to see a request raised before it started**, which decision AL then fixed. Rationale in §12 |

| AL | Whether an approver that arrives late may answer a request already waiting | **it may, and the set is no longer fixed when the request goes out.** The engine settled the eligible approvers as it fanned a request out and never looked again, so a front end that attached a second later was one it would not ask: a signature blocking a terminal could only be answered by something that happened to be running already, and `ssh` in, start the terminal approver, and the screen was empty while `git commit` hung. **That was never a rule about authority.** The question has been asked of this machine, a front end is authorised by the socket it is on (§14, "possession of the unix account is the authority"), and a late arrival can answer nothing an earlier one could not — the deadline stays the request's, the answer is signed and logged the same way, and the card is drawn from the same digest-covered bytes. It was where the fan-out kept its count. So an approver that registers is offered everything still waiting, and so is a local prompt the moment a soft lock is lifted from one, which is the same event: a set of approvers becoming eligible. **The count is the part this decision is careful about.** `prompt` denies with `NO_APPROVER` once every approver it asked has gone, and decision AC is the bug that lived in exactly that arithmetic — a peer with nobody to ask reported instantly, won every race, and vetoed every signature on the machine. The denominator therefore moves under a lock rather than being a `len()` in the loop, is re-read on each pass, and grows only through the one function that also refuses three things: a request that has been settled, a request whose context has finished, and an approver already asked. The eligibility test itself is shared with the fan-out's rather than copied, so a request from a peer cannot reach another peer through this door and a soft lock cannot be walked around by attaching. Results are sent with a `select` on the request's context, because a joiner may find a channel sized for the approvers asked up front already full and a blocking send would leak the goroutine for the life of the process. What surfaces get for free: a request joined this way carries its own `created_at`, so a card says how long the thing has really been waiting instead of how long this screen has been looking at it. Rejected: parking local requests the way the peer inbox parks them for a phone (§8), which is a second mechanism for the same idea and would have the front end poll for what the engine can hand it. Qualifies decision Z's "restarting the front end does not re-raise it", which is withdrawn. Rationale in §9 |

| AM | What an answer on the control socket names | **the prompt, not the request.** Two front ends attached at once are two approvers and both are asked (decision Z), so one request id names two cards on two screens. `AnswerApproval` carried only the id, so the daemon delivered the answer to every prompt waiting under it: both approvers' `Decide` returned with it, neither reached the branch that sends `WITHDRAWN`, and the desktop's popup went on asking after the terminal had answered and the commit had been signed. **The withdrawal machinery was never broken** — the engine cancels the losers on the first decision and a cancelled approver takes its own card down — it just never ran, because nobody lost. So the daemon mints a token per card, sends it on the `ApprovalPrompt`, and the front end echoes it back; the answer settles that one prompt and the rest are cancelled and withdrawn as they always were. Rejected: matching on the approver id, which two terminals share by default and which would have made the fix work on a desktop-plus-terminal pair and not on two terminals; and broadcasting `WITHDRAWN` to every prompt after an answer, which fixes the symptom by sending the answering front end a withdrawal it is expected to ignore because its card happens to be gone already — correct only by an accident of ordering. A front end that sends no token is answered the old way, which is right when it is the only one attached and cannot be got right when it is not, so it says so in the log. Not found by a test for a year because one attached front end is the case every test had; the reproduction attaches two that share a name. Rationale in §9 |

**Decision L in full.** It sharpens K rather than contradicting it: K
said the socket is the complete management surface, and L says it is the
only one. §14 used to say "daemon first, store fallback":
the CLI preferred the socket and opened `store.age` itself when nothing
was listening. That is withdrawn. The store is opened by exactly one
process — the one serving the instance's sockets — and every other path
to it is gone, including the one `ladulas init` used to have.

What the fallback cost, and why it is not a close call:

* `Vault.save` rewrites the whole document with no lock, so a second
  opener could silently discard the daemon's changes. There was never a
  guard, and one owner means there never needs to be one.
* It normalised the dangerous path. The `keys` verbs were written with
  only the direct-store path and no socket path at all, which meant they
  did not work at all on the box they were most needed on; `grants list`
  and `grants revoke` had the same defect until this change. Both were
  found by using the thing, not by reading it.
* It bought nothing. §14's authority model already makes the uid check
  the whole gate, so the socket is not the weaker path — it is the same
  authority, held by the process that already has the key.

The recovery story is `ladulasd run` in the foreground, and an age file
plus a passphrase if it comes to that. An explicit `--offline` flag can
be added if a real need appears; taking one away later is much harder
than adding one.

**Decision M in full.** The two halves of a pairing were treated as one
thing with one clock, and the clock belonged to the half that needed it
least. The code's five minutes pay for walking between two machines and
for keeping a fifty-bit secret out of reach of online guessing; the
confirmation asks a person whether two hashes match, which no amount of
time makes easier to fake. Sharing a deadline between them meant that
running out of time was a way for a pairing to fail, and running M6 on a
phone found what that costs: an approval in one machine's audit log, a
card taken off the other's screen, and no record anywhere of either.

What follows from splitting them:

* **The pending pairing is persisted, in the store.** Session id, the
  peer's identity key and fingerprint, its addresses, the roles this side
  would grant, which side dialled, and each side's answer so far. In the
  store rather than beside it because it is the same map the trust records
  are — and therefore invisible while sealed, which is a stated cost.
* **Completion is a reconciliation, not a report.** `SettlePairing` is
  idempotent and callable from either end as often as it likes, which is
  what makes a phone — the side that can never be dialled — able to finish
  a pairing it started before falling asleep. A completed pairing keeps
  its session id on the trust record so it can still answer for it.
* **Withdrawal is manual and propagates by asking.** No tombstone: a
  phone could not be handed one, and the ask-on-reconnect path has to
  exist regardless. The cost is a less precise reason when the peer was
  unreachable at the moment of the decision.
* **The pending set is bounded** at one per identity and sixteen in
  total — clutter control, not a boundary, since every entry is listed and
  dismissible.
* **A timeout is never an outcome.** The confirmation prompt has no
  budget in the policy at all (§9), and an engine that found nobody to ask
  leaves the pairing untouched and is asked again when an approver
  appears.

**Decision N in full.** M4 gave a requester one way to know a holder's
keys: ask. The answer lived in the link and nowhere else, so a holder that
could not be reached had no keys as far as every surface was concerned.
For two desktops that is defensible — unreachable is a fault, and it is
brief. For a phone it is not: a phone advertises no address and dials only
while its app is in the foreground, so "unreachable" is what it is nearly
all of the time. Dogfooding found the consequence in the plainest possible
form — a desktop paired with a phone holding a key, and `ladulas keys
list` reporting one local key and no trace of the phone's at all.

Two things had to be decided deliberately rather than fallen into.

**Whether the SSH agent socket advertises a cached key whose holder is
unreachable: no.** The argument for is symmetry — the complaint is
"a key silently missing", and the agent is one of the places it goes
missing. The argument against is what ssh does with an identity list: it
tries each identity in turn, each attempt counts against the server's
`MaxAuthTries`, and a key that cannot sign converts a clean failure into a
wasted attempt and, with a few such keys, into a login that fails with
"Too many authentication failures" — an error about ssh, when the truth is
that a phone's screen is off. The agent protocol has no field for "present
but unavailable", so it cannot tell the truth here even in principle;
`ladulas keys list` and the viewer can, and do, with the holder's name and
a last-seen. And the case that made the complaint concrete is not the
identity list at all: a git signature resolves a named key by blob, does
not consult the list, and is answered — see below. So the agent keeps
advertising what can sign, and being able to see what exists is served
where it can be served properly.

**What a signing or authentication attempt against an unreachable holder
does: it fails at once, naming the holder.** No new machinery was needed.
The requester already knows the state of the link, so the failure is
produced from what it knows rather than by dialling and waiting — measured
in milliseconds, against a default signing budget of an hour (§9).
Nothing here retries: the link reconnects on the backoff it already has
(§8), and the next attempt finds a holder that is there. Two things the
error must not be, and is not: a denial — nobody was asked, nothing was
refused, and somebody who reads "denied" goes and looks at their policy
instead of unlocking a laptop — and a reason to fall back to `ssh-keygen`,
since the private half is in another machine's store or another machine's
Secure Enclave and handing over can only bury the sentence worth reading.

What it costs: a store rewrite when what a holder offers changes, and one
more thing that can be stale. The staleness is bounded by saying so on
every surface, and the rewrites by not making one for a heartbeat that
learned the same answer again.

**What decision T changes about this, and what it leaves alone.** Both
answers above stand as written; what T revises is the word
"unreachable". N was written with a link in mind, so a holder was
reachable when a connection to it was up — and by that test a phone never
was, which made "the agent advertises what can sign" and "the phone's
keys are never advertised" the same sentence. A phone that is polling or
has announced a wake-up route can be reached, in the only sense that
matters here: the request gets to it and a signature comes back. So its
keys are advertised, and a holder that genuinely cannot be told anything
is still left out — which is the same rule, applied to what reaching a
phone actually consists of. The failure for one that cannot be reached is
unchanged, and now names a phone that cannot be woken as readily as a
laptop that is asleep.

**Decision T in full.** Two things had to be settled to make a key in a
pocket usable by ssh, and only one of them is about reachability.

**Who decides which keys an agent offers: whoever holds them, per key.**
The alternative was for the requester to decide, since it is the machine
whose agent socket does the advertising — and it is the wrong side. The
person with an opinion about whether a key should be thrown at every
server they log into is the person whose key it is, sitting at the device
that holds it; the requester is frequently a headless box with nobody at
it at all. So the setting is stored with the key, is projected onto the
public half like the label and the comment, and is respected by every
agent that borrows it. Making it advertising rather than permission is
what keeps it cheap: nothing about it can deny a signature, a stale copy
cannot break one, and the existing per-peer key permission (§7) remains
the thing that decides whether a key may be used at all. `disabled`
stays what it was — a key switched off entirely — and the two are
deliberately separate, because "do not offer this to ssh" and "do not
sign with this" are different sentences and the first one is the one
somebody with five keys actually wants.

**How the request gets to a phone: the inbox, again.** The dialled path
could not be reused, and nothing else had to be invented — the shape was
already there twice, for a parked approval (§3) and for a queued key
handover (decision S). A borrowed signature is a parked request with the
payload beside it and a signature on the answer, decided by the holder's
own engine through the same reconstruction of the payload the dialled
`RemoteSign` does. What is genuinely new is only the clock: an approval
can wait fifteen minutes for somebody to pick up their phone, and an ssh
login cannot wait more than about two, so this is the first thing in the
design where the wake-up is required rather than an optimization — and
the honest consequence is that a phone with notifications switched off
lends keys for signing and does not appear in the agent's identity list.

**Decision O in full.** §12 said the rich request UI is one HTML bundle
on every platform, and for a tray window that is right. On a phone it was
not. The first non-placeholder build put the whole shell in a
`WKWebView` — status pane, peer list, approval card — and what that
produced was a desktop tray window rendered at 390 points wide: no tab
bar, no swipe back, no pull to refresh, a list where a row is not a row,
and a card whose buttons a thumb reaches by scrolling. None of that is
fixable by writing more CSS, because none of it is about pixels. It is
about a phone having a navigation model, and the bundle having a
different one.

**So on iOS the shell draws, and the webview keeps the documents.** The
tabs, the home screen, the peer rows, the banners and the approval card
are SwiftUI. The diff behind a commit and the markdown a paired machine
published stay in the bundle, unchanged, opened as pages of it.

The line is not "native is nicer". It is what each side is good at:

* **A document is a document.** The diff is long, deeply structured and
  the most attacker-influenced content in the prompt; the markdown is
  the same shape of problem (§6). Both were already parsed in Go and are
  drawn by a renderer with a strict CSP, no network and no `innerHTML`
  in it. Rewriting either natively would be rewriting the one part that
  was genuinely expensive, to get a result no better.
* **Chrome is not.** Navigation, biometrics, gestures, a tab bar and a
  list belong to the platform, and every one of them was already native
  on the desktop too — the tray, the menus, the windows. The phone's
  equivalents were simply missing.
* **The seam does not move.** Everything the shell draws it reads from
  `/api/v1/*` through the same `Call` boundary the webview uses, and the
  answer goes back the same way. There is still one place that decides
  what a request means, one place that verifies it, and one place that
  words it.

What it costs, stated plainly: **the request card now exists twice.** A
new field on `RequestView` has to be drawn in `viewer/assets/cards.js`
and in `RequestCards.swift`, and a kind added to the engine has to be
added to both. That is a real, recurring tax and it was accepted with
open eyes — the alternative was one card that is wrong on the surface
where it is answered most often. The mitigation is that the two draw the
same JSON: neither can quietly disagree about what a request *is*, only
about how much of it is shown, and the fields with no drawing are
invisible rather than wrong.

Two consequences worth writing down. The shell's deployment target is
now iOS 26, because Liquid Glass is iOS 26 API and a second design for
older systems would be a second design nobody looks at — the phone is on
26 and an upload built against an older SDK is rejected anyway. And the
unlock screen, which §12 already argued should be native, stops being
the exception and becomes an ordinary case of the rule.

**Decision R in full — the doc browser goes the same way the card did.**
Decision O left the whole of §6's browser in the bundle, and it had the
same three problems the approval card had, for the same reason: a
directory listing is a list, a project is a place you navigate into and
back out of, and a search field belongs where a thumb is. What the
webview held that was worth holding was one markdown document. So the
bundle keeps exactly that — a document-only mode, the note saying which
reading of the project it is, and the outline and in-document search that
belong to the text — and the shell draws the rest.

Two things fall out of that, and neither is cosmetic:

* **A phone is shown what it can open.** The publisher lists more than it
  will hand over on purpose, and a viewer that renders markdown says so
  per entry rather than pretending the rest of the repository is not
  there. That is right for a window with room for a greyed-out row and a
  reason beside it, and wrong for a phone, where the same honesty is
  forty taps that do nothing. So a caller says which it is —
  `only=readable` on a directory or a search — and the core drops what
  cannot be shown *and reads on*, because paging is the publisher's and
  filtering can otherwise turn a full page into an empty one with a token
  still in it. The desktop does not ask, and is unchanged.
* **The technical details are behind an (i).** A repository's path,
  remote, branch and commit are what makes documentation worth reading
  beside a signing request, and they are also four lines between a reader
  and a README. They go in one sheet, reachable from the browser and from
  every page, ending with the sentence §6 requires be findable: none of
  this is evidence.

A link inside a document is handed back to the shell rather than followed
in place, which is what keeps one gesture doing one thing. Following it
in the webview meant two competing back gestures on the same screen and a
navigation title describing a file nobody was reading any more; handed
back, each document is a screen, and the swipe means what it means
everywhere else in the app.

**The picture beside a fingerprint.** A peer row draws an avatar
generated from the peer's identity fingerprint — a DiceBear Loops
pattern with a Lorelei character in front of it, composed in
`pkg/avatar` and served by the bridge, so every host draws the same
face for the same key. It exists because a fingerprint is the thing a
person is asked to compare and forty-four base64 characters are exactly
what a person does not compare: two instances with different keys look
nothing alike, and a row whose face is suddenly a stranger is worth a
second look at the characters underneath it.

**It is decoration, not security, and that has to stay written down.**
Nothing about it is checked or signed, and two fingerprints that draw
the same face are a collision in a hash a few bytes wide rather than a
collision in an identity key. It is a prompt to look, not a substitute
for looking, and the pairing card shows both fingerprints in full (§7) —
which is where the comparison a person is actually asked to make
happens, and it has not moved.

**Where the characters are, since 2026-08-14.** They used to be on the
peer card as well, shortened to sixteen characters under the name, on
both the home screen and the peer's own screen. That is gone. The reason
it went is that a truncated fingerprint is not a thing anybody compares
— it was two more lines of monospace teaching people to skim the one
surface where the characters matter, and it made the peer card tall
enough that the description of what the pairing allows had to be cut off
mid-clause to fit beside it. So the card is now the face, the name, what
the pairing allows in up to two lines, and the state; and the
fingerprint is whole, full-width and un-ellipsised one tap away in the
pairing settings, beside the addresses. **Do not put a shortened
fingerprint back on a row.** If a surface needs the characters it needs
all of them, and a surface that cannot give them the width should send
somebody to one that can.

The peer card is also one view, `PeerCard` in the phone's shell, drawn by
the home screen and by the
heading of the peer's own screen. Two near-identical cards that differed
in type size, in what they showed and in where the state pill sat read
as two different things about one machine; opening a peer should be a
card growing a list under it.

**Decision P in full.** Dogfooding M6 produced the complaint that settles
this: approve for an hour, and the next commit still waits for the phone
to be picked up. A grant that only applies while its approver is awake is
not a grant, it is a shorter prompt.

The 2026-08-08 resolution put grants on the approver, and gave a reason:
"a compromised requester cannot self-extend a grant". That reason does
not survive being looked at in the case that matters.

**When the key is the requester's own, the approval engine is already an
honour system about that machine.** The daemon holds the key. Nothing
cryptographic stops it signing whatever it likes; what the engine does is
gate the *programs* that come to the agent socket — git, ssh, anything
else running as that uid — none of which ever hold the key. So handing
that daemon a delegated grant gives it nothing it did not have:

* **Self-extension** is not the risk. A delegated grant is signed by the
  approver over a fixed scope and a fixed expiry; a requester cannot mint
  or widen one. What it can do is sign within the scope it was given —
  which is what the grant said.
* **Scope still binds the programs.** The delegation is held by the
  daemon, which goes on applying the scope to what its clients ask for,
  exactly as it applied the grant before.
* **Revocation** and **audit** are only weakened against a compromised
  daemon — and a daemon that would ignore a revocation is a daemon that
  would sign without a grant at all, and one that would drop a usage
  report is one whose account of itself was never evidence. Against an
  honest daemon both still work, and revocation works *better*: the party
  that must be reached is the always-on machine rather than the phone.

**When the key is in an approver's Secure Enclave, none of that applies
and nothing changes.** The private half cannot leave, so the holder
produces every signature itself; there is nothing to delegate. Worse, on
iOS a signing key is created with `.biometryCurrentSet`, so the platform
demands presence *per signature* whatever the engine decided. A grant
over a borrowed key can therefore only ever remove the reading, not the
tapping — and a background wake-up cannot raise that prompt at all. That
is a property of the hardware, and it is the reason the two cases get
different answers rather than one compromise.

The artifact: the existing `GrantScope`, an expiry, **both**
fingerprints — so a delegation issued to one machine cannot be replayed
at another — an id for revocation, and the approver's signature over the
whole thing under **its own domain separator**. Not
`ladulas-approval-v1\0`: a standing permission and an approval of one
specific request must never be confusable as bytes.

**Use is reported back.** The honest loss in delegating is that an honest
requester's grant-covered signing stops appearing on the approver at all,
and that is worth fixing rather than accepting: the requester keeps what
it self-approved and hands the list over the next time the two are
connected. The approver's log records those as **an account received,
not a decision made** — the distinction §18 already draws between a
requester's own narrative and the signed artifacts that are evidence.

How it is shown follows from that. A reported use is not an event in its
own right; it is something the grant did. So the activity list does not
gain a row per signature — the **grant** carries a count, and its detail
view lists what it covered. A grant used two hundred times is one line
that says two hundred, which is the number worth reading, and the two
hundred lines are there for whoever wants them.

**Decision Q in full.** Decision F chose a snapshot push with live
refresh, and the snapshot was the wrong half. Publishing was an *action*
that shipped a project's whole doc set to every approver, which is a lot
of bytes to move on the strength of a guess that somebody will read them
— and the guess gets worse the moment the set is not only markdown, which
it will not be.

**So publishing becomes a state, and browsing becomes a pull.** A project
is marked published on the requester and nothing leaves; an approver that
wants to read one asks for it. The RPCs that exist for the "live" half of
F3 stay, and grow the shape a real browser needs:

* **list** the projects a requester publishes;
* **list a directory**, a page at a time, with a name filter — never the
  whole tree, because a tree is unbounded and most of it is never looked
  at;
* **search by filename** across a project, also paged, because "where is
  the deployment runbook" is the actual question and walking a tree by
  hand to answer it is not browsing;
* **fetch one file**.

**And the approver keeps what it has opened.** The store that held pushed
snapshots is already content-addressed and sealed with the instance's own
key (§10), which is exactly what a cache wants: a page that has been read
stays readable on a phone with no signal, a page that has changed is
visibly a different digest, and nothing is ever stored because somebody
*might* read it.

The exchange, stated rather than glossed: **a project nobody has opened
is not readable offline.** F3 bought that with a push, and a push is what
this is getting rid of. A phone is offline by construction, so this is a
real loss — it is accepted because the alternative is every phone holding
every doc set of every machine it approves for, against the chance that
one page gets read on a bus.

What does not change: the staleness labelling of §6, which was always
computed from digests rather than from having a copy; and every safety
rail, which matters more here rather than less. Paths are canonicalized
against the project root on the serving side, so browsing cannot be
turned into reading arbitrary files from the requester. Names, page
sizes and file sizes are all capped — a directory listing is
attacker-influenced content too, and an approver that asked for one page
should not be handed a hundred thousand names. And everything served is
still requester-asserted context rather than evidence, rendered as
untrusted display content and labelled as such.

**Publishing gets a default worth having**: an instance may be set to
publish, automatically, any project it sends an approval request for. It
is the case that matters — the moment an approver most wants a project's
documentation is while it is being asked to sign something in it — and
having to remember to publish first is how nobody ever has it. It is a
setting rather than the only behaviour, because a machine that signs in
repositories it would rather not name should be able to say so.

The two places an approver reaches a project follow from that: from a
**peer**, which is "what does that machine work on", and from the
**approval card**, which is "what is this change part of".

Open questions resolved 2026-08-08:

* **TTL grants live approver-side.** The grant is the approver's promise:
  requests still flow to the approver and are auto-answered there with a
  passive notification; a compromised requester cannot self-extend a
  grant. Cost accepted: grants don't apply while the approver is
  unreachable. **Superseded in part by decision P**, which is that
  accepted cost coming due: it holds for a key the approver's hardware
  holds, and not for one the requester holds itself.
* **The encrypted store uses age** (`filippo.io/age` as a library), with
  scrypt passphrase recipients — a store backup is recoverable with
  standalone age/rage tooling and the passphrase.
* **Audit log is append-only JSONL** with identity-key-signed approval
  responses stored on both ends; hash-chaining the log itself is deferred.
* **mDNS/Bonjour discovery lands with the mobile milestone** (Bonjour is
  native on iOS); until then pairing types `host:port`, and the pairing QR
  carries the address anyway.

Still open, to resolve during early implementation:

1. Exact protobuf schema for requests/approvals, and the signed-response
   format (approval-as-artifact).
2. ~~Wake-up registration: how requesters learn which wake-up endpoint (relay
   instance ID, UnifiedPush URL) maps to which paired approver (likely
   exchanged at pairing, updated over the channel)~~ — settled by M9:
   **announced by the approver over the channel, and never exchanged at
   pairing.** The guess had two halves and only the second survives contact
   with a device token.

   A token does not exist at pairing time and does not stay the same
   afterwards. iOS issues one asynchronously, after the user has been asked
   about notifications — which on a phone paired the minute the app was
   installed is minutes later — and reissues it on a restore, a reinstall
   and sometimes an OS upgrade. So a field on `PairRequest` would be empty
   in the ordinary case, would need the announcement anyway, and would make
   a pairing something a wake-up can break, which this section forbids in as
   many words. One mechanism, and it is the update one.

   The approver drives it, for the reason it drives `ReconcileGrants`
   (decision P): it is the side that can always dial. `AnnounceWakeup` is
   idempotent, is authorized by the same half of a pairing as
   `FetchPending` — the caller is a peer this instance agreed may approve
   for it — and carries a route or nothing at all. Nothing at all is a
   withdrawal, which is what switching wake-ups off and having notification
   permission revoked both look like from the requester's side. The
   requester writes the route into the store beside the trust records,
   because the announcing side is asleep most of the time and a route kept
   in memory would be forgotten at every restart and not relearned until
   the phone was next picked up — precisely the moment it was there to
   save.

   **A rotated token is handled from both ends, and needs both.** The phone
   announces a new route the next time it has one, which covers the case
   where somebody is holding the phone. The relay answers
   `WAKE_OUTCOME_UNREGISTERED` when the platform says a token is dead, and
   the requester drops the route on that answer — which covers the case
   where the phone is in a drawer and the requester would otherwise knock
   at a door that has moved for as long as the pairing lasts. Revoking a
   pairing drops the route too, beside the borrowed keys and the
   delegations: a capability that wakes somebody's phone has no business
   outliving the trust it arrived under.

   The announcement carries one thing beyond the route: **until when this
   approver would answer that requester without asking anybody**, computed
   from its own live, undelegated grants. It is what the silent-push
   carve-out is decided from (§20, M9), and it is a hint in the strict
   sense — a requester that ignores it sends the alert it would always have
   sent. UnifiedPush, when it is built, is another `WakeupKind` on the same
   message and needs none of this to change.
3. Keyring library choice (`99designs/keyring` vs `zalando/go-keyring`).
4. ~~iOS first: verify Secure Enclave P-256 + biometry-gated signing
   through the gomobile boundary~~ — settled by M6. The boundary is four
   calls over strings and byte slices, the Go side holds a `crypto.Signer`
   that asks the platform for each signature, and `x/crypto/ssh` re-encodes
   the DER the platform returns. Nothing about a hardware identity reaches
   the transport or the approval engine: they see an identity like any
   other, which answers more slowly.
5. ~~Viewer bridge API shape~~ — settled by M2 and confirmed by M6 on a
   third host: one `http.Handler`, and each host differs only in how a
   method, a path and a body reach it.
6. ~~**Drawing a pairing QR on the requester.** The code a QR carries is
   specified and the phone reads one; what is missing is something that
   renders one. Either the viewer takes its first dependency, or a QR
   encoder is written, or `qrencode` stays the documented step (§12).~~ —
   settled by **decision AE**: the dependency is Go's rather than the
   bundle's. `rsc.io/qr` encodes, this repository renders the matrix to
   SVG, and the bridge serves it on a route beside the avatar's. `qrencode`
   remains what a headless box prints, which was never the part that was
   missing.

## 20. Milestones

1. **M1 — local agent, Linux**: core library skeleton; `ExtendedAgent`
   with request parsing + session-bind; encrypted store; local approval
   via a minimal Wails tray app; policies + audit log. *Replaces 1Password
   on one machine.*
2. **M2 — `ladulas-sign` + shared viewer**: rich git prompts locally; the
   viewer bundle (cards, commit/diff) in the Wails webview.
3. **M3 — desktop↔desktop**: identity, pairing, pinned-TLS transport,
   remote approval, first-response-wins fan-out. *Headless box approved
   from the desktop.*
4. **M4 — remote signing + project publishing**: keyless requester using
   desktop-held keys; `PublishProject`/doc browsing in the viewer; the
   projects verbs on the control surface (§14).
5. **M5 — lock states + unlock surfaces**: passphrase-primary cold start
   with a GUI unlock dialog; sealed/locked/unlocked states in the engine;
   suspend/session-lock triggers via logind; seal-on-sleep option;
   `systemd-ask-password` headless unlock; `ladulas lock`/`unlock`.
   *Full daily-driver security posture on desktop and headless.*
6. **M6 — iOS**: gomobile core, SwiftUI shell, viewer in WKWebView,
   Secure Enclave P-256 keys, pairing via QR; biometric app unlock with
   passphrase fallback; poll-on-open approvals (open-app-to-approve until
   push exists). The TestFlight pipeline is already in place from the M0
   groundwork.

   What it turned out to be: an inbox on the requester, because a phone
   never listens and a request has to wait somewhere until it comes (§3,
   §8); a store whose private halves are handles into the Secure Enclave
   rather than key material (§10); app unlock spelled with the wrappings
   the store already had, differing from the desktop only in the access
   control on the keychain item (§10); and a binding surface small enough
   that everything interesting stayed in Go and could be tested on a
   machine with no Apple hardware anywhere near it (§12).
7. **M7 — delegated grants** (decision P) — **built**: the signed
   `Delegation` under `ladulas-delegation-v1\0`, the requester-side engine
   path that applies one before asking anybody, `ladulas grants` showing
   where each promise lives and how much has been done under it, and the
   grouped presentation — a count on the grant, the individual uses in its
   detail view, on both surfaces.

   What it turned out to be: one question at the moment a TTL is agreed —
   whose key is this — answered with `HoldsKey`, and two shapes of the
   same promise sharing an identifier. Reconciliation is a single RPC on
   the requester's `InboxService`, driven by the approver in both
   directions at once, because the approver is the side that can always
   dial. Nothing about it is load-bearing: a delegation that cannot be
   reconciled goes on being honoured until it expires, which is what
   handing it over was for.

   It comes before push deliberately. "Approve for an hour" not working
   with the phone in a pocket is what dogfooding actually complained
   about, and this fixes it for requester-held keys **without any
   wake-up at all**. Push is a different problem — being told a request
   exists — and solves this one only while the app is resident.
8. **M8 — project browsing** (decision Q) — **built**: publishing as
   state, the paginated directory listing, filename search, fetch-and-keep
   on the approver, auto-publish for the project a request belongs to, and
   the two ways in — from a peer, and from the card asking for a
   signature.

   What it turned out to be: a cache with one rule — a page is here
   because somebody opened it, never because somebody might — and
   everything else following from that rule. The store that held pushed
   snapshots kept its shape and lost its meaning: content-addressed and
   sealed exactly as before, but what it holds is a record of reading,
   with the commit each page was read at, because that is what §6's
   staleness label now compares against. Confinement on the serving side
   is `os.Root` rather than a check, which is the one place in the
   codebase where the filesystem on the other side belongs to the machine
   the design distrusts most.

   The surprise was that every browsing surface has two states rather than
   one, and that the second is not an error. What the publisher says now,
   and what was true when somebody last read it: an unreachable machine
   gets a directory listing made of the pages that have a reader, marked
   as exactly that rather than as the directory. A phone is offline by
   construction, so a browser that answered "could not connect" would be
   useless precisely when it is wanted.

   Naming a project turned out to be the load-bearing detail. Once a
   project is named by the peer that publishes it and the identifier both
   ends derive — rather than by a key an approver invented when something
   arrived — the approval card can link to a project nothing has been read
   of, which is the ordinary case and the thing this milestone was for.
   The name goes in the query string rather than the path, because a
   fingerprint is base64 and every host would otherwise have to remember
   to escape one.

   `projects refresh` did not survive, and the verb that replaced it is
   `projects auto`: the setting rather than the action, which is what the
   whole of decision Q turns out to be.
9. **M9 — wake-ups** (decision G) — **built**: the publisher-hosted relay
   (APNs first, FCM when Android lands), `AnnounceWakeup` over the peer
   channel, and notification actions where the platform allows.

   For iOS specifically, a silent `content-available` push is worth having
   for grant-covered requests even though §11 rules it out for prompting a
   human: nothing is being asked, so a throttled wake that misses degrades
   to the alert push that would have been sent anyway. It works only while
   the app is resident — a terminated app cannot reach its data encryption
   key without a biometric prompt, and a background wake cannot raise one.

   What it turned out to be: one sentence, sent to a service that is told
   nothing else, at the one moment it is worth sending. The relay holds an
   opaque identifier and a device token and never learns a request, a
   fingerprint or a peer; the notification says the same words whoever
   asked and whatever they asked for — one of two sets of them since
   decision S, chosen by a subject the caller sends and this repository
   enumerates; and the payload is asserted whole in
   a test, because a test that looked for particular leaks would pass the
   day somebody added a field nobody thought to look for.

   §19's second open question answered itself once a device token was a
   real thing rather than a field: it does not exist at pairing time and
   does not stay the same afterwards, so there is one mechanism and it is
   the announcement (§19). Rotation needs both ends — the phone announces
   a new route when somebody is holding it, and the relay's
   "nothing is registered here" is what rescues a requester knocking at a
   phone in a drawer.

   The carve-out came out narrower than it was written. It is not "silent
   for grants" but "silent first, then loud", decided from a timestamp the
   approver announces and re-checked against whether the request is still
   parked twelve seconds later — so the quiet wake is an optimization on
   the loud one rather than a substitute for it, and a phone whose grant
   was revoked a second ago is woken quietly once and then asked properly.
   The iOS notification lost its Approve and Deny in the process, and the
   reason is the same one that makes a background wake useless on a
   terminated app: both buttons end at a Face ID sheet, and a Deny that
   ends at a sheet is a Deny people learn to tap without reading (§11).

   Everything here is layered on M6 and nothing is load-bearing, which is
   the test the milestone is actually judged by: with the relay pointed at
   a closed port, a request is still parked, poll-on-open still finds it,
   an approval still happens, and a fresh pairing still completes.
10. **M10 — Android** (intent, not started): Kotlin shell, Keystore P-256
    keys, the opt-in foreground-service live connection; Windows/macOS
    desktop parity. It is the one milestone in this list that has had no
    code written for it, and the numbering is deliberate rather than
    chronological — M11 and M12 landed first because dogfooding asked for
    them.
11. **M11 — portable keys** (decision S) — **built**: generating and
    importing a store-resident key on the phone, the LocalAuthentication
    gate in front of every signature made with one, and handing one to a
    paired peer — passphrase on the way out, an explicit acceptance on the
    way in, and the transfer written into both audit logs. The desktop half
    is a receiver and a `keys send`, because the store code is already the
    same code (§10). The receiver had no window until 2026-08-19: the
    control calls were there from the start and the CLI used them, and the
    desktop application listed neither what had arrived nor a way to answer
    it, so a key sent to a laptop looked from the sending side like a key
    sent into nothing.

    What it turned out to be: almost nothing in the store. `Vault` already
    decided per key rather than per instance, so a portable key on a phone
    is a key with no handle and every path it touches — listing, signing,
    lending over `RemoteSign`, removing — was code the desktop had been
    running since M1. What had to be built was the two ends and the road
    between them.

    The road is the surprise. A send is a queue entry first and always,
    because half the peers here cannot be dialled: a desktop is pushed at
    with `OfferKey`, and a phone is woken and comes to collect with
    `CollectKeyOffers` — the shape a parked approval already had. The
    acknowledgement rides on the next collection rather than having a call
    of its own, which makes a lost answer cost a redelivery instead of a
    key, and left exactly one case that had to be handled by hand: an offer
    accepted before its acknowledgement got out would otherwise be
    redelivered for ever, so a key the receiver already holds is
    acknowledged rather than refused.

    Two things came out honest rather than clean. The relay's alert body
    was one fixed sentence, so a phone woken about a key would have been
    told a signature was pending — the wake-up carries a subject now, and
    §11's claim about what a relay learns is one bit weaker for it. And the
    per-signature prompt on a portable key is LocalAuthentication, which is
    the app's promise rather than the enclave's; it is written down as that
    in §10 rather than presented as the same gate under a different name.
12. **M12 — the phone's keys in the agent** (decision T) — **built**: a key
    held on the phone appears in the desktop's agent socket and answers an
    ssh login, which is the half of "keyless requester" that M4 built for
    two desktops and no phone. The pieces are the announcement that replaces
    dialling a holder for its key list, the parked signature that replaces
    dialling it for a signature, the per-key setting for what an agent is
    offered, and — on the phone — a way to say that a paired machine may
    use its keys at all.

    What it turned out to be: three seams that already existed, pointed at
    a fourth case. What a holder offers was already remembered in the store
    (decision N), so a phone only had to be able to write to it from its
    own side; a request was already parked and woken for an approver that
    collects (§3, M6, M9), so a signature only had to be allowed to ride
    along with the payload; and a signature was already produced from a
    reconstruction of that payload by the holder's engine (§8, M4), which
    is the code both roads now end at.

    The uncomfortable discovery was the pairing rather than the keys.
    Nothing on the phone could grant a paired machine the use of a key: the
    permission existed, `ladulas peers allow --key` set it, and the device
    most likely to be holding the interesting key had no way to say yes.
    Until that was fixed the announcement was correct and empty, which is
    the least useful kind of correct.

    Then the first real login was refused by Ladulås itself, and the reason
    was two milestones old: ssh authenticates with
    `publickey-hostbound-v00@openssh.com`, not `publickey`, so the payload
    classified as opaque and the hard rule denied it before anybody was
    asked. §4's verified mechanics had been verified against the RFC and not
    against what ssh sends. The fix is worth more than the bug cost: the
    hostbound blob carries the server's host key *inside* the signature, so
    a phone deciding a login for a machine it does not trust now reads the
    destination out of the bytes instead of believing the requester, and a
    requester that claims a different one is refused. The audit entry naming
    the method is the only reason this took minutes to find — which is the
    argument for keeping opaque denials descriptive rather than tidy.

## 21. The public surface, and what nothing here checks

`pkg/` is a published import path, and the seventeen packages under it —
`agent`, `apns`, `approval`, `avatar`, `bridge`, `gitctx`, `hardware`,
`identity`, `keystore`, `peer`, `peercred`, `project`, `relay`, `sshsig`,
`storepb`, `transport` and `trust` — are out there because a mobile core
built out of this module reaches all of them. A phone is a peer and not a
client: it opens a store, serves an approval engine, holds keys in
hardware, dials the peer channel and renders the shared viewer bundle,
which is what `ladulasd` assembles, arranged for a device that sleeps. So
"what a bound core needs" turns out to be very nearly everything that is
not the desktop, and §18 is why the promise is still not made with it.

`internal/` is what nothing outside this module can reach, and that is
the whole of the distinction. Everything below is a consequence of the
other side of the seam being built somewhere this repository cannot see.

### The gomobile constraint on exported signatures

Nothing here compiles a `gomobile` bind surface. `gomobile` binds
strings, signed integers, booleans, `[]byte`, errors and types declared
in the bound package, and nothing else — so widening an exported
signature in `pkg/` to take a `map`, a slice of structs, an interface or
an unexported type compiles perfectly, passes every test in this
repository, and then fails to bind. There is no check on this side that
catches it, so a change to `pkg/` that widens an exported signature is
worth saying out loud.

Versions flow the same way. A consumer pins a pseudo-version of `main`
rather than a release, deliberately: a tag per consumer-visible change is
a tag for every one-line fix, and the thing worth having — knowing
exactly which commit is inside a given build — is what a pseudo-version
already is. The cost is that `main` has to stay green, because nothing
can be built out of a commit that does not compile.

### What else nothing here checks

This is the part worth reading before concluding that something is fine.

* **An acceptance that needs a phone.** M6 — a phone paired to a headless
  instance approving a real commit — and M12 — a key on the phone signing
  an SSH login through the agent socket of a machine that holds no key at
  all — need a device and a signing identity that this repository's CI
  does not have (§20). A regression in `peer`, `agent` or `approval` that
  only a phone would notice is not noticed here.
* **The icon.** `internal/branding/icon-1024.png` is the master, because
  the Linux packages need the drawing whatever else is built from it. The
  test in `internal/branding` catches a stale `tray-128.png`, since both
  are in this repository; it cannot catch a copy of the master kept
  anywhere else.
* **The daemon harness.** `startPeerInstance`, `buildCLI`, `buildSigner`
  and the `testutil` helpers are not exported. Publishing a test harness
  would be a second public surface for the sake of about three hundred
  lines, and a duplicated harness fails loudly when it drifts, which is
  the failure mode to prefer.

### What was rejected

Building `Mobile.xcframework` here and publishing it as a versioned
binary — a SwiftPM `binaryTarget` with a checksum, say — keeps every
package `internal/` and leaves nothing to bind against. That is a
genuinely smaller public surface, and it was turned down for the release
path it implies: a macOS runner inside this repository's CI, the relay URL
baked in on this side of the seam rather than by the application that
talks to it, and a release of this module standing between every change
made here and the consumer that needs it. The public surface is the price
paid for a consumer that can move at the speed of a `go get`.
