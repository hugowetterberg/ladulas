# Ladulås security audit — remaining items

Working document from the 2026-08-13 pre-release audit. **Do not commit** — this
is a to-do list to be deleted, not checked in.

The HIGH finding and all six MEDIUM findings are fixed on `main`
(commits `6eae50d`, `8743b35`, `6bf05f8`, `4c1b9e1`, `8550dfb`), along with the
documentation drift (`15ff1c2`), each with a regression test. The core trust
model — SPKI pinning, per-RPC authorization, prompt-matches-signed-bytes, SSHSIG
namespace separation, encryption at rest, doc-browser sandboxing, and the
"push is not security-critical" claim — was verified sound and needed no change.

What is left is the LOW / defense-in-depth tier: none of it forges an approval,
moves a key, or blocks letting other people try the app, but each is worth
closing on its own schedule.

## Relay / push (the gateway, still not production-ready)

- **Peer-announced wake-up relay URL accepts any HTTPS host** (`peer/wakeup.go`,
  `checkRelayURL`), and the `.ts.net`-suffix allowance for cleartext http trusts
  DNS that Tailscale Funnel can make public. Trusted-peer-only and low impact,
  but an outbound dial to an attacker-chosen host. Constrain to the configured
  relay and/or add a dial-time address check.
- **Unbounded unauthenticated relay registration** (`relay/relay.go` `Register`)
  — disk/memory DoS; cap per-key and total, and rate-limit, before any non-tailnet
  deployment.
- **Relay logs the instance-id capability in `Wake`** while deliberately avoiding
  it in `Register`; log a fingerprint or truncated hash instead.

## Transport / bind

- **CGNAT `100.64.0.0/10` is classified as tailnet/local** (`transport/bind.go`),
  so on some LTE/fiber ISPs the default bind could land on a WAN-reachable
  address.
- **DNS TOCTOU in the bind policy** (`transport/bind.go`, `checkBindHost` vs
  `net.Listen`) — resolve once and bind the vetted IPs.

## Signing / peer

- **RSA signature algorithm is requester-controlled on the borrowed-key path**
  (`peer/keys.go:245`) — negligible for the p256/ed25519 keys actually in use;
  add a guard mirroring `algorithmForFlags` if RSA keys are ever borrowed.
- **Peer-name collision at pairing** (`peer/pending.go`, `keystore/peers.go`) — a
  new peer can self-declare an existing peer's name; human confusion only
  (ref-resolution hijack is ruled out, oldest record wins). Apply `RenamePeer`'s
  uniqueness check, or auto-suffix, at pairing.

## Local surface

- **Latent `git` argument-injection in `gitctx`** — `from`/`to` revisions come
  from commit-object headers without hex-validation (`gitctx/collect.go`). Not
  reachable across a trust boundary today (git runs only on the object's own
  machine), but one refactor from mattering; validate as object names now.
- **`/tmp` socket fallback** (only when both `XDG_RUNTIME_DIR` and home are
  unresolvable) could land in an attacker-pre-created dir; the systemd units
  avoid it, so this is a belt-and-braces hardening for odd environments.
