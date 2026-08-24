# An identity mismatch that was a loopback address

**Fixed:** 2026-08-21, as decision AH. The dialler compares the pin it met
against its own before it compares it against the peer's, and an address that
turns out to be this machine is skipped rather than reported (§8). The failure
reported when every address fails is the most informative one rather than the
last. The mismatch message prints a pin against a pin. And the listener stops
advertising loopback to peers on other machines at all, because it now binds
one tier of addresses rather than every address it can find.

**Found:** 2026-08-21, on `guppy`, looking at the `Horatio` peer screen in
the desktop window; what it showed is under **Signal** below.
**Severity:** none to the working of anything, and an evening of somebody's
time. Signing and pairing were unaffected; what was wrong was the account
the instance gave of why a peer was unreachable, and the account named the
crypto stack.
**Areas:** `pkg/peer/dial.go` (`callOver`), `pkg/transport/client.go`
(`verifyPeer`), `pkg/transport/bind.go`, §8.

## Signal

The peer screen for `Horatio`, offline, with:

```
peer: reach [::1]:7373: unavailable: transport: the peer is not the expected
identity: got SHA256:eMKLRrpEabXB/y6YcrsnyKfI6hhpMGc0aavLoZsRzYk,
expected SPKI256:nKc8ln4ADVKUGY0RCtmxkKiDXGJMTAU6nq0Whpck24Q
```

and, above it in the same pane, the pairing's fingerprint —
`SHA256:y8wYEBxwQJIgjeJo3Uv+Wi46m7pUXEK0iQ6Ci9EU0TU` — which is what both
machines' `ladulas status` reported for Horatio's identity, and which agrees
with what the two humans compared when they paired.

Three things about that message, each of which sends the reader somewhere
else:

* the two hashes are printed in **different formats**, so the natural first
  reading is that one end has changed how it hashes a key. It has not. The
  `got` was `ssh.FingerprintSHA256` of the identity the handshake met and the
  `expected` was the SPKI pin, which are two hashes of two different
  encodings of two different keys;
* the identity it "got" is **guppy's own** — the machine doing the
  complaining. It is in guppy's own peer list under its own name;
* the address is `[::1]:7373`.

## What was actually happening

Nothing was wrong with any key. Reading the certificate off Horatio's
listener and doing the arithmetic:

```
$ openssl s_client -connect 127.0.0.1:7373 </dev/null |
    openssl x509 -noout -pubkey
MCowBQYDK2VwAyEAU3Dg+aHQUo9lzikmuZM6angZy5nhETkTZnH2T3lA+Q0=

SHA256:y8wYEBxwQJIgjeJo3Uv+Wi46m7pUXEK0iQ6Ci9EU0TU    # ssh fingerprint
SPKI256:nKc8ln4ADVKUGY0RCtmxkKiDXGJMTAU6nq0Whpck24Q   # transport pin
```

The pin Horatio presents is character for character the pin guppy expected.
Both ends had the right key, and the pin and the fingerprint are two views of
that one key exactly as §8 says they are.

What guppy had was a **trust record ending in `127.0.0.1:7373` and
`[::1]:7373`**. `localBindAddresses` put every private and tailnet address
the machine had into the list it bound, loopback last, and the same list was
what pairing advertised — so Horatio told guppy, truthfully about itself and
uselessly for guppy, that it could be reached on loopback. Dialling that from
guppy reaches guppy.

Then `callOver` returned `lastErr`. The address list is ordered best first,
so the last attempt is the one nobody expected to work, and on this record it
was the one that reached the dialler itself. Every earlier failure — the
tailnet address, the LAN address, the ones that mattered — was overwritten by
it on the way past.

The real reason Horatio was unreachable at the time is in its own journal:

```
level=INFO msg="lock state" state=sealed detail="… peers on (peering off), store sealed"
level=INFO msg="peer channel listening" addresses=[100.74.235.31:7373 …]   # 17 minutes later
```

The daemon had restarted and come up sealed, and a sealed instance has no
peer channel at all — the identity key that authenticates it is inside the
store (§10). So the honest report was "connection refused on every address
that is Horatio's", and what got printed instead was an accusation about an
identity, supported by evidence gathered from a socket on the same machine.

## Why the reading was so convincing

Every part of it pointed the same way and none of it was true:

* an error whose *first* clause is about identity, when the identity is
  fine;
* two hash formats side by side, which is what a changed crypto stack would
  actually look like;
* a fingerprint that really did not match the one on the screen above it,
  because it belonged to a third machine — the one reading the screen;
* and a peer that really was unreachable, so the symptom was not imaginary.

The lesson is narrower than "write better messages". **An error about a
peer's identity must not be reachable from a connection to ourselves**, and a
diagnosis assembled from several attempts must not report the attempt that
says least. Both of those are properties of the code rather than of the
wording, and both are now tests: `TestOurOwnAddressIsNotAnImpostor` and
`TestTheReportedFailureIsTheInformativeOne`.

## What was left alone

**A trust record still keeps the addresses the peer advertised when it
paired.** Pruning the advertisement stops new pairings from recording
loopback and a dozen container bridges; it does nothing for a record that
already has them, and there is no address-refresh RPC — a peer that has
pruned its own list has no way to say so. That is a deliberate non-fix for
now, on the grounds that the cost is bounded once the dialler skips its own
addresses and the link prefers the address that last worked. If it turns out
to be worth building, the place it belongs is the presence heartbeat, which
is the one call that already happens periodically in the direction that would
carry it.
