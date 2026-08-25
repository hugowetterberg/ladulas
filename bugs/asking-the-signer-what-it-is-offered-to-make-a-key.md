# Asking the signer what it is, and being offered a key

**Fixed:** 2026-08-25, as decision AI. A command line with no `-Y` in it is
not one git builds, so `ladulas-sign` answers it with its own usage instead
of handing it to `ssh-keygen` (§5). A help request exits 0; anything else
exits 1 with a sentence naming what was refused. Every command line git
builds is untouched.

**Found:** 2026-08-25, by a Claude Code session probing the binary with
`ladulas-sign -h` to see what it did. It got a key-generation prompt. The
session timed the command out, so nothing was written.
**Severity:** no key was compromised and no signature was affected — but the
worst case is a new private key written into `~/.ssh` by a program the
person believed they were reading the usage of, and `-help` reaches the
prompt to change the passphrase on an existing key rather than the one to
make a new one.
**Areas:** `internal/signcli/signcli.go` (`Run`), `internal/signcli/parse.go`
(`operationOf`), `cmd/ladulas-sign/main.go`, §5.

## Signal

```
$ ladulas-sign -h
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/hugo/.ssh/id_ed25519):
```

## What was actually happening

`Run` read the `-Y` value, found none, and did what §5 promised it would do
with anything that is not a signing request: handed the whole command line
to the real `ssh-keygen`. That promise is right, and the hand-over is what
keeps `git log --show-signature` working — it is exercised on every
verification git does.

What it does not survive is the fact that **`ssh-keygen` with no operation
flag is not a program that prints usage.** Its default action is to generate
a key, and `-h` is a valid flag of its own — the host-key flag for
certificate signing — which selects no action, so it falls through to the
default. `-help` is worse, because OpenSSH's getopt reads it as `-h -e -l -p`
and `-p` is "change the passphrase":

```
$ ssh-keygen -help
Enter file in which the key is (/home/hugo/.ssh/id_ed25519):
```

`-v` alone does the same thing as `-h`. `--help`, `-?` and `help` are the
lucky ones: they are rejected by getopt, so `ssh-keygen` prints *its* usage,
which is still not an answer to the question that was asked.

So every plausible way of asking this program what it is either opened an
interactive prompt about somebody's keys or described a different program.

## Why the hand-over rule was too wide

The rule was written as "not a signing request", which is one condition, and
it needed to be two: *git asked for something else*, or *nobody asked for
anything*. The first is a hand-over and always was. The second has nothing to
hand over to, because `ssh-keygen` has no way to be asked "what would you
have done with this" and its answer to an unrecognised command line is to
start doing something.

`-Y` is the discriminator, and that it is a complete one is a fact about git
rather than a hope. Pointing `gpg.ssh.program` at a script that logged its
argv, against git 2.55, through both signing arrangements — `user.signingkey`
naming a key file and naming a `key::` literal — and through `git commit`,
`git log --show-signature` and `git log --format=%GK`, produced five distinct
command lines and every one of them names an operation:

```
-Y sign -n git -f <keyfile> <payload>
-Y sign -n git -f <tmp-pubkey> -U <payload>
-Y find-principals -f <allowed_signers> -s <sig> -Overify-time=...
-Y verify -n git -f <allowed_signers> -I <principal> -s <sig> -Overify-time=...
```

`%GK` and `%GF` do not run the program at all; git reads the fingerprint out
of the signature.

## What was left alone

The enumeration that was not written. `ssh-keygen` has something like twenty
action-selecting flags, and refusing only the command lines that would reach
the key-generating default means keeping that list in step with another
project's getopt — and misclassifying every action flag OpenSSH adds after
this paragraph. The `-Y` test needs no list and asks the question that is
actually being asked: did git build this.

Intercepting `-h` alone, which is the literal bug that was reported, was
rejected for the same reason it was reported at all: `-help` and `-v` open
the same prompts, and a person probing a binary does not know which spelling
is the safe one.

Using `ladulas-sign` as a general `ssh-keygen` stand-in is what this gives
up. It never was one — it is a `gpg.ssh.program`, and the fallback it
promises is every command line git builds, which is exactly what still
passes through.
