# 05 — the review's own attacks

```
python attacks.py
```

Twenty-two attacks, drawn from the six adversarial passes this library has been through,
run against the shipped code through its public surface. Each one prints what the
*caller* received and what the *trail* said, because those are the two things you can
check without taking the library's word for anything.

Exit code is the number that reached something. CI runs it.

## Why this exists next to the test suite

The suite pins every one of these, one assertion at a time. That is what a suite is for
and it is also why none of it reads like evidence: `assert "leak" not in repr(out)` tells
you a property holds and nothing about what the attack was or what it would have cost.

The other reason is sharper. Most of these findings are not bugs that were written once
and fixed once — they are bugs that came back in a different shape after the fix. A
canary has escaped this library six distinct ways: inside a record the projector handed
back untouched, two `from None` suppressions below a raised error, re-chained onto a
strict audit sink's own exception, split across two return fields, carrying one
zero-width space, and hanging off the attribute of a `str` subclass. Five of those six
were found *after* the fix for the first one.

The sixth is the one worth reading twice, because it was nobody's mistake in particular.
`class Money(str)` must not be entered by the projector — reading its attributes would
shred `Money("12.30")` into `{"currency": "EUR"}`, replacing the value the caller asked
for with its decoration — and the scanners downstream inherited that refusal, though
their job is the exact reverse. Two passes wanted opposite answers about one value and
shared the function that gave it. The token left through the *default* configuration
with `effect=allow` and an empty `redactions`.

So they are collected in one place, phrased as attacks rather than as assertions, and
run together. If a seventh shape turns up, it goes here.

## What it covers

**The canary** — five ways the token has reached a caller.

**The trail** — deleting the log directory and starting again, reaching one log by two
mount spellings, respelling a decision so a human and the parser disagree, and the other
half that matters just as much: an honest log holding text that merely *looks* like an
escape must not be reported as forged. A verifier that cries wolf is what teaches an
operator to stop reading it.

Those first two are a pair, and they pull opposite ways. The erasure memory has to
survive `rm -rf logs && mkdir logs`, so it cannot be anchored to an inode; the write lock
has to collapse every spelling of one file, and `realpath` sees through symlinks and
stops — so it cannot be anchored to a path. One key served both and could only ever
satisfy one of them, which it did, alternately.

**The ruleset** — editing a Gate's live policy in place at three depths, and rewriting a
principal after it has been bound. A record naming a hash that did not decide it is the
one thing the trail cannot survive.

**The importers** — what a hostile server can do to you at import: a pattern that scores
under the per-run bound eight times over, a `$ref` sibling downgrading a sensitivity
marker, one malformed tool taking every healthy tool with it, and a vendor repointing the
host on a path item after review.

**Availability** — the control refusing honest work, which is a failure in the same way.
An ordinary `datetime` in a declared field once wiped an entire output; an ordinary
username validator was once refused at import, and `sources_from_mcp` skips a tool whose
pattern will not load, so the screen was deleting the tools it exists to protect.

`{"minimum": 1, "maximum": 100}` with no `type` is the newest of these and the clearest.
It is legal JSON Schema and what a great many MCP servers emit, and *both* answers to it
are failures: admitting it and enforcing nothing is a bound that reads as enforced, and
refusing it takes a whole tool down over one honest property. Neither is the answer —
the bound is dispatched on the value, exactly as the string bounds beside it always were.

## Reading a `REACHED`

It means the attack got somewhere. The detail line says where — the value the caller
holds, the verdict `verify_chain` returned, the count of edits that landed. None of it
is a claim by the library about itself.
