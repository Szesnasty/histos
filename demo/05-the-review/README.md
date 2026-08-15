# 05 — the review's own attacks

```
python attacks.py
```

Eighteen attacks, drawn from the five adversarial passes this library has been through,
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
canary has escaped this library five distinct ways: inside a record the projector handed
back untouched, two `from None` suppressions below a raised error, re-chained onto a
strict audit sink's own exception, split across two return fields, and carrying one
zero-width space. Four of those five were found *after* the fix for the first one.

So they are collected in one place, phrased as attacks rather than as assertions, and
run together. If a sixth shape turns up, it goes here.

## What it covers

**The canary** — five ways the token has reached a caller.

**The trail** — deleting the log directory and starting again, respelling a decision so a
human and the parser disagree, and the other half that matters just as much: an honest
log holding text that merely *looks* like an escape must not be reported as forged. A
verifier that cries wolf is what teaches an operator to stop reading it.

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

## Reading a `REACHED`

It means the attack got somewhere. The detail line says where — the value the caller
holds, the verdict `verify_chain` returned, the count of edits that landed. None of it
is a claim by the library about itself.
