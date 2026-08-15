"""Reading a trail back and saying whether it is still intact.

Split out of `audit.py`. Three questions, and they fail differently: is every record\'s
hash the one its contents produce, does each `prev` match the record before it, and does
the log still end where its sidecar says it does. The third is the only one that catches
truncation, because a chain proves the order of what is present and says nothing about
what was removed from the end.

A verifier that cries wolf is worse than no verifier — it is what teaches an operator to
stop reading it — so the two forgery checks it applies are exact about what they accept.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from histos.trail.logpath import _duplicate_key, _respelt_ascii, tip_path_for


def _chain_digest(body: str, key: bytes | None) -> str:
    raw = body.encode("utf-8", "surrogatepass")
    if key is not None:
        return hmac.new(key, raw, hashlib.sha256).hexdigest()
    return hashlib.sha256(raw).hexdigest()


def _tip_body(seq: int, tip: str) -> str:
    # Domain-separated from a record body so a record can never be replayed as a tip.
    return f"histos-audit-tip:v1:{seq}:{tip}"


def _read_last_line(fh: Any) -> str:
    """Last non-empty line of an open binary file, read from the end."""
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    data = b""
    while size > 0:
        step = min(4096, size)
        size -= step
        fh.seek(size)
        data = fh.read(step) + data
        if data.count(b"\n") >= 2:
            break
    for chunk in reversed(data.split(b"\n")):
        if chunk.strip():
            return chunk.decode("utf-8", "surrogatepass")
    return ""


def verify_chain(path: str | Path, *, key: bytes | None = None) -> tuple[bool, str]:
    """Re-walk a hash-chained JSONL audit log; return (ok, human-readable detail).

    Reports the FIRST broken link (line number + why): a recomputed-hash mismatch,
    a broken `prev` pointer, an out-of-order `seq`, or an unparseable line. This is
    what ``histos audit verify`` prints. Honest scope: it proves the ordering,
    integrity and **length** of the trace — a record removed from the end no longer
    passes, because the ``<log>.tip`` sidecar binds the count. It still cannot prove
    a decision was ever written (an unwritten record leaves no gap), and unkeyed it
    only resists accident, not a motivated writer (pass a key for real
    tamper-evidence).
    """
    try:
        return _verify_chain(Path(path), key)
    except (OSError, UnicodeDecodeError) as exc:
        return False, f"audit file is unreadable ({exc})"


def _verify_chain(p: Path, key: bytes | None) -> tuple[bool, str]:
    """Implementation separated so every filesystem/decoding failure has one boundary."""
    if not p.exists():
        return False, f"audit file not found: {p}"

    prev = ""
    count = 0
    with p.open("rb") as fh:
        for lineno, raw in enumerate(fh, start=1):
            stripped = raw.decode("utf-8", "surrogatepass").strip()
            if not stripped:
                continue
            try:
                rec = json.loads(stripped)
            except ValueError as exc:
                return False, f"line {lineno}: not valid JSON ({exc})"
            if not isinstance(rec, dict):
                return False, f"line {lineno}: record is {type(rec).__name__}, expected an object"
            if "hash" not in rec:
                return False, f"line {lineno}: record is not hash-chained (no `hash`)"
            stored = rec.pop("hash")
            if rec.get("prev", "") != prev:
                return False, f"line {lineno}: broken chain — `prev` does not match the previous record's hash"
            count += 1
            # `seq` lives inside the hashed body, so record N cannot be re-presented
            # as record N-2 even by someone who can recompute the chain.
            seq = rec.get("seq")
            if seq != count:
                if seq is None:
                    return False, f"line {lineno}: record carries no `seq` — it predates the numbered chain"
                return False, f"line {lineno}: record {count} is numbered {seq!r} — records were removed"
            # `record` hashes the ASCII serialisation now (see there). Logs written before
            # that hashed the identical record with `ensure_ascii=False`, and the two
            # bodies differ the moment any field holds a non-ASCII codepoint — so the old
            # spelling is accepted as a fallback rather than every pre-existing log
            # reporting "altered after it was written". Both are faithful serialisations of
            # the same parsed record, so accepting either forges nothing.
            body = json.dumps(rec, sort_keys=True, ensure_ascii=True)
            legacy_body = json.dumps(rec, sort_keys=True, ensure_ascii=False)
            canonical = hmac.compare_digest(_chain_digest(body, key), str(stored))
            matched = canonical or (
                legacy_body != body and hmac.compare_digest(_chain_digest(legacy_body, key), str(stored))
            )
            # A digest over the *parsed* record says nothing about the bytes a reader
            # sees. Two lines can parse to one dict and read differently — a repeated
            # key, where `json.loads` keeps the last and a human greps the first, is the
            # sharp case: the record verifies as `allow` while the file says `deny`. So
            # the line has to be a serialisation of the record it parses to.
            #
            # Which serialisation, though, is not something the check gets to dictate.
            # Requiring today's exact spelling looked safe because a legacy line was
            # thought to be "a different spelling by construction" — true only for the
            # records with a non-ASCII field, which is the rare case. For an ordinary
            # ASCII record the two bodies are byte-identical, so the legacy hash *is*
            # today's hash, the check fired, and `histos audit verify` told the operator
            # their untouched pre-0.1.0 log had been rewritten. That is a false accusation
            # about evidence, which is worse than the rewrite it was looking for.
            #
            # So: accept any spelling `json.dumps` can produce from the parsed record,
            # and run the check on every line rather than only on ones matching today's
            # digest — which also closes the legacy tamper hole that exemption left. The
            # sharp case is still caught: `json.loads` keeps document order, so an
            # unsorted dump reproduces legacy bytes exactly, while no dump of a parsed
            # dict can ever reproduce a duplicated key.
            # The real question is narrower than "is this the spelling we would have
            # written". Requiring one of four `json.dumps` spellings invented an
            # unwritten normative byte format and reported every other conformant
            # serialisation — a different key order, `separators=(",",":")`, a second
            # implementation's writer — as tampering. `spec/` describes no audit-log
            # byte format at all, so there is nothing to hold a line to.
            #
            # What the check exists for is the case where the bytes and the parsed record
            # *disagree*, and there is exactly one way for that to happen in JSON: a
            # repeated key, where `json.loads` keeps the last and a human greps the
            # first, so the record verifies as `allow` while the file says `deny`. Asked
            # directly, and nothing else is second-guessed.
            duplicate = _duplicate_key(stripped)
            if duplicate is not None:
                return False, (
                    f"line {lineno}: the record on disk repeats the key {duplicate!r}, so what a reader sees "
                    "and what the chain authenticates are different values"
                )
            respelt = _respelt_ascii(stripped)
            if respelt is not None:
                return False, (
                    f"line {lineno}: the record on disk spells a printable character as {respelt} — it parses "
                    "to a value no reader of the file can see, and no JSON writer produces that escape"
                )
            if not matched:
                return False, f"line {lineno}: hash mismatch — record was altered after it was written"
            prev = str(stored)

    ok, detail = _verify_tip(p, count, prev, key)
    if not ok:
        return False, detail
    keyed = "keyed (HMAC)" if key is not None else "unkeyed (accident-evident only)"
    return True, f"OK — {count} records, chain intact, {keyed}"


def _verify_tip(log: Path, count: int, tip: str, key: bytes | None) -> tuple[bool, str]:
    """Confirm the log still ends where its sidecar says it does."""
    sidecar = tip_path_for(log)
    if not sidecar.exists():
        return False, (
            f"no tip file at {sidecar.name} — the chain proves the order of what is present, "
            "not that the end of the log is still there; truncation cannot be ruled out"
        )
    try:
        text = sidecar.read_text(encoding="utf-8")
        # The sidecar is the one file whose whole job is to say how long the log is, and
        # it was exempt from the check every line of the log gets. Keeping the genuine
        # triple last and prepending a fabricated `records` makes `json.loads` take the
        # real one — so the MAC still authenticates — while a reader sees the forgery.
        forged = _duplicate_key(text) or _respelt_ascii(text)
        if forged is not None:
            return False, f"tip file {sidecar.name} says two different things about {forged!r}"
        rec = json.loads(text)
        expected_count = int(rec["records"])
        expected_tip = str(rec["hash"])
        mac = str(rec["mac"])
    except (ValueError, TypeError, KeyError, OSError) as exc:
        return False, f"tip file {sidecar.name} is unreadable ({exc})"
    if not hmac.compare_digest(_chain_digest(_tip_body(expected_count, expected_tip), key), mac):
        return False, f"tip file {sidecar.name} does not authenticate — it was altered, or the key is wrong"
    if expected_count != count or expected_tip != tip:
        removed = expected_count - count
        if removed > 0:
            return False, f"log ends at record {count} but the tip covers {expected_count} — {removed} removed"
        return False, f"log has {count} records but the tip covers {expected_count} — a write was interrupted"
    return True, ""
