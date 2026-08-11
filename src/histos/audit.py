"""The audit trail — the "Prove it" artifact.

Design points:

* **Records every decision, including DENIED.** Denied attempts are the whole
  value ("18 unauthorised attempts blocked").
* **Never stores raw argument values** — arguments can be PII. Each record keeps
  a keyed **HMAC-SHA256** digest of the arguments — a bare SHA of a low-entropy
  value is brute-forceable — plus the argument *keys*. That claim covers the
  *whole* record, not just the digest field, so a decision ``reason`` that quotes
  the offending value is rewritten on the way in — see :class:`AuditRecord`.
* **Verifiable, not "replayable".** You cannot reconstruct a call from a digest.
  What the trace lets you do is *verify* a decision: it records ``decision_id``,
  the ``policy_hash`` + ``policy_version`` + ``gate_version`` that produced it, the
  matched ``rule`` and the structured ``field/expected/received``.
* **Local and pluggable.** :class:`JSONLAuditSink` writes append-only JSONL with
  no proxy and no DB. :class:`InMemoryAuditSink` keeps a bounded window in memory —
  it is the default, so it must not be a leak in a long-lived server.
* **Optional tamper-evidence.** :class:`JSONLAuditSink` can hash-chain records.
* **Audit must never crash the gate, and never silently lose a record.** Both
  shipped sinks are safe to call from several threads, and the digest has no input
  it can refuse.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

try:  # POSIX only; Windows gets in-process locking and nothing more (documented).
    import fcntl
except ImportError:  # pragma: no cover - exercised only on Windows
    fcntl = None  # type: ignore[assignment]


def digest_args(args: dict[str, Any], key: bytes) -> str:
    """Keyed HMAC-SHA256 hex of the arguments — never the raw values.

    Uses the one canonical serializer (Phase 0.1) so the digest matches the approval
    fingerprint. Audit must never crash the gate, so an un-canonicalizable value
    falls back to a stable repr rather than raising.
    """
    from histos.canonical import canonical_json

    try:
        canonical = canonical_json(args)
    except (TypeError, ValueError):
        canonical = repr(sorted(args.items(), key=lambda kv: kv[0]))
    # `surrogatepass`, because a plain `.encode("utf-8")` here is a way to make a
    # decision disappear. The serializer rejects a lone surrogate, but the repr
    # fallback does not: an argument object whose `__repr__` returns one produced a
    # `UnicodeEncodeError` out of `Gate._emit` *before* the sink was reached, so the
    # call that provoked it was the one call with no record at all. There is no input
    # this digest is allowed to refuse.
    return "hmac-sha256:" + hmac.new(key, canonical.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()


# Decision rules whose `reason` this module composes itself, out of things the record
# already publishes or the operator already has: tool names, the caller's role, policy
# literals the developer wrote, field names, limit names. Safe to keep verbatim.
#
# Absent from the list, and therefore redacted: every rule whose reason is built by
# interpolating a *foreign* string — an exception raised by a host resolver, a confirm
# callback, or a check that fell over. `KeyError('jane.doe@x.com')` is the ordinary
# shape of such an exception, and it is a raw argument value on its way into an
# append-only file. An unrecognised rule redacts too, so a rule added later is assumed
# to quote data until someone says otherwise.
_REASON_IS_POLICY_TEXT: frozenset[str] = frozenset(
    {
        "allow",
        "confirmed",
        "unknown_tool",
        "no_arg_schema",
        "no_principal",
        "rbac",
        "arg_schema",
        "arg_binding_unresolved",
        "resource_constraint",
        "no_resource_resolver",
        "canary_exfil",
        "secret_detected",
        "injection_pattern",
        "exfiltration_pattern",
        "rate_limit",
        "budget",
        "requires_confirmation",
        "post_redaction",
        "exception_redaction",
        "output_schema",
    }
)

_REDACTED = "[redacted — this rule's reason quotes foreign text; it stays in the developer channel]"


@dataclass
class AuditRecord:
    """One gate decision, ready to serialise.

    The record is the **durable** channel, and it is held to the module's headline
    claim: no raw argument value reaches it, in any field. The engine's own denial
    text names rules and fields without quoting values, but a reason that carries a
    *foreign* exception (`resource_resolver raised: KeyError('jane.doe@x.com')`) does
    quote one, and copying that into an append-only file on disk is the outcome the
    argument digest exists to prevent. Those reasons are dropped here; the decision
    keeps its `rule`, `field` and `expected`, and the full text stays on the
    in-process `GateDenied.decision` where a developer debugging the denial reads it.
    """

    ts: float
    decision_id: int
    phase: str  # "pre" | "post"
    tool: str
    role: str
    identity: str | None
    effect: str
    rule: str
    reason: str
    args_digest: str
    arg_keys: list[str] = field(default_factory=list)
    #: Arguments the policy *overwrote* with a trusted principal attribute before the
    #: tool saw them — field names only, never values.
    #:
    #: A binding is an authorization decision, and it used to leave no trace. A run in
    #: which the gate silently redirected a message from an attacker's number to the
    #: caller's own recorded `effect=allow` and nothing else, which is
    #: indistinguishable in the trail from a call the policy had no opinion about. An
    #: auditor asking "why did this not go where the model asked" had nothing to read,
    #: and a measurement could not attribute the absence of harm to the policy.
    #:
    #: Only fields whose value actually changed are listed. A bound field the caller
    #: already had right was not overridden, and counting it would inflate the number
    #: of interventions the gate appears to have made.
    rebound_args: list[str] = field(default_factory=list)
    field_name: str = ""
    expected: str = ""
    received: str = ""
    redactions: list[str] = field(default_factory=list)
    enforced: bool = True
    # Whether the tool body actually ran for this call. In observe mode a DENY
    # still executes, so `effect=deny enforced=false executed=true` is the record
    # that must never be mistaken for a block.
    executed: bool = True
    latency_us: int | None = None
    policy_hash: str = ""
    policy_version: str = ""
    gate_version: str = ""

    def __post_init__(self) -> None:
        if self.rule not in _REASON_IS_POLICY_TEXT:
            self.reason = _REDACTED
            # `received` is shape-only everywhere the engine sets it (`resource.<field>`,
            # a detector kind, the caller's role), but it is held to the same rule as
            # the reason rather than trusted to stay that way.
            self.received = _REDACTED if self.received else ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@runtime_checkable
class AuditSink(Protocol):
    def record(self, entry: dict[str, Any]) -> None: ...


# A default that grows forever is not a safe default. `protect(my_tools, policy=...)`
# installs this sink when the caller says nothing, and two records per call over a
# week of traffic is a leak proportional to how much the gate is used.
_DEFAULT_MAX_ENTRIES = 10_000


class InMemoryAuditSink:
    """Keeps recent records in memory — the default, and what tests assert against.

    Bounded: the oldest record is dropped once ``maxlen`` is reached, and
    :attr:`dropped` counts how many were lost so the gap is visible rather than
    silent. Pass ``maxlen=None`` for the old unbounded behaviour, and use
    :class:`JSONLAuditSink` for anything that has to keep the whole trace.

    Thread-safe: ``record`` holds ``_lock``.
    """

    def __init__(self, maxlen: int | None = _DEFAULT_MAX_ENTRIES) -> None:
        self.entries: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self.dropped = 0
        self._lock = threading.Lock()

    def record(self, entry: dict[str, Any]) -> None:
        with self._lock:
            if self.entries.maxlen is not None and len(self.entries) == self.entries.maxlen:
                self.dropped += 1
            self.entries.append(entry)

    @property
    def denied(self) -> list[dict[str, Any]]:
        return [e for e in self.entries if e["effect"] == "deny"]


def tip_path_for(log: str | Path) -> Path:
    """The sidecar that binds a hash-chained log to its length. See :class:`JSONLAuditSink`."""
    p = Path(log)
    return p.with_name(p.name + ".tip")


class JSONLAuditSink:
    """Append-only JSONL on the local filesystem. Optionally hash-chained.

    With ``hash_chain=True`` each record gains ``seq`` (its 1-based position in this
    file), ``prev`` (the previous record's hash) and ``hash`` (over its own canonical
    body, which includes ``seq`` and ``prev``).

    **Tamper-evidence, stated honestly:**

    * **Unkeyed** (``key=None``, default) the chain uses plain sha256. It detects
      reordering, deletion and naive single-record edits — but an attacker with
      write access to the file can rewrite a record and *recompute every
      downstream hash* (the algorithm is public), and :meth:`verify` then passes.
      So unkeyed = integrity against accident/careless edit, **not** against a
      motivated writer.
    * **Keyed** (pass ``key=<secret>`` kept off this machine) the chain uses
      HMAC-SHA256, so recomputation requires the secret and content rewriting is
      detectable. Use a key for real tamper-evidence.

    **Why there is a sidecar.** A forward-walking chain can only prove that what is
    *present* is in order. Deleting records off the *end* forges nothing — the
    shorter prefix is a valid chain — so a truncated log verified clean and an
    attacker's denied attempts were simply the last lines of the file. Detecting that
    needs one piece of state the log itself cannot hold, so every append also rewrites
    ``<log>.tip``: the record count, the tip hash, and a digest over both. Keyed, that
    digest is an HMAC the attacker cannot produce for a count they never saw; unkeyed
    it is accident-evident only, exactly like the chain.

    **Concurrency.** ``record`` is safe from several threads (``_lock``) and, on
    POSIX, from several processes (``flock`` on the log). The chain tip is re-read
    from the file inside that lock rather than cached, because a snapshot taken at
    construction is wrong the moment a second writer exists — and one honest
    concurrent append used to break the chain permanently, which taught operators to
    stop believing ``histos audit verify``.
    """

    def __init__(self, path: str | Path, *, hash_chain: bool = True, key: bytes | None = None) -> None:
        self.path = Path(path)
        self.tip_path = tip_path_for(self.path)
        self.hash_chain = hash_chain
        self._key = key
        self._lock = threading.Lock()

    def _digest(self, body: str) -> str:
        return _chain_digest(body, self._key)

    def _tail(self, fh: Any) -> tuple[int, str]:
        """(seq, hash) of the last record in the open file — the only chain state."""
        last = _read_last_line(fh)
        if not last:
            return 0, ""
        try:
            rec = json.loads(last)
        except ValueError:
            return 0, ""
        if not isinstance(rec, dict):
            return 0, ""
        seq = rec.get("seq")
        return (seq if isinstance(seq, int) else 0), str(rec.get("hash", ""))

    def _write_tip(self, seq: int, tip: str) -> None:
        body = _tip_body(seq, tip)
        payload = json.dumps({"records": seq, "hash": tip, "mac": self._digest(body)})
        # Replaced, never edited in place: a reader that catches the file mid-write
        # must see the previous tip, not half of two.
        tmp = self.tip_path.with_name(self.tip_path.name + ".new")
        tmp.write_text(payload + "\n", encoding="utf-8")
        os.replace(tmp, self.tip_path)

    def record(self, entry: dict[str, Any]) -> None:
        payload = dict(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a+b") as fh:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            if self.hash_chain:
                seq, prev = self._tail(fh)
                payload["seq"] = seq + 1
                payload["prev"] = prev
                payload["hash"] = self._digest(json.dumps(payload, sort_keys=True, ensure_ascii=False))
            line = json.dumps(payload, ensure_ascii=False) + "\n"
            # `surrogatepass` for the same reason as `digest_args`: an argument *key*
            # can carry a lone surrogate, and a sink that raises deletes the record.
            fh.write(line.encode("utf-8", "surrogatepass"))
            fh.flush()
            if self.hash_chain:
                self._write_tip(payload["seq"], payload["hash"])

    def verify(self) -> bool:
        """Re-walk the file and confirm the hash chain is intact."""
        ok, _ = verify_chain(self.path, key=self._key)
        return ok


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
    p = Path(path)
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
            body = json.dumps(rec, sort_keys=True, ensure_ascii=False)
            if not hmac.compare_digest(_chain_digest(body, key), str(stored)):
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
        rec = json.loads(sidecar.read_text(encoding="utf-8"))
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
