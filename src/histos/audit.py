"""The audit trail — the "Prove it" artifact.

Design points:

* **Records every decision, including DENIED.** Denied attempts are the whole
  value ("18 unauthorised attempts blocked").
* **Never stores raw argument values** — arguments can be PII. Each record keeps
  a keyed **HMAC-SHA256** digest of the arguments — a bare SHA of a low-entropy
  value is brute-forceable — plus the argument *keys*.
* **Verifiable, not "replayable".** You cannot reconstruct a call from a digest.
  What the trace lets you do is *verify* a decision: it records ``decision_id``,
  the ``policy_hash`` + ``policy_version`` + ``gate_version`` that produced it, the
  matched ``rule`` and the structured ``field/expected/received``.
* **Local and pluggable.** :class:`JSONLAuditSink` writes append-only JSONL with
  no proxy and no DB. :class:`InMemoryAuditSink` is for tests.
* **Optional tamper-evidence.** :class:`JSONLAuditSink` can hash-chain records.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


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
    return "hmac-sha256:" + hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass
class AuditRecord:
    """One gate decision, ready to serialise."""

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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@runtime_checkable
class AuditSink(Protocol):
    def record(self, entry: dict[str, Any]) -> None: ...


class InMemoryAuditSink:
    """Keeps records in a list — the default, and what tests assert against."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def record(self, entry: dict[str, Any]) -> None:
        self.entries.append(entry)

    @property
    def denied(self) -> list[dict[str, Any]]:
        return [e for e in self.entries if e["effect"] == "deny"]


class JSONLAuditSink:
    """Append-only JSONL on the local filesystem. Optionally hash-chained.

    With ``hash_chain=True`` each record gains ``prev`` (the previous record's
    hash) and ``hash`` (over its own canonical body + ``prev``).

    **Tamper-evidence, stated honestly:**

    * **Unkeyed** (``key=None``, default) the chain uses plain sha256. It detects
      truncation, reordering and naive single-record edits — but an attacker with
      write access to the file can rewrite a record and *recompute every
      downstream hash* (the algorithm is public), and :meth:`verify` then passes.
      So unkeyed = integrity against accident/careless edit, **not** against a
      motivated writer.
    * **Keyed** (pass ``key=<secret>`` kept off this machine) the chain uses
      HMAC-SHA256, so recomputation requires the secret and content rewriting is
      detectable. Use a key for real tamper-evidence.
    """

    def __init__(self, path: str | Path, *, hash_chain: bool = True, key: bytes | None = None) -> None:
        self.path = Path(path)
        self.hash_chain = hash_chain
        self._key = key
        self._prev_hash = self._load_tail_hash() if hash_chain else ""

    def _digest(self, body: str) -> str:
        raw = body.encode("utf-8")
        if self._key is not None:
            return hmac.new(self._key, raw, hashlib.sha256).hexdigest()
        return hashlib.sha256(raw).hexdigest()

    def _load_tail_hash(self) -> str:
        if not self.path.exists():
            return ""
        last = ""
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last = stripped
        if not last:
            return ""
        try:
            return json.loads(last).get("hash", "")
        except (ValueError, TypeError):
            return ""

    def record(self, entry: dict[str, Any]) -> None:
        payload = dict(entry)
        if self.hash_chain:
            payload["prev"] = self._prev_hash
            body = json.dumps(payload, sort_keys=True, ensure_ascii=False)
            payload["hash"] = self._digest(body)
            self._prev_hash = payload["hash"]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def verify(self) -> bool:
        """Re-walk the file and confirm the hash chain is intact."""
        ok, _ = verify_chain(self.path, key=self._key)
        return ok


def verify_chain(path: str | Path, *, key: bytes | None = None) -> tuple[bool, str]:
    """Re-walk a hash-chained JSONL audit log; return (ok, human-readable detail).

    Reports the FIRST broken link (line number + why): a recomputed-hash mismatch,
    a broken `prev` pointer, or an unparseable line. This is what
    ``histos audit verify`` prints. Honest scope: it proves ordering and
    integrity of what is *present* — not completeness (an unwritten record leaves
    no gap), and unkeyed it only resists accident, not a motivated writer (pass a
    key for real tamper-evidence).
    """
    p = Path(path)
    if not p.exists():
        return False, f"audit file not found: {p}"

    def _digest(body: str) -> str:
        raw = body.encode("utf-8")
        if key is not None:
            return hmac.new(key, raw, hashlib.sha256).hexdigest()
        return hashlib.sha256(raw).hexdigest()

    prev = ""
    count = 0
    with p.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            stripped = line.strip()
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
            body = json.dumps(rec, sort_keys=True, ensure_ascii=False)
            if _digest(body) != stored:
                return False, f"line {lineno}: hash mismatch — record was altered after it was written"
            prev = stored
            count += 1
    keyed = "keyed (HMAC)" if key is not None else "unkeyed (accident-evident only)"
    return True, f"OK — {count} records, chain intact, {keyed}"
