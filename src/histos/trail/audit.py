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

import threading
from collections import deque
from typing import Any, Protocol, runtime_checkable

try:  # POSIX only; Windows gets in-process locking and nothing more (documented).
    import fcntl
except ImportError:  # pragma: no cover - exercised only on Windows
    fcntl = None  # type: ignore[assignment]


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


# One lock per log file, process-wide. Keyed by resolved path so two sinks pointed at
# the same file cannot interleave, which a per-instance lock allowed.

from histos.trail.jsonlsink import JSONLAuditSink as JSONLAuditSink  # noqa: E402
