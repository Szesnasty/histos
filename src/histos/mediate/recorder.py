"""The audit side of a Gate, as an object rather than as five attributes on one.

Split out of `gate.py`. Emitting a decision needs a monotonic id, a sink, an HMAC key,
the mode, the policy hash and a failure counter — six pieces of state that no other part
of a Gate touches, which is the definition of a collaborator rather than a section.

The rule it enforces is one sentence and it took three findings to get right: **only
`strict` may decide a call\'s fate.** Not a warning filter (`-W error` made the warning
itself the thing that killed a completed call), not the phase (the "the side effect
already happened" argument is true on POST and false on PRE), and not a sink that
absorbs its own errors, whose losses are counted here so a host has something to alarm
on other than a RuntimeWarning.
"""

from __future__ import annotations

import contextlib
import sys
import threading
import time
import warnings
from typing import Any

from histos._version import __version__
from histos.mediate import callctx
from histos.policy.contracts import GateDecision, Principal
from histos.trail.auditrecord import AuditRecord, digest_args


class DecisionRecorder:
    """Writes one row per decision, and never decides a call."""

    def __init__(self, audit: Any, key: bytes, *, enforced: bool) -> None:
        self.audit = audit
        self.enforced = enforced
        self._key = key
        self._seq = 0
        self._lock = threading.Lock()
        # Decisions this Gate could not record, whatever the sink was. `JSONLAuditSink`
        # counts its own, but `AuditSink` is a Protocol and a host's collector cannot be
        # made to — so the gap in the trail was legible only as a RuntimeWarning, which
        # is not something a monitor reads.
        self.failures = 0
        # Where the sink's own counter stood when this recorder was built, and the most
        # this recorder has seen it move. Read against a baseline rather than diffed
        # around each write: `failed` is shared by every thread using the sink and by
        # every Gate sharing it — the documented "two Gates in one process" shape — so a
        # delta attributed every other thread's loss to whichever emit was in flight, and
        # the count came out several times high under load.
        self._absorbed_base: int | None = None
        self._absorbed = 0
        # Set by the Gate whenever its ruleset is swapped, so a record can never name a
        # hash that did not decide it.
        self.policy_hash = ""
        self.policy_version = "0"

    def record(
        self,
        tool: str,
        args: dict[str, Any],
        decision: GateDecision,
        phase: str,
        started: float,
        principal: Principal | None,
        executed: bool,
        rebound: list[str] | None = None,
    ) -> None:
        # `+= 1` is a read-modify-write, so two threads sharing a Gate could stamp the
        # same `decision_id` on two different decisions — and `decision_id` is what an
        # investigator uses to say "this call, not that one". Cheap to make atomic.
        with self._lock:
            self._seq += 1
            decision_id = self._seq

        # One read of the call's snapshot, bound before the record is built: as three
        # separate reads inside the argument list it depended on evaluation order,
        # and a walrus there is bound after the line above it needs it.
        snapshot = callctx.current()
        record = AuditRecord(
            ts=time.time(),
            decision_id=decision_id,
            phase=phase,
            tool=tool,
            role=principal.role if principal is not None else "<none>",
            identity=principal.identity if principal is not None else None,
            effect=decision.effect.value,
            rule=decision.rule,
            reason=decision.reason,
            args_digest=digest_args(args, self._key),
            arg_keys=sorted(args),
            rebound_args=sorted(rebound or ()),
            field_name=decision.field,
            expected=decision.expected,
            received=decision.received,
            redactions=list(decision.redactions),
            # From the call's snapshot, like the hash and the version above it. Read
            # live, a mode changed mid-call inverted this field: a call blocked by
            # enforce recorded `enforced=false`, and one that ran under observe
            # recorded `enforced=true`. The execution was right both times; the row
            # said the opposite of it, in the direction that reads as safe.
            enforced=snapshot.enforce if snapshot else self.enforced,
            executed=executed,
            latency_us=int((time.perf_counter() - started) * 1_000_000),
            # Both halves from one snapshot. They came from two places — the hash from
            # the call, the version from this recorder's live field — so a swap mid-call
            # produced a record pairing one ruleset's hash with another's version, which
            # identifies no ruleset at all.
            policy_hash=snapshot.policy_hash if snapshot else self.policy_hash,
            policy_version=snapshot.policy_version if snapshot else self.policy_version,
            gate_version=__version__,
        )
        # The shipped sinks are total, and `AuditSink` is a Protocol, so a host's own
        # sink — a database write, an HTTP post to a collector — cannot be made to be.
        # `_emit` runs on the POST path too, after the tool body has produced its side
        # effect, so a sink that raises there does not prevent anything: it replaces a
        # completed call's result with the collector's traceback and throws the value
        # away. Reporting the sink is right; letting it take the call with it is not.
        # `failed` is read either side because the shipped sink is *total*: it absorbs
        # its own write errors, so the gate saw a clean return and could not count the
        # loss. That is the ordinary configuration, and it was the one where a host had
        # nothing to alarm on but a RuntimeWarning.
        before = self._absorbed_count()
        if self._absorbed_base is None and before is not None:
            self._absorbed_base = before
        try:
            self.audit.record(record.to_dict())
        except Exception as exc:  # noqa: BLE001 — only `strict` may decide a call's fate
            self._sink_failed(exc, phase, executed)
        else:
            after = self._absorbed_count()
            if after is not None and self._absorbed_base is not None:
                self._absorbed = max(self._absorbed, after - self._absorbed_base)

    def _absorbed_count(self) -> int | None:
        """The sink's own count of records it swallowed, read so it cannot decide a call.

        `getattr(obj, name, default)` only swallows `AttributeError`, and both reads sat
        outside the `try` that exists so a sink never decides a call's fate. A `failed`
        implemented as a property — a gauge read off the collector, which is the obvious
        way to implement the counter the gate asks for — handed whatever it raised
        straight out of `_emit`, past a total sink whose `record()` could not raise at all.
        """
        with contextlib.suppress(Exception):
            count = getattr(self.audit, "failed", None)
            return count if isinstance(count, int) else None
        return None

    def _sink_failed(self, exc: Exception, phase: str, executed: bool) -> None:
        """One rule for a sink that raised: only ``strict`` makes it fatal.

        Three separate things were wrong with catching it here and warning.

        *`strict` was inert.* `JSONLAuditSink(strict=True)` re-raises, and this was the
        only caller of `record()` in the library, so the blanket `except` caught the
        re-raise and turned it back into a warning. `strict=True` and `strict=False`
        behaved identically through `protect()`, `gate()` and `Gate` — every entry point
        the README teaches — while the sink's own warning text named `strict=True` as
        the remedy. It is honoured here now, on both phases, because "a lost record is
        worse than a failed call" is a statement about evidence, not about timing.

        *The justification was post-only.* "The side effect already happened, so raising
        prevents nothing" is true on POST and false on PRE, where the tool has not run
        and a raising sink is the only thing between an allowed call and an execution
        with no record of the decision. The default is still to continue — a collector
        outage should not stop an agent, and enforcement is unaffected either way, as
        the denial path never reaches the tool — but the message says which side of the
        call it is on instead of claiming the harmless one, and `audit_failures` counts
        it for a host that wants to alarm on the gap rather than parse warnings.

        *The warning could raise.* Under ``-W error`` — a perfectly ordinary CI setting
        — `warnings.warn` raises, so the "totality" the sink documents ended at this
        line: on POST the side effect stood, the record was lost *and* the caller got a
        RuntimeWarning instead of the value. A warning filter is a reporting choice, not
        a security one, so it does not get to decide a call. When the warning cannot be
        delivered the loss goes to stderr, which cannot be turned into an exception.
        """
        with self._lock:
            self.failures += 1
        if phase == "post":
            note = "the call had already run, so its side effect stands"
        elif executed:
            note = "the call is about to run with no record of the decision that allowed it"
        else:
            note = "the call was refused, and the refusal went unrecorded"
        message = (
            f"histos: the audit sink {type(self.audit).__name__} raised while recording this call "
            f"({phase} phase): {type(exc).__name__}: {exc}. This record is lost and {note}. "
            "Read Gate.audit_failures for the count, or give the sink strict=True to raise instead."
        )
        # Exactly `True`. A generic attribute answerer — an RPC or manager proxy, a
        # `__getattr__`-forwarding wrapper, a bare `unittest.mock.Mock` — returns a
        # truthy object for every name, so "evidence outranks availability" was an
        # opt-in nobody had to write and a mock sink silently made every audit failure
        # fatal. The shipped sink stores a bool; anything else is not opting in.
        if getattr(self.audit, "strict", False) is True:
            # Detached and suppressed, both. `record()` is called from inside the
            # wrapper's `except` handler, so CPython had already stamped `__context__`
            # on the sink's exception at the moment the sink raised — and that context
            # is the tool's *original*, unredacted error, which still carries whatever
            # the post-gate took out of the message the caller sees. SECURITY.md states
            # the original is attached as neither `__cause__` nor `__context__`, and
            # `traceback.format_exception` walks both, so `strict=True` put the canary
            # back on screen through the one flag that exists to make evidence stricter.
            # `from None` alone hides it from the formatted traceback and leaves the
            # attribute set on the object for an error reporter to pick up.
            exc.__context__ = None
            raise exc from None
        try:
            warnings.warn(message, RuntimeWarning, stacklevel=3)
        except Exception:  # noqa: BLE001 — `-W error` is a reporting choice, not a veto
            with contextlib.suppress(Exception):
                print(message, file=sys.stderr)
