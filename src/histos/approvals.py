"""Trusted, out-of-band confirmation — approvals bound to an exact request.

Confirmation must come from **outside the model** (a human approver, a trusted
console, a secure channel), never a boolean the agent can influence — the same
rule as identity. A naive ``confirm=lambda req: True`` (or one that reads a field
the agent controls) lets an injected agent self-approve a destructive action.

:class:`ApprovalStore` is the safe primitive:

* the gate raises ``GateConfirmationRequired`` on an unconfirmed high-risk call;
* a **trusted host** — never the agent — calls :meth:`grant` out-of-band with the
  request's :func:`request_fingerprint` (the host knows the tool/args/principal it
  attempted), e.g. after a human clicks approve;
* the agent retries the **same** call and the gate consumes the approval.

Approvals are **single-use** and **bound to the exact (tool, args, principal)**, so
one cannot be replayed to a different action, and the agent — which cannot write
to the store — cannot approve itself.
"""

from __future__ import annotations

import hashlib
import threading

from histos.canonical import canonical_json
from histos.contracts import GateRequest, Principal


def request_fingerprint(tool_name: str, args: dict, principal: Principal) -> str:
    """Stable fingerprint of a specific action: (tool, args, role, identity).

    Uses the one canonical serializer (Phase 0.1) so `1` and `"1"` do not collide
    and an approval binds to the exact action. Un-canonicalizable args raise — an
    action the gate cannot fingerprint stably cannot be safely approved (fail-closed).
    """
    body = canonical_json({"tool": tool_name, "args": args, "role": principal.role, "identity": principal.identity})
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def fingerprint_of(request: GateRequest) -> str:
    return request_fingerprint(request.tool_name, request.args, request.principal)


class ApprovalStore:
    """Out-of-band, single-use approvals keyed by request fingerprint (thread-safe)."""

    def __init__(self) -> None:
        self._approved: set[str] = set()
        self._lock = threading.Lock()

    def grant(self, fingerprint: str) -> None:
        """Record an out-of-band approval for one exact action. Host-only."""
        with self._lock:
            self._approved.add(fingerprint)

    def revoke(self, fingerprint: str) -> None:
        with self._lock:
            self._approved.discard(fingerprint)

    def consume(self, request: GateRequest) -> bool:
        """Single-use check used as the gate's ``confirm`` callback."""
        fingerprint = fingerprint_of(request)
        with self._lock:
            if fingerprint in self._approved:
                self._approved.discard(fingerprint)
                return True
            return False

    def as_confirm(self):
        """Return the callback to pass as ``Gate(confirm=...)``."""
        return self.consume
