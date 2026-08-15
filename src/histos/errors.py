"""Exceptions raised by the gate.

Two families:

* ``PolicyError`` — the *developer* wired something wrong (structural problem in
  the policy). Raised eagerly, at wrap time, because the trust model
  says the developer is cooperating and wants to know immediately.
* ``GateDenied`` / ``GateConfirmationRequired`` — a *runtime* decision. The gate
  refused (or paused) a call. These carry the :class:`~histos.policy.contracts.GateDecision`
  so the caller can inspect exactly which rule fired.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from histos.policy.contracts import GateDecision, GateRequest


class GateError(Exception):
    """Base class for everything this package raises."""


class PolicyError(GateError):
    """The policy is structurally invalid — a developer wiring mistake.

    Fail loud, fail early.

    ``code`` is a stable, machine-readable slug from the **POLICY** namespace of the
    decision vocabulary (``spec/decision-codes.json``) — a different namespace from
    the RUNTIME codes a :class:`GateDecision` carries, because "this policy cannot be
    loaded" and "this call is refused" are different kinds of answer and a
    conformance suite must be able to tell them apart across implementations.
    """

    def __init__(self, message: str, *, code: str = "policy_invalid") -> None:
        self.code = code
        super().__init__(message)


def _with_remedy(message: str, decision: GateDecision) -> str:
    """Append the decision's remedy, because the message is where a developer reads it.

    Every rule carries a remedy — "bind an identity with use_principal()", "declare the
    tool in `tools:`" — and it was reachable only as ``exc.decision.remedy``, which
    means it was read by nobody debugging their first denial. The first thing a new
    user hits is ``no_principal``, and the message they got named the rule and stopped.
    """
    remedy = getattr(decision, "remedy", None)
    return f"{message} — fix: {remedy}" if remedy else message


class GateDenied(GateError):
    """A call was denied by a gate decision — the fail-closed default."""

    def __init__(self, decision: GateDecision) -> None:
        self.decision = decision
        super().__init__(_with_remedy(f"gate denied [{decision.rule}]: {decision.reason}", decision))

    @property
    def public_reason(self) -> str:
        """The non-coaching code safe to hand back to the model (two-audience)."""
        return self.decision.public_reason


class GateConfirmationRequired(GateError):
    """A call needs explicit human/operator confirmation before it may proceed.

    Carries the ``request`` the gate paused, and that is not a convenience. An approval
    is bound to a fingerprint over the tool, the principal **and the arguments the tool
    would actually run with** — which is not what the caller passed, because ``bind``
    has already overwritten every bound field with the principal's trusted attribute by
    the time this is raised. A host holding only its own arguments computes a
    fingerprint that never matches, so ``grant()`` appears to work, the retry pauses
    again, and the call loops forever with nothing in the logs to say why. The host
    cannot derive these arguments from anything it has; only the gate knows them.

    ``request.args`` is a detached copy, so nothing a host does to it reaches the call.
    """

    def __init__(self, decision: GateDecision, request: GateRequest | None = None) -> None:
        self.decision = decision
        self.request = request
        super().__init__(_with_remedy(f"confirmation required [{decision.rule}]: {decision.reason}", decision))

    @property
    def public_reason(self) -> str:
        return self.decision.public_reason

    @property
    def fingerprint(self) -> str | None:
        """The :func:`~histos.mediate.approvals.request_fingerprint` to pass to ``grant()``.

        ``None`` only when the exception was constructed without a request, which the
        gate never does — a host building one by hand gets ``None`` rather than a
        fingerprint that would authorise the wrong call.
        """
        if self.request is None:
            return None
        from histos.mediate.approvals import fingerprint_of  # local: approvals imports contracts

        return fingerprint_of(self.request)


class ToolErrorRedacted(GateError):
    """A tool raised, and its error text carried content the policy redacts.

    An exception is the *other* way a tool returns something to the model, so it
    goes through the same content controls as a return value (canary tokens and
    recognised secrets). When nothing had to be removed the original exception is
    re-raised untouched; this type appears **only** when something was.

    The original exception object is deliberately **not** attached — neither as
    ``__cause__`` nor as an attribute — because its ``args`` still hold the
    unredacted text, and a traceback printer would put it back on screen. Only the
    type *name* survives, so a caller can still tell a ``TimeoutError`` from a
    ``ValueError``.
    """

    def __init__(self, decision: GateDecision, original_type: str, text: str) -> None:
        self.decision = decision
        self.original_type = original_type
        super().__init__(text)

    @property
    def public_reason(self) -> str:
        """The non-coaching code safe to hand back to the model (two-audience)."""
        return self.decision.public_reason


class ResourceNotFound(GateError):
    """A ``resource_resolver`` raises this to signal the resource does not exist.

    The engine turns it into a clean ``resource_not_found`` DENY (not a mismatch and
    not an internal error), so "row deleted" reads differently from "resolver threw".
    """
