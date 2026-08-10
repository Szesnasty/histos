"""Exceptions raised by the gate.

Two families:

* ``PolicyError`` — the *developer* wired something wrong (structural problem in
  the policy). Raised eagerly, at wrap time, because the trust model
  says the developer is cooperating and wants to know immediately.
* ``GateDenied`` / ``GateConfirmationRequired`` — a *runtime* decision. The gate
  refused (or paused) a call. These carry the :class:`~histos.contracts.GateDecision`
  so the caller can inspect exactly which rule fired.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from histos.contracts import GateDecision


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


class GateDenied(GateError):
    """A call was denied by a gate decision — the fail-closed default."""

    def __init__(self, decision: GateDecision) -> None:
        self.decision = decision
        super().__init__(f"gate denied [{decision.rule}]: {decision.reason}")

    @property
    def public_reason(self) -> str:
        """The non-coaching code safe to hand back to the model (two-audience)."""
        return self.decision.public_reason


class GateConfirmationRequired(GateError):
    """A call needs explicit human/operator confirmation before it may proceed."""

    def __init__(self, decision: GateDecision) -> None:
        self.decision = decision
        super().__init__(f"confirmation required [{decision.rule}]: {decision.reason}")

    @property
    def public_reason(self) -> str:
        return self.decision.public_reason


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
