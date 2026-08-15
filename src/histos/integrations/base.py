"""Framework-agnostic adapter core — the single chokepoint (Phase 0.1).

An adapter's whole job is to make the gate the **only path** a tool call travels:
route the framework's invocation through PRE/POST, and translate a denial into the
**agent-facing, non-coaching** result (`ACTION_NOT_AUTHORIZED`) instead of the rich
developer detail (two-audience, contracts §6). This module is the deterministic core
those adapters share, and it is fully testable without any framework installed.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from histos.contracts import GateDecision, Principal
from histos.errors import GateConfirmationRequired, GateDenied, PolicyError
from histos.gate import Gate
from histos.toolref import _adopt_metadata

ON_DENIED = ("message", "raise")


def denial_message(decision: GateDecision) -> str:
    """The agent-facing string an adapter returns into the loop on a block.

    Deliberately non-coaching — it carries the stable `public_reason` code and
    nothing tunable (no threshold, allowlist, or field). The rich detail stays in
    the audit trail / `GateDenied.decision`.
    """
    return f"[{decision.public_reason}] this tool call was blocked by policy."


def guard_callable(
    fn: Callable[..., Any],
    *,
    name: str,
    gate: Gate,
    on_denied: str = "message",
    fixed_principal: Principal | None = None,
) -> Callable[..., Any]:
    """Wrap one tool callable so every invocation goes through ``gate``.

    ``on_denied="message"`` (default) returns the non-coaching :func:`denial_message`
    as the tool result so the agent loop degrades gracefully; ``on_denied="raise"``
    re-raises the gate exception for the host to handle.

    An ``async def`` tool gets an ``async def`` wrapper. Handing one to the sync
    wrapper looked like it worked — the call returned a coroutine object, so nothing
    raised — while the gate had not run, nothing was audited, and the denial surfaced
    at the framework's ``await`` site as a bare ``GateDenied`` instead of the
    non-coaching result this function exists to return.

    Leave ``fixed_principal`` unset on a server — identity belongs per request, via
    ``use_principal()``. It exists for single-identity scripts and workers.
    """
    if on_denied not in ON_DENIED:
        # A typo here ("Raise", "throw") used to fall through to the message branch,
        # so a host that meant "escalate every denial" silently fed denials back to
        # the model as ordinary tool results. Closed vocabularies fail at wrap time.
        raise PolicyError(f"on_denied must be one of {ON_DENIED}, got {on_denied!r}")

    guarded = gate.wrap(fn, name=name, fixed_principal=fixed_principal)

    if inspect.iscoroutinefunction(guarded):

        async def safe(*args: Any, **kwargs: Any) -> Any:
            try:
                return await guarded(*args, **kwargs)
            except (GateDenied, GateConfirmationRequired) as exc:
                if on_denied == "raise":
                    raise
                return denial_message(exc.decision)

    else:

        def safe(*args: Any, **kwargs: Any) -> Any:  # type: ignore[no-redef,misc]
            try:
                return guarded(*args, **kwargs)
            except (GateDenied, GateConfirmationRequired) as exc:
                if on_denied == "raise":
                    raise
                return denial_message(exc.decision)

    # The same chokepoint `Gate.wrap` uses, for the same reason, and reached through
    # the shared helper rather than re-implemented here. `functools.wraps` used to do
    # this job and was exactly wrong twice over: it publishes `__wrapped__ = fn`, a
    # public pointer at the *ungated* callable that `inspect.unwrap` and every
    # decorator-aware framework follows, and its WRAPPER_UPDATES step copies the
    # target's whole instance `__dict__` — so guarding a callable object holding
    # `self.func = raw_tool` republished the raw tool as `safe.func`. Popping
    # `__wrapped__` afterwards closed the first hole and left the second open, and this
    # adapter is the path a framework's tools actually travel.
    _adopt_metadata(safe, fn, name)
    return safe


def protect_functions(
    functions: list[Callable[..., Any]],
    *,
    policy: Any = None,
    gate: Gate | None = None,
    mode: str = "enforce",
    on_denied: str = "message",
    fixed_principal: Principal | None = None,
) -> tuple[list[Callable[..., Any]], Gate]:
    """Guard a list of plain callables (the framework-free path). Returns
    ``(guarded_functions, gate)`` so the caller can inspect coverage/audit.
    """
    g = gate or Gate(policy, mode=mode)
    guarded = []
    for fn in functions:
        fn_name = getattr(fn, "__name__", None)
        if not fn_name:
            raise ValueError("cannot determine a tool name; wrap it with a name= via guard_callable")
        guarded.append(guard_callable(fn, name=fn_name, gate=g, on_denied=on_denied, fixed_principal=fixed_principal))
    return guarded, g
