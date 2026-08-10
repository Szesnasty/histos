"""LangChain adapter (Phase 0.1) — route every LangChain tool through the gate.

Import-guarded: LangChain is **not** a dependency of histos. If it is not
installed, importing this module raises a clear error telling you to install it.

The protected tool is a **copy** of the one you passed in with its execution
replaced, so the model still sees an unchanged tool and nothing else about it is
lost. A denial is returned to the agent as the non-coaching ``public_reason``
(``ACTION_NOT_AUTHORIZED``) — the loop degrades gracefully instead of crashing.

What this adapter will **not** do is guess. It gates a tool that carries its own
implementation in ``func`` / ``coroutine``; a ``BaseTool`` subclass that runs its own
``_run`` is refused with a ``TypeError`` naming the alternative, because the only way
to gate one here was to rebuild it as something else and drop the rest of it.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from histos.errors import PolicyError
from histos.gate import Gate
from histos.integrations.base import ON_DENIED, denial_message, guard_callable

try:  # pragma: no cover - exercised only where langchain is installed
    from langchain_core.tools import StructuredTool

    _HAVE_LANGCHAIN = True
except ImportError:  # pragma: no cover
    StructuredTool = None  # type: ignore[assignment,misc]
    _HAVE_LANGCHAIN = False


def _require_langchain() -> None:
    if not _HAVE_LANGCHAIN:  # pragma: no cover
        raise ImportError(
            "the LangChain adapter needs `langchain-core` installed "
            "(`pip install langchain-core`); histos itself has no such dependency."
        )


def _underlying_callables(tool: Any) -> tuple[Callable[..., Any] | None, Callable[..., Any] | None]:
    """The tool's own ``(sync, async)`` implementations — never the framework's.

    Picking the first callable among ``func``/``_run``/``run`` meant an async-only
    ``StructuredTool`` (``func=None, coroutine=...``) resolved to LangChain's own
    ``StructuredTool._run`` dispatcher. Gating that produced a tool that raised
    ``TypeError: _run() missing 1 required keyword-only argument: 'config'`` on every
    call while the real implementation stayed ungated on ``coroutine``. Both halves
    come from the fields that actually hold an implementation, or neither does.
    """
    fn = getattr(tool, "func", None)
    coro = getattr(tool, "coroutine", None)
    if callable(fn) or callable(coro):
        sync_fn = fn if callable(fn) else None
        async_fn = coro if callable(coro) else None
        if sync_fn is not None and async_fn is None and inspect.iscoroutinefunction(sync_fn):
            return None, sync_fn  # a coroutine parked in `func` is still a coroutine
        return sync_fn, async_fn
    if callable(tool) and not hasattr(tool, "_run"):
        return (None, tool) if inspect.iscoroutinefunction(tool) else (tool, None)
    raise TypeError(
        f"cannot gate {getattr(tool, 'name', tool)!r}: it exposes no `func` or `coroutine`. "
        "A BaseTool subclass executes its own `_run`, which this adapter cannot replace "
        "without rebuilding the tool as something else; gate the implementation with "
        "histos.integrations.base.guard_callable and build the tool around the result."
    )


def protect_tool(tool: Any, *, gate: Gate, on_denied: str = "message") -> Any:
    """Return a copy of ``tool`` whose execution — sync *and* async — is gated."""
    _require_langchain()
    if on_denied not in ON_DENIED:
        raise PolicyError(f"on_denied must be one of {ON_DENIED}, got {on_denied!r}")
    name = getattr(tool, "name", None) or getattr(tool, "__name__", None)
    if not name:
        raise TypeError("tool has no `name`")

    fn, coro = _underlying_callables(tool)
    guarded = guard_callable(fn, name=name, gate=gate, on_denied=on_denied) if fn is not None else None
    aguarded = guard_callable(coro, name=name, gate=gate, on_denied=on_denied) if coro is not None else None

    copier = getattr(tool, "model_copy", None)
    if callable(copier):
        # Copy and swap the implementation, never rebuild. `from_function` knew about
        # four fields, so `return_direct` (which changes the agent's control flow),
        # `response_format`, `metadata`, `tags`, `callbacks` and `handle_tool_error`
        # were silently dropped the moment a tool was protected.
        return copier(update={"func": guarded, "coroutine": aguarded})
    return StructuredTool.from_function(
        func=guarded,
        coroutine=aguarded,
        name=name,
        description=getattr(tool, "description", "") or "",
        args_schema=getattr(tool, "args_schema", None),
    )


def protect_tools(
    tools: list[Any],
    *,
    policy: Any = None,
    gate: Gate | None = None,
    mode: str = "enforce",
    on_denied: str = "message",
) -> list[Any]:
    """Gate a list of LangChain tools. Pass a shared ``gate`` or a ``policy``."""
    _require_langchain()
    g = gate or Gate(policy, mode=mode)
    return [protect_tool(t, gate=g, on_denied=on_denied) for t in tools]


__all__ = ["denial_message", "protect_tool", "protect_tools"]
