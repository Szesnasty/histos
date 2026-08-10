"""LangChain adapter (Phase 0.1) — route every LangChain tool through the gate.

Import-guarded: LangChain is **not** a dependency of histos. If it is not
installed, importing this module raises a clear error telling you to install it.

The adapter preserves each tool's ``name`` / ``description`` / ``args_schema`` so
the model still sees an unchanged tool, and replaces its execution with the gated
callable. A denial is returned to the agent as the non-coaching ``public_reason``
(``ACTION_NOT_AUTHORIZED``) — the loop degrades gracefully instead of crashing.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from histos.gate import Gate
from histos.integrations.base import denial_message, guard_callable

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


def _underlying_callable(tool: Any) -> Callable[..., Any]:
    for attr in ("func", "_run", "run"):
        fn = getattr(tool, attr, None)
        if callable(fn):
            return fn
    if callable(tool):
        return tool
    raise TypeError(f"cannot find a callable to gate on tool {getattr(tool, 'name', tool)!r}")


def protect_tool(tool: Any, *, gate: Gate, on_denied: str = "message") -> Any:  # pragma: no cover - needs langchain
    """Return a LangChain ``StructuredTool`` whose execution is gated."""
    _require_langchain()
    name = getattr(tool, "name", None) or getattr(tool, "__name__", None)
    if not name:
        raise TypeError("tool has no `name`")
    guarded = guard_callable(_underlying_callable(tool), name=name, gate=gate, on_denied=on_denied)
    return StructuredTool.from_function(
        func=guarded,
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
    _require_langchain()  # pragma: no cover
    g = gate or Gate(policy, mode=mode)  # pragma: no cover
    return [protect_tool(t, gate=g, on_denied=on_denied) for t in tools]  # pragma: no cover


__all__ = ["denial_message", "protect_tool", "protect_tools"]
