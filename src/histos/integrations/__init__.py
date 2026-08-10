"""Framework adapters — the chokepoint that makes the gate the only path to effect.

The core (:mod:`histos.integrations.base`) is framework-agnostic and always
importable. The framework modules (``langchain``, ``langgraph``) import their
framework lazily, so ``import histos.integrations`` never requires it.
"""

from __future__ import annotations

from histos.integrations.base import (
    denial_message,
    guard_callable,
    protect_functions,
)

__all__ = ["denial_message", "guard_callable", "protect_functions"]
