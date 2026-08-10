"""LangGraph adapter (Phase 0.1).

LangGraph's ``ToolNode`` runs LangChain tools, so protecting a tool set for
LangGraph is the same operation as for LangChain: the returned tools are gated and
ready to hand to a ``ToolNode``. Kept as its own module so the import path matches
the framework the developer is using (one policy, any adapter).
"""

from __future__ import annotations

from histos.integrations.langchain import protect_tool, protect_tools

__all__ = ["protect_tool", "protect_tools"]
