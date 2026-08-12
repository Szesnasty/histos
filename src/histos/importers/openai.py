"""Import OpenAI tool / function definitions into ``ToolContract``.

Two shapes are in circulation and both are accepted, because both are what people
actually paste in:

* the current tools form, ``{"type": "function", "function": {...}}`` or a flat
  ``{"type": "function", "name": ..., "parameters": ...}``;
* the legacy functions form, ``{"name", "description", "parameters"}``.

``parameters`` is a JSON Schema object, so the shared bridge does the work and the
projection is identical to the one MCP gets. A function declares no return schema,
so ``returns`` is always ``None`` here and must be written in the policy if the
result surface needs projecting or redacting.

**Strict mode composes cleanly.** OpenAI's structured-output mode requires
``additionalProperties: false`` with every property listed in ``required``; the
bridge is closed-by-default on the argument surface, so a strict definition imports
unchanged. A *non*-strict definition still imports closed — the disagreement is in
the safe direction, and widening it is an explicit edit in the policy.
"""

from __future__ import annotations

from typing import Any

from histos.contracts import ToolContract
from histos.importers.json_schema import schema_from_json_schema
from histos.importers.sources import (
    UNREVIEWED_ACCESS,
    UNREVIEWED_SENSITIVITY,
    ToolSource,
    contracts_of,
    project_tools,
    register_source_kind,
)


def _unwrap(tool: dict[str, Any]) -> dict[str, Any]:
    """Return the object carrying `name` / `description` / `parameters`."""
    inner = tool.get("function")
    return inner if isinstance(inner, dict) else tool


def source_from_openai(tool: dict[str, Any]) -> ToolSource:
    """One OpenAI tool/function definition → its recorded source and contract."""
    body = _unwrap(tool)
    name = body.get("name")
    if not name:
        raise ValueError("OpenAI tool definition has no 'name'")

    parameters = body.get("parameters")
    description = body.get("description")
    return ToolSource(
        name=name,
        kind="openai",
        description=description if isinstance(description, str) else None,
        # Normative shape for `openai`: the parameters object under "input", and
        # "output": null so the hash has the same shape as every other kind. A
        # function declares no return schema; recording the absence keeps a later
        # addition visible as drift.
        shape={"input": parameters if isinstance(parameters, dict) else None, "output": None},
        # A function definition declares no more about blast radius than MCP does, so
        # it inherits the same unreviewed assumption rather than a friendlier one.
        contract=ToolContract(
            name=name,
            args=schema_from_json_schema(parameters) if isinstance(parameters, dict) else None,
            access=UNREVIEWED_ACCESS,
            sensitivity=UNREVIEWED_SENSITIVITY,
        ),
    )


def sources_from_openai(source: list[dict[str, Any]] | dict[str, Any]) -> list[ToolSource]:
    """Read a list of tool definitions, or an object with a ``tools``/``functions`` key."""
    if isinstance(source, dict):
        tools = source.get("tools")
        if tools is None:
            tools = source.get("functions")
        if tools is None:
            raise ValueError(
                "OpenAI import expects a list of tool definitions, or an object with a 'tools' or "
                f"'functions' key. Got an object with keys: {', '.join(sorted(source)) or '<none>'}."
            )
    else:
        tools = source

    if not isinstance(tools, list):
        raise ValueError(f"OpenAI 'tools' must be a list of tool definitions, got {type(tools).__name__}")

    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            raise ValueError(f"OpenAI tool at position {index} is a {type(tool).__name__}, expected an object")

    return project_tools("openai", tools, lambda t: str(_unwrap(t).get("name") or "<unnamed>"), source_from_openai)


def contracts_from_openai(source: list[dict[str, Any]] | dict[str, Any]) -> list[ToolContract]:
    return contracts_of(sources_from_openai(source))


register_source_kind("openai", sources_from_openai)
