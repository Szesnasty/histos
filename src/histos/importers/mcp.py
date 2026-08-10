"""Import MCP (Model Context Protocol) tool definitions into ``ToolContract``.

An MCP tool is ``{"name", "description", "inputSchema", "outputSchema"?}`` where
the schemas are JSON Schema objects. We map ``inputSchema`` → args and
``outputSchema`` → returns. MCP declares neither read/write nor sensitivity, so both
come back as :data:`~histos.importers.sources.UNREVIEWED_ACCESS` /
:data:`~histos.importers.sources.UNREVIEWED_SENSITIVITY` — the most damaging reading,
held until a human writes one in the policy bundle. ``review_policy`` reports every
tool still carrying that assumption as an outstanding decision.
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
    register_source_kind,
)


def source_from_mcp(tool: dict[str, Any]) -> ToolSource:
    """One MCP tool definition → its recorded source plus the projected contract."""
    name = tool.get("name")
    if not name:
        raise ValueError("MCP tool definition has no 'name'")
    input_schema = tool.get("inputSchema")
    output_schema = tool.get("outputSchema")
    description = tool.get("description")
    return ToolSource(
        name=name,
        kind="mcp",
        description=description if isinstance(description, str) else None,
        # Normative shape for `mcp`: the two schemas, under these two keys, and
        # nothing else. `name` is the lock's own key and `description` is hashed
        # separately, so neither belongs here.
        shape={
            "input": input_schema if isinstance(input_schema, dict) else None,
            "output": output_schema if isinstance(output_schema, dict) else None,
        },
        contract=ToolContract(
            name=name,
            args=schema_from_json_schema(input_schema) if isinstance(input_schema, dict) else None,
            returns=schema_from_json_schema(output_schema) if isinstance(output_schema, dict) else None,
            access=UNREVIEWED_ACCESS,
            sensitivity=UNREVIEWED_SENSITIVITY,
        ),
    )


def contract_from_mcp(tool: dict[str, Any]) -> ToolContract:
    return source_from_mcp(tool).contract


def sources_from_mcp(source: list[dict[str, Any]] | dict[str, Any]) -> list[ToolSource]:
    """Read MCP tool definitions, from either shape people actually have.

    A ``tools/list`` response is ``{"tools": [...]}``, and that is what somebody
    importing a real server will paste in. A bare list is what you get after
    unwrapping it yourself. Both are accepted, because refusing the first one
    means the very first command in the funnel fails on the very file the
    protocol told the user to expect.
    """
    if isinstance(source, dict):
        tools = source.get("tools")
        if tools is None:
            raise ValueError(
                "MCP import expects a tools/list response with a 'tools' key, or a bare list of tool "
                f"definitions. Got an object with keys: {', '.join(sorted(source)) or '<none>'}."
            )
    else:
        tools = source

    if not isinstance(tools, list):
        raise ValueError(f"MCP 'tools' must be a list of tool definitions, got {type(tools).__name__}")

    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            raise ValueError(f"MCP tool at position {index} is a {type(tool).__name__}, expected an object")

    return [source_from_mcp(t) for t in tools]


def contracts_from_mcp(source: list[dict[str, Any]] | dict[str, Any]) -> list[ToolContract]:
    """The contracts alone — one code path with :func:`sources_from_mcp`, so an
    import and a drift check can never disagree about what a definition means."""
    return contracts_of(sources_from_mcp(source))


register_source_kind("mcp", sources_from_mcp)
