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

from histos.errors import PolicyError
from histos.importers.json_schema import schema_from_json_schema
from histos.importers.sources import (
    UNREVIEWED_ACCESS,
    UNREVIEWED_SENSITIVITY,
    ToolSource,
    contracts_of,
    project_tools,
    register_source_kind,
)
from histos.policy.contracts import ToolContract

# Hashed under their own keys, or not part of the shape at all: `name` is the lock's
# key, `description` has its own hash so a description-only change is distinguishable.
_HASHED_ELSEWHERE = frozenset({"name", "description", "inputSchema", "outputSchema"})


def source_from_mcp(tool: dict[str, Any]) -> ToolSource:
    """One MCP tool definition → its recorded source plus the projected contract."""
    name = tool.get("name")
    if not name:
        # `PolicyError`, not `ValueError`: `project_tools` catches `PolicyError` and
        # nothing else, so a per-tool problem raised as anything else escapes the
        # per-tool skip and aborts the whole manifest — every healthy tool in the
        # document lost to one nameless entry. `_reject_unusable_name` already
        # raises `PolicyError` for a name of the wrong type; this is its sibling for
        # a name that is missing, null, empty or `0`.
        raise PolicyError("MCP tool definition has no 'name'", code="invalid_import")
    input_schema = tool.get("inputSchema")
    output_schema = tool.get("outputSchema")
    description = tool.get("description")
    for field, value in (("inputSchema", input_schema), ("outputSchema", output_schema)):
        if field in tool and not isinstance(value, dict):
            raise PolicyError(
                f"MCP tool {name!r} has {field}={value!r}; {field} must be a schema object",
                code="invalid_import",
            )
    if "description" in tool and description is not None and not isinstance(description, str):
        raise PolicyError(
            f"MCP tool {name!r} description must be a string or null, got {type(description).__name__}",
            code="invalid_import",
        )
    return ToolSource(
        name=name,
        kind="mcp",
        description=description,
        # Normative shape for `mcp`: the two schemas under their own keys, plus
        # everything else the server sent under `rest`. `name` is the lock's own key
        # and `description` is hashed separately, so neither belongs here.
        #
        # `rest` exists because the two schemas were the whole shape, and MCP carries
        # more than two fields that a model reads: `title` is displayed instead of the
        # name, `annotations.readOnlyHint` tells a client the tool is safe, `_meta` is
        # open-ended. A vendor could rewrite any of them after review and `histos drift`
        # reported clean — the exact rug pull this demo and this lock exist to catch,
        # through the fields the lock did not look at. Recorded as "the tool object
        # minus what is hashed elsewhere" rather than as a list of known keys, so a
        # field MCP adds next year is inside the hash on the day it appears.
        shape={
            "input": input_schema if isinstance(input_schema, dict) else None,
            "output": output_schema if isinstance(output_schema, dict) else None,
            "rest": {k: v for k, v in sorted(tool.items()) if k not in _HASHED_ELSEWHERE} or None,
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

    # A malformed *manifest* is still a hard failure — nothing in it can be trusted to
    # mean what it says. A tool the projection cannot carry is scoped to that tool; see
    # `project_tools`.
    return project_tools("mcp", tools, lambda t: str(t.get("name") or "<unnamed>"), source_from_mcp)


def contracts_from_mcp(source: list[dict[str, Any]] | dict[str, Any]) -> list[ToolContract]:
    """The contracts alone — one code path with :func:`sources_from_mcp`, so an
    import and a drift check can never disagree about what a definition means."""
    return contracts_of(sources_from_mcp(source))


register_source_kind("mcp", sources_from_mcp)
