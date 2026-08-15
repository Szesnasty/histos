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


def _unwrap(tool: dict[str, Any]) -> dict[str, Any]:
    """Return the object carrying `name` / `description` / `parameters`."""
    if "function" not in tool:
        return tool
    inner = tool["function"]
    if not isinstance(inner, dict):
        raise PolicyError(
            f"OpenAI tool's `function` must be an object, got {type(inner).__name__}",
            code="invalid_import",
        )
    return inner


def _display_name(tool: dict[str, Any]) -> str:
    """Best-effort name for a skip warning; unlike projection, this never raises."""
    inner = tool.get("function")
    body = inner if isinstance(inner, dict) else tool
    return str(body.get("name") or "<unnamed>")


def source_from_openai(tool: dict[str, Any]) -> ToolSource:
    """One OpenAI tool/function definition → its recorded source and contract."""
    declared_type = tool.get("type")
    if "type" in tool and declared_type != "function":
        raise PolicyError(
            f"OpenAI tool type must be 'function' for this importer, got {declared_type!r}",
            code="invalid_import",
        )
    body = _unwrap(tool)
    name = body.get("name")
    if not name:
        # `PolicyError`, not `ValueError`: `project_tools` catches `PolicyError` and
        # nothing else, so a per-tool problem raised as anything else escapes the
        # per-tool skip and aborts the whole manifest — every healthy tool in the
        # document lost to one nameless entry. `_reject_unusable_name` already
        # raises `PolicyError` for a name of the wrong type; this is its sibling for
        # a name that is missing, null, empty or `0`.
        raise PolicyError("OpenAI tool definition has no 'name'", code="invalid_import")

    parameters = body.get("parameters")
    description = body.get("description")
    if "parameters" in body and not isinstance(parameters, dict):
        raise PolicyError(
            f"OpenAI function {name!r} parameters must be a schema object, got {type(parameters).__name__}",
            code="invalid_import",
        )
    if "description" in body and description is not None and not isinstance(description, str):
        raise PolicyError(
            f"OpenAI function {name!r} description must be a string or null, got {type(description).__name__}",
            code="invalid_import",
        )
    wrapped = body is not tool
    container_rest = {key: value for key, value in sorted(tool.items()) if key != "function"} if wrapped else None
    definition_rest = {
        key: value for key, value in sorted(body.items()) if key not in {"name", "description", "parameters"}
    }
    return ToolSource(
        name=name,
        kind="openai",
        description=description,
        # Normative shape for `openai`: the parameters object under "input", and
        # "output": null so the hash has the same shape as every other kind. A
        # function declares no return schema; recording the absence keeps a later
        # addition visible as drift.
        # Everything outside the projected schema is still source evidence. `strict`,
        # the outer tool type and future provider fields can change what the model or
        # host sees even when Histos' contract projection is identical. Keep them under
        # stable buckets so a lock cannot report clean about an un-hashed definition.
        shape={
            "input": parameters if isinstance(parameters, dict) else None,
            "output": None,
            "rest": {"container": container_rest, "definition": definition_rest or None},
        },
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

    return project_tools("openai", tools, _display_name, source_from_openai)


def contracts_from_openai(source: list[dict[str, Any]] | dict[str, Any]) -> list[ToolContract]:
    return contracts_of(sources_from_openai(source))


register_source_kind("openai", sources_from_openai)
