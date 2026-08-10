"""Import an OpenAPI 3 spec into ``ToolContract`` objects (best-effort).

Each ``path`` × ``method`` operation becomes a tool:

* ``operationId`` (or ``method_path``) → tool name
* ``parameters`` (path/query/header) + JSON ``requestBody`` properties → args
* a ``2xx`` JSON response schema → returns
* ``GET`` → ``access="read"``; ``POST/PUT/PATCH/DELETE`` → ``access="write"``

This covers the common REST-tool shape. ``$ref`` resolution is intentionally
minimal (local ``#/components/schemas`` refs one level deep); anything more exotic
should be imported via MCP/JSON Schema or authored in the policy bundle.
"""

from __future__ import annotations

from typing import Any

from histos.contracts import ToolContract
from histos.importers.json_schema import field_from_json_schema, schema_from_json_schema
from histos.importers.sources import ToolSource, contracts_of
from histos.schema import Schema

_METHODS = ("get", "post", "put", "patch", "delete")


def _deref(spec: dict[str, Any], node: Any) -> Any:
    if isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if isinstance(ref, str) and ref.startswith("#/"):
            target: Any = spec
            for part in ref[2:].split("/"):
                if not isinstance(target, dict) or part not in target:
                    return {}
                target = target[part]
            return target
    return node


def _json_schema_of(spec: dict[str, Any], content: dict[str, Any]) -> dict[str, Any] | None:
    body = content.get("application/json", {})
    schema = _deref(spec, body.get("schema")) if isinstance(body, dict) else None
    return schema if isinstance(schema, dict) else None


def sources_from_openapi(spec: dict[str, Any]) -> list[ToolSource]:
    """Read every operation as a tool, recording what was actually consumed.

    The normative shape for ``openapi`` holds the **dereferenced** fragments the
    projection read — parameters, request body schema, response schema — rather than
    the operation as written. Hashing the raw operation would miss a
    ``#/components/schemas`` target changing underneath an unchanged ``$ref``.
    """
    sources: list[ToolSource] = []
    paths = spec.get("paths", {})
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in _METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue

            name = op.get("operationId") or f"{method}_{path.strip('/').replace('/', '_') or 'root'}"

            fields = {}
            resolved_params: list[Any] = []
            for param in op.get("parameters", []):
                param = _deref(spec, param)
                resolved_params.append(param)
                pname = param.get("name")
                if not pname:
                    continue
                schema = param.get("schema", {}) if isinstance(param.get("schema"), dict) else {}
                fields[pname] = field_from_json_schema(schema, required=bool(param.get("required")))

            body_schema = None
            request_body = op.get("requestBody", {})
            if isinstance(request_body, dict):
                body_schema = _json_schema_of(spec, request_body.get("content", {}))
                if body_schema:
                    for fname, field in schema_from_json_schema(body_schema).fields.items():
                        fields[fname] = field

            args = Schema(fields) if fields else None

            returns = None
            response_schema = None
            responses = op.get("responses", {})
            for code in ("200", "201", "default"):
                resp = _deref(spec, responses.get(code)) if isinstance(responses.get(code), dict) else None
                if isinstance(resp, dict):
                    rschema = _json_schema_of(spec, resp.get("content", {}))
                    if rschema:
                        response_schema = rschema
                        returns = schema_from_json_schema(rschema)
                        break

            access = "read" if method == "get" else "write"
            description = op.get("description") or op.get("summary")
            sources.append(
                ToolSource(
                    name=name,
                    kind="openapi",
                    description=description if isinstance(description, str) else None,
                    shape={
                        "method": method,
                        "path": path,
                        "parameters": resolved_params,
                        "requestBody": body_schema,
                        "responses": response_schema,
                    },
                    contract=ToolContract(name=name, args=args, returns=returns, access=access),
                )
            )

    return sources


def contracts_from_openapi(spec: dict[str, Any]) -> list[ToolContract]:
    return contracts_of(sources_from_openapi(spec))
