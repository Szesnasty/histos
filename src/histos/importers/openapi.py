"""Import an OpenAPI 3 spec into ``ToolContract`` objects (best-effort).

Each ``path`` × ``method`` operation becomes a tool:

* ``operationId`` (or ``method_path``) → tool name
* ``parameters`` (path/query/header) + JSON ``requestBody`` properties → args
* a ``2xx`` JSON response schema → returns
* ``GET`` → ``access="read"``; ``POST/PUT/PATCH/DELETE`` → ``access="write"``
* ``sensitivity`` is not expressible in OpenAPI, so it imports as
  :data:`~histos.importers.sources.UNREVIEWED_SENSITIVITY` until a human writes one

This covers the common REST-tool shape. Local ``#/components`` references are
resolved — the whole document is handed to the JSON Schema bridge as the root a
``$ref`` points into, which is the only way ``parameters[].schema.$ref``, a
``$ref``'d parameter *object*, and a ``requestBody`` property ``$ref`` can carry
their bounds. The bridge used to be called with no root at all, so every one of
those refused with "no document was supplied to resolve it against" or, worse, with
"names nothing in this document" about a target sitting in ``components/schemas``.
Only a spec with no ``$ref`` in it imported, which is close to no spec at all.
Anything beyond a local pointer — a remote or a recursive reference — is refused by
the bridge and should be imported via MCP/JSON Schema or authored by hand.
"""

from __future__ import annotations

from typing import Any

from histos.contracts import ToolContract
from histos.errors import PolicyError
from histos.importers.json_schema import field_from_json_schema, schema_from_json_schema
from histos.importers.sources import (
    UNREVIEWED_SENSITIVITY,
    ToolSource,
    contracts_of,
    project_tools,
    register_source_kind,
)
from histos.schema import Schema

_METHODS = ("get", "post", "put", "patch", "delete")


def _deref(spec: dict[str, Any], node: Any, *, where: str) -> Any:
    """Follow a local ``$ref`` on a non-schema construct — a parameter or a response.

    A miss used to come back as ``{}``: a ``$ref`` to a parameter that is not in
    ``components/parameters`` produced an *empty parameter*, so the argument it
    declared vanished from the contract without a word. A reference this importer
    cannot follow is now refused, the same way the JSON Schema bridge refuses one.
    """
    if not (isinstance(node, dict) and "$ref" in node):
        return node
    ref = node["$ref"]
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise PolicyError(
            f"imported OpenAPI {where} declares $ref={ref!r}, which is not a pointer into this "
            "document. This importer never fetches a document, so what the reference declares "
            "cannot be imported.",
            code="invalid_import",
        )
    target: Any = spec
    for raw in ref[2:].split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, dict) or part not in target:
            raise PolicyError(
                f"imported OpenAPI {where} declares $ref={ref!r}, which names nothing in this "
                "document. The source is malformed; importing it would silently drop whatever the "
                "reference was meant to supply.",
                code="invalid_import",
            )
        target = target[part]
    return target


def _json_schema_of(spec: dict[str, Any], content: dict[str, Any], *, where: str) -> dict[str, Any] | None:
    body = content.get("application/json", {})
    schema = _deref(spec, body.get("schema"), where=where) if isinstance(body, dict) else None
    return schema if isinstance(schema, dict) else None


def _source_from_operation(spec: dict[str, Any], path: str, method: str, op: dict[str, Any], name: str) -> ToolSource:
    """One ``path`` × ``method`` operation → its recorded source plus the contract.

    ``spec`` is threaded into every bridge call as the document a local ``$ref``
    resolves against; in OpenAPI the definitions live in ``#/components/schemas``,
    which is nowhere near the fragment being projected.
    """
    fields = {}
    resolved_params: list[Any] = []
    for index, raw_param in enumerate(op.get("parameters", [])):
        param = _deref(spec, raw_param, where=f"parameter {index} of {name!r}")
        if not isinstance(param, dict):
            continue
        resolved_params.append(param)
        pname = param.get("name")
        if not pname:
            continue
        schema = param.get("schema", {}) if isinstance(param.get("schema"), dict) else {}
        fields[pname] = field_from_json_schema(schema, required=bool(param.get("required")), root=spec, name=pname)

    body_schema = None
    request_body = op.get("requestBody", {})
    if isinstance(request_body, dict):
        body_schema = _json_schema_of(spec, request_body.get("content", {}), where=f"requestBody of {name!r}")
        if body_schema:
            for fname, field in schema_from_json_schema(body_schema, root=spec).fields.items():
                fields[fname] = field

    args = Schema(fields) if fields else None

    returns = None
    response_schema = None
    responses = op.get("responses", {})
    for code in ("200", "201", "default"):
        raw_response = responses.get(code)
        if not isinstance(raw_response, dict):
            continue
        where = f"response {code} of {name!r}"
        resp = _deref(spec, raw_response, where=where)
        if isinstance(resp, dict):
            rschema = _json_schema_of(spec, resp.get("content", {}), where=where)
            if rschema:
                response_schema = rschema
                returns = schema_from_json_schema(rschema, root=spec)
                break

    # The method is the one security semantic OpenAPI genuinely declares, so
    # `access` is read from the document rather than assumed. Sensitivity is
    # not declared anywhere in OpenAPI, so it stays unreviewed: a `GET
    # /patients/{id}` is a read, and nothing in the spec says whether reading
    # it matters.
    access = "read" if method == "get" else "write"
    description = op.get("description") or op.get("summary")
    return ToolSource(
        name=name,
        kind="openapi",
        description=description if isinstance(description, str) else None,
        shape={
            "method": method,
            "path": path,
            # Where the call actually goes. The operation-level override wins over the
            # document's, exactly as OpenAPI resolves it. Outside the shape, a vendor
            # could repoint every request at their own host after review and `histos
            # drift` reported clean: same method, same path, same schemas, different
            # server. Nothing about the tool's *shape* had changed, and that was the
            # bug — the shape was not describing the whole tool.
            "servers": op.get("servers") or spec.get("servers") or None,
            "parameters": resolved_params,
            "requestBody": body_schema,
            "responses": response_schema,
        },
        contract=ToolContract(
            name=name, args=args, returns=returns, access=access, sensitivity=UNREVIEWED_SENSITIVITY
        ),
    )


def sources_from_openapi(spec: dict[str, Any]) -> list[ToolSource]:
    """Read every operation as a tool, recording what was actually consumed.

    The normative shape for ``openapi`` holds the **dereferenced** fragments the
    projection read — parameters, request body schema, response schema — rather than
    the operation as written. Hashing the raw operation would miss a
    ``#/components/schemas`` target changing underneath an unchanged ``$ref``.
    """
    operations: list[tuple[str, str, dict[str, Any], str]] = []
    paths = spec.get("paths", {})
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in _METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            name = op.get("operationId") or f"{method}_{path.strip('/').replace('/', '_') or 'root'}"
            operations.append((path, method, op, name))

    return project_tools(
        "openapi",
        operations,
        lambda entry: entry[3],
        lambda entry: _source_from_operation(spec, *entry),
    )


def contracts_from_openapi(spec: dict[str, Any]) -> list[ToolContract]:
    return contracts_of(sources_from_openapi(spec))


register_source_kind("openapi", sources_from_openapi)
