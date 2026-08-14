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
from histos.importers.json_schema import _malformed, field_from_json_schema, schema_from_json_schema
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
    # One hop was not enough: a document that points `parameters/A` at `parameters/B`
    # returned a node still carrying `$ref`, and the caller then read no `name` off it
    # and dropped the argument silently — the miss this function was written to stop,
    # one indirection further out. Bounded and cycle-checked like the schema bridge.
    seen: set[str] = set()
    for _ in range(_MAX_DEREF_DEPTH):
        if not (isinstance(node, dict) and "$ref" in node):
            return node
        pointer = node["$ref"]
        if isinstance(pointer, str) and pointer in seen:
            raise PolicyError(
                f"imported OpenAPI {where} follows a $ref cycle through {pointer!r}",
                code="invalid_import",
            )
        if isinstance(pointer, str):
            seen.add(pointer)
        node = _deref_once(spec, node, where=where)
    raise PolicyError(
        f"imported OpenAPI {where} follows a $ref chain deeper than {_MAX_DEREF_DEPTH} hops",
        code="invalid_import",
    )


_MAX_DEREF_DEPTH = 8


def _deref_once(spec: dict[str, Any], node: Any, *, where: str) -> Any:
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


def _json_schema_of(spec: dict[str, Any], content: Any, *, where: str) -> dict[str, Any] | None:
    # `content` is type-checked rather than assumed. A `content:` key left empty in YAML
    # parses to `None` and a sequence parses to a list, and both reached `.get` here as
    # an `AttributeError` — which is not a `PolicyError`, so `project_tools` did not skip
    # the one bad tool and the CLI's handler chain did not turn it into an exit code. The
    # user got a traceback out of `histos import` and no policy file. Seven of the eight
    # malformed nodes in this module behaved that way.
    if content is None:
        return None
    if not isinstance(content, dict):
        raise _malformed(f"the `content` of {where}", content, "a mapping of media type to schema")
    body = content.get("application/json", {})
    schema = _deref(spec, body.get("schema"), where=where) if isinstance(body, dict) else None
    return schema if isinstance(schema, dict) else None


def _source_from_operation(
    spec: dict[str, Any],
    path: str,
    method: str,
    op: dict[str, Any],
    name: str,
    item: dict[str, Any] | None = None,
) -> ToolSource:
    """One ``path`` × ``method`` operation → its recorded source plus the contract.

    ``spec`` is threaded into every bridge call as the document a local ``$ref``
    resolves against; in OpenAPI the definitions live in ``#/components/schemas``,
    which is nowhere near the fragment being projected.
    """
    fields = {}
    resolved_params: list[Any] = []
    # Path-item parameters first, then the operation's own. OpenAPI 3.x lets a `path`
    # item carry `parameters` that apply to every operation under it, which is the
    # normal place to put a shared path variable — and reading only `op["parameters"]`
    # meant that variable was simply absent from the contract. The schema is closed, so
    # the caller then had an argument the tool needs and the gate denies, with nothing
    # anywhere saying why. The operation's entry wins on a `(name, in)` collision, which
    # is what the specification says overriding means.
    merged: dict[tuple[str, str], Any] = {}
    ordered: list[Any] = []
    for source, raw_params in (
        ("path item", (item or {}).get("parameters", [])),
        ("operation", op.get("parameters", [])),
    ):
        if not isinstance(raw_params, list):
            raise _malformed(f"the {source} `parameters` of {name!r}", raw_params, "a list")
        for index, raw_param in enumerate(raw_params):
            param = _deref(spec, raw_param, where=f"{source} parameter {index} of {name!r}")
            if not isinstance(param, dict):
                continue
            key = (str(param.get("name")), str(param.get("in")))
            if key in merged:
                ordered[ordered.index(merged[key])] = param
            else:
                ordered.append(param)
            merged[key] = param
    for param in ordered:
        resolved_params.append(param)
        pname = param.get("name")
        if not pname:
            continue
        schema = param.get("schema") if isinstance(param.get("schema"), dict) else None
        if schema is None:
            # The `content` form: a parameter whose value is a serialised media type
            # rather than a plain scalar. `schema` is absent and the schema lives one
            # level down. It used to fall through to `{}` — an untyped `any` field
            # carrying none of the bounds the document wrote, which is the silent drop
            # this module refuses everywhere else.
            content = param.get("content")
            if isinstance(content, dict) and content:
                schema = _json_schema_of(spec, content, where=f"parameter {pname!r} of {name!r}")
                if schema is None:
                    raise _malformed(
                        f"parameter {pname!r} of {name!r}",
                        sorted(content),
                        "a `content` block this projection can read (application/json)",
                    )
            else:
                schema = {}
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
    responses = op.get("responses")
    responses = {} if responses is None else responses
    if not isinstance(responses, dict):
        raise _malformed(f"the `responses` of {name!r}", responses, "a mapping of status code to response")
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
            # Where the call actually goes. Outside the shape, a vendor could repoint
            # every request at their own host after review and `histos drift` reported
            # clean: same method, same path, same schemas, different server. Nothing
            # about the tool's *shape* had changed, and that was the bug — the shape was
            # not describing the whole tool.
            #
            # OpenAPI resolves `servers` at **three** levels, and this read two of them.
            # The path item sits between the operation and the document, and adding
            # `servers` there repoints every method on that path at once — a smaller
            # diff than editing each operation, and it was the invisible one: the same
            # host repoint was caught at the operation level and passed drift at the
            # path-item level, exit 0.
            "servers": op.get("servers") or (item or {}).get("servers") or spec.get("servers") or None,
            "parameters": resolved_params,
            "requestBody": body_schema,
            "responses": response_schema,
        },
        contract=ToolContract(name=name, args=args, returns=returns, access=access, sensitivity=UNREVIEWED_SENSITIVITY),
    )


def sources_from_openapi(spec: dict[str, Any]) -> list[ToolSource]:
    """Read every operation as a tool, recording what was actually consumed.

    The normative shape for ``openapi`` holds the **dereferenced** fragments the
    projection read — parameters, request body schema, response schema — rather than
    the operation as written. Hashing the raw operation would miss a
    ``#/components/schemas`` target changing underneath an unchanged ``$ref``.
    """
    operations: list[tuple[str, str, dict[str, Any], str, dict[str, Any]]] = []
    paths = spec.get("paths")
    paths = {} if paths is None else paths
    # A document-level shape, so a document-level refusal: this one is not about a tool
    # and there is no tool to skip. It used to reach `.items()` as an `AttributeError`
    # and fly out of the CLI as a traceback.
    if not isinstance(paths, dict):
        raise _malformed("the document's `paths`", paths, "a mapping of path to path item")
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in _METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            name = op.get("operationId") or f"{method}_{path.strip('/').replace('/', '_') or 'root'}"
            operations.append((path, method, op, name, item))

    return project_tools(
        "openapi",
        operations,
        lambda entry: entry[3],
        lambda entry: _source_from_operation(spec, *entry),
    )


def contracts_from_openapi(spec: dict[str, Any]) -> list[ToolContract]:
    return contracts_of(sources_from_openapi(spec))


register_source_kind("openapi", sources_from_openapi)
