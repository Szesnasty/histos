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

from histos.errors import PolicyError
from histos.importers.json_schema import _malformed, field_from_json_schema, schema_from_json_schema
from histos.importers.sources import (
    UNREVIEWED_SENSITIVITY,
    ToolSource,
    contracts_of,
    project_tools,
    register_source_kind,
)
from histos.policy.contracts import ToolContract
from histos.policy.schema import Schema

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
    if not isinstance(content, dict):
        raise _malformed(f"the `content` of {where}", content, "a mapping of media type to schema")
    # Matched by base type, not by exact spelling. `application/json; charset=utf-8`,
    # `application/vnd.api+json` (JSON:API) and `application/merge-patch+json` (RFC 7396,
    # which Azure ARM and a great many REST APIs use) are all JSON, and reading them as
    # "no JSON here" used to drop the body silently. Since the drop became a refusal that
    # is the whole operation, so the match has to be the one the media type means.
    body = content.get("application/json")
    if not isinstance(body, dict):
        body = next(
            (
                media
                for media_type, media in content.items()
                if isinstance(media_type, str) and isinstance(media, dict) and _is_json_media_type(media_type)
            ),
            None,
        )
    schema = _deref(spec, body.get("schema"), where=where) if isinstance(body, dict) else None
    return schema if isinstance(schema, dict) else None


def _is_json_media_type(media_type: str) -> bool:
    """`application/json`, with any parameters, and the `+json` structured suffixes."""
    base = media_type.split(";", 1)[0].strip().lower()
    return base == "application/json" or base.endswith("+json")


def _schema_names_fields(spec: dict[str, Any], schema: Any, where: str, depth: int = 0) -> bool:
    """Whether this schema, or anything it composes with, declares named properties.

    `allOf: [{$ref: '#/components/schemas/Form'}]` is the ordinary way a hand-written or
    generated spec extends a shared model, and looking only at the top level read it as
    "declares nothing" — so a composed form body went back to being dropped in silence,
    which is the whole finding this function was written for.
    """
    if not isinstance(schema, dict):
        return False
    if depth > 4:
        # Giving up is not evidence of absence. Returning False here said "declares
        # nothing", and the caller reads that as "a byte stream, drop it" — the silent
        # drop this function exists to prevent, reachable on a hostile spec for the cost
        # of six lines of nested `allOf`.
        return True
    if schema.get("properties"):
        return True
    for keyword in ("allOf", "anyOf", "oneOf"):
        branches = schema.get(keyword)
        if not isinstance(branches, list):
            continue
        for branch in branches:
            try:
                resolved = _deref(spec, branch, where=where)
            except PolicyError:
                return True  # a branch that cannot even be resolved is not a byte stream
            if _schema_names_fields(spec, resolved, where, depth + 1):
                return True
    return False


def _declares_fields(spec: dict[str, Any], content: Any, name: str) -> bool:
    """Whether a non-JSON request body declares named fields the projection would lose.

    A form body (`application/x-www-form-urlencoded`, `multipart/form-data`) is an
    object with properties: every one of those is an argument, and dropping the body
    silently means the gate denies each of them at call time. A byte stream
    (`application/octet-stream`, an image, a PDF) declares no names at all — there is
    nothing for the projection to lose, and refusing it would cost the operation its
    perfectly importable query parameters.
    """
    if not isinstance(content, dict):
        return False
    for media_type, media in content.items():
        if not isinstance(media, dict):
            continue
        try:
            schema = _deref(spec, media.get("schema"), where=f"requestBody {media_type} of {name!r}")
        except PolicyError:
            return True  # a body whose schema cannot even be resolved is not a stream
        # `properties` only. A bare `{"type": "object"}` — the opaque-payload shape a
        # merge-patch body and every "free-form object" body uses — names nothing, so
        # there is nothing for the projection to lose and refusing it costs the operation
        # its query parameters for no gain. The docstring above always said "declares
        # named fields"; the extra arm contradicted it.
        if _schema_names_fields(spec, schema, f"requestBody {media_type} of {name!r}"):
            return True
    return False


def _effective_servers(spec: dict[str, Any], item: dict[str, Any], op: dict[str, Any], name: str) -> list[Any] | None:
    """Return the nearest declared server list, preserving explicit emptiness."""
    for level, owner in (("operation", op), ("path item", item), ("document", spec)):
        if "servers" not in owner:
            continue
        servers = owner["servers"]
        if not isinstance(servers, list):
            raise _malformed(f"the {level} `servers` of {name!r}", servers, "a list of server objects")
        for index, server in enumerate(servers):
            if not isinstance(server, dict):
                raise _malformed(f"{level} server {index} of {name!r}", server, "an object")
            url = server.get("url")
            if not isinstance(url, str) or not url:
                raise _malformed(f"the URL of {level} server {index} of {name!r}", url, "a non-empty string")
        return servers
    return None


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
                raise _malformed(f"{source} parameter {index} of {name!r}", param, "an object or local $ref")
            pname = param.get("name")
            location = param.get("in")
            if not isinstance(pname, str) or not pname:
                raise _malformed(f"the name of {source} parameter {index} of {name!r}", pname, "a non-empty string")
            if not isinstance(location, str) or location not in {"query", "header", "path", "cookie"}:
                raise _malformed(
                    f"the `in` value of parameter {pname!r} of {name!r}",
                    location,
                    "one of 'query', 'header', 'path', or 'cookie'",
                )
            key = (pname, location)
            if key in merged:
                ordered[ordered.index(merged[key])] = param
            else:
                ordered.append(param)
            merged[key] = param
    for param in ordered:
        resolved_params.append(param)
        pname = param.get("name")
        has_schema = "schema" in param
        has_content = "content" in param
        if has_schema and has_content:
            raise _malformed(
                f"parameter {pname!r} of {name!r}",
                {key: param[key] for key in ("schema", "content") if key in param},
                "an object containing at most one of `schema` or `content`",
            )
        if has_schema:
            schema = param["schema"]
            if not isinstance(schema, dict):
                raise _malformed(f"the schema of parameter {pname!r} of {name!r}", schema, "a schema object")
        elif has_content:
            # The `content` form: a parameter whose value is a serialised media type
            # rather than a plain scalar. `schema` is absent and the schema lives one
            # level down. It used to fall through to `{}` — an untyped `any` field
            # carrying none of the bounds the document wrote, which is the silent drop
            # this module refuses everywhere else.
            content = param["content"]
            if not isinstance(content, dict) or not content:
                raise _malformed(
                    f"the content of parameter {pname!r} of {name!r}",
                    content,
                    "a non-empty mapping of media type to schema",
                )
            schema = _json_schema_of(spec, content, where=f"parameter {pname!r} of {name!r}")
            if schema is None:
                raise _malformed(
                    f"parameter {pname!r} of {name!r}",
                    sorted(map(str, content)),
                    "a `content` block this projection can read (application/json)",
                )
        else:
            # Kept for the importer's documented best-effort mode: a parameter with no
            # shape is represented honestly as an untyped field. A *present* malformed
            # schema/content is different — it reads as a bound and is refused above.
            schema = {}
        required = param.get("required", False)
        if not isinstance(required, bool):
            raise _malformed(f"required on parameter {pname!r} of {name!r}", required, "a boolean")
        if param.get("in") == "path" and required is not True:
            raise _malformed(
                f"required on path parameter {pname!r} of {name!r}",
                required,
                "true (OpenAPI path parameters are always required)",
            )
        fields[pname] = field_from_json_schema(schema, required=required, root=spec, name=pname)

    body_schema = None
    request_body = _deref(spec, op.get("requestBody", {}), where=f"requestBody of {name!r}")
    if not isinstance(request_body, dict):
        raise _malformed(f"the requestBody of {name!r}", request_body, "an object or local $ref")
    if request_body:
        body_required = request_body.get("required", False)
        if not isinstance(body_required, bool):
            raise _malformed(f"required on requestBody of {name!r}", body_required, "a boolean")
        if "content" not in request_body:
            raise _malformed(f"the requestBody of {name!r}", request_body, "an object containing `content`")
        content = request_body.get("content", {})
        body_schema = _json_schema_of(spec, content, where=f"requestBody of {name!r}")
        # The parameter path refuses an unsupported media type loudly, naming the
        # parameter and what it found; this one took the same `None` and dropped the
        # entire body without a word. `args` then kept only the path and query
        # parameters, `allow_extra` stayed False, and the gate denied every argument the
        # document declares with `arg_schema: unexpected argument (not in schema)` —
        # which says nothing about the source. Worse for review: `shape["requestBody"]`
        # recorded null, so `histos drift` had nothing to compare and the tool read as
        # having no body at all.
        #
        # Only when the body would lose *named fields*. Refusing every non-JSON media
        # type takes out `application/octet-stream` — a raw upload stream, which
        # declares no arguments to lose and whose operation's query parameters import
        # perfectly well. `uploadFile` in the standard Petstore document is exactly
        # that. So the question is whether the body declares an object with properties:
        # a form body does, and dropping it is the silent drop; a byte stream does not,
        # and refusing it would be the false positive.
        if body_schema is None and _declares_fields(spec, content, name):
            raise _malformed(
                f"the requestBody of {name!r}",
                sorted(content),
                "a `content` carrying an application/json schema — this importer projects that media "
                "type only, and this body declares named fields, so dropping it would produce a policy "
                "that denies every one of them at call time with nothing naming the source",
            )
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
    for source_field in ("description", "summary"):
        value = op.get(source_field)
        if source_field in op and value is not None and not isinstance(value, str):
            raise _malformed(f"the {source_field} of {name!r}", value, "a string or null")
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
            "servers": _effective_servers(spec, item or {}, op, name),
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
    if not isinstance(spec, dict):
        raise _malformed("the OpenAPI document", spec, "an object")
    operations: list[tuple[str, str, dict[str, Any], str, dict[str, Any]]] = []
    paths = spec.get("paths")
    paths = {} if paths is None else paths
    # A document-level shape, so a document-level refusal: this one is not about a tool
    # and there is no tool to skip. It used to reach `.items()` as an `AttributeError`
    # and fly out of the CLI as a traceback.
    if not isinstance(paths, dict):
        raise _malformed("the document's `paths`", paths, "a mapping of path to path item")
    for path, item in paths.items():
        if not isinstance(path, str):
            raise _malformed("a key in the document's `paths`", path, "a path string")
        if not isinstance(item, dict):
            raise _malformed(f"path item {path!r}", item, "an object")
        for method in _METHODS:
            if method not in item:
                continue
            op = item.get(method)
            if not isinstance(op, dict):
                raise _malformed(f"operation {method.upper()} {path}", op, "an object")
            # Missing operationId gets a deterministic fallback. Present-but-empty or
            # malformed is different: it is a declared identity we cannot preserve and
            # is refused per tool by ToolSource rather than silently renamed.
            name = (
                op["operationId"] if "operationId" in op else f"{method}_{path.strip('/').replace('/', '_') or 'root'}"
            )
            operations.append((path, method, op, name, item))

    return project_tools(
        "openapi",
        operations,
        lambda entry: str(entry[3] or "<unnamed>"),
        lambda entry: _source_from_operation(spec, *entry),
    )


def contracts_from_openapi(spec: dict[str, Any]) -> list[ToolContract]:
    return contracts_of(sources_from_openapi(spec))


register_source_kind("openapi", sources_from_openapi)
