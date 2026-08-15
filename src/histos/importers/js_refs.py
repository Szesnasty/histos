"""Following a `$ref`, and composing what is written beside it.

Split out of `json_schema.py`. pydantic — and therefore FastMCP and the MCP Python SDK
— writes every enum and every nested model as a local `$ref`, so refusing them would
make the importer useless on honest servers. A remote, dangling or recursive one is
still refused, because this module never fetches a document and a reference it cannot
follow would silently drop whatever it was meant to supply.

A `$ref` composes by **conjunction**: both the referenced definition and the keywords
beside it must hold. A plain merge is only equivalent when the sibling narrows, and a
sibling that widens threw away the shared definition\'s bound — which is what
`_intersect` is for, and what it was once wrong about for `x-sensitive`, for the
draft-04 booleans, and for `properties`.
"""

from __future__ import annotations

from typing import Any

from histos.errors import PolicyError
from histos.importers.js_vocab import _MAX_REF_DEPTH, _malformed


def _pointer(documents: tuple[dict[str, Any], ...], ref: str) -> Any:
    """Resolve a local JSON pointer (``#/$defs/Mode``) against the documents it may live in."""
    for document in documents:
        node: Any = document
        for raw in ref[2:].split("/"):
            part = raw.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                node = None
                break
            node = node[part]
        if node is not None:
            return node
    return None


def _resolve_refs(node: Any, documents: tuple[dict[str, Any], ...], *, where: str) -> Any:
    """Follow a local ``$ref`` to the schema it names; refuse the ones that cannot be followed.

    Every pydantic-generated schema — so every FastMCP and MCP Python SDK server —
    writes an enum or a nested model as ``{"$ref": "#/$defs/X"}``. That has no
    ``type``, so it used to import as ``type: any``: the enum, the pattern and the
    lengths behind the reference all silently gone, on an honest server. A remote ref
    would mean fetching a document, and this bridge never touches the network; a
    recursive one describes a shape a flat field cannot hold. Both are refused.
    """
    seen: set[str] = set()
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise PolicyError(
                f"imported schema for {where} declares $ref={ref!r}, which is not a pointer into this "
                "document. This bridge never fetches a schema, so the bounds behind that reference "
                "cannot be imported and the field would carry none of them.",
                code="invalid_import",
            )
        if not documents:
            raise PolicyError(
                f"imported schema for {where} declares $ref={ref!r} but no document was supplied to "
                "resolve it against, so the bounds behind the reference cannot be imported.",
                code="invalid_import",
            )
        if ref in seen or len(seen) >= _MAX_REF_DEPTH:
            raise PolicyError(
                f"imported schema for {where} follows $ref={ref!r} into a recursive or over-deep "
                "chain. The projection is one flat field per argument and cannot hold it.",
                code="invalid_import",
            )
        seen.add(ref)
        target = _pointer(documents, ref)
        if not isinstance(target, dict):
            raise PolicyError(
                f"imported schema for {where} declares $ref={ref!r}, which names nothing in this "
                "document. The source is malformed; importing it would produce a field carrying "
                "none of the bounds the reference was meant to supply.",
                code="invalid_import",
            )
        # 2020-12 lets keywords sit next to a `$ref`, and §8.2.3.1 applies the target
        # *in addition to* them — the intersection, not an override. A plain merge is
        # only equivalent when the sibling narrows, and a sibling that widens then
        # silently threw away the shared definition's bound: `{"$ref": "#/$defs/Short",
        # "maxLength": 4096}` produced a field with no short bound at all, which reads
        # as "this schema narrows a shared definition" and does the opposite.
        node = _intersect(target, {k: v for k, v in node.items() if k != "$ref"}, where=where)
    return node


# Bounds where the *tighter* of two values is the intersection, and which way tighter
# runs. Anything not named here is an annotation or a shape the projection carries
# whole, and the sibling simply wins.
_TIGHTER = {
    "maxLength": min,
    "maxItems": min,
    "maximum": min,
    "exclusiveMaximum": min,
    "minLength": max,
    "minItems": max,
    "minimum": max,
    "exclusiveMinimum": max,
}


def _intersect(target: dict[str, Any], sibling: dict[str, Any], *, where: str) -> dict[str, Any]:
    """Apply ``sibling`` on top of ``target`` the way a `$ref` composes: both must hold."""
    merged = dict(target)
    for key, value in sibling.items():
        if key not in merged or merged[key] == value:
            merged[key] = value
            continue
        if key == "x-sensitive":
            # The one keyword this module says is invisible downstream — "nothing later
            # can tell 'not sensitive' from 'meant to be sensitive'" — and it was in
            # neither the tightening table nor the refusal list, so it fell through to
            # sibling-wins. A `$ref` to a definition marked `secret` with
            # `"x-sensitive": "pii"` written beside it imported as `pii`: a downgrade of
            # the marker, written by whoever authored the document. A `$ref` composes by
            # conjunction, so the stricter of the two is the only answer that composes.
            merged[key] = "secret" if "secret" in (merged[key], value) else value
            continue
        tighter = _TIGHTER.get(key)
        if tighter is not None:
            a, b = merged[key], value
            if isinstance(a, bool) or isinstance(b, bool):
                # `True`/`False` are ints, so `min(100, False)` is `False` and
                # `max(0, True)` is `True`. `_numeric` then sees a bool on
                # `exclusiveMinimum`/`exclusiveMaximum`, recognises the draft-04
                # modifier spelling and returns None — so a sibling that is a *no-op*
                # (`exclusiveMaximum: false` means "the maximum is not exclusive")
                # deleted the referenced definition's numeric bound outright. The
                # docstring says the boolean form is ignored rather than guessed at;
                # ignoring it has to leave the numeric one standing.
                merged[key] = b if isinstance(a, bool) else a
                continue
            try:
                merged[key] = tighter(a, b)
                continue
            except TypeError:
                pass
        if key == "properties" and isinstance(merged[key], dict) and isinstance(value, dict):
            # A `$ref` composes by conjunction, so the intersection of two property maps
            # is their union — both objects' properties must hold. The fall-through
            # replaced the map wholesale, which deleted every property the shared
            # definition declared: the exact "a sibling that widens silently threw away
            # the shared definition's bound" that `_intersect` was written to stop, left
            # covering the two composite keywords the object level actually projects.
            merged[key] = {**merged[key], **value}
            continue
        if key == "required" and isinstance(merged[key], list) and isinstance(value, list):
            # By equality, not by hash. A `$ref` sibling whose `required` holds a list
            # or an object raised `TypeError` from inside `_intersect`, and
            # `project_tools` catches `PolicyError` and nothing else — so one malformed
            # tool took the whole manifest down instead of being skipped.
            merged[key] = [*merged[key], *(v for v in value if v not in merged[key])]
            continue
        if key in ("type", "pattern", "enum", "const", "format"):
            # Two of these cannot both hold unless they agree, and guessing which the
            # author meant is how a bound disappears. `type` is the sharp one: a `$ref`
            # to a string definition with `"type": "integer"` beside it is a document
            # that says two things.
            raise _malformed(
                f"{where} $ref sibling {key!r}",
                value,
                f"a value that agrees with the referenced definition ({merged[key]!r}) — a `$ref` applies "
                "in addition to the keywords beside it, so two different values cannot both hold",
            )
        merged[key] = value
    return merged
