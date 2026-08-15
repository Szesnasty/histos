"""The shared bridge: a JSON Schema object → a histos :class:`Schema`.

Deliberately a *subset* — the pieces that map cleanly onto deterministic
validation: ``type``, ``required``, ``enum``, ``minLength`` / ``maxLength``,
``pattern``, the numeric bounds (``minimum``, ``maximum``, ``exclusiveMinimum``,
``exclusiveMaximum``, ``multipleOf``), and for an array ``items.type`` plus those
same scalar bounds when they are written inside ``items`` — the engine applies them
per element already. An ``x-sensitive`` extension (``"pii"`` | ``"secret"``) marks a
field for post-gate redaction on a *return* schema.

A bound the tool author already wrote must survive the import. Dropping one is
worse than never having it: the generated policy *looks* like it carries the
constraint, and the reviewer has no reason to re-derive it by hand. Draft-4's
boolean form of ``exclusiveMinimum`` / ``exclusiveMaximum`` is ignored rather than
guessed at — only the numeric (draft 6+) form is honoured.

That invariant used to hold for malformed *values* only. A malformed
``maxLength: "50"`` was refused, while an unrecognised *keyword* was dropped in
silence: ``{"$ref": "#/$defs/Mode"}`` has no ``type``, so it imported as
``type: any`` — no type, no enum, no pattern, weaker than never importing the field
at all — and ``const``, ``minItems``, ``anyOf`` and a nested ``properties`` went the
same way. So an assertion keyword this bridge cannot project is now refused by name,
exactly as a malformed value is. Annotations (``title``, ``description``,
``default``, ``examples``, ``format``, ``$comment``, ``readOnly``, vendor ``x-``
keys) assert nothing about a value and are still ignored in silence.

A ``$ref`` into the same document is resolved rather than refused: pydantic — and
therefore FastMCP and the MCP Python SDK — writes every enum and every nested model
that way, so refusing it would make the MCP importer useless on honest servers. A
remote, dangling or recursive one is refused.

Refusing by name was over-applied in its first round, and that is its own release
blocker: an ordinary pydantic surface stopped importing at all, because ``const``,
``anyOf: [T, null]`` — what *every* ``Optional[T]`` emits — and an element ``enum``
were all on the refusal list even though each of them projects onto this Field model
without losing anything. A screen that refuses honest input teaches its user to stop
importing, which is the same outcome as the hole it closed. So the three shapes that
are honestly projectable are projected (see ``_collapse_union``, ``_fold_const`` and
``_element_enum_pattern``), and only what genuinely cannot be held by one flat field
— a real union, a nested object, a recursive model — is still refused.

The refusal list is written out rather than derived as "every keyword we do not
recognise", because a real document also carries vendor keys that constrain nothing.
The honest limit of that choice: an assertion keyword from a draft newer than the
list is still dropped silently, so the list has to grow when the draft does.

Security stance: ``additionalProperties`` defaults to **closed** here (unknown
arguments rejected), the opposite of JSON Schema's permissive default — the gate
is deny-by-default on the argument surface too. Pass an object whose
``additionalProperties`` is explicitly ``true`` to open it.
"""

from __future__ import annotations

import math
from typing import Any

from histos.errors import PolicyError
from histos.importers.js_refs import _resolve_refs
from histos.importers.js_unions import (
    _NULL_ONLY,
    _collapse_union,
    _element_enum,
    _fold_const,
    _resolve_type,
)
from histos.importers.js_vocab import (
    _DRAFT4_MODIFIERS,
    _TYPE_OF,
    _UNPROJECTED_ASSERTIONS,
    _UNPROJECTED_AT_OBJECT_LEVEL,
    _UNPROJECTED_IN_ITEMS,
    _malformed,
    _refuse_unprojected,
    _sensitivity_marker,
)
from histos.policy.schema import Field, Schema


def _numeric(keyword: str, value: Any) -> float | None:
    """Keep a JSON Schema numeric bound, drop draft-4's boolean form, refuse the rest.

    ``bool`` is not read as a number: it is a subclass of ``int`` in Python, and
    draft-4 wrote ``exclusiveMinimum: true`` as a *modifier* of ``minimum``. Reading
    that as the number 1 would invent a bound nobody asked for, so that one spelling
    is dropped. A boolean anywhere else, or a string, or a non-finite value, is a
    malformed source: it is refused rather than dropped, because a dropped bound
    leaves a policy that reads as constrained and enforces nothing.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        # `keyword` is the source spelling, which for an array element bound reads
        # `items.exclusiveMinimum`, so the draft-4 test is on its last segment.
        if keyword.rsplit(".", 1)[-1] in _DRAFT4_MODIFIERS:
            return None
        raise _malformed(keyword, value, "a number")
    if not isinstance(value, int | float):
        raise _malformed(keyword, value, "a number")
    if isinstance(value, float) and not math.isfinite(value):
        # `1e999` is valid JSON that json.loads overflows to inf. A bound of inf is
        # satisfied by every value, so it would import as a cap that never caps.
        raise _malformed(keyword, value, "a finite number")
    return value


def _flag(keyword: str, value: Any) -> bool:
    """A boolean assertion, read as one rather than coerced with ``bool()``.

    `bool(prop.get("uniqueItems"))` read `"false"` as True and `[]` as False — the same
    "malformed value silently becomes a bound nobody wrote" that `_length` exists to
    stop one keyword over.
    """
    if value is None:
        return False
    if not isinstance(value, bool):
        raise _malformed(keyword, value, "a boolean")
    return value


def _length(keyword: str, value: Any) -> int | None:
    """A ``minLength`` / ``maxLength`` must be a non-negative whole number.

    Unguarded, ``maxLength: true`` reached ``Field.max_length`` as ``True`` and
    ``len(value) > True`` silently became a one-character cap; ``maxLength: "50"``
    raised TypeError from inside the gate, where a decision was owed.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _malformed(keyword, value, "a non-negative whole number")
    if isinstance(value, float) and not (math.isfinite(value) and value.is_integer()):
        raise _malformed(keyword, value, "a non-negative whole number")
    if value < 0:
        raise _malformed(keyword, value, "a non-negative whole number")
    return int(value)


def _checked_enum(enum: Any, ftype: str, *, nullable: bool) -> tuple[Any, ...] | None:
    """An ``enum`` whose members contradict the declared ``type`` is refused.

    A string enum on an integer field cannot ever be satisfied — the type check runs
    first, so every call to that tool is denied. That is fail-closed and therefore
    silent: the tool simply stops working, with nothing naming the source document
    that broke it. Catching it at import puts the failure where it can be fixed.
    """
    if enum is None:
        return None
    # The one malformed value this module used to drop in silence, against its own
    # stated invariant: a dropped bound leaves a policy that reads as constrained and
    # enforces nothing. `enum: "read"` is the ordinary slip, and it iterated into one
    # allowed value per character everywhere else it was written.
    if not isinstance(enum, list) or not enum:
        raise _malformed("enum", enum, "a non-empty list of allowed values")
    expected = _TYPE_OF.get(ftype)
    if expected is not None:
        for member in enum:
            if member is None and nullable:
                continue
            wrong_type = not isinstance(member, expected)
            # bool is a subclass of int; an integer field's enum must not hold `true`.
            if ftype in ("integer", "number") and isinstance(member, bool):
                wrong_type = True
            if wrong_type:
                raise PolicyError(
                    f"imported schema declares type {ftype!r} with enum member {member!r} "
                    f"({type(member).__name__}) — no value can satisfy both, so every call to this "
                    "tool would be denied. Fix the source document.",
                    code="invalid_import",
                )
    return tuple(enum)


def _bound(prop: dict[str, Any], items: dict[str, Any] | None, keyword: str) -> tuple[str, Any]:
    """Return ``(source spelling, value)`` for one bound, reading ``items`` for an array.

    An array's element bounds are enforced from the array field's own spec —
    ``_check_string_value`` / ``_check_number`` run per element in
    :mod:`histos.policy.schema` — so ``{"type": "array", "items": {"maxLength": 5}}``
    projects onto ``max_length`` and is enforced there. Only ``items.type`` used to
    be read, which meant an array of ``^[a-z]+$``, five-character scopes imported as
    an array of arbitrary strings. The array's own copy wins if a document writes
    both; the spelling comes back so an error names where the bad value was written.
    """
    if keyword in prop:
        return keyword, prop[keyword]
    # `maxItems`/`minItems` describe the array, never an element, so they are asked
    # of the property alone and `items` comes through as None for them.
    if items and keyword in items:
        return f"items.{keyword}", items[keyword]
    return keyword, None


def _field(prop: Any, *, required: bool, documents: tuple[dict[str, Any], ...], name: str | None) -> Field:
    where = f"argument {name!r}" if name else "an argument"
    prop = _resolve_refs(prop, documents, where=where)
    if not isinstance(prop, dict):
        raise _malformed(where, prop, "a schema object")
    prop, optional = _collapse_union(prop, documents, where=where)
    prop = _fold_const(prop, where=where)
    _refuse_unprojected(prop, _UNPROJECTED_ASSERTIONS, where=where)

    ftype, nullable = _resolve_type(prop.get("type"), where=where)
    nullable = nullable or optional
    # A property that admits only `null` becomes `any` plus an enum of exactly `None`,
    # unless the document wrote an enum of its own — in which case that is what it says
    # and `_checked_enum` below decides whether it is coherent.
    null_only = ftype == _NULL_ONLY
    if null_only:
        ftype = "any"

    items: dict[str, Any] = {}
    item_type: str | None = None
    raw_items = prop.get("items")
    if raw_items is not None:
        if ftype != "array":
            # `items` on a non-array is either a mistyped document or an argument
            # whose `type` this bridge degraded to `any`. Either way the element
            # bounds would vanish, which is the drop this module refuses to do quietly.
            raise _malformed("items", raw_items, f"projectable: {where} is not declared as an array")
        resolved = _resolve_refs(raw_items, documents, where=f"{where} items")
        if not isinstance(resolved, dict):
            raise _malformed("items", raw_items, "a schema object")
        # The element schema is collapsed the same way the property is. `_fold_const`
        # and the element enum were applied here and `_collapse_union` was not, so
        # `list[str | None]` — a union the projection handles perfectly one level up —
        # refused the whole tool.
        # The nullability flag is *read*, not discarded. One level up the same union
        # sets `Field.nullable` and a null element is accepted; one level down there is
        # no `item_nullable`, so throwing the flag away turned a loud refusal into a
        # silent narrowing — `list[str | None]`, which is exactly what pydantic emits
        # for `list[Optional[str]]` and the shape this collapse was added for, imported
        # as `item_type: "string"` and the gate then denied every call carrying a null.
        # Widening to an untyped element is the honest answer: the source says a null
        # may be there, and refusing to say more is better than saying the wrong thing.
        resolved, item_nullable = _collapse_union(resolved, documents, where=f"{where} items")
        items = _fold_const(resolved, where=where, prefix="items.")
        _refuse_unprojected(items, _UNPROJECTED_IN_ITEMS, where=where, prefix="items.")
        raw_item_type = _resolve_type(items.get("type"), where=f"{where} items")[0]
        # The sentinel is converted back the same way the property branch three lines
        # above converts it. It was not, and `Field.__post_init__` validates `type`
        # against `_TYPE_CHECKS` but never `item_type` — so the sentinel survived into
        # the contract, `_check_scalar` did `_TYPE_CHECKS.get(spec.item_type, object)`,
        # and a source saying "an array of nulls" accepted an element of every type.
        item_type = None if raw_item_type == _NULL_ONLY or item_nullable else raw_item_type

    _, pattern = _bound(prop, items, "pattern")
    # An element enum and an element pattern now live in separate fields and are both
    # enforced, so a document may write either or both — the intersection is what the
    # engine applies, which is what the source says.
    item_enum = _element_enum(items["enum"], item_type=item_type or "any", where=where) if "enum" in items else None

    # Read on the element schema as well as the property. Every other element-level
    # keyword reaches `Field` through `_bound`; this one did not, so an array of PII
    # marked the only place it can be marked — on the element — imported un-redacted.
    # It is also the one keyword whose absence is invisible downstream: nothing later
    # can tell "not sensitive" from "meant to be sensitive", which is why the marker
    # carries a near-miss screen at all. `secret` wins over `pii` when both are present.
    sensitive = _sensitivity_marker(prop, where=where)
    if items:
        element = _sensitivity_marker(items, where=f"{where} items")
        if element is not None and (sensitive is None or element == "secret"):
            sensitive = element

    return Field(
        type=ftype,
        required=required and not nullable,
        nullable=nullable,
        enum=(None,) if null_only and "enum" not in prop else _checked_enum(prop.get("enum"), ftype, nullable=nullable),
        max_length=_length(*_bound(prop, items, "maxLength")),
        min_length=_length(*_bound(prop, items, "minLength")),
        pattern=pattern,
        sensitive=sensitive,
        item_enum=item_enum,
        unique_items=_flag("uniqueItems", prop.get("uniqueItems")) if ftype == "array" else False,
        item_type=item_type,
        max_items=_length(*_bound(prop, None, "maxItems")),
        min_items=_length(*_bound(prop, None, "minItems")),
        minimum=_numeric(*_bound(prop, items, "minimum")),
        maximum=_numeric(*_bound(prop, items, "maximum")),
        exclusive_minimum=_numeric(*_bound(prop, items, "exclusiveMinimum")),
        exclusive_maximum=_numeric(*_bound(prop, items, "exclusiveMaximum")),
        multiple_of=_numeric(*_bound(prop, items, "multipleOf")),
    )


def field_from_json_schema(
    prop: dict[str, Any],
    *,
    required: bool,
    root: dict[str, Any] | None = None,
    name: str | None = None,
) -> Field:
    """Convert one JSON Schema property to a :class:`~histos.policy.schema.Field`.

    ``root`` is the document the property was read from: a local ``$ref`` is resolved
    against it, and without one a ``$ref`` is refused rather than imported as an
    unconstrained field. ``name`` is only there to let a refusal say which argument
    it is talking about.
    """
    return _field(prop, required=required, documents=() if root is None else (root,), name=name)


def schema_from_json_schema(obj: dict[str, Any], *, root: dict[str, Any] | None = None) -> Schema:
    """Convert a JSON Schema *object* (``type: object`` with ``properties``).

    ``obj`` is itself the document a local ``$ref`` resolves against — ``$defs`` sits
    at the top of every pydantic-generated schema. Pass ``root`` as well when the
    object was lifted out of a larger document whose ``#/components/schemas`` its
    references point into; both are searched, ``obj`` first.
    """
    documents = (obj,) if root is None or root is obj else (obj, root)
    resolved = _resolve_refs(obj, documents, where="the argument object")
    if not isinstance(resolved, dict):
        raise _malformed("the argument object", obj, "a schema object")
    _refuse_unprojected(resolved, _UNPROJECTED_AT_OBJECT_LEVEL, where="the argument object")

    properties = resolved.get("properties", {})
    if not isinstance(properties, dict):
        raise _malformed("properties", properties, "an object")
    # Type-checked for the same reason `{"name": 7}` is: `project_tools` catches
    # `PolicyError` and nothing else, so a `required` that is a bool, an int or a string
    # raises past the per-tool skip and takes every healthy tool in the manifest with it
    # — the failure mode that machinery exists to prevent, reached through the type
    # system. A bare string is the sharp one: it iterates character by character and
    # every single letter becomes a required property name.
    raw_required = resolved.get("required", [])
    if not isinstance(raw_required, list) or not all(isinstance(n, str) for n in raw_required):
        raise _malformed("required", raw_required, "a list of property names")
    required = set(raw_required)
    fields = {
        name: _field(prop, required=name in required, documents=documents, name=name)
        for name, prop in properties.items()
    }
    allow_extra = resolved.get("additionalProperties", False) is True
    return Schema(fields, allow_extra=allow_extra)
