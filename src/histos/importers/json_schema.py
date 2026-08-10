"""The shared bridge: a JSON Schema object → a histos :class:`Schema`.

Deliberately a *subset* — the pieces that map cleanly onto deterministic
validation: ``type``, ``required``, ``enum``, ``minLength`` / ``maxLength``,
``pattern``, the numeric bounds (``minimum``, ``maximum``, ``exclusiveMinimum``,
``exclusiveMaximum``, ``multipleOf``) and ``items.type`` for arrays. An
``x-sensitive`` extension (``"pii"`` | ``"secret"``) marks a field for post-gate
redaction on a *return* schema.

A bound the tool author already wrote must survive the import. Dropping one is
worse than never having it: the generated policy *looks* like it carries the
constraint, and the reviewer has no reason to re-derive it by hand. Draft-4's
boolean form of ``exclusiveMinimum`` / ``exclusiveMaximum`` is ignored rather than
guessed at — only the numeric (draft 6+) form is honoured.

Security stance: ``additionalProperties`` defaults to **closed** here (unknown
arguments rejected), the opposite of JSON Schema's permissive default — the gate
is deny-by-default on the argument surface too. Pass an object whose
``additionalProperties`` is explicitly ``true`` to open it.
"""

from __future__ import annotations

import math
from typing import Any

from histos.errors import PolicyError
from histos.schema import Field, Schema

_JS_TYPES = {"string", "integer", "number", "boolean", "array", "object"}

# Only these two ever legitimately carry a boolean: draft-4 wrote
# `exclusiveMinimum: true` as a *modifier* of `minimum`. Everywhere else a boolean
# is a malformed document, not an older dialect.
_DRAFT4_MODIFIERS = frozenset({"exclusiveMinimum", "exclusiveMaximum"})

# What a JSON Schema `type` promises about the values that satisfy it. Used to catch
# an `enum` that contradicts the type it sits next to.
_TYPE_OF: dict[str, type | tuple[type, ...]] = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": (list, tuple),
    "object": dict,
}


def _malformed(keyword: str, value: Any, expected: str) -> PolicyError:
    return PolicyError(
        f"imported schema declares {keyword}={value!r}, which is not {expected}. The source is "
        "malformed; importing it would produce a policy that looks like it carries this bound and "
        "does not.",
        code="invalid_import",
    )


def _resolve_type(js_type: Any) -> tuple[str, bool]:
    """Return ``(schema_type, nullable)`` for a JSON Schema ``type`` value."""
    if isinstance(js_type, list):
        nullable = "null" in js_type
        concrete = [t for t in js_type if t != "null"]
        chosen = concrete[0] if concrete else "any"
        return (chosen if chosen in _JS_TYPES else "any"), nullable
    if isinstance(js_type, str) and js_type in _JS_TYPES:
        return js_type, False
    return "any", False


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
        if keyword in _DRAFT4_MODIFIERS:
            return None
        raise _malformed(keyword, value, "a number")
    if not isinstance(value, int | float):
        raise _malformed(keyword, value, "a number")
    if isinstance(value, float) and not math.isfinite(value):
        # `1e999` is valid JSON that json.loads overflows to inf. A bound of inf is
        # satisfied by every value, so it would import as a cap that never caps.
        raise _malformed(keyword, value, "a finite number")
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
    if not isinstance(enum, list):
        return None
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


def field_from_json_schema(prop: dict[str, Any], *, required: bool) -> Field:
    """Convert one JSON Schema property to a :class:`~histos.schema.Field`."""
    ftype, nullable = _resolve_type(prop.get("type", "any"))

    item_type: str | None = None
    if ftype == "array":
        items = prop.get("items")
        if isinstance(items, dict):
            item_type = _resolve_type(items.get("type", "any"))[0]

    sensitive = prop.get("x-sensitive")
    if sensitive not in (None, "pii", "secret"):
        sensitive = None

    return Field(
        type=ftype,
        required=required and not nullable,
        enum=_checked_enum(prop.get("enum"), ftype, nullable=nullable),
        max_length=_length("maxLength", prop.get("maxLength")),
        min_length=_length("minLength", prop.get("minLength")),
        pattern=prop.get("pattern"),
        sensitive=sensitive,
        item_type=item_type,
        minimum=_numeric("minimum", prop.get("minimum")),
        maximum=_numeric("maximum", prop.get("maximum")),
        exclusive_minimum=_numeric("exclusiveMinimum", prop.get("exclusiveMinimum")),
        exclusive_maximum=_numeric("exclusiveMaximum", prop.get("exclusiveMaximum")),
        multiple_of=_numeric("multipleOf", prop.get("multipleOf")),
    )


def schema_from_json_schema(obj: dict[str, Any]) -> Schema:
    """Convert a JSON Schema *object* (``type: object`` with ``properties``)."""
    properties = obj.get("properties", {})
    required = set(obj.get("required", []))
    fields = {name: field_from_json_schema(prop, required=name in required) for name, prop in properties.items()}
    allow_extra = obj.get("additionalProperties", False) is True
    return Schema(fields, allow_extra=allow_extra)
