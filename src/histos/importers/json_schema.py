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

from typing import Any

from histos.schema import Field, Schema

_JS_TYPES = {"string", "integer", "number", "boolean", "array", "object"}


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


def _numeric(value: Any) -> float | None:
    """Keep a JSON Schema numeric bound, or drop it if it is not a number.

    ``bool`` is excluded on purpose: it is a subclass of ``int`` in Python, and
    draft-4 wrote ``exclusiveMinimum: true`` as a *modifier* of ``minimum``. Reading
    that as the number 1 would invent a bound nobody asked for.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return value


def field_from_json_schema(prop: dict[str, Any], *, required: bool) -> Field:
    """Convert one JSON Schema property to a :class:`~histos.schema.Field`."""
    ftype, nullable = _resolve_type(prop.get("type", "any"))

    item_type: str | None = None
    if ftype == "array":
        items = prop.get("items")
        if isinstance(items, dict):
            item_type = _resolve_type(items.get("type", "any"))[0]

    enum = tuple(prop["enum"]) if isinstance(prop.get("enum"), list) else None
    sensitive = prop.get("x-sensitive")
    if sensitive not in (None, "pii", "secret"):
        sensitive = None

    return Field(
        type=ftype,
        required=required and not nullable,
        enum=enum,
        max_length=prop.get("maxLength"),
        min_length=prop.get("minLength"),
        pattern=prop.get("pattern"),
        sensitive=sensitive,
        item_type=item_type,
        minimum=_numeric(prop.get("minimum")),
        maximum=_numeric(prop.get("maximum")),
        exclusive_minimum=_numeric(prop.get("exclusiveMinimum")),
        exclusive_maximum=_numeric(prop.get("exclusiveMaximum")),
        multiple_of=_numeric(prop.get("multipleOf")),
    )


def schema_from_json_schema(obj: dict[str, Any]) -> Schema:
    """Convert a JSON Schema *object* (``type: object`` with ``properties``)."""
    properties = obj.get("properties", {})
    required = set(obj.get("required", []))
    fields = {name: field_from_json_schema(prop, required=name in required) for name, prop in properties.items()}
    allow_extra = obj.get("additionalProperties", False) is True
    return Schema(fields, allow_extra=allow_extra)
