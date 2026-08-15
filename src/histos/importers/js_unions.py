"""The three shapes that are not one flat field, and project onto one anyway.

Split out of `json_schema.py`. Each of these was on the refusal list once and each of
them removal was a release blocker, because they are what an ordinary pydantic model
emits:

* `anyOf: [T, null]` — every `Optional[T]` in existence. It is a union, and it is also
  exactly `T` plus a nullability flag, which this `Field` model holds.
* `const` — a one-member enum wearing a different keyword.
* an element `enum` inside `items` — a bounded set, one level down.

Refusing a shape that projects without losing anything teaches the user to stop
importing, which leaves them with no policy at all. Only what genuinely cannot be held
by one flat field — a real union, a nested object, a recursive model — is still refused.
"""

from __future__ import annotations

from typing import Any

from histos.errors import PolicyError
from histos.importers.js_refs import _resolve_refs
from histos.importers.js_vocab import (
    _JS_TYPES,
    _KEYWORDS_THAT_ASSERT,
    _TYPE_OF,
    _VALUE_SET_KEYWORDS,
    _malformed,
)


def _type_of_value(value: Any) -> str | None:
    """The JSON Schema ``type`` a literal satisfies, or None for ``null``.

    ``bool`` is tested before ``int`` because it is a subclass of it in Python, and
    ``const: true`` typed as an integer would be a field no boolean could satisfy.
    """
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return None


def _fold_const(node: dict[str, Any], *, where: str, prefix: str = "") -> dict[str, Any]:
    """``const: x`` is ``enum: [x]`` — one allowed value, which ``Field.enum`` holds exactly.

    It used to be refused as unprojectable, which is how a pydantic ``Literal["invoice"]``
    and every discriminator field stopped importing. There is nothing to lose here: an
    enum of one member denies precisely what the const denies. The type is inferred from
    the value when the document did not write one, so the field also carries the type
    check the const implies rather than degrading to ``any``.
    """
    if "const" not in node:
        return node
    if "enum" in node:
        raise PolicyError(
            f"imported schema for {where} declares both {prefix}const and {prefix}enum. JSON Schema "
            "reads that as the intersection of the two, which this projection does not compute, so "
            "importing it would produce a field wider than the source. Write one of them.",
            code="invalid_import",
        )
    value = node["const"]
    folded = {k: v for k, v in node.items() if k != "const"}
    folded["enum"] = [value]
    inferred = _type_of_value(value)
    if "type" not in folded and inferred is not None:
        folded["type"] = inferred
    return folded


def _value_set(branch: dict[str, Any]) -> list[Any] | None:
    """The values a union branch admits, when a fixed set is *all* it admits, else None."""
    if any(k in _KEYWORDS_THAT_ASSERT and k not in _VALUE_SET_KEYWORDS for k in branch):
        return None
    if "const" in branch:
        # `const` and `enum` together is an intersection this bridge does not compute,
        # so the branch is not a value set it can read.
        return None if "enum" in branch else [branch["const"]]
    enum = branch.get("enum")
    return list(enum) if isinstance(enum, list) and enum else None


def _collapse_union(
    node: dict[str, Any], documents: tuple[dict[str, Any], ...], *, where: str
) -> tuple[dict[str, Any], bool]:
    """Flatten the two ``anyOf``/``oneOf`` shapes that are honestly one field.

    Returns ``(node, nullable)``. Every combinator used to be refused outright, which
    took ``Optional[str]`` with it — pydantic writes that as
    ``{"anyOf": [{"type": "string"}, {"type": "null"}]}``, so the refusal removed the
    single commonest argument shape an MCP server emits. Two collapses are exact and
    only two:

    * one concrete branch beside one or more ``{"type": "null"}`` — that is an optional
      T and nothing else, so the branch becomes the field and ``required`` goes false;
    * every concrete branch carrying only a value set (``const``/``enum``), which is how
      a ``Literal["a", "b"]`` and a union of literals are written — they concatenate
      into one enum, provided they agree on a type.

    Anything else is a genuine union of *shapes*, and one flat field cannot hold it, so
    it falls through to `_refuse_unprojected` and is named there. A single-branch union
    with no null in it is left alone too: it is equivalent to its branch, but nothing
    real emits it, and a screen that guesses at degenerate spellings is a screen whose
    behaviour nobody can predict.
    """
    for combinator in ("anyOf", "oneOf"):
        branches = node.get(combinator)
        if not isinstance(branches, list) or not branches:
            continue
        resolved = [_resolve_refs(b, documents, where=f"{where} {combinator}") for b in branches]
        if not all(isinstance(b, dict) for b in resolved):
            continue
        concrete = [b for b in resolved if b.get("type") != "null"]
        nullable = len(concrete) < len(resolved)
        # Keywords written next to the combinator win over the branch, on the same rule
        # `_resolve_refs` uses for a sibling of `$ref`.
        siblings = {k: v for k, v in node.items() if k != combinator}
        if nullable and len(concrete) == 1:
            return {**concrete[0], **siblings}, True
        sets = [_value_set(b) for b in concrete]
        if len(concrete) > 1 and all(sets):
            members = [v for s in sets if s for v in s]
            types = {_type_of_value(v) for v in members}
            if len(types) == 1 and None not in types:
                return {"type": types.pop(), "enum": members, **siblings}, nullable
    return node, False


def _element_enum(members: Any, *, item_type: str, where: str) -> tuple[Any, ...]:
    """The value set each element of an array must be drawn from.

    ``Field.enum`` is matched against the *whole* argument, so copying an element enum
    there would deny every call — round one drew the right conclusion from that and
    refused the keyword, which removed the shape real MCP tools use for scopes and
    permissions from the importable surface. Round two carried it as an escaped
    alternation in ``pattern``, which works only because the per-element screen happens
    to be a string screen, and therefore left `items: {type: integer, enum: [1, 2]}`
    unimportable for a reason that was about the implementation rather than the source.

    ``Field.item_enum`` is the thing itself: the engine checks each element against it,
    whatever its type. The members still have to agree with the declared element type,
    because a value set that contradicts it can never be satisfied.
    """
    if not isinstance(members, list) or not members:
        raise _malformed("items.enum", members, "a non-empty list of allowed values")
    expected = _TYPE_OF.get(item_type)
    if expected is not None and not all(isinstance(m, expected) and not _is_stray_bool(m, item_type) for m in members):
        raise _malformed(f"{where} items.enum", members, f"a list of {item_type} values")
    return tuple(members)


def _is_stray_bool(member: Any, item_type: str) -> bool:
    """`True` is an `int` in Python; a boolean in an integer enum is a malformed source."""
    return isinstance(member, bool) and item_type in ("integer", "number")


# The sentinel `_resolve_type` returns for a property whose only permitted value is
# `null`. Not a `Field` type — `_field` converts it to `any` plus an enum of exactly
# `None`, which is what "admits null and nothing else" means to the engine.
_NULL_ONLY = "\0null-only"


def _resolve_type(js_type: Any, *, where: str = "an imported schema") -> tuple[str, bool]:
    """Return ``(schema_type, nullable)`` for a JSON Schema ``type`` value.

    A ``type`` this projection does not know is refused rather than degraded. Falling
    back to ``any`` turned a typo — ``"strin"``, ``"boolean "`` with a trailing space,
    ``"int"`` from someone thinking in Python — into a field that accepts every value
    of every type, which is the one direction a validation bug must not go. Absent is
    still ``any``: a property with no ``type`` at all genuinely says nothing, and that
    is visible in `histos review` as an untyped argument.
    """
    if js_type is None:
        return "any", False
    if isinstance(js_type, list):
        nullable = "null" in js_type
        concrete = [t for t in js_type if t != "null"]
        if not concrete:
            # `["null"]`, the list spelling of null-only. Same answer as the scalar one
            # below, and for the same reason.
            return _NULL_ONLY, True
        unknown = [t for t in concrete if t not in _JS_TYPES]
        if unknown:
            raise _malformed(f"{where} type", unknown[0], f"one of {', '.join(sorted(_JS_TYPES))}")
        if len(concrete) > 1:
            # `return concrete[0]` dropped every type after the first without a word, so
            # a document declaring string-or-integer produced a policy that denies the
            # integer. The `anyOf` spelling of the same union is refused; this is the
            # same statement written the other way, and gets the same answer.
            raise _malformed(
                f"{where} type",
                js_type,
                "a single type, optionally with 'null' — a union of value types has no single Field to project onto",
            )
        return concrete[0], nullable
    if js_type == "null":
        # A distinct answer, not `("any", True)`. Both spellings say the property admits
        # exactly one value — `null` — and `any` + nullable says the opposite: no type
        # check at all, so a field admitting only null projected to one admitting
        # strings, objects, anything. Before the scalar spelling was accepted at all it
        # was refused as an unknown type, which skipped the tool and was safe; accepting
        # it by mapping it onto the list spelling's behaviour inherited that spelling's
        # bug rather than fixing it. `_field` turns this into `enum=(None,)`.
        return _NULL_ONLY, True
    if isinstance(js_type, str) and js_type in _JS_TYPES:
        return js_type, False
    raise _malformed(f"{where} type", js_type, f"one of {', '.join(sorted(_JS_TYPES))}")
