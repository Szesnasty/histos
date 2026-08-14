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

# Assertion keywords the projection cannot carry. Every one of them narrows what the
# source accepts, so dropping it produces a field that is weaker than the document it
# came from — the same trap `_malformed` closes for a malformed value, which is why
# these are refused by name instead. `$ref` is not here: it is followed (see
# `_resolve_refs`) and refused only when it cannot be.
_UNPROJECTED_ASSERTIONS = frozenset(
    {
        # combinators and conditionals — the projection is one flat field, not a tree
        "allOf",
        "anyOf",
        "oneOf",
        "not",
        "if",
        "then",
        "else",
        "$dynamicRef",
        "$recursiveRef",
        "extends",
        "disallow",
        # nested object shape beyond "it is an object". `properties`, `required` and
        # `additionalProperties` are projected as far as this model goes — the field
        # keeps `type: object`, which is what the engine checks — because refusing them
        # took out every pydantic model with a nested model in it, and 4 of the 19
        # operations in the standard Swagger Petstore document. The inner contract is
        # genuinely not carried, and docs/policy-reference.md has always said a
        # `type: object` argument is checked for being an object and never for its
        # contents.
        #
        # `additionalProperties` was left on this list for every level below the root,
        # and that was the same mistake one keyword later. It is not extra shape a
        # generator writes occasionally — it is written *whenever* a nested object is
        # written: pydantic `extra="forbid"` emits `false`, `dict[str, str]` emits a
        # subschema, and OpenAI's structured-output strict mode *requires* `false` on
        # every object. So the importer refused the single most common real tool
        # definition there is, and told the author to write the argument by hand.
        "patternProperties",
        "unevaluatedProperties",
        "propertyNames",
        "dependencies",
        "dependentSchemas",
        "dependentRequired",
        "minProperties",
        "maxProperties",
        # array shape beyond the element type
        "prefixItems",
        "additionalItems",
        "unevaluatedItems",
        "contains",
        "minContains",
        "maxContains",
        # single-value assertions with no `Field` equivalent
        "const",
        "divisibleBy",
    }
)

# `properties` and `required` are the whole point at the top level, and are the nested
# object's own contract below it — carried as far as `type: object` either way.
_UNPROJECTED_AT_OBJECT_LEVEL = _UNPROJECTED_ASSERTIONS - {"properties", "required"}

# Inside `items`: the element type, the scalar bounds `_bound` reads, and an element
# `enum`/`const` (see `_element_enum_pattern`). A nested `items` is still a shape one
# flat field cannot hold — and so are `minItems`/`maxItems`, which are projected on the
# *array* and have no meaning one level down. They are named here explicitly because
# this set is derived from `_UNPROJECTED_ASSERTIONS`, so giving them a home on `Field`
# and taking them off that list silently deleted the refusal covering the element
# schema too. `_bound` reads them property-only, precisely so an element bound is never
# mistaken for an array bound, which left `items: {maxItems: 3}` dropped in silence.
# `uniqueItems` is on this list for the same reason and was left off it: it was taken
# off `_UNPROJECTED_ASSERTIONS` in the same commit that gave it a home on `Field`, and
# `_field` reads it property-only — so an element-level `uniqueItems` went from a named
# refusal to a silent drop, which is the exact failure the paragraph above describes.
_UNPROJECTED_IN_ITEMS = _UNPROJECTED_ASSERTIONS | {"items", "minItems", "maxItems", "uniqueItems"}

# Every keyword that reaches the projection, carried or refused. Used to decide whether
# a union branch holds *only* a set of allowed values — a branch that also writes a
# `pattern` or a length is a real union member, not a spelling of an enum. `x-sensitive`
# is in here because flattening a branch that carries it would drop a redaction marker,
# and that one drops open.
_KEYWORDS_THAT_ASSERT = _UNPROJECTED_ASSERTIONS | {
    "$ref",
    "type",
    "enum",
    "x-sensitive",
    "minLength",
    "maxLength",
    "pattern",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "items",
}
_VALUE_SET_KEYWORDS = frozenset({"type", "const", "enum"})

# A `$ref` chain longer than this is a document doing something the flat projection
# was never going to hold, and the bound is also how a cycle through two files' worth
# of `$defs` terminates.
_MAX_REF_DEPTH = 8


def _malformed(keyword: str, value: Any, expected: str) -> PolicyError:
    return PolicyError(
        f"imported schema declares {keyword}={value!r}, which is not {expected}. The source is "
        "malformed; importing it would produce a policy that looks like it carries this bound and "
        "does not.",
        code="invalid_import",
    )


_SENSITIVITIES = ("pii", "secret")

# Spellings close enough to `x-sensitive` that seeing one means somebody meant it. A
# vendor `x-` key is otherwise ignored on purpose — that is what the extension space is
# for — and this is the one extension histos itself defines, so a near miss is a typo
# rather than another vendor's annotation.
_SENSITIVE_TYPOS = frozenset(
    {"x-sensitiv", "x-sensitivity", "x_sensitive", "xsensitive", "x-Sensitive", "sensitive", "x-pii", "x-secret"}
)


def _sensitivity_marker(prop: dict[str, Any], *, where: str) -> str | None:
    """Read ``x-sensitive``, refusing a spelling that would silently disable redaction.

    This used to be ``prop.get("x-sensitive")`` followed by "if it is not one of the two
    words, treat it as absent". Every way of getting it slightly wrong therefore
    produced a field that imports cleanly, validates cleanly, reviews cleanly and is
    not redacted: ``"PII"`` in the wrong case, ``"confidential"`` from another vendor's
    vocabulary, ``x-sensitiv`` off by a letter. The marker's whole job is to be the
    reason a value does not reach the model, and it is the one keyword here whose
    absence is invisible in the resulting policy — nothing downstream can tell "not
    sensitive" from "meant to be sensitive, spelled wrong".
    """
    for key in prop:
        if key in _SENSITIVE_TYPOS or (key.lower().replace("_", "-") == "x-sensitive" and key != "x-sensitive"):
            raise PolicyError(
                f"imported schema for {where} declares {key!r}. The marker histos reads is exactly "
                f"'x-sensitive' (one of {', '.join(map(repr, _SENSITIVITIES))}); a near miss imports as "
                "un-redacted, and nothing downstream can tell that apart from a field nobody marked.",
                code="invalid_import",
            )
    marker = prop.get("x-sensitive")
    if marker is None:
        return None
    if marker not in _SENSITIVITIES:
        raise _malformed(f"{where} x-sensitive", marker, f"one of {', '.join(map(repr, _SENSITIVITIES))}")
    return str(marker)


def _refuse_unprojected(node: dict[str, Any], unprojected: frozenset[str], *, where: str, prefix: str = "") -> None:
    """Refuse a source keyword the projection would otherwise drop on the floor."""
    dropped = sorted(f"{prefix}{k}" for k in node if k in unprojected)
    if not dropped:
        return
    raise PolicyError(
        f"imported schema for {where} declares {', '.join(dropped)}, which this projection does not "
        "carry (see spec/json-schema-projection-0.1.md). Dropping it would produce a policy that "
        "looks like it carries that bound and does not, so the import is refused instead. Write the "
        "argument by hand in the bundle if the tool really needs it.",
        code="invalid_import",
    )


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
    :mod:`histos.schema` — so ``{"type": "array", "items": {"maxLength": 5}}``
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
        resolved, _ = _collapse_union(resolved, documents, where=f"{where} items")
        items = _fold_const(resolved, where=where, prefix="items.")
        _refuse_unprojected(items, _UNPROJECTED_IN_ITEMS, where=where, prefix="items.")
        item_type = _resolve_type(items.get("type"), where=f"{where} items")[0]

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
    """Convert one JSON Schema property to a :class:`~histos.schema.Field`.

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
