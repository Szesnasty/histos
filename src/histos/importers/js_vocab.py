"""Which JSON Schema keywords this bridge can carry, and what it does with the rest.

Split out of `json_schema.py`. The projection is one flat `Field`, so a keyword that
narrows what the source accepts and has nowhere to go is **refused by name** rather than
dropped: a dropped bound produces a policy that looks like it carries the constraint,
and the reviewer has no reason to re-derive it by hand.

The refusal list is written out rather than computed as "anything unrecognised", because
a real document also carries vendor keys that constrain nothing. The honest cost of that
choice is stated where it is made: an assertion keyword from a draft newer than the list
is still dropped silently, so the list has to grow when the draft does.

Refusing by name was over-applied once and that was its own release blocker — an
ordinary pydantic surface stopped importing at all. A screen that refuses honest input
teaches its user to stop importing, which is the same outcome as the hole it closed.
"""

from __future__ import annotations

from typing import Any

from histos.errors import PolicyError

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
