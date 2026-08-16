"""A deliberately tiny, deterministic schema validator.

This is **not** a JSON-Schema engine. It is the minimal, dependency-free subset
needed to (a) validate tool *arguments* before execution and (b) describe a
tool's *return* shape so sensitive fields can be redacted after execution.
Everything here is pure and fail-closed by construction: an unrecognised type or
a validation error is reported, never silently accepted.

Kept intentionally small so policy evaluation stays microsecond-scale and easy to
reason about — a policy bug becomes an availability incident, so the evaluator
must stay simple enough to hold in your head.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from histos.errors import PolicyError
from histos.policy.canonical import canonical_json
from histos.policy.frozen import detach_mapping, detach_sequence

# Largest magnitude a numeric bound may carry. Beyond this, `float()` on the value
# overflows and the comparison/`multiple_of` arithmetic in `_check_number` raises
# OverflowError *inside the gate* — an uncaught exception where a decision belongs.
_MAX_BOUND = 1e308

_TYPE_CHECKS: dict[str, type | tuple[type, ...]] = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": (list, tuple),
    "object": dict,
    "any": object,
}


def _portable_value(value: Any, where: str) -> Any:
    """Return the JSON spelling a policy literal is hashed and enforced as."""
    try:
        canonical_json(value, numbers_as_text=True)
    except (TypeError, ValueError) as exc:
        raise PolicyError(f"{where} cannot be hashed reproducibly: {exc}", code="invalid_field") from exc

    def walk(node: Any) -> Any:
        if node is None or isinstance(node, str | bool | int):
            return node
        if isinstance(node, float):
            if not math.isfinite(node):
                raise PolicyError(f"{where} contains a non-finite number {node!r}", code="invalid_field")
            return node
        if isinstance(node, list | tuple):
            # JSON has one sequence type and the policy hash deliberately gives Python
            # lists and tuples one spelling. Enforcement must do the same: otherwise
            # `enum=([1],)` and `enum=((1,),)` share a hash while accepting opposite
            # Python values.
            return [walk(item) for item in node]
        if isinstance(node, dict):
            out: dict[str, Any] = {}
            for key, item in node.items():
                if not isinstance(key, str):
                    raise PolicyError(
                        f"{where} contains an object key {key!r}; policy object keys must be strings",
                        code="invalid_field",
                    )
                out[key] = walk(item)
            return out
        # `canonical_json` can represent bytes and sets for call fingerprints, but a
        # policy bundle cannot. Accepting them here makes an in-memory policy impossible
        # to dump and, for a set used as the outer enum, makes its hash process-order
        # dependent once it is converted to a tuple.
        raise PolicyError(
            f"{where} contains {type(node).__name__}; enum literals must be JSON values",
            code="invalid_field",
        )

    return walk(value)


# Which declared types actually consult each keyword. `any` is exempt from all of it,
# and that exemption is only honest because `_check_scalar` dispatches every one of these
# on the *value*: a string bound fires on a string, a numeric bound on a number, an
# element bound on a list. It briefly was not — the numeric and array keywords keyed on
# the declared type — and narrowing the exemption to match turned the dead bound into a
# refusal of the whole tool, which is the same failure facing the other way.
# `{"minimum": 1, "maximum": 100}` with no `type` is legal, ordinary JSON Schema.
_KEYWORD_APPLIES_TO: dict[str, frozenset[str]] = {
    # `_check_string_value`, reached for a string scalar and for each element of an
    # array whose `item_type` is string.
    "max_length": frozenset({"string", "array"}),
    "min_length": frozenset({"string", "array"}),
    "pattern": frozenset({"string", "array"}),
    # `_check_number`, reached the same two ways.
    "minimum": frozenset({"integer", "number", "array"}),
    "maximum": frozenset({"integer", "number", "array"}),
    "exclusive_minimum": frozenset({"integer", "number", "array"}),
    "exclusive_maximum": frozenset({"integer", "number", "array"}),
    "multiple_of": frozenset({"integer", "number", "array"}),
    # Consulted only inside `if spec.type == "array"`.
    "max_items": frozenset({"array"}),
    "min_items": frozenset({"array"}),
    "item_enum": frozenset({"array"}),
    "item_type": frozenset({"array"}),
    "unique_items": frozenset({"array"}),
}


def _check_bound(name: str, value: Any) -> None:
    """A numeric bound must be a real, finite, comparable number.

    NaN makes every IEEE comparison False and ±Inf makes one side of every
    comparison True, so a non-finite bound is a bound that never fires — the exact
    silent fail-open this module refuses for non-finite *values*. An integer past
    the float range is worse still: it survives load and then raises OverflowError
    from inside the gate, where a decision was owed.
    """
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise PolicyError(f"{name} must be a number, got {type(value).__name__}", code="invalid_field")
    if isinstance(value, float) and not math.isfinite(value):
        raise PolicyError(
            f"{name} is {value!r} — a non-finite bound never fires (every comparison against NaN is "
            "False, and every value satisfies ±Inf), so it would read as a bound and enforce nothing",
            code="invalid_field",
        )
    if abs(value) > _MAX_BOUND:
        raise PolicyError(
            f"{name} has {len(str(abs(value)))} digits, past the range a float can compare against — "
            "evaluating it would raise OverflowError from inside the gate instead of returning a decision",
            code="invalid_field",
        )


def _check_length_bound(name: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PolicyError(f"{name} must be a non-negative integer, got {value!r}", code="invalid_field")


@dataclass(frozen=True)
class Field:
    """One field in a :class:`Schema`.

    ``sensitive`` is only meaningful on a *return* schema: ``"pii"`` or
    ``"secret"`` fields are redacted by the post-gate unless the caller's role is
    explicitly allowed to see them.
    """

    type: str = "string"
    required: bool = True
    enum: tuple[Any, ...] | None = None
    max_length: int | None = None
    min_length: int | None = None
    pattern: str | None = None
    sensitive: str | None = None  # None | "pii" | "secret"
    #: Whether an explicit ``None`` is a legal value for this field.
    #:
    #: Distinct from ``required``, which is about the key being *present*. An optional
    #: Python parameter (`note: str | None = None`) and a JSON Schema
    #: `anyOf: [T, null]` both say the value may be null, and both imported as a plain
    #: `string` — so a caller passing the null the source explicitly allows was denied
    #: `arg_schema`, with nothing in the policy format able to express what it wanted.
    nullable: bool = False
    item_type: str | None = None  # element type for "array"
    #: Element-count bounds for an ``array``. `maxItems` is a bound the source author
    #: wrote and the projection had nowhere to put, so an ordinary
    #: `list[str] = Field(max_length=10)` refused the whole tool rather than lose it.
    #: Distinct from ``max_length``, which bounds each string *element*.
    max_items: int | None = None
    min_items: int | None = None
    #: Allowed values for each *element* of an ``array``.
    #:
    #: Distinct from ``enum``, which the engine matches against the whole argument — so
    #: copying an element enum there would deny every call. Carried as an escaped
    #: alternation in ``pattern`` for one release, which worked for strings and left
    #: `{"type": "array", "items": {"type": "integer", "enum": [1, 2]}}` unimportable
    #: because there was nothing to hang a value set on that was not a string screen.
    item_enum: tuple[Any, ...] | None = None
    #: Whether every element of an ``array`` must be distinct.
    #:
    #: The same case `max_items` was rescued from, left behind in the same pass:
    #: `uniqueItems` is what every pydantic `set[T]` emits, and refusing a bound a real
    #: source writes cost the whole tool rather than the bound. Compared by equality
    #: rather than by hash, so a list of dicts — which is what a `set[Model]` becomes
    #: once it is JSON — is checked too.
    unique_items: bool = False
    # Numeric value bounds (integer/number, and per numeric array element). A
    # non-finite value (NaN/±Inf) is denied outright — a NaN makes every IEEE
    # comparison False, so a naive `<=` bound would silently pass it (Phase 0.1).
    minimum: float | None = None
    maximum: float | None = None
    exclusive_minimum: float | None = None
    exclusive_maximum: float | None = None
    multiple_of: float | None = None

    def __post_init__(self) -> None:
        # Detached first, before any check reads them. Annotated `tuple` and handed a
        # list, these stayed the caller's: `allowed.append("evil")` widened a live
        # gate's argument enum after it had already refused that value. See
        # `detach_sequence`.
        for name in ("enum", "item_enum"):
            declared = getattr(self, name)
            if declared is not None:
                if not isinstance(declared, list | tuple):
                    raise PolicyError(
                        f"{name} must be a list or tuple of portable values, got {type(declared).__name__}",
                        code="invalid_field",
                    )
                if not declared:
                    raise PolicyError(f"{name} must contain at least one allowed value", code="invalid_field")
                portable = tuple(_portable_value(value, f"{name}[{index}]") for index, value in enumerate(declared))
                object.__setattr__(self, name, detach_sequence(portable))
        for name in ("required", "nullable", "unique_items"):
            declared = getattr(self, name)
            if not isinstance(declared, bool):
                raise PolicyError(f"{name} must be true or false, got {declared!r}", code="invalid_field")
        # Every failure here is a PolicyError: a malformed field is a structural
        # problem in the policy, and a host that wraps `load_policy` in the
        # documented `except PolicyError: fail_closed()` must catch it rather than
        # take an unhandled ValueError on a typo.
        if not isinstance(self.type, str) or self.type not in _TYPE_CHECKS:
            raise PolicyError(f"unknown field type: {self.type!r}", code="invalid_field")
        if self.item_type is not None and (not isinstance(self.item_type, str) or self.item_type not in _TYPE_CHECKS):
            raise PolicyError(f"unknown array item_type: {self.item_type!r}", code="invalid_field")
        if self.sensitive not in (None, "pii", "secret"):
            raise PolicyError(f"sensitive must be None|'pii'|'secret', got {self.sensitive!r}", code="invalid_field")
        for bound in ("minimum", "maximum", "exclusive_minimum", "exclusive_maximum", "multiple_of"):
            _check_bound(bound, getattr(self, bound))
        for bound in ("max_length", "min_length", "max_items", "min_items"):
            _check_length_bound(bound, getattr(self, bound))
        # A bound consulted only under one `type` reads as enforced and enforces nothing
        # anywhere else, so every keyword is checked against the types that actually
        # consult it. This was a hand-written list covering the array keywords only, and
        # its own stated rule caught its siblings: `_check_scalar` applies the numeric
        # bounds only under `if spec.type in ("integer", "number")` and the string bounds
        # only under `isinstance(value, str)`, so `Field(type="string", maximum=10)` and
        # `Field(type="integer", pattern="^a+$")` loaded clean and checked nothing —
        # exactly the case the list was written for, one keyword to the side.
        #
        # `string` and `array` share the string and numeric bounds because an array's
        # elements are checked with the same two helpers, which is how
        # `item_type="string", max_length=8` bounds each element.
        for attr, applies_to in _KEYWORD_APPLIES_TO.items():
            if self.type in applies_to or self.type == "any":
                continue
            declared = getattr(self, attr)
            if declared is None or declared is False:
                continue
            raise PolicyError(
                f"{attr} is only meaningful on {' or '.join(sorted(applies_to))}, and this field is "
                f"{self.type!r} — it would read as a bound and enforce nothing",
                code="invalid_field",
            )
        # Every twin pair, not just the array one. The identical contradiction in the
        # pairs declared a few lines above and below — `min_length`/`max_length`,
        # `minimum`/`maximum`, `exclusive_minimum`/`exclusive_maximum` — constructed
        # fine, `Policy.validate()` returned `[]`, and every value was then denied at
        # call time with `arg_schema`: a field nothing can satisfy, discovered in
        # production rather than at load.
        for low, high in (
            ("min_items", "max_items"),
            ("min_length", "max_length"),
            ("minimum", "maximum"),
            ("exclusive_minimum", "exclusive_maximum"),
        ):
            lo, hi = getattr(self, low), getattr(self, high)
            if lo is not None and hi is not None and lo > hi:
                raise PolicyError(
                    f"{low} {lo} is greater than {high} {hi}, so no value can ever satisfy this field",
                    code="invalid_field",
                )
        # An array is granted the string and numeric keywords because its *elements* are
        # checked with the same two helpers — but only when `item_type` says which. On
        # `Field(type="array", max_length=8)` with no element type declared, nothing ever
        # reads `max_length`, which is the same dead bound the table above refuses on a
        # scalar. The untyped element path dispatches on the element, so a string bound
        # is live there; a *numeric* one on an array of strings is not.
        if self.type == "array" and self.item_type is not None:
            for attr, needs in (
                ("max_length", ("string", "any")),
                ("min_length", ("string", "any")),
                ("pattern", ("string", "any")),
                ("minimum", ("integer", "number", "any")),
                ("maximum", ("integer", "number", "any")),
                ("exclusive_minimum", ("integer", "number", "any")),
                ("exclusive_maximum", ("integer", "number", "any")),
                ("multiple_of", ("integer", "number", "any")),
            ):
                if getattr(self, attr) is not None and self.item_type not in needs:
                    raise PolicyError(
                        f"{attr} bounds each element of an array, and this one declares "
                        f"item_type={self.item_type!r} — it would read as a bound and enforce nothing",
                        code="invalid_field",
                    )
        # A bound on one side and its strict twin on the other are a pair too. `minimum=10`
        # with `exclusive_maximum=10` admits nothing, and neither loop above compares them.
        for low, high, admits_equal in (
            ("minimum", "exclusive_maximum", False),
            ("exclusive_minimum", "maximum", False),
        ):
            lo, hi = getattr(self, low), getattr(self, high)
            if lo is not None and hi is not None and (lo > hi or (lo == hi and not admits_equal)):
                raise PolicyError(
                    f"{low} {lo} and {high} {hi} leave no value that satisfies this field",
                    code="invalid_field",
                )
        # The exclusive pair is unsatisfiable when equal too: nothing is both strictly
        # above and strictly below the same number.
        if (
            self.exclusive_minimum is not None
            and self.exclusive_maximum is not None
            and self.exclusive_minimum == self.exclusive_maximum
        ):
            raise PolicyError(
                f"exclusive_minimum and exclusive_maximum are both {self.exclusive_minimum}, so no value "
                "can ever satisfy this field",
                code="invalid_field",
            )
        if self.multiple_of is not None and self.multiple_of == 0:
            raise PolicyError(f"multiple_of must be non-zero, got {self.multiple_of!r}", code="invalid_field")
        if self.pattern is not None:
            if not isinstance(self.pattern, str):
                raise PolicyError(f"pattern must be a string, got {type(self.pattern).__name__}", code="invalid_field")
            # Compile eagerly so an invalid regex fails LOUDLY at policy-load
            # instead of silently fail-closing every call at runtime, and screen it
            # for catastrophic backtracking in the same pass — an imported pattern
            # is attacker-influenced input and gets checked before it can run.
            try:
                compiled = re.compile(self.pattern)
            except re.error as exc:
                raise PolicyError(f"invalid regex pattern {self.pattern!r}: {exc}", code="invalid_field") from exc
            # Lazy on purpose. The structural screen reads CPython's private regex
            # parse tree so it agrees with the engine it protects. Importing it at
            # module load made *all* of Histos unimportable on an implementation that
            # does not expose those internals, even for policies with no patterns.
            # Such an implementation may use the rest of the gate; asking it to load a
            # pattern fails closed here, at policy construction, with a useful error.
            try:
                from histos.redos import reject_catastrophic_backtracking

                reject_catastrophic_backtracking(self.pattern, compiled)
            except PolicyError:
                # A successfully running screen reports unsafe user input with its
                # own precise reason. Do not blur that into an availability problem.
                raise
            except Exception as exc:  # noqa: BLE001 — private parser drift fails closed
                raise PolicyError(
                    "pattern validation is unavailable on this Python implementation; "
                    "Histos will not run an unscreened backtracking regex",
                    code="unsafe_pattern",
                ) from exc


@dataclass(frozen=True)
class Schema:
    """An ordered map of field-name → :class:`Field`.

    ``allow_extra=False`` (the default) means an argument not named in the schema
    is rejected — deny-by-default extended to the argument surface.
    """

    fields: dict[str, Field] = field(default_factory=dict)
    allow_extra: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.allow_extra, bool):
            raise PolicyError(f"allow_extra must be true or false, got {self.allow_extra!r}", code="invalid_field")
        if not isinstance(self.fields, Mapping):
            raise PolicyError(
                f"schema fields must be a mapping of field names to Field values, got {type(self.fields).__name__}",
                code="invalid_field",
            )
        for name, spec in self.fields.items():
            if not isinstance(name, str) or not name:
                raise PolicyError(f"a schema field name must be a non-empty string, got {name!r}", code="invalid_field")
            if not isinstance(spec, Field):
                raise PolicyError(
                    f"schema field {name!r} must be a Field value, got {type(spec).__name__}",
                    code="invalid_field",
                )
        # One level, which is enough: the values are `Field`s that detach their own
        # collections. What this stops is the *map* growing — an argument appearing in a
        # schema that was validated without it. See `detach_mapping`.
        object.__setattr__(self, "fields", detach_mapping(self.fields))


from histos.policy.validation import sensitive_fields as sensitive_fields  # noqa: E402
from histos.policy.validation import validate as validate  # noqa: E402
