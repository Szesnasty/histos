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
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from histos.errors import PolicyError
from histos.redos import reject_catastrophic_backtracking
from histos.redos.alphabet import _MAX_PATTERN_INPUT

# Cap the input a regex ever sees. This is a size bound and nothing more: at a
# backtracking degree of three or four, 4 KiB is not a bound at all — a merely
# *polynomial* pattern turns it into hours, and an exponential one into years. The
# time bound is `_reject_catastrophic_backtracking` below, which refuses such a
# pattern at policy-load time. Both apply; only the second one bounds time.

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


# Which declared types actually consult each keyword. `any` is exempt from all of it:
# a field with no declared type is the one place a bound cannot be shown to be dead.
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
        # Every failure here is a PolicyError: a malformed field is a structural
        # problem in the policy, and a host that wraps `load_policy` in the
        # documented `except PolicyError: fail_closed()` must catch it rather than
        # take an unhandled ValueError on a typo.
        if self.type not in _TYPE_CHECKS:
            raise PolicyError(f"unknown field type: {self.type!r}", code="invalid_field")
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
            reject_catastrophic_backtracking(self.pattern, compiled)


@dataclass(frozen=True)
class Schema:
    """An ordered map of field-name → :class:`Field`.

    ``allow_extra=False`` (the default) means an argument not named in the schema
    is rejected — deny-by-default extended to the argument surface.
    """

    fields: dict[str, Field] = field(default_factory=dict)
    allow_extra: bool = False


def _check_string_value(name: str, spec: Field, value: str) -> list[str]:
    """Length and pattern checks for a string — a scalar arg *or* one array element.

    The absolute ``_MAX_PATTERN_INPUT`` cap is a DoS/ReDoS bound and always applies;
    ``max_length`` and ``pattern`` apply when declared. At most one error is
    reported (the first that fails), matching the scalar path.
    """
    if len(value) > _MAX_PATTERN_INPUT:
        return [f"{name}: value too long ({len(value)} > {_MAX_PATTERN_INPUT})"]
    if spec.min_length is not None and len(value) < spec.min_length:
        return [f"{name}: shorter than min_length {spec.min_length}"]
    if spec.max_length is not None and len(value) > spec.max_length:
        return [f"{name}: longer than max_length {spec.max_length}"]
    if spec.pattern is not None and not re.fullmatch(spec.pattern, value):
        return [f"{name}: does not match required pattern"]
    return []


def _check_unique(name: str, value: Sequence[Any]) -> list[str]:
    """`unique_items`, in linear time for anything a hash can separate.

    The first version was an equality scan against a growing list, on the reasoning that
    once a `set[Model]` has been through JSON it is a list of dicts and `set()` on that
    raises rather than deduplicating. True, and it made the check O(n^2) on the one
    input an attacker chooses freely. It runs at pre-gate step 3, *before* the output
    size budget at step 5, and `re` is not the only thing in this process that does not
    release the GIL: 8 000 distinct integers cost 461 ms of held CPU, per call, for a
    payload that builds in under a millisecond. The duplicate case short-circuits, so
    only the *valid* payload is expensive — which is the one an attacker sends.

    Hashable elements go in a set, which is exact and linear. Unhashable ones — dicts and
    lists, the `set[Model]`-through-JSON case — fall back to the equality scan, but only
    against each other, and under a bound: past `_MAX_EQUALITY_SCAN` of them the field is
    refused rather than scanned, because "this costs too much to check" and "this is
    fine" are not the same answer. A caller who needs more than that on unhashable
    elements has a `max_items` to declare.
    """
    hashed: set[Any] = set()
    unhashable: list[Any] = []
    for item in value:
        try:
            if item in hashed:
                return [f"{name}: has a repeated element, and unique_items is set"]
            hashed.add(item)
        except TypeError:
            if len(unhashable) >= _MAX_EQUALITY_SCAN:
                return [
                    f"{name}: has more than {_MAX_EQUALITY_SCAN} elements that cannot be hashed, "
                    "and unique_items cannot be checked on them without a quadratic scan — "
                    "declare max_items, or drop unique_items for this field"
                ]
            if item in unhashable:
                return [f"{name}: has a repeated element, and unique_items is set"]
            unhashable.append(item)
    return []


# Unhashable elements cost an equality scan each. 512 of them is about 130 000
# comparisons — under a millisecond on the shapes this sees — and the wall past which
# the field is refused instead of checked.
_MAX_EQUALITY_SCAN = 512


def _check_number(name: str, spec: Field, value: int | float) -> list[str]:
    """Value bounds for a number — a scalar arg or one numeric array element.

    A non-finite float (NaN/±Inf) is denied first: it cannot satisfy a bound
    consistently, so allowing it would be a silent fail-open.
    """
    if isinstance(value, float) and not math.isfinite(value):
        return [f"{name}: non-finite number is not allowed"]
    if spec.minimum is not None and value < spec.minimum:
        return [f"{name}: below minimum {spec.minimum}"]
    if spec.maximum is not None and value > spec.maximum:
        return [f"{name}: above maximum {spec.maximum}"]
    if spec.exclusive_minimum is not None and value <= spec.exclusive_minimum:
        return [f"{name}: not above exclusive_minimum {spec.exclusive_minimum}"]
    if spec.exclusive_maximum is not None and value >= spec.exclusive_maximum:
        return [f"{name}: not below exclusive_maximum {spec.exclusive_maximum}"]
    if spec.multiple_of is not None:
        if isinstance(value, int) and isinstance(spec.multiple_of, int):
            ok = value % spec.multiple_of == 0
        else:
            q = value / spec.multiple_of
            ok = math.isclose(q, round(q), rel_tol=1e-9, abs_tol=1e-9)
        if not ok:
            return [f"{name}: not a multiple of {spec.multiple_of}"]
    return []


def _check_scalar(name: str, spec: Field, value: Any) -> list[str]:
    errors: list[str] = []
    # A declared-nullable field accepts the null and stops there: every bound below
    # describes a value, and `None` is the absence of one.
    if value is None and spec.nullable:
        return errors
    expected = _TYPE_CHECKS[spec.type]

    # bool is a subclass of int/float — keep numbers distinct from booleans.
    if spec.type in ("integer", "number") and isinstance(value, bool):
        return [f"{name}: expected {spec.type}, got boolean"]
    if spec.type != "any" and not isinstance(value, expected):
        return [f"{name}: expected {spec.type}, got {type(value).__name__}"]

    if spec.enum is not None and value not in spec.enum:
        errors.append(f"{name}: not one of the allowed values {list(spec.enum)}")

    if isinstance(value, str):
        errors.extend(_check_string_value(name, spec, value))
    if spec.type in ("integer", "number"):
        errors.extend(_check_number(name, spec, value))

    if spec.type == "array" and isinstance(value, (list, tuple)):
        if spec.min_items is not None and len(value) < spec.min_items:
            errors.append(f"{name}: has {len(value)} items, fewer than min_items {spec.min_items}")
        if spec.max_items is not None and len(value) > spec.max_items:
            errors.append(f"{name}: has {len(value)} items, more than max_items {spec.max_items}")
        if spec.unique_items:
            errors.extend(_check_unique(name, value))

    if spec.type == "array" and spec.item_enum is not None and isinstance(value, (list, tuple)):
        allowed = spec.item_enum
        errors.extend(
            f"{name}[{i}]: not one of the allowed values {list(allowed)}"
            for i, item in enumerate(value)
            if item not in allowed
        )

    if spec.type == "array" and spec.item_type is not None:
        item_expected = _TYPE_CHECKS.get(spec.item_type, object)
        numeric_item = spec.item_type in ("integer", "number")
        for i, item in enumerate(value):
            iname = f"{name}[{i}]"
            if numeric_item and isinstance(item, bool):
                errors.append(f"{iname}: expected {spec.item_type}, got boolean")
            elif spec.item_type != "any" and not isinstance(item, item_expected):
                errors.append(f"{iname}: expected {spec.item_type}, got {type(item).__name__}")
            elif spec.item_type == "string" and isinstance(item, str):
                # Bound each string element by the same length/pattern caps as a
                # scalar string — otherwise a huge or malformed element bypasses the
                # scalar bounds and flows into the canary scan and the tool. Nested
                # objects are still only shallow-checked.
                errors.extend(_check_string_value(iname, spec, item))
            elif numeric_item:
                errors.extend(_check_number(iname, spec, item))
    return errors


def validate(schema: Schema, data: dict[str, Any]) -> list[str]:
    """Return a list of human-readable validation errors (empty = valid).

    **No error here ever interpolates an argument value.** These strings become the
    ``reason`` on a ``GateDecision``, which is written to the audit record and put in
    the ``GateDenied`` message — both of which the docs promise carry only a keyed
    digest of the arguments. An enum or bound violation naming the value it rejected
    would put the rejected PII (or a canary token, since ``arg_schema`` is evaluated
    before the canary check) verbatim into a log file. Names, types and the
    *declared* bounds are policy, not caller data, and are safe to state.
    """
    errors: list[str] = []

    for fname, spec in schema.fields.items():
        if fname not in data:
            if spec.required:
                errors.append(f"{fname}: required but missing")
            continue
        errors.extend(_check_scalar(fname, spec, data[fname]))

    if not schema.allow_extra:
        for key in data:
            if key not in schema.fields:
                errors.append(f"{key}: unexpected argument (not in schema)")

    return errors


def sensitive_fields(schema: Schema, *, allowed: frozenset[str] = frozenset()) -> list[str]:
    """Names of fields marked sensitive that the caller is *not* allowed to see.

    ``allowed`` is ``Principal.can_view``: the **sensitivity classes** — ``"pii"`` /
    ``"secret"`` — this caller may receive in the clear. Classes, not field names,
    because that is what the policy marks and what the docs document; matching field
    names instead made the documented `can_view={"pii"}` silently redact everything,
    and made an escape hatch out of a name the policy never published.

    Anything in ``allowed`` that is not a class this engine knows matches nothing, so
    a typo or a stale name redacts rather than discloses.
    """
    return [
        name for name, spec in schema.fields.items() if spec.sensitive is not None and spec.sensitive not in allowed
    ]
