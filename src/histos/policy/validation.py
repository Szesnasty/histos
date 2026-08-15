"""Checking one call\'s arguments against the schema that declares them.

Split out of `schema.py`: declaring a shape and checking a value against it are
different jobs, and only the second one runs on the hot path with attacker-chosen input.
Everything here is therefore written to a second rule as well as to correctness — it must
not be made expensive by what it is given. `unique_items` is the cautionary tale: an
equality scan against a growing list is correct and cost 461 ms of held CPU for eight
thousand distinct elements, at a step that runs *before* the size budget.

Errors accumulate into a list rather than raising, because the gate reports every problem
with a call at once. A check that cannot be performed is an error too — never a pass.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from typing import Any

from histos.policy.schema import _TYPE_CHECKS, Field, Schema
from histos.redos.alphabet import _MAX_PATTERN_INPUT


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
        # Exact arithmetic whenever both sides are whole numbers, whatever Python type
        # they arrived as. Keying the exact path on `isinstance(..., int)` made
        # `multiple_of=3` and `multiple_of=3.0` two different rules: the other path is a
        # division plus `isclose(rel_tol=1e-9)`, and at 1e18 that tolerance is a window
        # about a billion wide, so the float spelling admitted what the int spelling
        # refused. `canonical_number` renders both as `"3"` and hands them one
        # `content_hash` — deliberately, because `JSON.parse` cannot tell them apart —
        # so those were two rulesets behind one hash, and a pinned hash, a bound
        # approval and a drift check all reported green across the difference.
        #
        # The float path stays for the case it was written for: a bound that is genuinely
        # fractional, where exact integer arithmetic has nothing to say.
        bound = spec.multiple_of
        if isinstance(bound, float) and bound.is_integer():
            bound = int(bound)
        if isinstance(value, int) and isinstance(bound, int):
            ok = value % bound == 0
        else:
            q = value / bound
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
    # Dispatched on the value, exactly like the string bounds on the line above. Keying
    # on the *declared* type instead is an asymmetry two adjacent lines made invisible,
    # and it left every numeric bound stone dead on a field with no declared type —
    # while `{"minimum": 1, "maximum": 100}` with no `type` is legal JSON Schema and what
    # a great many MCP servers emit. The schema layer then refused such a field outright
    # rather than admit a dead bound, so one honest property took its whole tool down.
    # Both halves of that were the same mistake: a bound the source wrote is enforced on
    # the values it can be enforced on.
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        errors.extend(_check_number(name, spec, value))

    # `any` for the same reason. An untyped field holding a list gets the element bounds
    # its source declared; one holding anything else is not an array and skips them.
    sequence = isinstance(value, (list, tuple)) and spec.type in ("array", "any")
    if sequence:
        if spec.min_items is not None and len(value) < spec.min_items:
            errors.append(f"{name}: has {len(value)} items, fewer than min_items {spec.min_items}")
        if spec.max_items is not None and len(value) > spec.max_items:
            errors.append(f"{name}: has {len(value)} items, more than max_items {spec.max_items}")
        if spec.unique_items:
            errors.extend(_check_unique(name, value))

    if sequence and spec.item_enum is not None:
        allowed = spec.item_enum
        errors.extend(
            f"{name}[{i}]: not one of the allowed values {list(allowed)}"
            for i, item in enumerate(value)
            if item not in allowed
        )

    if sequence:
        item_expected = _TYPE_CHECKS.get(spec.item_type, object) if spec.item_type else object
        numeric_item = spec.item_type in ("integer", "number")
        for i, item in enumerate(value):
            iname = f"{name}[{i}]"
            if spec.item_type is None:
                # No declared element type — `list[str | None]` is the ordinary source —
                # but the bounds beside it are still bounds. They used to be skipped
                # entirely, so `items: {anyOf: [{type: string, maxLength: 3}, null]}`
                # carried `max_length=3` into the contract and enforced nothing: a bound
                # that reads as enforced and is not, which is the one shape this module
                # refuses everywhere else. Dispatched on the element instead, exactly as
                # a scalar of unknown type is.
                if isinstance(item, str):
                    errors.extend(_check_string_value(iname, spec, item))
                elif isinstance(item, (int, float)) and not isinstance(item, bool):
                    errors.extend(_check_number(iname, spec, item))
                continue
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
