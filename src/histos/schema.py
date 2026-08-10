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
from dataclasses import dataclass, field
from typing import Any

# Bound every regex match so a pathological pattern/input can never stall the
# event loop (ReDoS). Args longer than this are rejected outright by the field.
_MAX_PATTERN_INPUT = 4_096

_TYPE_CHECKS: dict[str, type | tuple[type, ...]] = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": (list, tuple),
    "object": dict,
    "any": object,
}


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
    item_type: str | None = None  # element type for "array"
    # Numeric value bounds (integer/number, and per numeric array element). A
    # non-finite value (NaN/±Inf) is denied outright — a NaN makes every IEEE
    # comparison False, so a naive `<=` bound would silently pass it (Phase 0.1).
    minimum: float | None = None
    maximum: float | None = None
    exclusive_minimum: float | None = None
    exclusive_maximum: float | None = None
    multiple_of: float | None = None

    def __post_init__(self) -> None:
        if self.type not in _TYPE_CHECKS:
            raise ValueError(f"unknown field type: {self.type!r}")
        if self.multiple_of is not None and self.multiple_of == 0:
            raise ValueError(f"multiple_of must be non-zero, got {self.multiple_of!r}")
        if self.sensitive not in (None, "pii", "secret"):
            raise ValueError(f"sensitive must be None|'pii'|'secret', got {self.sensitive!r}")
        if self.pattern is not None:
            # Compile eagerly so an invalid regex fails LOUDLY at policy-load
            # instead of silently fail-closing every call at runtime. NOTE: this
            # does not defend against ReDoS — a catastrophic-backtracking pattern
            # from an *imported* (untrusted) tool schema can still stall the thread
            # on a crafted input. stdlib `re` has no execution bound; keep patterns
            # simple and treat imported patterns as untrusted (see SECURITY.md).
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"invalid regex pattern {self.pattern!r}: {exc}") from exc


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


def _check_number(name: str, spec: Field, value: int | float) -> list[str]:
    """Value bounds for a number — a scalar arg or one numeric array element.

    A non-finite float (NaN/±Inf) is denied first: it cannot satisfy a bound
    consistently, so allowing it would be a silent fail-open.
    """
    if isinstance(value, float) and not math.isfinite(value):
        return [f"{name}: non-finite number ({value!r}) is not allowed"]
    if spec.minimum is not None and value < spec.minimum:
        return [f"{name}: {value} < minimum {spec.minimum}"]
    if spec.maximum is not None and value > spec.maximum:
        return [f"{name}: {value} > maximum {spec.maximum}"]
    if spec.exclusive_minimum is not None and value <= spec.exclusive_minimum:
        return [f"{name}: {value} <= exclusive_minimum {spec.exclusive_minimum}"]
    if spec.exclusive_maximum is not None and value >= spec.exclusive_maximum:
        return [f"{name}: {value} >= exclusive_maximum {spec.exclusive_maximum}"]
    if spec.multiple_of is not None:
        if isinstance(value, int) and isinstance(spec.multiple_of, int):
            ok = value % spec.multiple_of == 0
        else:
            q = value / spec.multiple_of
            ok = math.isclose(q, round(q), rel_tol=1e-9, abs_tol=1e-9)
        if not ok:
            return [f"{name}: {value} is not a multiple of {spec.multiple_of}"]
    return []


def _check_scalar(name: str, spec: Field, value: Any) -> list[str]:
    errors: list[str] = []
    expected = _TYPE_CHECKS[spec.type]

    # bool is a subclass of int/float — keep numbers distinct from booleans.
    if spec.type in ("integer", "number") and isinstance(value, bool):
        return [f"{name}: expected {spec.type}, got boolean"]
    if spec.type != "any" and not isinstance(value, expected):
        return [f"{name}: expected {spec.type}, got {type(value).__name__}"]

    if spec.enum is not None and value not in spec.enum:
        errors.append(f"{name}: {value!r} not in allowed values {list(spec.enum)}")

    if isinstance(value, str):
        errors.extend(_check_string_value(name, spec, value))
    if spec.type in ("integer", "number"):
        errors.extend(_check_number(name, spec, value))

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
    """Return a list of human-readable validation errors (empty = valid)."""
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

    ``allowed`` is the set of field names the caller's role may view in the clear.
    """
    return [name for name, spec in schema.fields.items() if spec.sensitive is not None and name not in allowed]
