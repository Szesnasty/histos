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
import re._constants as _re_const
import re._parser as _re_parser
from dataclasses import dataclass, field
from typing import Any

from histos.errors import PolicyError

# Cap the input a regex ever sees. This is a size bound, not a time bound — a
# pattern that backtracks exponentially turns 4 KiB into years — so the real
# defence is `_reject_catastrophic_backtracking` below, which refuses such a
# pattern at policy-load time. Both apply.
_MAX_PATTERN_INPUT = 4_096

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

# ── ReDoS screen ─────────────────────────────────────────────────────────
#
# A `pattern` reaching this module is untrusted: it may come from an MCP/OpenAPI
# server the user merely pointed at. `re` is a backtracking engine with no step
# budget and no timeout, and it does not release the GIL, so a catastrophic
# pattern cannot be interrupted by a watchdog thread once it starts — by the time
# a bad pattern is running it is already too late. The only fail-closed answer
# available without a new engine is to refuse the pattern *before* it can run.
#
# So the pattern is parsed with the stdlib's own parser and refused when its shape
# admits exponential backtracking. Three shapes cover the catastrophic families:
#
#   nested variable repeat   (a+)+      — 2ⁿ ways to split the input
#   alternation in a repeat  (a|ab)*    — same, via ambiguous branches
#   repeat of the same thing \d+\d+     — every split of the run has to be tried
#
# The screen is deliberately conservative: it rejects some patterns that happen to
# be safe (`(a|b)*`, which a character class expresses anyway). A false positive is
# a loud load-time error with a suggested rewrite; a false negative is a hung
# process holding the GIL. Atomic groups and possessive quantifiers cannot be
# backtracked into, so they reset the analysis rather than tripping it.
#
# Adjacency is judged on the repeated body, so `\d+\d+` is refused while `\w+\s+\w+`
# — adjacent but unambiguous — loads. Two adjacent repeats over *overlapping but
# unequal* classes (`[a-z]+[a-z0-9]+`) still pass and remain quadratic; that is the
# one case where `_MAX_PATTERN_INPUT` is doing the bounding rather than this screen.
_BACKTRACKING_REPEATS = frozenset({_re_const.MAX_REPEAT, _re_const.MIN_REPEAT})
_ATOMIC_REPEATS = frozenset({_re_const.POSSESSIVE_REPEAT})


def _variable_width(av: tuple[Any, ...]) -> bool:
    """True when a repeat's ``(min, max)`` lets it match a variable number of items."""
    return av[0] != av[1]


def _shape_key(node: Any) -> Any:
    """A hashable, comparable form of a parse subtree (``SubPattern`` is list-like)."""
    if isinstance(node, tuple | list | _re_parser.SubPattern):
        return tuple(_shape_key(item) for item in node)
    return node


def _backtracking_risk(seq: Any, *, in_repeat: bool) -> str | None:
    """Describe the first exponential-backtracking shape in a parsed pattern, if any."""
    previous_body: Any = None
    for op, av in seq:
        body_key: Any = None
        if op in _BACKTRACKING_REPEATS:
            variable_repeat = _variable_width(av)
            if in_repeat and variable_repeat:
                return "a variable-length repeat nested inside another repeat, e.g. `(a+)+`"
            if variable_repeat:
                body_key = _shape_key(av[2])
                if body_key == previous_body:
                    return "the same thing repeated twice in a row, e.g. `\\d+\\d+`"
            risk = _backtracking_risk(av[2], in_repeat=in_repeat or variable_repeat)
        elif op is _re_const.BRANCH:
            if in_repeat:
                return "an alternation inside a repeat, e.g. `(a|ab)*` — use a character class"
            risk = next((r for b in av[1] if (r := _backtracking_risk(b, in_repeat=False))), None)
        elif op is _re_const.SUBPATTERN:
            risk = _backtracking_risk(av[3], in_repeat=in_repeat)
        elif op in (_re_const.ASSERT, _re_const.ASSERT_NOT):
            # A lookaround runs its own match, so it starts a fresh analysis.
            risk = _backtracking_risk(av[1], in_repeat=False)
        elif op is _re_const.ATOMIC_GROUP or op in _ATOMIC_REPEATS:
            body = av[2] if op in _ATOMIC_REPEATS else av
            risk = _backtracking_risk(body, in_repeat=False)
        elif op is _re_const.GROUPREF_EXISTS:
            risk = next((r for b in av[1:] if b and (r := _backtracking_risk(b, in_repeat=in_repeat))), None)
        else:
            risk = None  # every remaining opcode is a leaf (literal, class, anchor, backref)
        if risk is not None:
            return risk
        previous_body = body_key
    return None


def _reject_catastrophic_backtracking(pattern: str) -> None:
    risk = _backtracking_risk(_re_parser.parse(pattern), in_repeat=False)
    if risk is None:
        return
    raise PolicyError(
        f"pattern {pattern!r} can backtrack exponentially — refusing it. It contains {risk}. "
        "`re` has no step budget and does not release the GIL, so one crafted argument would "
        "stall this process; the pattern is refused at load rather than at 4 KiB of input. "
        "Rewrite it with a character class, a bounded repeat `{m,n}`, or an atomic group `(?>...)`.",
        code="unsafe_pattern",
    )


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
        for bound in ("max_length", "min_length"):
            _check_length_bound(bound, getattr(self, bound))
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
                re.compile(self.pattern)
            except re.error as exc:
                raise PolicyError(f"invalid regex pattern {self.pattern!r}: {exc}", code="invalid_field") from exc
            _reject_catastrophic_backtracking(self.pattern)


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
