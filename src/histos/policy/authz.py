"""Resource-aware authorization: the part that turns a role check into a decision.

Split out of `contracts.py`. "May this role call this tool?" is a question about the
policy; "may this principal do *this* to *that* resource?" is a question about a value
the host resolved, and the two have different failure modes. A constraint that cannot be
evaluated is a DENY with a reason, never a pass — the resource attribute is fetched by a
trusted resolver and its absence means the gate does not know, which is not the same as
permission.

A constraint literal that cannot be canonicalised is refused when the policy is built
rather than when it is hashed, because a `content_hash` that is not reproducible is
worse than one that fails: pinning, approval binding and drift detection all keep
reporting green while comparing two different rulesets.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from histos.errors import PolicyError
from histos.policy.canonical import canonical_json
from histos.policy.frozen import Principal, _snapshot_value

_UNSET: Any = object()

# The value types a Policy Format 0.1 document can carry, plus the Python spellings that
# canonicalize deterministically (a tuple is a list; a set is how anyone writes an `in`
# test in code). Anything else reached `content_hash` and was flattened by `default=str`,
# which both collided distinct policies and, for a set, captured PYTHONHASHSEED-dependent
# iteration order in a hash that approvals bind to.
_JSON_SCALARS = (str, int, float, bool, type(None))

# ── resource-aware authorization ──────────────────────────────

_OPS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "in": lambda a, b: a in b,
    "not_in": lambda a, b: a not in b,
    "le": lambda a, b: a <= b,
    "lt": lambda a, b: a < b,
    "ge": lambda a, b: a >= b,
    "gt": lambda a, b: a > b,
}


def _portable_value(value: Any, where: str) -> Any:
    """Return the JSON spelling a constraint hashes, dumps and enforces as.

    A policy whose ``content_hash`` is not reproducible is worse than one that fails
    to load: pinning, approval binding and drift detection all keep reporting green
    while comparing two different rulesets. So the refusal happens here, at the point
    the policy is built, rather than silently at hash time.
    """
    try:
        canonical_json(value, numbers_as_text=True)
    except (TypeError, ValueError) as exc:
        raise PolicyError(f"{where}: value cannot be hashed reproducibly: {exc}") from exc

    if isinstance(value, _JSON_SCALARS):
        return value
    if isinstance(value, list | tuple):
        # The format and the published hash have one array type. Keeping a tuple here
        # made it enforce differently from a list while both shared one content_hash.
        return [_portable_value(item, where) for item in value]
    if isinstance(value, set | frozenset):
        # A set is the natural Python RHS of an `in` constraint, but the document has no
        # set type. Canonical order gives it the same portable list in every process.
        items = [_portable_value(item, where) for item in value]
        return sorted(items, key=lambda item: canonical_json(item, numbers_as_text=True))
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise PolicyError(f"{where}: object key {key!r} is not a string and cannot be written to JSON")
            out[key] = _portable_value(item, where)
        return out
    raise PolicyError(
        f"{where}: value of type {type(value).__name__!r} cannot be written as a policy literal; expected a JSON value"
    )


@dataclass(frozen=True)
class ConstraintResult:
    """The outcome of one constraint.

    Two channels, deliberately: ``reason`` / ``expected`` / ``received`` name the rule
    and the shape of the failure and are safe to put in a durable audit record, while
    ``detail`` quotes the actual resource attribute and is developer-only. The
    resolved resource is real business data — the owner's account number, a patient
    id — and a denial message is not a place to write it down forever.
    """

    ok: bool
    field: str = ""
    op: str = ""
    expected: str = ""
    received: str = ""
    reason: str = ""
    detail: str = ""


@dataclass(frozen=True)
class Constraint:
    """A row-level authorization predicate over the **resolved resource**.

    Compares an attribute of the resource actually being acted on — fetched by a
    trusted, host-provided resolver — against either a trusted ``principal_attr`` or
    a literal ``value``. Exactly one of the two must be given.

    ::

        Constraint.owns("tenant_id")                 # the row-ownership case
        Constraint("status", "ne", value="cancelled")  # a condition on resource state

    **There is no way to constrain a call argument here, on purpose** (Policy Format
    0.1). Draft 0.1 removed that capability because every use of it was one of two
    things, and neither belonged in the authorization layer:

    * *Redundant* — ``Constraint("amount", "le", value=1000)`` is
      ``amount: {maximum: 1000}`` written worse. It skips type validation and hides
      the bound outside the tool's contract, where a reader looks for it.
    * *A confused deputy* — comparing a caller-supplied ``tenant_id`` argument to the
      principal's proves the caller **named** their own tenant, not that the resource
      is theirs. With the resource keyed by a different argument (``invoice_id``),
      ``invoice_id=<someone else's>, tenant_id=<mine>`` passed every check. That is an
      IDOR, and a format where it is *unexpressible* beats one that warns about it.

    Three mechanisms, three jobs, no overlap:

    ==================  ====================================================
    argument schema     is this argument value admissible at all?
    ``Binding``         what the model must not be allowed to choose
    ``Constraint``      may this principal act on this *actual* resource?
    ==================  ====================================================

    The comparison is **static policy**: an attacker may influence the arguments, but
    never what the constraint requires — it can only fail.
    """

    field: str
    op: str
    value: Any = _UNSET
    principal_attr: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.field, str) or not self.field:
            raise PolicyError(f"constraint field must be a non-empty string, got {self.field!r}")
        if not isinstance(self.op, str) or self.op not in _OPS:
            raise PolicyError(f"unknown constraint op {self.op!r}; allowed: {sorted(_OPS)}")
        if self.principal_attr is not None and (not isinstance(self.principal_attr, str) or not self.principal_attr):
            raise PolicyError(f"constraint principal_attr must be a non-empty string, got {self.principal_attr!r}")
        has_value = self.value is not _UNSET
        has_attr = self.principal_attr is not None
        if has_value == has_attr:
            raise PolicyError("constraint needs exactly one of value= or principal_attr=")
        if has_value:
            portable = _portable_value(self.value, f"constraint {self.field!r} {self.op}")
            # A literal may be a list or a dict — `_reject_unhashable_value` allows both
            # — and the caller kept it. `literal.append("evil")` widened an `in`
            # constraint on a gate that was already running. Detached after the check,
            # so what is validated is what is stored.
            object.__setattr__(self, "value", _snapshot_value(portable))

    @classmethod
    def owns(cls, field: str, principal_attr: str | None = None) -> Constraint:
        """Row ownership: the resolved resource's ``field`` must equal the principal's.

        ``owns("tenant_id")`` == ``Constraint("tenant_id", "eq", principal_attr="tenant_id")``.
        The resolver looks the accessed resource up in the datastore and returns its
        *real* owner, so this is genuine resource authorization rather than a
        restatement of what the caller claimed.
        """
        return cls(field, "eq", principal_attr=principal_attr or field)

    def evaluate(self, resource: dict[str, Any], principal: Principal) -> ConstraintResult:
        if self.field not in resource:
            return ConstraintResult(
                False,
                self.field,
                self.op,
                "<present>",
                "<missing>",
                f"resolved resource has no attribute {self.field!r}",
            )
        lhs = resource[self.field]

        if self.principal_attr is not None:
            if self.principal_attr not in principal.attributes:
                return ConstraintResult(
                    False,
                    self.field,
                    self.op,
                    f"principal.{self.principal_attr}",
                    "<unset>",
                    f"principal attribute {self.principal_attr!r} is not set",
                )
            rhs: Any = principal.attributes[self.principal_attr]
            # Name the source, never the value: a trusted attribute is still the
            # tenant's identifier, and `expected` is copied into the audit record.
            expected = f"principal.{self.principal_attr}"
        else:
            rhs = self.value
            expected = repr(rhs)  # a policy literal — written by the developer, not observed

        # `received` names the *shape* of what was compared. The value itself is the
        # resolved resource's real attribute, so it goes to the developer channel only.
        received = f"resource.{self.field}"
        detail = f"resource.{self.field}={lhs!r} vs {rhs!r}"

        try:
            ok = _OPS[self.op](lhs, rhs)
        except TypeError as exc:
            return ConstraintResult(False, self.field, self.op, expected, received, f"type error: {exc}", detail)

        reason = "" if ok else f"constraint {self.field} {self.op} {expected} not satisfied"
        return ConstraintResult(ok, self.field, self.op, expected, received, reason, detail)

    def fingerprint(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "op": self.op,
            "value": None if self.value is _UNSET else self.value,
            "principal_attr": self.principal_attr,
        }


@dataclass(frozen=True)
class Binding:
    """Override a named argument with a TRUSTED value the model cannot control.

    Before a call executes the gate injects ``principal.attributes[principal_attr]``
    into ``field`` — so a hijacked model that passes ``tenant_id="attacker"`` simply
    has it replaced with its real tenant. This *dominates* validation: instead of
    catching a wrong value (which self-declaration makes an IDOR footgun), the wrong
    value becomes un-passable. Fail-closed: if the principal lacks the attribute, the
    call is denied — the gate never injects a missing/None trusted value.
    """

    field: str
    principal_attr: str

    def __post_init__(self) -> None:
        if not isinstance(self.field, str) or not self.field:
            raise PolicyError(f"binding field must be a non-empty string, got {self.field!r}")
        if not isinstance(self.principal_attr, str) or not self.principal_attr:
            raise PolicyError(f"binding principal_attr must be a non-empty string, got {self.principal_attr!r}")
