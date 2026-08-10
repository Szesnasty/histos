"""The typed contracts the gate reasons about.

This module is the concrete form of the spec's core ideas:

* the **input contract** — :class:`GateRequest` is the *only* thing a
  decision may look at: tool name, arguments, a **trusted** principal, and the
  static policy. Never conversation, documents, or prior tool outputs.
* the **tool contract** — :class:`ToolContract` describes a tool by
  more than its name: the arguments it accepts *and* what it returns.
* **resource-aware authorization** — :class:`Constraint`
  expresses Cedar-style ``principal / action / resource / context`` rules, e.g.
  "``delete_invoice`` only if ``resource.tenant_id == principal.tenant_id``". This
  is what turns "may this role call this tool?" into "may this principal perform
  *this* operation on *this* resource?".

Everything here is a plain, serialisable dataclass — no ORM, no DB, no network.
A :class:`Policy` is the portable, **versioned, integrity-checked** artifact:
another tool may generate one, but the gate loads it with nothing else present.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from histos.canonical import normalize_numbers
from histos.errors import PolicyError
from histos.schema import Schema

_UNSET: Any = object()

SCHEMA_VERSION = "histos.policy/0.1"


class Effect(StrEnum):
    """What a gate decided to do."""

    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"  # post-gate only: return, but with sensitive/canary content removed
    REQUIRE_CONFIRMATION = "require_confirmation"


class Sensitivity(StrEnum):
    """How much damage a call to this tool can do. Advisory: it drives review
    findings and reads in an audit trail, and never changes a decision by itself."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Principal:
    """Who is making the call.

    **Trusted, and bound out-of-band**. The host sets this from
    workload identity or an authenticated session — it must NEVER be derived from
    a tool argument or model output. The gate is only as strong as this value.

    ``attributes`` carry trusted context used by resource-aware constraints
    (e.g. ``{"tenant_id": "acme", "region": "eu"}``). ``can_view`` lists return
    fields this principal may see in the clear even when marked sensitive.
    """

    role: str
    identity: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    can_view: frozenset[str] = frozenset()


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


@dataclass(frozen=True)
class ConstraintResult:
    ok: bool
    field: str = ""
    op: str = ""
    expected: str = ""
    received: str = ""
    reason: str = ""


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
        if self.op not in _OPS:
            raise PolicyError(f"unknown constraint op {self.op!r}; allowed: {sorted(_OPS)}")
        has_value = self.value is not _UNSET
        has_attr = self.principal_attr is not None
        if has_value == has_attr:
            raise PolicyError("constraint needs exactly one of value= or principal_attr=")

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
        else:
            rhs = self.value

        try:
            ok = _OPS[self.op](lhs, rhs)
        except TypeError as exc:
            return ConstraintResult(False, self.field, self.op, repr(rhs), repr(lhs), f"type error: {exc}")

        reason = "" if ok else f"constraint {self.field} {self.op} {rhs!r} not satisfied"
        return ConstraintResult(ok, self.field, self.op, repr(rhs), repr(lhs), reason)

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


@dataclass(frozen=True)
class ToolContract:
    """A full description of a gated tool."""

    name: str
    args: Schema | None = None
    returns: Schema | None = None
    access: str = "read"  # "read" | "write"
    sensitivity: Sensitivity = Sensitivity.LOW
    rate_limit: int | None = None  # max calls per window (see LimitStore)
    budget: int | None = None  # max total calls, no window
    requires_confirmation: bool = False
    # Seconds an out-of-band approval stays usable once granted. None = no expiry
    # enforced by the engine (the ApprovalStore is in-process and single-use anyway);
    # the field exists because the *format* carries it to whoever routes approvals.
    confirmation_expires_in: int | None = None
    constraints: tuple[Constraint, ...] = ()  # resource-level authorization
    bindings: tuple[Binding, ...] = ()  # trusted-arg injection (Phase 0.1)
    scan_output_for_canary: bool = True
    deny_secret_args: bool = True  # deny a checksum-confidence secret in an argument
    redact_secret_output: bool = True  # redact detected secrets from the output
    project_output: bool = False  # drop return fields not declared in `returns`
    # Malformed-output policy. When strict_returns is True the post-gate validates
    # the output against `returns`; a mismatch (unexpected/typed-wrong fields, or a
    # non-object shape) is handled per on_output_violation — because name-based
    # field redaction cannot save a secret that lands in an undeclared field.
    strict_returns: bool = False
    on_output_violation: str = "redact_all"  # "redact_all" | "deny" | "allow"

    def __post_init__(self) -> None:
        if self.access not in ("read", "write"):
            raise PolicyError(f"tool {self.name!r}: access must be 'read'|'write', got {self.access!r}")
        if self.on_output_violation not in ("redact_all", "deny", "allow"):
            raise PolicyError(
                f"tool {self.name!r}: on_output_violation must be 'redact_all'|'deny'|'allow', "
                f"got {self.on_output_violation!r}"
            )

    def needs_resource_resolver(self) -> bool:
        """Every constraint is resource-bound in Policy Format 0.1, so any constraint
        means the host must supply a resolver (absent one, the call fails closed)."""
        return bool(self.constraints)

    def shape_fingerprint(self) -> dict[str, Any]:
        """The **imported** half of this contract: argument and return shape, nothing else.

        Deliberately excludes `access`, `constraints`, `bindings`, `confirmation`, limits
        and the output rules. Those are the security semantics a human writes and no
        schema can supply, so they must not register as *contract drift* when somebody
        adds an ownership rule. See ``histos.lockfile``.
        """
        return {"args": _schema_fingerprint(self.args), "returns": _schema_fingerprint(self.returns)}


def _schema_fingerprint(schema: Schema | None) -> Any:
    """The hashable view of a schema, with every bound rendered as decimal text.

    Normalising *here* rather than at each call site is what keeps `content_hash` and
    the lock's `contract_sha256` on one rule: both read this, so neither can drift
    into hashing `500` differently from `500.0`. See :func:`histos.canonical.canonical_number`.
    """
    if schema is None:
        return None
    return normalize_numbers(
        {
            "allow_extra": schema.allow_extra,
            "fields": {
                name: {
                    "type": f.type,
                    "required": f.required,
                    "enum": list(f.enum) if f.enum is not None else None,
                    "max_length": f.max_length,
                    "min_length": f.min_length,
                    "pattern": f.pattern,
                    "sensitive": f.sensitive,
                    "item_type": f.item_type,
                    "minimum": f.minimum,
                    "maximum": f.maximum,
                    "exclusive_minimum": f.exclusive_minimum,
                    "exclusive_maximum": f.exclusive_maximum,
                    "multiple_of": f.multiple_of,
                }
                for name, f in schema.fields.items()
            },
        }
    )


@dataclass(frozen=True)
class Policy:
    """The static, developer-owned policy — the portable artifact.

    Carries **versioning + integrity** metadata: ``policy_id``,
    ``policy_version``, ``created_at``, ``schema_version`` and a structural
    :meth:`content_hash`. The gate records the hash on every decision, so a trace
    can be tied back to the exact ruleset that produced it.
    """

    tools: dict[str, ToolContract] = field(default_factory=dict)
    permissions: dict[str, frozenset[str]] = field(default_factory=dict)
    role_inherits: dict[str, str] = field(default_factory=dict)
    canaries: frozenset[str] = frozenset()
    policy_id: str | None = None
    policy_version: str = "0"
    created_at: str | None = None  # ISO-8601, set by the exporter — not auto-stamped
    schema_version: str = SCHEMA_VERSION

    def contract_for(self, tool_name: str) -> ToolContract | None:
        return self.tools.get(tool_name)

    def allowed_tools(self, role: str) -> frozenset[str]:
        """Tools ``role`` may call, following inheritance (cycle-safe)."""
        seen: set[str] = set()
        allowed: set[str] = set()
        current: str | None = role
        while current is not None and current not in seen:
            seen.add(current)
            allowed |= self.permissions.get(current, frozenset())
            current = self.role_inherits.get(current)
        return frozenset(allowed)

    def fingerprint(self) -> dict[str, Any]:
        """Canonical structural view used for :meth:`content_hash` (metadata excluded)."""
        structure = {
            "schema_version": self.schema_version,
            "tools": {
                name: {
                    "args": _schema_fingerprint(t.args),
                    "returns": _schema_fingerprint(t.returns),
                    "access": t.access,
                    "sensitivity": t.sensitivity.value,
                    "rate_limit": t.rate_limit,
                    "budget": t.budget,
                    "requires_confirmation": t.requires_confirmation,
                    "confirmation_expires_in": t.confirmation_expires_in,
                    "constraints": [c.fingerprint() for c in t.constraints],
                    "bindings": [[b.field, b.principal_attr] for b in t.bindings],
                    "scan_output_for_canary": t.scan_output_for_canary,
                    "deny_secret_args": t.deny_secret_args,
                    "redact_secret_output": t.redact_secret_output,
                    "project_output": t.project_output,
                    "strict_returns": t.strict_returns,
                    "on_output_violation": t.on_output_violation,
                }
                for name, t in sorted(self.tools.items())
            },
            "permissions": {role: sorted(tools) for role, tools in sorted(self.permissions.items())},
            "role_inherits": dict(sorted(self.role_inherits.items())),
            "canaries": sorted(self.canaries),
        }
        # Every number in the fingerprint becomes decimal text before it is hashed.
        # Without this, `maximum: 500` and `maximum: 500.0` are two different policies
        # to this engine and one policy to any JavaScript one — and `content_hash` is
        # what policy pinning and approval binding rest on, so the divergence would be
        # silent and would land on approvals that quietly stop matching. See
        # `canonical_number`. Only the *hash input* is text; the engine still compares
        # against the real numbers.
        return normalize_numbers(structure)

    def content_hash(self) -> str:
        body = json.dumps(self.fingerprint(), sort_keys=True, ensure_ascii=False, default=str)
        return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()

    def validate(self) -> list[str]:
        """Structural problems that should fail loud. Empty = OK."""
        issues: list[str] = []
        for role, tools in self.permissions.items():
            for tool_name in tools:
                if tool_name not in self.tools:
                    issues.append(f"role {role!r} grants unknown tool {tool_name!r}")
        for role, parent in self.role_inherits.items():
            if parent not in self.permissions and parent not in self.role_inherits:
                issues.append(f"role {role!r} inherits from unknown role {parent!r}")
        reachable: set[str] = set()
        for role in self.permissions:
            reachable |= self.allowed_tools(role)
        for name, tool in self.tools.items():
            if tool.args is None:
                issues.append(f"tool {name!r} has no arg schema — cannot validate arguments")
            # NOTE: there is no IDOR check here any more, and that is the point.
            # Policy Format 0.1 removed the self-declared-argument constraint from
            # the language, so the footgun cannot be written down. A check for an
            # unexpressible mistake is dead code; the format does the work.
            for b in tool.bindings:
                if tool.args is not None and not tool.args.allow_extra and b.field not in tool.args.fields:
                    issues.append(f"tool {name!r} binds unknown argument {b.field!r} (not in its arg schema)")
        return issues


@dataclass(frozen=True)
class GateRequest:
    """The *only* inputs a decision may read."""

    tool_name: str
    args: dict[str, Any]
    principal: Principal
    phase: str = "pre"  # "pre" | "post"


# Developer-facing "how to fix it" hints (developer/audit channel ONLY — never the
# model channel, which only ever gets the non-coaching public_reason). Keyed by rule.
_REMEDY: dict[str, str] = {
    "no_principal": "bind a trusted Principal out-of-band — use_principal() per request, or "
    "fixed_principal= for a single-identity script; the gate never infers one",
    "internal_error": "a check raised and the call was refused (fail-closed); this is a bug — "
    "the reason carries the exception",
    "unknown_tool": "add this tool to the policy (import it or declare a ToolContract)",
    "no_arg_schema": "give the tool an arg Schema so its arguments can be validated",
    "rbac": "grant this tool to the caller's role (or a role it inherits)",
    "arg_schema": "fix the argument to match the tool's schema (type / range / length / pattern)",
    "resource_constraint": "the resolved resource does not satisfy the constraint for this principal",
    # NOTE: `self_declared_authz` is deliberately absent — it is a review/validate
    # warning, never a runtime decision rule. This table is keyed by decision code
    # and is the published vocabulary; an entry with no matching decision is noise.
    "no_resource_resolver": "configure a resource_resolver on the Gate — every resource constraint needs one",
    "resource_not_found": "the resolver reported the resource does not exist",
    "resolver_error": "the resource_resolver raised — check it and the resource store",
    "arg_binding_unresolved": "the principal is missing the trusted attribute this tool injects",
    "canary_exfil": "a canary token appeared in an argument (planted-secret exfil attempt)",
    "secret_detected": "a recognised secret (key/token/PAN/IBAN) was passed as an argument",
    "rate_limit": "raise the tool's rate_limit or slow the caller",
    "budget": "raise the tool's budget for this principal",
    "requires_confirmation": "obtain an out-of-band approval for this exact action",
    "confirm_error": "the confirm callback raised, or is async while the tool is sync",
    "output_schema": "the tool output did not match its declared return schema",
}


@dataclass(frozen=True)
class GateDecision:
    """The outcome of evaluating a request against the policy.

    Carries **structured, actionable detail** so a developer
    sees *why* — ``rule`` (machine slug), ``field`` / ``expected`` / ``received``
    — not just an opaque denial.
    """

    effect: Effect
    rule: str  # machine slug of the check that decided, for the audit trail
    reason: str = ""
    field: str = ""
    expected: str = ""
    received: str = ""
    escalate: bool = False  # seam to a semantic tier; with none wired this collapses to DENY
    redactions: tuple[str, ...] = ()  # fields/tokens removed by a REDACT decision

    @property
    def allowed(self) -> bool:
        return self.effect in (Effect.ALLOW, Effect.REDACT)

    @property
    def public_reason(self) -> str:
        """The non-coaching message safe to return INTO the model loop (two-audience).

        Never leaks the threshold / allowlist / field a denial reveals — that stays in
        the developer/audit channel (rule/field/expected/received). Adapters return
        THIS to the agent by default.
        """
        if self.effect is Effect.REQUIRE_CONFIRMATION:
            return "CONFIRMATION_REQUIRED"
        if self.effect is Effect.DENY:
            return "ACTION_NOT_AUTHORIZED"
        if self.effect is Effect.REDACT:
            return "OUTPUT_REDACTED"
        return "OK"

    @property
    def remedy(self) -> str:
        """Developer-facing hint on how to fix the denial (developer channel only)."""
        return _REMEDY.get(self.rule, "")

    def explain(self) -> str:
        """One-line, human-readable explanation for logs and exceptions."""
        parts = [f"{self.effect.value.upper()} [{self.rule}]"]
        if self.field:
            parts.append(f"field={self.field}")
        if self.expected:
            parts.append(f"expected={self.expected}")
        if self.received:
            parts.append(f"received={self.received}")
        if self.reason:
            parts.append(f"— {self.reason}")
        return " ".join(parts)
