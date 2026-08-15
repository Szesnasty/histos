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
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

# Re-exported with `as`, which is the explicit-re-export spelling: `histos.contracts.
# Principal` and `.Constraint` are documented and stay resolvable even though the
# definitions moved to the modules that own their machinery.
from histos.authz import Binding as Binding
from histos.authz import Constraint as Constraint
from histos.authz import ConstraintResult as ConstraintResult
from histos.canonical import canonical_json, normalize_numbers
from histos.errors import PolicyError
from histos.frozen import Principal as Principal
from histos.frozen import ReadOnlyList as ReadOnlyList
from histos.schema import Schema

_UNSET: Any = object()

# The value types a Policy Format 0.1 document can actually carry, plus the Python
# spellings of them that canonicalize deterministically (a tuple is a list; a set is
# how anyone writes an `in` membership test in code). Anything else — a Decimal, a
# datetime, an arbitrary object — used to reach `content_hash` and be flattened by
# `default=str`, which both collided distinct policies and, for a set, captured
# PYTHONHASHSEED-dependent iteration order in a hash that approvals bind to.
_JSON_SCALARS = (str, int, float, bool, type(None))

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
    # Route this call through the host's semantic tier before it may proceed. The tier
    # is the *only* thing that can let it continue: with none wired the call is denied
    # (`no_escalation_tier`), which is what makes adding meaning unable to widen the
    # gate and lacking it unable to open one. See `Engine._escalate`.
    requires_escalation: bool = False
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

    def shape_structure(self) -> dict[str, Any]:
        """The same half, with its types intact — what the lock's hashes are taken over.

        :meth:`shape_fingerprint` is the *projection*: a published, flattened view that
        `conformance/projection` pins and that does not move. Hashing that view is what
        made the lock blind to the change it exists to catch: a source shipping
        ``enum: ["1", "2"]`` where the honest one shipped ``enum: [1, 2]`` flattened to
        the same bytes, so all three lock hashes matched, ``histos drift`` exited 0, and
        enforcement had silently inverted — the exact MCP rug-pull the lock is for.
        """
        return {"args": _schema_structure(self.args), "returns": _schema_structure(self.returns)}


def _schema_structure(schema: Schema | None) -> Any:
    """Every declared keyword of a schema, typed exactly as it was written.

    *Every* one. A keyword that enforces something and is not listed here is a pair of
    policies that decide differently and hash the same — so an approval issued against
    one binds the other, `histos drift` reports CLEAN across the flip, and the lock's
    `contract_sha256` collides. `unique_items` was left out when it was added and did
    all four. `tests/test_release_round4.py` now walks `Field`'s dataclass fields and
    fails on the next omission rather than waiting for a review to find it.
    """
    if schema is None:
        return None
    return {
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
                "nullable": f.nullable,
                "item_enum": list(f.item_enum) if f.item_enum is not None else None,
                "item_type": f.item_type,
                "max_items": f.max_items,
                "min_items": f.min_items,
                "unique_items": f.unique_items,
                "minimum": f.minimum,
                "maximum": f.maximum,
                "exclusive_minimum": f.exclusive_minimum,
                "exclusive_maximum": f.exclusive_maximum,
                "multiple_of": f.multiple_of,
            }
            for name, f in schema.fields.items()
        },
    }


def _schema_fingerprint(schema: Schema | None) -> Any:
    """The **lock's** view of a schema, with every bound flattened to decimal text.

    This exact structure is pinned by ``conformance/projection`` and is what
    ``contract_sha256`` is defined over, so it is a published artifact and does not
    move. It shares one rule with ``content_hash`` — every number is rendered through
    :func:`histos.canonical.canonical_number`, so `500` and `500.0` are one policy —
    but not one *encoding*: flattening a number to a bare string is lossy, and
    `Policy.content_hash` needs a form in which the integer `1` and the string `"1"`
    stay distinguishable (see :meth:`Policy.fingerprint`).
    """
    return normalize_numbers(_schema_structure(schema))


# A canary is a token planted to be conspicuous; anything this short is a fragment of
# one, and matching it turns every ordinary argument into an exfiltration alert. Lives
# here rather than in `bundle`, so the Python constructor and the file format cannot
# come to different conclusions about the same policy.
_MIN_CANARY_LENGTH = 6


@dataclass(frozen=True)
class Policy:
    """The static, developer-owned policy — the portable artifact.

    Carries **versioning + integrity** metadata: ``policy_id``,
    ``policy_version``, ``created_at``, ``schema_version`` and a structural
    :meth:`content_hash`. The gate records the hash on every decision, so a trace
    can be tied back to the exact ruleset that produced it.
    """

    # `Mapping`, not `dict`: a Gate hands its own ruleset out through `gate.policy`,
    # and holds it as a read-only view so an in-place edit cannot take effect against a
    # `policy_hash` computed before it. Callers building a Policy still pass plain
    # dicts; only the type says what the gate is allowed to assume.
    tools: Mapping[str, ToolContract] = field(default_factory=dict)
    permissions: Mapping[str, frozenset[str]] = field(default_factory=dict)
    role_inherits: Mapping[str, str] = field(default_factory=dict)
    canaries: frozenset[str] = frozenset()
    policy_id: str | None = None
    policy_version: str = "0"
    created_at: str | None = None  # ISO-8601, set by the exporter — not auto-stamped
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Coerce and check `canaries`, the twin of the `can_view` fix that missed it.

        `Principal.can_view` learned that a bare string is one sensitivity class and not
        a set of characters. `canaries` is annotated `frozenset[str]`, is set from the
        same kind of constructor call, and had no check at all — so
        `Policy(canaries="SECRET-TOKEN")` became eleven one-character canaries, every
        one of which appears in ordinary text. The result is a policy that denies every
        call and redacts every result, from one missing pair of brackets.

        The file-format path has guarded exactly this typo all along (`bundle._canaries`);
        this is the Python path agreeing with it, minimum length included.
        """
        canaries = self.canaries
        if isinstance(canaries, str):
            canaries = frozenset({canaries})
        elif not isinstance(canaries, frozenset):
            canaries = frozenset(canaries)
        for token in canaries:
            if not isinstance(token, str):
                raise PolicyError(f"canary {token!r} is a {type(token).__name__}; canaries are string tokens")
            if len(token) < _MIN_CANARY_LENGTH:
                raise PolicyError(
                    f"canary {token!r} is shorter than {_MIN_CANARY_LENGTH} characters — a token this short "
                    "appears in ordinary text, so it would deny every call and redact every result"
                )
        if canaries is not self.canaries:
            object.__setattr__(self, "canaries", canaries)

        # `permissions` is declared four lines above `canaries` and got none of this,
        # although the argument for coercing `canaries` applies to it word for word: the
        # natural typo silently half-works. `Policy(permissions={"analyst": "read_doc"})`
        # and the equally natural `{"analyst": ["read_doc"]}` reach `allowed_tools`,
        # where `allowed |= ...` raised an uncaught `TypeError` — out of `validate()`,
        # which is documented as *returning* a list of structural problems, so a host
        # doing `except PolicyError: fail_closed()` took an unhandled exception instead.
        # A string is one tool name, not a set of characters, for the same reason a
        # canary is one token.
        coerced: dict[str, frozenset[str]] = {}
        changed = False
        for role, grant in self.permissions.items():
            if isinstance(grant, frozenset):
                coerced[role] = grant
                continue
            changed = True
            if isinstance(grant, str):
                coerced[role] = frozenset({grant})
                continue
            try:
                coerced[role] = frozenset(grant)
            except TypeError as exc:
                raise PolicyError(
                    f"permissions[{role!r}] is a {type(grant).__name__}; a grant is a tool name or a collection of them"
                ) from exc
        if changed:
            object.__setattr__(self, "permissions", coerced)

    def contract_for(self, tool_name: str) -> ToolContract | None:
        return self.tools.get(tool_name)

    def allowed_tools(self, role: str) -> frozenset[str]:
        """Tools ``role`` may call, following inheritance (cycle-safe)."""
        seen: set[str] = set()
        allowed: set[str] = set()
        current: str | None = role
        while current is not None and current not in seen:
            seen.add(current)
            # `update`, not `|=`: `__post_init__` coerces every grant, but a `Policy`
            # rebuilt through `dataclasses.replace` on a path that skips it, or a future
            # gap of the same kind, should degrade rather than raise out of a method
            # `validate()` calls to *report* problems.
            allowed.update(self.permissions.get(current, frozenset()))
            current = self.role_inherits.get(current)
        return frozenset(allowed)

    def fingerprint(self) -> dict[str, Any]:
        """Canonical structural view used for :meth:`content_hash` (metadata excluded)."""
        structure = {
            "schema_version": self.schema_version,
            "tools": {
                name: {
                    "args": _schema_structure(t.args),
                    "returns": _schema_structure(t.returns),
                    "access": t.access,
                    "sensitivity": t.sensitivity.value,
                    "rate_limit": t.rate_limit,
                    "budget": t.budget,
                    "requires_confirmation": t.requires_confirmation,
                    "confirmation_expires_in": t.confirmation_expires_in,
                    # Present unconditionally, like every other key here. Emitting it
                    # only when set would keep pre-escalation hashes stable at the cost
                    # of a conditional rule in the one artifact two implementations
                    # must reproduce byte for byte — and a hash rule nobody can restate
                    # in one sentence is how approvals silently stop matching.
                    "requires_escalation": t.requires_escalation,
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
        # Returned with its types intact. Flattening numbers to bare text here is what
        # made `value: 1` and `value: "1"` the same policy to `content_hash` while the
        # engine still gave them opposite verdicts — a collision by construction, in
        # the one value approvals and policy pinning are bound to. The number rule
        # (`500` and `500.0` are one policy, because no JavaScript parser can tell them
        # apart) still applies, but it is applied by the canonicalizer, which tags the
        # type first. See `canonical_json(numbers_as_text=True)`.
        return structure

    def content_hash(self) -> str:
        """A structural identity two implementations can agree on, byte for byte.

        Not `json.dumps(..., default=str)`: that had no type tags, so distinct policies
        collided, and it inherited Python's iteration order for sets, so the same
        `Policy` object hashed differently in two processes with different
        `PYTHONHASHSEED` — which silently unbinds every approval issued by one worker
        from every other worker.
        """
        body = canonical_json(self.fingerprint(), numbers_as_text=True)
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
    "no_escalation_tier": "this tool is marked `escalate` and no semantic tier is wired — "
    "pass Gate(escalate=...), or drop `escalate` from the policy; the gate will not "
    "let an unjudged call through",
    "escalation_denied": "the semantic tier refused this call",
    "escalation_error": "the escalate callback raised, or is async while the tool is sync",
    "output_schema": "the tool output did not match its declared return schema",
    "confirm_suspended": "resume the run and retry once the approval is granted; nothing was decided",
    "unnameable_args": "call the tool with keyword arguments — a policy names its fields, so the gate "
    "cannot check what it cannot name",
    "uninspectable_output": "collect the result first — `list(...)`, `dict(...)`, `bytes(...)` — and return "
    "that; the output half of the gate can only inspect a materialised value",
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
    # A MARKER, never a control input: true on every decision that came out of the
    # semantic seam — the tier's approval, its refusal, its failure, and the collapse
    # when no tier is wired. It records that meaning was consulted (or should have
    # been) so an audit trail can separate those calls; the verdict itself is entirely
    # in `effect`/`rule`. It is deliberately not an `Effect` member: adding one to a
    # public StrEnum turns every `if effect is DENY` in every host into a silently
    # non-exhaustive match, and the branch such code falls through to is "proceed".
    # A flag nobody reads cannot fail open; an effect nobody handles can.
    escalate: bool = False
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

        Only ALLOW says OK, and the fallthrough is the refusal rather than the other
        way round. An effect this table has not been taught is a bug, and the message
        it hands the model on the way out must not be the one that reads as consent.
        """
        if self.effect is Effect.REQUIRE_CONFIRMATION:
            return "CONFIRMATION_REQUIRED"
        if self.effect is Effect.REDACT:
            return "OUTPUT_REDACTED"
        if self.effect is Effect.ALLOW:
            return "OK"
        return "ACTION_NOT_AUTHORIZED"

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
