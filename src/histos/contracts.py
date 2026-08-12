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
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from histos.canonical import canonical_json, normalize_numbers
from histos.errors import PolicyError
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


class ReadOnlyDict(dict):  # type: ignore[type-arg]
    """A mapping that refuses to be edited, and is still a `dict` to the stdlib.

    `MappingProxyType` was the obvious choice and cost two things the stdlib does by
    `isinstance(obj, dict)`. `dataclasses.asdict` recurses into exact dicts, lists and
    dataclasses and falls back to `copy.deepcopy` for everything else — and a proxy
    cannot be deep-copied, so `dataclasses.asdict(gate.policy)` raised. `pickle` has the
    same hole, which `Policy.__getstate__` had to paper over. A `dict` subclass takes
    those branches, and refusing every mutator keeps the guarantee the proxy was chosen
    for: a ruleset a Gate owns cannot be edited under a `policy_hash` computed before
    the edit.
    """

    __slots__ = ()

    def _readonly(self, *_a: Any, **_k: Any) -> Any:
        raise TypeError(
            "this mapping is read-only: a Gate's ruleset cannot be edited in place, because every audit "
            "record would keep naming the hash computed before the edit. Swap the whole policy with "
            "`gate.policy = ...`, which re-hashes."
        )

    def __setitem__(self, *_a: Any, **_k: Any) -> Any:
        self._readonly()

    def __delitem__(self, *_a: Any, **_k: Any) -> Any:
        self._readonly()

    def pop(self, *_a: Any, **_k: Any) -> Any:
        self._readonly()

    def popitem(self, *_a: Any, **_k: Any) -> Any:
        self._readonly()

    def clear(self) -> None:
        self._readonly()

    def update(self, *_a: Any, **_k: Any) -> None:
        self._readonly()

    def setdefault(self, *_a: Any, **_k: Any) -> Any:
        self._readonly()

    def __reduce__(self) -> Any:
        return (self.__class__, (dict(self),))

    def copy(self) -> dict[str, Any]:
        return dict(self)


def _snapshot(attributes: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy what can be copied; keep what cannot, rather than refusing the request.

    The copy exists so a tool handed a bound attribute cannot edit the trust anchor
    through it. But a host legitimately parks unclonable things here — a database
    session, an HTTP client, a lock — and `deepcopy` raises on those, which turned
    building a `Principal` into something that could fail. A host builds one per
    request, so that is an outage, and it is a worse outcome than the sharing it
    prevents: an object with no `__deepcopy__` is one a tool could not meaningfully
    mutate into a different authorization answer anyway. Copy per value, so one
    uncopyable entry does not cost the snapshot on the others.
    """
    return {key: _snapshot_value(value) for key, value in attributes.items()}


def _snapshot_value(value: Any) -> Any:
    """Deep-copy ``value``, sharing by reference only the leaves that cannot be copied.

    The fallback used to be per *attribute*: `deepcopy(value)`, and on any exception the
    original object was stored whole. That reads as "one uncopyable entry does not cost
    the snapshot on the others" and is true only at the top level. `deepcopy` of a
    container raises if *any* descendant refuses — so a single `threading.Lock` (or an
    open file, a socket, a DB session) anywhere inside `{"tenant": {"id": "acme",
    "lock": Lock()}}` left the whole subtree aliased to the caller's live object,
    including every authorization-relevant scalar in it. A host that then edited its own
    dict flipped a constraint verdict from deny to allow on an already-bound Principal.

    So the walk is structural: containers are rebuilt element by element, and only the
    individual leaf that raises is shared. That leaf is, by the same argument as before,
    one a tool could not mutate into a different authorization answer anyway.
    """
    if isinstance(value, dict):
        return {_snapshot_value(k): _snapshot_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [_snapshot_value(v) for v in value]
        try:
            return type(value)(items)
        except (TypeError, ValueError):
            return type(value)(items) if type(value) in (list, tuple, set, frozenset) else items
    try:
        return deepcopy(value)
    except Exception:  # noqa: BLE001 — an uncopyable leaf must not fail the request
        return value


@dataclass(frozen=True)
class Principal:
    """Who is making the call.

    **Trusted, and bound out-of-band**. The host sets this from
    workload identity or an authenticated session — it must NEVER be derived from
    a tool argument or model output. The gate is only as strong as this value.

    ``attributes`` carry trusted context used by resource-aware constraints
    (e.g. ``{"tenant_id": "acme", "region": "eu"}``). ``can_view`` lists the
    **sensitivity classes** — ``"pii"``, ``"secret"`` — this principal may see in the
    clear; it is not a list of field names, and putting one there unredacts nothing.
    Attribute values are deep-copied on binding, so a value handed to a tool through a
    ``bind`` is a copy and the trust anchor cannot be rewritten through it.
    """

    role: str
    identity: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    can_view: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        # `frozen=True` froze the *binding* and nothing else: the dict it points at
        # stayed writable, so the trust anchor of the whole library could be edited
        # after the gate had been built from it. Take a snapshot behind a read-only
        # view, so a Principal handed to a gate cannot change under it and a caller
        # who kept the dict they passed in cannot change it either.
        #
        # `deepcopy`, not `dict(...)`: that was a shallow copy behind a read-only view,
        # so `{"tenants": [...]}` was still the caller's live list. Two ways that bites.
        # `Gate._apply_bindings` writes the trusted value straight into the tool's
        # arguments, so the tool body received the trust anchor itself and an ordinary
        # `args["tenants"].append(...)` edited what the *next* call would be authorized
        # against; and a host that kept its own dict could rewrite a bound principal
        # mid-request. A snapshot has to be a snapshot all the way down.
        object.__setattr__(self, "attributes", ReadOnlyDict(_snapshot(dict(self.attributes))))
        # A list here is the natural thing to write and it silently half-worked: it
        # compared as a member of nothing, and it made `hash(principal)` raise, which
        # is the one thing `__hash__` below exists to allow. Coerce rather than refuse —
        # the meaning of `["pii"]` is not in doubt.
        # A bare string is one sensitivity class, not a set of characters. `frozenset("pii")`
        # is `{'p','i'}`, which matches nothing and silently turns a grant into a denial —
        # the coercion that was added to accept a list quietly broke the shortest spelling.
        if isinstance(self.can_view, str):
            object.__setattr__(self, "can_view", frozenset({self.can_view}))
        elif not isinstance(self.can_view, frozenset):
            object.__setattr__(self, "can_view", frozenset(self.can_view))

    def __hash__(self) -> int:
        # The generated hash covered `attributes`, which is a mapping and unhashable,
        # so a "frozen" Principal could not go in a set or key a cache — the obvious
        # thing to want from the type the host binds per request. Attribute *values*
        # are host-supplied and may themselves be unhashable (a list of regions), so
        # only the key set takes part; `__eq__` still separates principals that differ
        # only in a value, which is all a hash has to allow.
        return hash((self.role, self.identity, self.can_view, tuple(sorted(self.attributes))))


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


def _reject_unhashable_value(value: Any, where: str) -> None:
    """Refuse a constraint literal the engine cannot hash reproducibly.

    A policy whose ``content_hash`` is not reproducible is worse than one that fails
    to load: pinning, approval binding and drift detection all keep reporting green
    while comparing two different rulesets. So the refusal happens here, at the point
    the policy is built, rather than silently at hash time.
    """
    if isinstance(value, _JSON_SCALARS):
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _reject_unhashable_value(item, where)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_unhashable_value(key, where)
            _reject_unhashable_value(item, where)
        return
    raise PolicyError(
        f"{where}: value of type {type(value).__name__!r} cannot be hashed reproducibly; "
        "a constraint literal must be a JSON value (string, number, boolean, null, array, object)"
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
        if self.op not in _OPS:
            raise PolicyError(f"unknown constraint op {self.op!r}; allowed: {sorted(_OPS)}")
        has_value = self.value is not _UNSET
        has_attr = self.principal_attr is not None
        if has_value == has_attr:
            raise PolicyError("constraint needs exactly one of value= or principal_attr=")
        if has_value:
            _reject_unhashable_value(self.value, f"constraint {self.field!r} {self.op}")

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
    """Every declared keyword of a schema, typed exactly as it was written."""
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
