"""The decision engine — pure policy evaluation.

``pre()`` decides whether a call may execute; ``post()`` inspects the result and
redacts leaked/sensitive content. Both are **fail-closed**: any exception inside
a check becomes a DENY, never a silent allow.

The pre-gate chain (fail-fast), review-revised:

1. ``unknown_tool``     — no contract → deny-by-default
2. ``rbac``             — role allow-list
3. ``arg_schema``       — arguments validated against the tool contract
4. ``resource_constraint`` — **resource-aware authorization**
5. ``canary_exfil``     — exact-match canary in an argument
6. ``content_rule``     — OPTIONAL heuristic patterns, only if opted in
7. ``rate_limit`` / ``budget``
8. ``requires_confirmation``

The engine reads only the :class:`~histos.contracts.GateRequest` and the
static :class:`~histos.contracts.Policy` — never conversation, documents, or
prior outputs. Resource attributes come from a **trusted,
developer-provided** resolver, never from model output.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any

from histos import canary, detectors
from histos.content_rules import ContentRules
from histos.contracts import Effect, GateDecision, GateRequest, Policy
from histos.errors import ResourceNotFound
from histos.limits import LimitStore
from histos.schema import sensitive_fields, validate

# A resolver may be sync or async — looking a resource's real owner up is usually
# IO. The async form is only awaited on the async path (``apre``); handing one to a
# sync tool is a wiring error and fails closed rather than comparing a coroutine.
ResourceResolver = Callable[[str, dict[str, Any]], dict[str, Any] | Awaitable[dict[str, Any]]]

# "the resource was not fetched yet" — distinct from a resolver that legitimately
# returned an empty dict.
_UNRESOLVED: Any = object()


def _stringify(value: Any) -> str:
    return value if isinstance(value, str) else str(value)


def _stringify_args(args: dict[str, Any]) -> str:
    return " ".join(_stringify(v) for v in args.values())


def _redact_structure(obj: Any, tokens: frozenset[str]) -> tuple[Any, list[str]]:
    """Recursively replace verbatim canary tokens in strings within ``obj``.

    Traverses str, bytes, dict (keys *and* values), list, tuple, set and
    frozenset. **Residual (honest):** it cannot reach into opaque objects
    (dataclass/Pydantic attributes, custom __str__), so a canary hidden inside
    such an object's fields is not redacted — canary is a verbatim, structural
    control, not a general exfiltration guard (see SECURITY.md).
    """
    found: list[str] = []
    if isinstance(obj, str):
        return canary.redact(obj, tokens)
    if isinstance(obj, bytes):
        out_b = obj
        for tok in sorted(tokens, key=len, reverse=True):  # longer first (see canary.redact)
            tb = tok.encode("utf-8", "ignore")
            if tb and tb in out_b:
                found.append(tok)
                out_b = out_b.replace(tb, b"[REDACTED-CANARY]")
        return out_b, found
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            new_k, khits = _redact_structure(k, tokens)
            new_v, vhits = _redact_structure(v, tokens)
            out[new_k] = new_v
            found.extend(khits)
            found.extend(vhits)
        return out, found
    if isinstance(obj, (list, tuple)):
        items = []
        for v in obj:
            new_v, hits = _redact_structure(v, tokens)
            items.append(new_v)
            found.extend(hits)
        return type(obj)(items), found
    if isinstance(obj, (set, frozenset)):
        items = []
        for v in obj:
            new_v, hits = _redact_structure(v, tokens)
            items.append(new_v)
            found.extend(hits)
        return type(obj)(items), found
    return obj, found


def _validate_output(schema: Any, out: Any) -> list[str]:
    """Validate a tool output against its declared return schema.

    A dict is validated directly; a list/tuple is validated element-by-element
    (each must be an object); anything else is an unknown structure and fails.
    """
    if isinstance(out, dict):
        return validate(schema, out)
    if isinstance(out, (list, tuple)):
        errors: list[str] = []
        for i, item in enumerate(out):
            if isinstance(item, dict):
                errors.extend(f"[{i}] {e}" for e in validate(schema, item))
            else:
                errors.append(f"[{i}] is not an object")
        return errors
    return ["output is not an object or list of objects"]


def _redact_sensitive(obj: Any, sensitive_names: frozenset[str]) -> tuple[Any, list[str]]:
    """Recursively redact any dict key in ``sensitive_names`` — anywhere in ``obj``.

    Applies to nested structures and to *lists of records* (a common tool return),
    which the earlier top-level-dict-only check silently leaked. Redaction is by
    field *name* anywhere in the structure (conservative: over-redacts a same-named
    field rather than leak a sensitive one).
    """
    found: list[str] = []
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            if k in sensitive_names:
                out[k] = "[REDACTED]"
                found.append(str(k))
            else:
                out[k], hits = _redact_sensitive(v, sensitive_names)
                found.extend(hits)
        return out, found
    if isinstance(obj, (list, tuple)):
        items = []
        for v in obj:
            new_v, hits = _redact_sensitive(v, sensitive_names)
            items.append(new_v)
            found.extend(hits)
        return type(obj)(items), found
    return obj, found


def _project_output(obj: Any, allowed: frozenset[str]) -> tuple[Any, list[str]]:
    """Deny-by-default on the OUTPUT surface: drop any dict key not in ``allowed``.

    The surgical alternative to strict_returns' all-or-nothing — an undeclared field
    (where a secret can hide, out of reach of name-based redaction) simply never
    egresses. Recurses into nested objects and lists-of-records.
    """
    dropped: list[str] = []

    def go(o: Any) -> Any:
        if isinstance(o, dict):
            kept: dict[Any, Any] = {}
            for k, v in o.items():
                if k in allowed:
                    kept[k] = go(v)
                else:
                    dropped.append(str(k))
            return kept
        if isinstance(o, (list, tuple)):
            return type(o)(go(x) for x in o)
        return o

    return go(obj), dropped


def _redact_secrets_structure(obj: Any) -> tuple[Any, list[str]]:
    """Redact recognised secrets (checksum + structural) in every string leaf."""
    found: list[str] = []
    if isinstance(obj, str):
        red, kinds = detectors.redact_string(obj)
        found.extend(kinds)
        return red, found
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            out[k], hits = _redact_secrets_structure(v)
            found.extend(hits)
        return out, found
    if isinstance(obj, (list, tuple)):
        items = []
        for v in obj:
            new_v, hits = _redact_secrets_structure(v)
            items.append(new_v)
            found.extend(hits)
        return type(obj)(items), found
    return obj, found


class Engine:
    def __init__(
        self,
        policy: Policy,
        limits: LimitStore,
        *,
        content_rules: ContentRules | None = None,
        resource_resolver: ResourceResolver | None = None,
    ) -> None:
        self.policy = policy
        self.limits = limits
        self.content_rules = content_rules
        self.resource_resolver = resource_resolver

    # ── pre-gate ─────────────────────────────────────────────────────

    def pre(self, req: GateRequest) -> GateDecision:
        """Decide a call synchronously; a resource constraint resolves inline."""
        try:
            return self._pre(req, _UNRESOLVED)
        except Exception as exc:  # noqa: BLE001 — fail-closed is the whole point
            return GateDecision(Effect.DENY, "internal_error", f"fail-closed on exception: {exc!r}")

    async def apre(self, req: GateRequest) -> GateDecision:
        """Same decision, but awaiting an async ``resource_resolver``.

        Only the resolver hop is async — evaluation itself stays synchronous and
        CPU-only, so the two paths cannot drift into different verdicts.
        """
        try:
            contract = self.policy.contract_for(req.tool_name)
            resource: Any = _UNRESOLVED
            if contract is not None and contract.constraints and contract.needs_resource_resolver():
                if self.resource_resolver is None:
                    return self._no_resolver_decision(req.tool_name)
                try:
                    resolved = self.resource_resolver(req.tool_name, req.args)
                    if inspect.isawaitable(resolved):
                        resolved = await resolved
                except ResourceNotFound as exc:
                    return GateDecision(Effect.DENY, "resource_not_found", f"resource not found: {exc}")
                except Exception as exc:  # noqa: BLE001 — a raising resolver fails closed
                    return GateDecision(Effect.DENY, "resolver_error", f"resource_resolver raised: {exc!r}")
                resource = resolved or {}
            return self._pre(req, resource)
        except Exception as exc:  # noqa: BLE001 — fail-closed
            return GateDecision(Effect.DENY, "internal_error", f"fail-closed on exception: {exc!r}")

    @staticmethod
    def _no_resolver_decision(tool_name: str) -> GateDecision:
        return GateDecision(
            Effect.DENY,
            "no_resource_resolver",
            f"tool {tool_name!r} has resource constraints but no resource_resolver is configured",
        )

    def _pre(self, req: GateRequest, resource: Any = _UNRESOLVED) -> GateDecision:
        contract = self.policy.contract_for(req.tool_name)

        # 1. Deny-by-default: a tool with no contract is not gated → refused.
        if contract is None:
            return GateDecision(Effect.DENY, "unknown_tool", f"no policy for tool {req.tool_name!r}")

        # 2. RBAC allow-list (deny-by-default per role).
        if req.tool_name not in self.policy.allowed_tools(req.principal.role):
            return GateDecision(
                Effect.DENY,
                "rbac",
                f"role {req.principal.role!r} may not call {req.tool_name!r}",
                field="role",
                expected=f"grant for {req.tool_name!r}",
                received=req.principal.role,
            )

        # 3. Argument schema. A gated tool with no schema cannot be validated →
        #    fail closed, never wave the call through.
        if contract.args is None:
            return GateDecision(
                Effect.DENY, "no_arg_schema", f"tool {req.tool_name!r} has no arg schema; cannot gate safely"
            )
        errors = validate(contract.args, req.args)
        if errors:
            first = errors[0]
            field = first.split(":", 1)[0]
            return GateDecision(Effect.DENY, "arg_schema", "; ".join(errors), field=field)

        # 4. Resource-aware authorization. Compares call/resource
        #    attributes against trusted principal context or literals.
        constraint_decision = self._check_constraints(req, contract, resource)
        if constraint_decision is not None:
            return constraint_decision

        # 5. Canary exfiltration attempt via an argument (verbatim + normalized).
        blob = _stringify_args(req.args)
        if self.policy.canaries and (
            canary.find(blob, self.policy.canaries) or canary.find_normalized(blob, self.policy.canaries)
        ):
            return GateDecision(Effect.DENY, "canary_exfil", "argument contains a canary token")

        # 5b. A recognised secret in an argument — a checksum-confidence match denies;
        #     a structural-only match stays advisory (redacted on output, not a hard deny).
        if contract.deny_secret_args:
            for det in detectors.scan_string(blob):
                if det.confidence == detectors.CHECKSUM:
                    return GateDecision(
                        Effect.DENY,
                        "secret_detected",
                        f"argument contains a {det.kind} secret",
                        expected="no secret",
                        received=det.kind,
                    )

        # 6. OPTIONAL heuristic content rules, only if the host opted in.
        if self.content_rules is not None:
            hit = self.content_rules.scan(blob)
            if hit is not None:
                rule, _pattern = hit
                return GateDecision(Effect.DENY, rule, f"argument matched {rule}")

        # 7. Rate / budget limits (checked here, consumed later by the wrapper).
        limit_rule = self.limits.check(
            req.principal.identity, req.tool_name, rate_limit=contract.rate_limit, budget=contract.budget
        )
        if limit_rule is not None:
            return GateDecision(Effect.DENY, limit_rule, f"{limit_rule} exceeded for {req.tool_name!r}")

        # 8. Explicit confirmation gate.
        if contract.requires_confirmation:
            return GateDecision(
                Effect.REQUIRE_CONFIRMATION, "requires_confirmation", f"{req.tool_name!r} requires confirmation"
            )

        return GateDecision(Effect.ALLOW, "allow")

    def _check_constraints(self, req: GateRequest, contract: Any, prefetched: Any = _UNRESOLVED) -> GateDecision | None:
        if not contract.constraints:
            return None

        resource: dict[str, Any] = {} if prefetched is _UNRESOLVED else prefetched
        if prefetched is _UNRESOLVED and contract.needs_resource_resolver():
            if self.resource_resolver is None:
                return self._no_resolver_decision(req.tool_name)
            try:
                resolved = self.resource_resolver(req.tool_name, req.args)
            except ResourceNotFound as exc:
                return GateDecision(Effect.DENY, "resource_not_found", f"resource not found: {exc}")
            except Exception as exc:  # noqa: BLE001 — a raising resolver fails closed, distinct from internal_error
                return GateDecision(Effect.DENY, "resolver_error", f"resource_resolver raised: {exc!r}")
            if inspect.isawaitable(resolved):
                # An async resolver on the sync path: comparing a coroutine to a
                # principal attribute would "fail" for the wrong reason. Close it so
                # Python does not warn about a never-awaited coroutine, and say why.
                closer = getattr(resolved, "close", None)
                if callable(closer):
                    closer()
                return GateDecision(
                    Effect.DENY,
                    "resolver_error",
                    f"resource_resolver for {req.tool_name!r} is async but the tool is sync — "
                    "an async resolver can only be awaited on the async path",
                )
            resource = resolved or {}

        for c in contract.constraints:
            result = c.evaluate(resource, req.principal)
            if not result.ok:
                return GateDecision(
                    Effect.DENY,
                    "resource_constraint",
                    result.reason,
                    field=result.field,
                    expected=result.expected,
                    received=result.received,
                )
        return None

    # ── post-gate ────────────────────────────────────────────────────

    def post(self, req: GateRequest, result: Any) -> tuple[GateDecision, Any]:
        try:
            return self._post(req, result)
        except Exception as exc:  # noqa: BLE001 — fail-closed
            return GateDecision(Effect.DENY, "internal_error", f"fail-closed on exception: {exc!r}"), None

    def post_exception(self, req: GateRequest, exc: BaseException) -> tuple[GateDecision, str]:
        """The POST chain for a *raising* tool.

        A raised exception is the other way a tool hands content back to the model,
        so it must not be the one path out of the process that skips redaction. Only
        the controls that apply to unstructured text run here — canary tokens and
        recognised secrets. Output projection, strict returns and sensitive-field
        redaction are all keyed on a declared return *shape*, which an exception does
        not have, so applying them would be inventing semantics.
        """
        try:
            return self._post_exception(req, exc)
        except Exception as inner:  # noqa: BLE001 — fail-closed
            # The redaction machinery itself failed, so nothing about the original
            # text can be trusted to be safe. Drop it entirely rather than pass it on.
            return (
                GateDecision(
                    Effect.DENY,
                    "internal_error",
                    f"fail-closed redacting a raised exception: {inner!r}",
                ),
                "[REDACTED: the tool raised, and the error text could not be safely redacted]",
            )

    def _post_exception(self, req: GateRequest, exc: BaseException) -> tuple[GateDecision, str]:
        contract = self.policy.contract_for(req.tool_name)
        text = f"{type(exc).__name__}: {exc}"
        redactions: list[str] = []

        if contract is not None and contract.scan_output_for_canary and self.policy.canaries:
            text, found = canary.redact(text, self.policy.canaries)
            redactions.extend(f"canary:{tok}" for tok in found)

        if contract is not None and contract.redact_secret_output:
            text, kinds = detectors.redact_string(text)
            redactions.extend(f"secret:{k}" for k in dict.fromkeys(kinds))

        if redactions:
            return (
                GateDecision(
                    Effect.REDACT,
                    "exception_redaction",
                    "redacted sensitive/canary content from a raised exception",
                    redactions=tuple(redactions),
                ),
                text,
            )
        return GateDecision(Effect.ALLOW, "allow"), text

    def _post(self, req: GateRequest, result: Any) -> tuple[GateDecision, Any]:
        contract = self.policy.contract_for(req.tool_name)
        redactions: list[str] = []
        out = result

        # 0. Malformed-output policy (strict returns). Name-based redaction cannot
        #    save a secret that lands in an *undeclared* field, so an output that
        #    does not conform to the declared return schema is handled up front:
        #    known schema + conforming → deterministic field redaction (below);
        #    schema violation / unknown shape → deny or redact-all (conservative).
        if contract is not None and contract.strict_returns and contract.returns is not None:
            errors = _validate_output(contract.returns, out)
            if errors and contract.on_output_violation != "allow":
                if contract.on_output_violation == "deny":
                    return GateDecision(
                        Effect.DENY, "output_schema", f"output did not match declared return schema: {errors[0]}"
                    ), None
                return (
                    GateDecision(
                        Effect.REDACT,
                        "output_schema",
                        "output did not match declared return schema — redacted",
                        redactions=("output:redacted_all",),
                    ),
                    "[REDACTED: tool output did not match its declared return schema]",
                )

        # 0b. Output field projection — deny-by-default on the return surface: drop
        #     any key not declared in `returns` (undeclared fields, where a secret can
        #     hide out of reach of name-based redaction, never egress).
        if contract is not None and contract.project_output and contract.returns is not None:
            out, dropped = _project_output(out, frozenset(contract.returns.fields))
            redactions.extend(f"drop:{k}" for k in dict.fromkeys(dropped))

        # 1. Canary leak in the output → redact verbatim tokens anywhere in the structure.
        if contract is not None and contract.scan_output_for_canary and self.policy.canaries:
            out, found = _redact_structure(out, self.policy.canaries)
            redactions.extend(f"canary:{tok}" for tok in found)

        # 2. Sensitive return fields the caller's role may not see → redact by name,
        #    recursively (covers lists of records + nested structures, not just a
        #    top-level dict).
        if contract is not None and contract.returns is not None:
            sensitive = frozenset(sensitive_fields(contract.returns, allowed=req.principal.can_view))
            if sensitive:
                out, hidden = _redact_sensitive(out, sensitive)
                redactions.extend(f"field:{f}" for f in dict.fromkeys(hidden))

        # 3. Recognised secrets anywhere in the output (checksum + structural) → redact.
        if contract is not None and contract.redact_secret_output:
            out, secret_kinds = _redact_secrets_structure(out)
            redactions.extend(f"secret:{k}" for k in dict.fromkeys(secret_kinds))

        if redactions:
            return (
                GateDecision(
                    Effect.REDACT, "post_redaction", "redacted sensitive/canary content", redactions=tuple(redactions)
                ),
                out,
            )
        return GateDecision(Effect.ALLOW, "allow"), out
