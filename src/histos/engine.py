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
8. ``escalate``         — the seam to a host **semantic tier**; DENY with none wired
9. ``requires_confirmation``

Step 8 sits where it does for two reasons. It is last of the machine checks because
reaching a semantic tier is a model call, and nothing should pay for one on behalf of
a caller the cheap deterministic chain already refuses. It is *before* confirmation
because a human is the last word: a tool declaring both would otherwise have its
escalation skipped the moment an approval arrived.

The engine reads only the :class:`~histos.contracts.GateRequest` and the
static :class:`~histos.contracts.Policy` — never conversation, documents, or
prior outputs. Resource attributes come from a **trusted,
developer-provided** resolver, never from model output.
"""

from __future__ import annotations

import copy
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import replace
from typing import Any

from histos import canary, detectors
from histos import postgate as _postgate
from histos.budget import (
    _MAX_OUTPUT_SCAN_CHARS,
    _MAX_SCAN_CHARS,
    _stringify_args,
)
from histos.content_rules import ContentRules
from histos.contracts import Effect, GateDecision, GateRequest, Policy
from histos.errors import PolicyError, ResourceNotFound
from histos.limits import LimitStore
from histos.schema import validate

# A resolver may be sync or async — looking a resource's real owner up is usually
# IO. The async form is only awaited on the async path (``apre``); handing one to a
# sync tool is a wiring error and fails closed rather than comparing a coroutine.
ResourceResolver = Callable[[str, dict[str, Any]], dict[str, Any] | Awaitable[dict[str, Any]]]

# The **semantic tier** a host wires behind a policy's ``escalate``: given the request,
# say whether meaning-level judgement lets it continue. Sync or async, like the
# resolver, because reaching one is usually a model call. A truthy return is the only
# outcome that continues the chain — and continuing is all it can do. There is no
# verdict here that allows something the deterministic chain refused, which is the
# property that keeps a probabilistic tier from ever widening a deterministic gate.
EscalationTier = Callable[[GateRequest], Any]

# "the resource was not fetched yet" — distinct from a resolver that legitimately
# returned an empty dict.
_UNRESOLVED: Any = object()


def _callback_args(args: dict[str, Any]) -> dict[str, Any]:
    """The argument view a host callback gets — a copy, never the live dict.

    ``confirm`` used to receive the very dict the gate then splats into the tool, so a
    well-meant normalisation in an approvals UI (rounding an amount, defaulting a
    field) landed in the executed call *after* every check had passed, and the audit
    record digested the mutated values. The semantic tier is handed the same request
    and is a far more likely place for a callback to rewrite what it was given.

    ``resource_resolver`` gets the same treatment, and it is the worst of the three to
    leave live: it runs *after* argument validation, so anything it writes into the
    dict reaches the tool having been checked against nothing. A resolver is ordinary
    application code — an ORM lookup, a cache fill — and normalising an id in passing
    is exactly the sort of thing it does.
    """
    try:
        return copy.deepcopy(args)
    except Exception:  # noqa: BLE001 — an uncopyable argument must not fail the call
        return dict(args)


def for_callback(req: GateRequest) -> GateRequest:
    """The request a host callback sees: same identity, a detached copy of the args."""
    return GateRequest(req.tool_name, _callback_args(req.args), req.principal, phase=req.phase)


# The canary/secret scan is linear in the argument text, and `Field` has no cap on how
# many elements an array may carry — so one schema-valid call could hand the gate tens
# of megabytes and stall the calling thread (6.7 s measured for 20k max-length strings)
# inside a control that is supposed to be microsecond-scale. The blob is therefore
# budgeted, and a call that exceeds the budget is DENIED rather than scanned partially:


class Engine:
    def __init__(
        self,
        policy: Policy,
        limits: LimitStore,
        *,
        content_rules: ContentRules | None = None,
        resource_resolver: ResourceResolver | None = None,
        escalate: EscalationTier | None = None,
        output_budget: int = _MAX_OUTPUT_SCAN_CHARS,
    ) -> None:
        # Validated like every other policy knob. `0` and negatives were accepted in
        # silence and turned every textual return into a redact-all: the post-gate
        # reports "output exceeded the scan budget" for a two-character string, which
        # reads as a tool fault and is a typo in the host's configuration.
        if not isinstance(output_budget, int) or isinstance(output_budget, bool) or output_budget < 1:
            raise PolicyError(f"output_budget must be a positive number of characters, got {output_budget!r}")
        self.policy = policy
        self.limits = limits
        self.content_rules = content_rules
        self.resource_resolver = resource_resolver
        self.escalate = escalate
        # How much tool output the post-gate will read. A hard module constant was the
        # wrong shape: it is a deployment question — a reporting tool legitimately
        # returns tens of megabytes — and the answer decides whether a result is
        # dropped, so it belongs where the host can set it.
        self._output_budget = output_budget

    # ── pre-gate ─────────────────────────────────────────────────────

    def pre(self, req: GateRequest) -> GateDecision:
        """Decide a call synchronously; a resource constraint resolves inline."""
        try:
            return self._pre(req, _UNRESOLVED)
        except Exception as exc:  # noqa: BLE001 — fail-closed is the whole point
            return GateDecision(Effect.DENY, "internal_error", f"fail-closed on exception: {exc!r}")

    async def apre(self, req: GateRequest) -> GateDecision:
        """Same decision *and the same side effects*, awaiting an async ``resource_resolver``.

        Only the resolver hop is async — evaluation itself stays synchronous and
        CPU-only, so the two paths cannot drift into different verdicts. The cheap
        checks (steps 1–3) run **before** the resolver on both paths: this path used to
        resolve first, so an unauthorized caller, or one whose arguments the schema
        rejects, still drove a real lookup in the host's trusted datastore — an
        existence/timing oracle and an SSRF primitive the sync path denied outright.
        """
        try:
            contract = self.policy.contract_for(req.tool_name)
            early = self._pre_before_resource(req, contract)
            if early is not None:
                return early
            resource: Any = _UNRESOLVED
            if contract is not None and contract.constraints and contract.needs_resource_resolver():
                if self.resource_resolver is None:
                    return self._no_resolver_decision(req.tool_name)
                try:
                    resolved = self.resource_resolver(req.tool_name, _callback_args(req.args))
                    if inspect.isawaitable(resolved):
                        resolved = await resolved
                except ResourceNotFound as exc:
                    return GateDecision(Effect.DENY, "resource_not_found", f"resource not found: {exc}")
                except Exception as exc:  # noqa: BLE001 — a raising resolver fails closed
                    return GateDecision(Effect.DENY, "resolver_error", f"resource_resolver raised: {exc!r}")
                resource = resolved or {}
            return await self._apre_after_resource(req, contract, resource)
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
        early = self._pre_before_resource(req, contract)
        if early is not None:
            return early
        return self._pre_after_resource(req, contract, resource)

    def _pre_before_resource(self, req: GateRequest, contract: Any) -> GateDecision | None:
        """Steps 1–3: the CPU-only checks that must precede any resolver side effect.

        Returns None when the call has earned a resource lookup — and only then, which
        is what keeps `pre` and `apre` identical in *what they touch*, not just in what
        they answer.
        """
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
        return None

    def _pre_after_resource(self, req: GateRequest, contract: Any, resource: Any = _UNRESOLVED) -> GateDecision:
        """Steps 4–9, resolving a sync semantic tier inline."""
        blocked = self._pre_checks(req, contract, resource)
        if blocked is not None:
            return blocked
        if not contract.requires_escalation:
            return self._chain_end(req, contract)
        refusal = self._escalate(req)
        return refusal if refusal is not None else self._after_escalation(req, contract)

    async def _apre_after_resource(self, req: GateRequest, contract: Any, resource: Any) -> GateDecision:
        """The same tail, awaiting an async semantic tier.

        The two paths are duplicated for exactly one hop, the same way the resolver is:
        everything that decides is in ``_pre_checks`` / ``_chain_end`` / a shared
        verdict reader, so the sync and async gates cannot drift into different
        verdicts — only into different ways of waiting for the same answer.
        """
        blocked = self._pre_checks(req, contract, resource)
        if blocked is not None:
            return blocked
        if not contract.requires_escalation:
            return self._chain_end(req, contract)
        refusal = await self._aescalate(req)
        return refusal if refusal is not None else self._after_escalation(req, contract)

    def _pre_checks(self, req: GateRequest, contract: Any, resource: Any = _UNRESOLVED) -> GateDecision | None:
        """Steps 4–7: every remaining check that is CPU-only. None = keep going.

        Split out so the sync and async paths share it verbatim, and so the two steps
        that can reach *outside* the process — the semantic tier, and the human behind
        confirmation — sit after every check that cannot.
        """
        # 4. Resource-aware authorization. Compares call/resource
        #    attributes against trusted principal context or literals.
        constraint_decision = self._check_constraints(req, contract, resource)
        if constraint_decision is not None:
            return constraint_decision

        # 5. Canary exfiltration attempt via an argument (verbatim + normalized).
        blob, oversized = _stringify_args(req.args)
        if oversized:
            # Arguments too large to scan are refused, not scanned in part: the canary
            # and secret checks below are only meaningful over the WHOLE argument text.
            return GateDecision(
                Effect.DENY,
                "arg_schema",
                f"arguments exceed the {_MAX_SCAN_CHARS} character budget the gate will scan",
                field=next(iter(req.args), ""),
                expected=f"<= {_MAX_SCAN_CHARS} characters of argument text",
                received="oversized",
            )
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
            # See `Gate._consume_limit`: the window is not in the policy format, so the
            # decision names it rather than leaving the reader of `rate_limit: 3` to guess.
            window = f" (window: {self.limits.window_seconds:g}s)" if limit_rule == "rate_limit" else ""
            return GateDecision(Effect.DENY, limit_rule, f"{limit_rule} exceeded for {req.tool_name!r}{window}")

        return None

    # ── the semantic seam (step 8) ───────────────────────────────────

    def _escalate(self, req: GateRequest) -> GateDecision | None:
        """Consult the semantic tier. ``None`` means it let the call continue.

        Every other outcome ends the call, **including having no tier at all**. That is
        the whole property: the seam has no verdict meaning "allow more than the
        deterministic chain already allowed", so wiring meaning in can never widen the
        gate, and leaving it out can never open one. There is deliberately no
        configuration — no ``on_missing``, no default callback, no mode — that turns the
        absence of a tier into an allow; the branch simply does not exist.
        """
        if self.escalate is None:
            return self._no_tier_decision(req.tool_name)
        try:
            verdict = self.escalate(for_callback(req))
        except Exception as exc:  # noqa: BLE001 — a raising tier fails closed
            return self._tier_error(f"escalate callback raised: {exc!r}")
        if inspect.isawaitable(verdict):
            # An async tier on the sync path: a coroutine object is truthy, so treating
            # it as a verdict would let every escalated call through un-judged — the one
            # mistake this seam exists to make impossible.
            closer = getattr(verdict, "close", None)
            if callable(closer):
                closer()
            return self._tier_error(
                f"escalate callback for {req.tool_name!r} is async but the tool is sync — "
                "an async tier can only be awaited on the async path"
            )
        return self._read_verdict(req, verdict)

    async def _aescalate(self, req: GateRequest) -> GateDecision | None:
        """:meth:`_escalate` with the one hop awaited. Same verdicts, same collapse."""
        if self.escalate is None:
            return self._no_tier_decision(req.tool_name)
        try:
            verdict = self.escalate(for_callback(req))
            if inspect.isawaitable(verdict):
                verdict = await verdict
        except Exception as exc:  # noqa: BLE001 — a raising tier fails closed
            return self._tier_error(f"escalate callback raised: {exc!r}")
        return self._read_verdict(req, verdict)

    @staticmethod
    def _read_verdict(req: GateRequest, verdict: Any) -> GateDecision | None:
        """Truthy continues the chain; anything else refuses. Shared by both paths."""
        if verdict:
            return None
        return GateDecision(
            Effect.DENY,
            "escalation_denied",
            f"the semantic tier refused {req.tool_name!r}",
            escalate=True,
        )

    @staticmethod
    def _no_tier_decision(tool_name: str) -> GateDecision:
        return GateDecision(
            Effect.DENY,
            "no_escalation_tier",
            f"tool {tool_name!r} must be escalated to a semantic tier but none is wired",
            expected="a semantic tier passed as Gate(escalate=...)",
            received="<none>",
            escalate=True,
        )

    @staticmethod
    def _tier_error(reason: str) -> GateDecision:
        return GateDecision(Effect.DENY, "escalation_error", reason, escalate=True)

    def _after_escalation(self, req: GateRequest, contract: Any) -> GateDecision:
        """The chain resumed once the tier let the call through.

        Never a bare ALLOW that skips step 9: a tool declaring both ``escalate`` and
        ``confirmation`` still has to reach the human, and the tier's approval is
        recorded on that decision rather than substituted for it.
        """
        decision = self._chain_end(req, contract)
        if decision.effect is Effect.ALLOW:
            return GateDecision(
                Effect.ALLOW,
                "escalated",
                f"the semantic tier approved {req.tool_name!r}",
                escalate=True,
            )
        return replace(decision, escalate=True)

    def _chain_end(self, req: GateRequest, contract: Any) -> GateDecision:
        """Step 9, and the ALLOW that ends the pre-gate."""
        if contract.requires_confirmation:
            return self._confirmation_decision(req, contract)
        return GateDecision(Effect.ALLOW, "allow")

    @staticmethod
    def _confirmation_decision(req: GateRequest, contract: Any) -> GateDecision:
        """The REQUIRE_CONFIRMATION decision, carrying the declared approval window.

        ``confirmation.expires_in`` is read defensively (``getattr``) because the field
        is part of the policy *format* and an engine must not break on a contract object
        that predates it. A window the engine cannot honour — zero, negative, or not an
        integer — is refused rather than downgraded to "no expiry": an approval that can
        never be inside its window must not be treated as one that never leaves it.

        The window itself is published on the decision so the host's approval store can
        enforce the clock (the engine has no clock and never consumes approvals); see
        the handoff in ``histos.approvals``.
        """
        window = getattr(contract, "confirmation_expires_in", None)
        if window is None:
            return GateDecision(
                Effect.REQUIRE_CONFIRMATION, "requires_confirmation", f"{req.tool_name!r} requires confirmation"
            )
        if isinstance(window, bool) or not isinstance(window, int) or window <= 0:
            return GateDecision(
                Effect.DENY,
                "confirm_error",
                f"tool {req.tool_name!r} declares an unusable confirmation window ({window!r}); "
                "no approval could ever be valid",
                field="confirmation.expires_in",
                expected="a positive number of seconds",
                received=repr(window),
            )
        return GateDecision(
            Effect.REQUIRE_CONFIRMATION,
            "requires_confirmation",
            f"{req.tool_name!r} requires confirmation",
            expected=f"an approval granted within {window}s",
        )

    def _check_constraints(self, req: GateRequest, contract: Any, prefetched: Any = _UNRESOLVED) -> GateDecision | None:
        if not contract.constraints:
            return None

        resource: dict[str, Any] = {} if prefetched is _UNRESOLVED else prefetched
        if prefetched is _UNRESOLVED and contract.needs_resource_resolver():
            if self.resource_resolver is None:
                return self._no_resolver_decision(req.tool_name)
            try:
                resolved = self.resource_resolver(req.tool_name, _callback_args(req.args))
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
        """The POST chain for a tool that returned. See :mod:`histos.postgate`."""
        return _postgate.post(self, req, result)

    def post_exception(self, req: GateRequest, exc: BaseException, *, mutate: bool = True) -> tuple[GateDecision, str]:
        """The POST chain for a tool that raised. See :mod:`histos.postgate`."""
        return _postgate.post_exception(self, req, exc, mutate=mutate)
