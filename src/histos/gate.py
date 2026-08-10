"""The public surface: wrap a tool in a single call.

``gate(my_tool, policy=...)`` is the one-liner; ``protect(tools, policy=...)``
does a whole tool set and hands back a coverage report. For several tools that
should share limit counters and one audit trail, build a :class:`Gate` once and
call ``.wrap()``.

**Identity is bound out-of-band**. The primary path is
:func:`use_principal`, a context variable a *trusted* host sets per request from
workload identity or an authenticated session. ``fixed_principal=`` is the
escape hatch for single-identity scripts and workers — it binds **one identity
for the lifetime of the wrapper**, which on a multi-tenant server would mean
every caller runs as that identity, so it is named to be hard to reach for by
accident. With neither, the gate fails closed.

**Enforcement modes**: ``mode="enforce"`` (default) blocks and
redacts; ``mode="observe"`` evaluates and audits exactly as it would enforce but
never blocks or modifies — a dry-run for calibration. Observe records carry
``executed: true`` next to a ``deny`` effect so watching is never mistaken for
protecting.

**Async**: a coroutine tool is detected automatically and gets an
``async`` wrapper; the ``resource_resolver`` and ``confirm`` callbacks may then be
sync or async. Detection unwraps decorators and ``functools.partial`` and checks a
callable object's ``__call__``; a genuinely ambiguous target raises at wrap time
rather than silently picking a path.
"""

from __future__ import annotations

import functools
import inspect
import os
import time
import warnings
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from histos._version import __version__
from histos.audit import AuditRecord, AuditSink, InMemoryAuditSink, digest_args
from histos.bundle import load_policy
from histos.content_rules import ContentRules
from histos.contracts import Effect, GateDecision, GateRequest, Policy, Principal
from histos.engine import Engine, ResourceResolver
from histos.errors import GateConfirmationRequired, GateDenied, PolicyError, ToolErrorRedacted
from histos.infer import infer_contract, infer_schema
from histos.limits import LimitStore
from histos.review import PolicyReview, review_policy

# Anything `load_policy` accepts, plus an already-built Policy and None (which
# means "empty policy" — every call then denies by default).
PolicySource = Policy | str | Path | dict[str, Any] | None

# The trusted, request-scoped identity. Set by the host, never by the agent.
_current_principal: ContextVar[Principal | None] = ContextVar("histos_principal", default=None)


def set_principal(principal: Principal) -> Token[Principal | None]:
    """Bind the current trusted principal; returns a token for :func:`reset_principal`."""
    return _current_principal.set(principal)


def reset_principal(token: Token[Principal | None]) -> None:
    _current_principal.reset(token)


@contextmanager
def use_principal(principal: Principal) -> Iterator[None]:
    """Scope a trusted principal to a ``with`` block (e.g. one request)."""
    token = _current_principal.set(principal)
    try:
        yield
    finally:
        _current_principal.reset(token)


# ── policy / mode coercion ───────────────────────────────────────────────


def _coerce_policy(policy: PolicySource) -> Policy:
    if policy is None:
        return Policy()
    if isinstance(policy, Policy):
        return policy
    return load_policy(policy)


def _resolve_mode(mode: str | None, enforcement: str | None) -> str:
    """``mode`` is the public spelling; ``enforcement`` is the original kwarg."""
    if mode is not None and enforcement is not None and mode != enforcement:
        raise PolicyError(f"mode={mode!r} and enforcement={enforcement!r} disagree; pass one of them")
    resolved = mode if mode is not None else (enforcement if enforcement is not None else "enforce")
    if resolved not in ("enforce", "observe"):
        raise PolicyError(f"mode must be 'enforce'|'observe', got {resolved!r}")
    return resolved


def _resolve_fixed_principal(fixed_principal: Principal | None, principal: Principal | None) -> Principal | None:
    if principal is None:
        return fixed_principal
    if fixed_principal is not None:
        raise PolicyError("pass either fixed_principal= or the deprecated principal=, not both")
    warnings.warn(
        "`principal=` is deprecated; use `fixed_principal=`. It reads like the per-request identity but "
        "binds ONE identity for the lifetime of the wrapper — on a multi-tenant server every caller then "
        "runs as that identity. The per-request path is use_principal().",
        DeprecationWarning,
        stacklevel=3,
    )
    return principal


# ── async detection ────────────────────────────────────────────


def _unwrap_target(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Follow ``functools.partial`` targets and ``__wrapped__`` chains to the real callable."""
    target = fn
    for _ in range(64):  # bounded so a pathological decorator chain cannot hang a wrap
        if isinstance(target, functools.partial):
            target = target.func
            continue
        try:
            unwrapped = inspect.unwrap(target)
        except ValueError:  # a __wrapped__ cycle
            return target
        if unwrapped is target:
            return target
        target = unwrapped
    return target


def _is_coroutine_callable(fn: Any) -> bool:
    if inspect.iscoroutinefunction(fn):  # already unwraps functools.partial
        return True
    if not (inspect.isfunction(fn) or inspect.ismethod(fn)) and callable(fn):
        # Not a callability test (B004's concern) — we need the __call__ *descriptor*
        # itself to ask whether it is a coroutine function. callable() cannot do that.
        call = getattr(type(fn), "__call__", None)  # noqa: B004
        if call is not None and inspect.iscoroutinefunction(call):
            return True
    return False


def _detect_async(tool: Callable[..., Any], tool_name: str) -> bool:
    """True if ``tool`` should be wrapped as async. Raises when it cannot be sure."""
    if _is_coroutine_callable(tool):
        return True
    if _is_coroutine_callable(_unwrap_target(tool)):
        # A SYNC callable wrapping an ASYNC one: whether calling it returns a
        # coroutine or a value depends on the decorator, and guessing wrong either
        # never awaits the tool or awaits a plain value. Make the developer say.
        raise PolicyError(
            f"cannot tell whether tool {tool_name!r} is async: a sync wrapper around an async function. "
            "Pass is_async=True if calling it returns a coroutine, is_async=False if it does not — "
            "the gate will not guess."
        )
    return False


# ── protect() result ─────────────────────────────────────────────────────


@dataclass
class ProtectResult:
    """What :func:`protect` / :meth:`Gate.protect` return.

    A small object, never a tuple — a tuple return ages badly. ``.tools`` maps
    each tool's name to its wrapped form, ``.coverage`` says which tools had a
    contract and a grant, and ``.review`` is the full tri-state
    :class:`~histos.review.PolicyReview` for the resulting policy.

    Iterating the result yields the wrapped tools, so
    ``agent.tools = list(protect(tools, policy=p))`` reads naturally.
    """

    tools: dict[str, Callable[..., Any]] = field(default_factory=dict)
    coverage: list[dict[str, Any]] = field(default_factory=list)
    review: PolicyReview | None = None

    @property
    def report(self) -> list[dict[str, Any]]:
        """Deprecated alias for :attr:`coverage`."""
        return self.coverage

    def __iter__(self) -> Iterator[Callable[..., Any]]:
        return iter(self.tools.values())

    def summary(self) -> str:
        ready = sum(1 for r in self.coverage if r["status"] == "ready")
        needs = [r["tool"] for r in self.coverage if r["status"] != "ready"]
        line = f"{ready}/{len(self.coverage)} tools fully covered"
        if needs:
            line += f"; needs a decision: {', '.join(needs)}"
        return line


class Gate:
    """Holds a policy plus shared limit + audit state, and wraps tools against it."""

    def __init__(
        self,
        policy: PolicySource,
        *,
        audit: AuditSink | None = None,
        limits: LimitStore | None = None,
        confirm: Callable[[GateRequest], Any] | None = None,
        content_rules: ContentRules | None = None,
        resource_resolver: ResourceResolver | None = None,
        mode: str | None = None,
        enforcement: str | None = None,
        audit_key: bytes | None = None,
        strict: bool = False,
    ) -> None:
        self.enforcement = _resolve_mode(mode, enforcement)
        self.policy = _coerce_policy(policy)
        if strict:
            issues = self.policy.validate()
            if issues:
                raise PolicyError("invalid policy: " + "; ".join(issues))
        self.limits = limits if limits is not None else LimitStore()
        self.engine = Engine(self.policy, self.limits, content_rules=content_rules, resource_resolver=resource_resolver)
        self.audit = audit if audit is not None else InMemoryAuditSink()
        self._enforce = self.enforcement == "enforce"
        self._confirm = confirm
        # Per-Gate HMAC key so audit digests resist brute-forcing low-entropy args
        # . Pass a stable key to correlate digests across processes.
        self._audit_key = audit_key if audit_key is not None else os.urandom(32)
        self._decision_seq = 0
        self._wrapped_tools: set[str] = set()
        self._refresh_policy_hash()

    @property
    def mode(self) -> str:
        """The public spelling of :attr:`enforcement`."""
        return self.enforcement

    def _refresh_policy_hash(self) -> None:
        self._policy_hash = self.policy.content_hash()

    # ── coverage / "no silent bypass" ─────

    def declared_but_unwrapped(self) -> set[str]:
        """Tools the policy declares that were never actually wrapped."""
        return set(self.policy.tools) - self._wrapped_tools

    def coverage(self, tool_names: Iterable[str]) -> dict[str, list[str]]:
        """Compare the tools exposed to the agent against the policy (Phase 0.1).

        ``undeclared`` — exposed to the agent but **not** in the policy: a silent gap
        (a forgotten tool the agent can call ungated at the framework layer). This is
        what ``histos coverage`` fails CI on. ``unwrapped`` — declared but never
        wrapped by this Gate.
        """
        exposed = set(tool_names)
        declared = set(self.policy.tools)
        return {
            "covered": sorted(exposed & declared),
            "undeclared": sorted(exposed - declared),
            "unwrapped": sorted(declared - self._wrapped_tools),
        }

    # ── shared per-call steps (identical on the sync and async paths) ──

    def _no_principal(self) -> GateDecision:
        return GateDecision(Effect.DENY, "no_principal", "no trusted principal set; identity must be bound out-of-band")

    def _apply_bindings(self, tool_name: str, active: Principal, call_args: dict[str, Any]) -> GateDecision | None:
        """Overwrite bound args with trusted principal attributes (Phase 0.1).

        The bound value is what the tool and every check see, so a hijacked model
        passing ``tenant_id="attacker"`` simply has it replaced. Fail closed if the
        principal lacks the attribute — never inject a missing/None trusted value.
        """
        contract = self.engine.policy.contract_for(tool_name)
        if contract is None or not contract.bindings:
            return None
        for b in contract.bindings:
            if b.principal_attr not in active.attributes:
                return GateDecision(
                    Effect.DENY,
                    "arg_binding_unresolved",
                    f"principal is missing trusted attribute {b.principal_attr!r} for arg {b.field!r}",
                    field=b.field,
                )
            call_args[b.field] = active.attributes[b.principal_attr]
        return None

    def _consume_limit(self, tool_name: str, active: Principal) -> GateDecision | None:
        """Atomically consume a limit slot at the point of execution.

        Closing the check→consume race matters: two concurrent callers must not both
        pass a ``budget=1``.
        """
        contract = self.engine.policy.contract_for(tool_name)
        raced = self.limits.try_consume(
            active.identity,
            tool_name,
            rate_limit=contract.rate_limit if contract else None,
            budget=contract.budget if contract else None,
        )
        if raced is None:
            return None
        return GateDecision(Effect.DENY, raced, f"{raced} exceeded for {tool_name!r}")

    def _will_execute(self, decision: GateDecision) -> bool:
        """Whether the tool body actually runs given this decision and the mode."""
        return decision.effect is Effect.ALLOW or not self._enforce

    def _confirmed(self, decision: GateDecision, req: GateRequest, outcome: Any) -> GateDecision:
        return GateDecision(Effect.ALLOW, "confirmed", f"{req.tool_name!r} confirmed") if outcome else decision

    # ── the one-liner ────────────────────────────────────────────────

    def wrap(
        self,
        tool: Callable[..., Any],
        *,
        name: str | None = None,
        fixed_principal: Principal | None = None,
        principal: Principal | None = None,
        is_async: bool | None = None,
    ) -> Callable[..., Any]:
        """Wrap one tool. Returns an async wrapper for a coroutine tool.

        ``is_async`` overrides detection for the cases the gate refuses to guess.
        """
        tool_name = name or getattr(tool, "__name__", None)
        if not tool_name:
            raise PolicyError("cannot determine tool name; pass name=...")
        bound = _resolve_fixed_principal(fixed_principal, principal)
        self._wrapped_tools.add(tool_name)

        run_async = is_async if is_async is not None else _detect_async(tool, tool_name)
        return self._wrap_async(tool, tool_name, bound) if run_async else self._wrap_sync(tool, tool_name, bound)

    def _wrap_sync(self, tool: Callable[..., Any], tool_name: str, bound: Principal | None) -> Callable[..., Any]:
        @functools.wraps(tool)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if args:
                raise PolicyError(f"gated tool {tool_name!r} must be called with keyword arguments only")
            call_args = dict(kwargs)
            started = time.perf_counter()
            active = bound or _current_principal.get()

            # No trusted identity → fail closed. Identity is never inferred.
            if active is None:
                decision = self._no_principal()
                self._emit(tool_name, call_args, decision, "pre", started, None, self._will_execute(decision))
                if self._enforce:
                    raise GateDenied(decision)
                return tool(**call_args)

            binding_denial = self._apply_bindings(tool_name, active, call_args)
            if binding_denial is not None:
                self._emit(
                    tool_name, call_args, binding_denial, "pre", started, active, self._will_execute(binding_denial)
                )
                if self._enforce:
                    raise GateDenied(binding_denial)
                return tool(**call_args)

            req = GateRequest(tool_name, call_args, active, phase="pre")
            pre = self.engine.pre(req)

            # Human/operator confirmation resolved via a host callback (never a tool
            # the agent can call) — an injected agent cannot self-approve.
            if pre.effect is Effect.REQUIRE_CONFIRMATION and self._confirm is not None:
                outcome = self._confirm(req)
                if inspect.isawaitable(outcome):
                    closer = getattr(outcome, "close", None)
                    if callable(closer):
                        closer()
                    pre = GateDecision(
                        Effect.DENY,
                        "confirm_error",
                        f"confirm callback for {tool_name!r} is async but the tool is sync — "
                        "an async confirm can only be awaited on the async path",
                    )
                else:
                    pre = self._confirmed(pre, req, outcome)

            if pre.effect is Effect.ALLOW:
                raced = self._consume_limit(tool_name, active)
                if raced is not None:
                    pre = raced

            self._emit(tool_name, call_args, pre, "pre", started, active, self._will_execute(pre))
            if self._enforce:
                if pre.effect is Effect.DENY:
                    raise GateDenied(pre)
                if pre.effect is Effect.REQUIRE_CONFIRMATION:
                    raise GateConfirmationRequired(pre)

            redacted: BaseException | None = None
            try:
                result = tool(**call_args)
            except Exception as exc:
                outcome = self._finish_exception(tool_name, call_args, active, started, exc)
                if outcome is exc:
                    raise
                redacted = outcome
            # Raised *outside* the handler on purpose: inside it, the interpreter
            # would attach the original — which still holds the unredacted text — as
            # __context__, and anything walking the exception chain would print it
            # straight back out. `from None` alone only suppresses the display.
            if redacted is not None:
                raise redacted from None
            return self._finish(tool_name, call_args, active, started, result)

        return wrapped

    def _wrap_async(self, tool: Callable[..., Any], tool_name: str, bound: Principal | None) -> Callable[..., Any]:
        @functools.wraps(tool)
        async def wrapped(*args: Any, **kwargs: Any) -> Any:
            if args:
                raise PolicyError(f"gated tool {tool_name!r} must be called with keyword arguments only")
            call_args = dict(kwargs)
            started = time.perf_counter()
            active = bound or _current_principal.get()

            if active is None:
                decision = self._no_principal()
                self._emit(tool_name, call_args, decision, "pre", started, None, self._will_execute(decision))
                if self._enforce:
                    raise GateDenied(decision)
                return await tool(**call_args)

            binding_denial = self._apply_bindings(tool_name, active, call_args)
            if binding_denial is not None:
                self._emit(
                    tool_name, call_args, binding_denial, "pre", started, active, self._will_execute(binding_denial)
                )
                if self._enforce:
                    raise GateDenied(binding_denial)
                return await tool(**call_args)

            req = GateRequest(tool_name, call_args, active, phase="pre")
            pre = await self.engine.apre(req)

            if pre.effect is Effect.REQUIRE_CONFIRMATION and self._confirm is not None:
                try:
                    outcome = self._confirm(req)
                    if inspect.isawaitable(outcome):
                        outcome = await outcome
                except Exception as exc:  # noqa: BLE001 — a raising confirm fails closed
                    pre = GateDecision(Effect.DENY, "confirm_error", f"confirm callback raised: {exc!r}")
                else:
                    pre = self._confirmed(pre, req, outcome)

            # Consumed after the last await so no lock is held across a suspension.
            if pre.effect is Effect.ALLOW:
                raced = self._consume_limit(tool_name, active)
                if raced is not None:
                    pre = raced

            self._emit(tool_name, call_args, pre, "pre", started, active, self._will_execute(pre))
            if self._enforce:
                if pre.effect is Effect.DENY:
                    raise GateDenied(pre)
                if pre.effect is Effect.REQUIRE_CONFIRMATION:
                    raise GateConfirmationRequired(pre)

            redacted: BaseException | None = None
            try:
                result = await tool(**call_args)
            except Exception as exc:
                outcome = self._finish_exception(tool_name, call_args, active, started, exc)
                if outcome is exc:
                    raise
                redacted = outcome
            # See the sync path: raised outside the handler so the original is not
            # attached as __context__.
            if redacted is not None:
                raise redacted from None
            return self._finish(tool_name, call_args, active, started, result)

        return wrapped

    def _finish(
        self,
        tool_name: str,
        call_args: dict[str, Any],
        active: Principal,
        started: float,
        result: Any,
    ) -> Any:
        """The POST chain — pure and synchronous, so both paths share it verbatim."""
        post_req = GateRequest(tool_name, call_args, active, phase="post")
        post, final = self.engine.post(post_req, result)
        # The tool has already run by definition on the post phase.
        self._emit(tool_name, call_args, post, "post", started, active, True)
        if post.effect is Effect.DENY and self._enforce:
            raise GateDenied(post)
        # observe mode never modifies the result.
        return final if self._enforce else result

    def _finish_exception(
        self,
        tool_name: str,
        call_args: dict[str, Any],
        active: Principal,
        started: float,
        exc: Exception,
    ) -> BaseException:
        """The POST chain for a raising tool. Returns the exception to raise.

        A tool that raises used to be the one way out of the process that skipped the
        post-gate entirely, so a canary or a secret in the error text reached the model
        unredacted while the audit trail recorded only the pre-decision. Both paths
        share this, and it is pure and synchronous for the same reason ``_finish`` is.

        Returns ``exc`` itself when nothing had to be removed — the caller re-raises it
        with its original traceback intact, so the common case is unchanged.
        """
        post_req = GateRequest(tool_name, call_args, active, phase="post")
        post, text = self.engine.post_exception(post_req, exc)
        # The tool ran — it just ended by raising.
        self._emit(tool_name, call_args, post, "post", started, active, True)
        # observe mode records what it *would* have removed and changes nothing.
        if post.effect is Effect.ALLOW or not self._enforce:
            return exc
        return ToolErrorRedacted(post, type(exc).__name__, text)

    # ── protect the whole tool set ────────────────────

    def protect(
        self,
        tools: list[Callable[..., Any]],
        *,
        fixed_principal: Principal | None = None,
        principal: Principal | None = None,
        infer_missing: bool = True,
    ) -> ProtectResult:
        """Wrap every tool, inferring missing arg schemas, and report coverage.

        ``infer_missing`` fills in an argument schema from each tool's signature
        so args are still validated — but a tool with no RBAC grant
        or no contract stays denied-by-default until a human adds the policy.
        The report says exactly which tools "need a decision".
        """
        bound = _resolve_fixed_principal(fixed_principal, principal)
        result = ProtectResult()
        for tool in tools:
            tool_name = getattr(tool, "__name__", None)
            if not tool_name:
                raise PolicyError("cannot determine a tool name in protect(); wrap it individually with name=")

            contract = self.policy.contract_for(tool_name)
            has_policy = contract is not None
            if contract is None and infer_missing:
                self.policy.tools[tool_name] = infer_contract(tool)
            elif contract is not None and contract.args is None and infer_missing:
                self.policy.tools[tool_name] = replace(contract, args=infer_schema(tool))

            granted = any(tool_name in self.policy.allowed_tools(role) for role in self.policy.permissions)
            if has_policy and granted:
                status = "ready"
            elif not has_policy:
                status = "needs-policy"  # inferred schema only; no RBAC → denies by default
            else:
                status = "needs-grant"  # contract exists but no role may call it yet

            result.tools[tool_name] = self.wrap(tool, name=tool_name, fixed_principal=bound)
            result.coverage.append(
                {"tool": tool_name, "status": status, "granted": granted, "had_contract": has_policy}
            )

        self._refresh_policy_hash()
        result.review = review_policy(self.policy)
        return result

    # ── audit emit ───────────────────────────────────────────────────

    def _emit(
        self,
        tool: str,
        args: dict[str, Any],
        decision: GateDecision,
        phase: str,
        started: float,
        principal: Principal | None,
        executed: bool,
    ) -> None:
        self._decision_seq += 1
        record = AuditRecord(
            ts=time.time(),
            decision_id=self._decision_seq,
            phase=phase,
            tool=tool,
            role=principal.role if principal is not None else "<none>",
            identity=principal.identity if principal is not None else None,
            effect=decision.effect.value,
            rule=decision.rule,
            reason=decision.reason,
            args_digest=digest_args(args, self._audit_key),
            arg_keys=sorted(args),
            field_name=decision.field,
            expected=decision.expected,
            received=decision.received,
            redactions=list(decision.redactions),
            enforced=self._enforce,
            executed=executed,
            latency_us=int((time.perf_counter() - started) * 1_000_000),
            policy_hash=self._policy_hash,
            policy_version=self.policy.policy_version,
            gate_version=__version__,
        )
        self.audit.record(record.to_dict())


def gate(
    tool: Callable[..., Any],
    *,
    policy: PolicySource,
    fixed_principal: Principal | None = None,
    principal: Principal | None = None,
    audit: AuditSink | None = None,
    limits: LimitStore | None = None,
    confirm: Callable[[GateRequest], Any] | None = None,
    content_rules: ContentRules | None = None,
    resource_resolver: ResourceResolver | None = None,
    mode: str | None = None,
    enforcement: str | None = None,
    name: str | None = None,
    strict: bool = False,
    is_async: bool | None = None,
) -> Callable[..., Any]:
    """Wrap a single tool. For multiple tools sharing state, use :func:`protect`.

    ``policy`` may be a :class:`Policy`, a path to a ``.yaml``/``.json`` bundle, a
    parsed bundle dict, or ``None`` (which denies everything).
    """
    g = Gate(
        policy,
        audit=audit,
        limits=limits,
        confirm=confirm,
        content_rules=content_rules,
        resource_resolver=resource_resolver,
        mode=mode,
        enforcement=enforcement,
        strict=strict,
    )
    return g.wrap(tool, name=name, fixed_principal=fixed_principal, principal=principal, is_async=is_async)


def protect(
    tools: list[Callable[..., Any]],
    *,
    policy: PolicySource,
    fixed_principal: Principal | None = None,
    audit: AuditSink | None = None,
    limits: LimitStore | None = None,
    confirm: Callable[[GateRequest], Any] | None = None,
    content_rules: ContentRules | None = None,
    resource_resolver: ResourceResolver | None = None,
    mode: str | None = None,
    enforcement: str | None = None,
    strict: bool = False,
    infer_missing: bool = True,
) -> ProtectResult:
    """Wrap a whole tool set against one policy, sharing limits and one audit trail.

    Returns a :class:`ProtectResult` — ``.tools`` (wrapped, by name), ``.coverage``
    (which tools had a contract and a grant) and ``.review`` (the tri-state policy
    verdict). Nothing is silently left ungated: a tool with no contract or no grant
    is wrapped **and denies by default**, and says so in the report.
    """
    g = Gate(
        policy,
        audit=audit,
        limits=limits,
        confirm=confirm,
        content_rules=content_rules,
        resource_resolver=resource_resolver,
        mode=mode,
        enforcement=enforcement,
        strict=strict,
    )
    return g.protect(tools, fixed_principal=fixed_principal, infer_missing=infer_missing)
