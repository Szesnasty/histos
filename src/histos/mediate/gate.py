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

**Host callbacks**: three seams, all passed to :class:`Gate` and all guarded the same
way — ``resource_resolver`` (fetch the real record a constraint judges), ``confirm``
(a trusted human approval) and ``escalate`` (a semantic tier). One raising, or being
async while the tool is sync, is a denial rather than an escape. Leaving one unwired
is a denial too, for every call the policy routes through it: ``no_resource_resolver``
and ``no_escalation_tier`` exist so a control the policy asks for is never quietly
skipped by a host that did not finish wiring it.

**Async**: a coroutine tool is detected automatically and gets an
``async`` wrapper; the ``resource_resolver``, ``confirm`` and ``escalate`` callbacks
may then be sync or async. Detection unwraps decorators and ``functools.partial`` and checks a
callable object's ``__call__``; a genuinely ambiguous target raises at wrap time
rather than silently picking a path. A **streaming** tool (a generator or async
generator) is refused at wrap time: the output half of the gate can only inspect a
materialised value, and a gate that silently skips it is worse than none. A tool that
merely *returns* something lazy — a genexp, a ``map``, a view, an un-awaited coroutine,
anywhere inside the structure it returns — cannot be seen at wrap time and is refused on
the way out instead, with the honest limit that the tool has already run by then: the
refusal stops the unscanned payload reaching the model, it does not undo the call.

**Arguments are named, not positional.** A policy names its fields, so the gate maps a
positional call back to parameter names through the tool's own signature before anything
is checked. Two shapes have no honest mapping — ``*args``, and a callable exposing no
signature — and a positional call to one of those is denied as ``unnameable_args``.

**Identity is per-context, not per-thread-forever.** ``use_principal`` unbinds on
exit. Bare ``set_principal`` without :func:`reset_principal` leaves the identity
bound in *that* context — on a pooled worker thread the next task submitted to the
same worker inherits it. Use ``use_principal`` (or reset the token) in any pooled
or long-lived worker.
"""

from __future__ import annotations

import contextlib
import os
import weakref
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace
from typing import Any

from histos.decide.content_rules import ContentRules
from histos.decide.engine import _MAX_OUTPUT_SCAN_CHARS as _DEFAULT_OUTPUT_BUDGET
from histos.decide.engine import Engine, EscalationTier, ResourceResolver
from histos.decide.limits import LimitStore
from histos.errors import PolicyError
from histos.mediate import coverage as _coverage
from histos.mediate import wrappers as _wrappers
from histos.mediate.callsig import (
    _any_gate_stamp,
    _schema_constrains,
)
from histos.mediate.inspection import (
    _detect_async,
    _streaming_kind,
)
from histos.mediate.policyref import (
    PolicySource,
    _coerce_policy,
    _resolve_fixed_principal,
    _resolve_mode,
)
from histos.mediate.recorder import DecisionRecorder
from histos.mediate.toolref import (
    _IdentityRef,
    _same_tool,
    _wrap_identity,
)
from histos.policy.contracts import Effect, GateDecision, GateRequest, Policy, Principal, ToolContract
from histos.policy.frozen import _snapshot_value
from histos.provenance.infer import infer_contract, infer_schema

# The pieces `gate.py` used to hold inline, now beside it. `_current_principal` and
# `_scope_tokens` are imported rather than re-declared on purpose: they are
# process-wide singletons, and a second copy of either means `use_principal` binds
# one while the engine reads the other, with every test of both modules still green.
# `tests/test_characterisation.py` pins that they stay single.
from histos.review import PolicyReview, review_policy
from histos.trail.audit import AuditSink, InMemoryAuditSink

# ── protect() result ─────────────────────────────────────────────────────


@dataclass
class ProtectResult:
    """What :func:`protect` / :meth:`Gate.protect` return.

    A small object, never a tuple — a tuple return ages badly. ``.tools`` maps
    each tool's name to its wrapped form, ``.coverage`` says which tools had a
    contract and a grant, and ``.review`` is the full tri-state
    :class:`~histos.review.PolicyReview` for the resulting policy.

    Iterating the result yields the wrapped tools, so
    ``agent.tools = list(protect(tools, policy=p))`` reads naturally — and reads
    naturally is the point. These are **new** objects; the originals stay alive and
    ungated, so a result that is computed and dropped protects nothing while every
    name-based report stays green. :meth:`Gate.ungated_tools` is the assertion that
    catches it, and it has to be asked of the objects the agent is handed.
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
        confirm_suspends: tuple[type[BaseException], ...] = (),
        content_rules: ContentRules | None = None,
        resource_resolver: ResourceResolver | None = None,
        escalate: EscalationTier | None = None,
        mode: str | None = None,
        enforcement: str | None = None,
        audit_key: bytes | None = None,
        output_budget: int = _DEFAULT_OUTPUT_BUDGET,
        strict: bool = False,
    ) -> None:
        # The recorder is built first, before anything that can push into it. The
        # `policy` setter re-stamps the hash the recorder writes on every row, and it
        # runs two lines below — so constructing the recorder after it was an
        # AttributeError on the ordinary path, which is the kind of ordering a
        # collaborator makes visible and five attributes on one object did not.
        self.audit = audit if audit is not None else InMemoryAuditSink()
        # Per-Gate HMAC key so audit digests resist brute-forcing low-entropy args.
        # Pass a stable key to correlate digests across processes.
        self._audit_key = audit_key if audit_key is not None else os.urandom(32)
        self.enforcement = _resolve_mode(mode, enforcement)
        self._recorder = DecisionRecorder(self.audit, self._audit_key, enforced=self._enforce)
        # The setter takes a `PolicySource` and coerces it; mypy type-checks the
        # assignment against the *getter*, which is narrower by design.
        self.policy = policy  # type: ignore[assignment]
        if strict:
            issues = self.policy.validate()
            if issues:
                raise PolicyError("invalid policy: " + "; ".join(issues))
        self.limits = limits if limits is not None else LimitStore()
        self.engine = Engine(
            self.policy,
            self.limits,
            content_rules=content_rules,
            resource_resolver=resource_resolver,
            escalate=escalate,
            output_budget=output_budget,
        )
        self._confirm = confirm
        self._confirm_suspends = confirm_suspends

        self._wrapped_tools: set[str] = set()
        # tool name -> the raw callable gated under it, so a second `protect()` call on
        # this Gate cannot quietly enforce a different function against the same contract.
        self._wrapped_targets: dict[tuple[str, bool], Any] = {}
        # The wrappers this Gate handed back, by identity. Weak, so a Gate does not keep
        # every tool it ever wrapped alive, and identity-compared rather than hashed —
        # a framework's tool object is often an unhashable model instance.
        self._wrappers: list[weakref.ReferenceType[Any]] = []
        self._refresh_policy_hash()

    @property
    def audit_failures(self) -> int:
        """Decisions this Gate could not record, whatever the sink did with them.

        The count lives on the recorder; it is read here because a host alarming on a
        gap in the trail should not have to know that.
        """
        return self._recorder.failures + self._recorder._absorbed

    @property
    def enforcement(self) -> str:
        return self._enforcement

    @enforcement.setter
    def enforcement(self, value: str) -> None:
        """Swap the mode, and make the swap actually take effect.

        Every branch in the call path reads the cached boolean ``_enforce``, which used
        to be computed once in ``__init__``. So ``gate.enforcement = "enforce"`` — which
        reads exactly like turning protection on, and is what an operator promoting a
        calibrated policy writes — set the string, left the boolean alone, and kept
        observing: the denied call still ran, and ``gate.mode`` cheerfully answered
        ``"enforce"`` while it did. The one line that decides whether this library
        blocks anything is not somewhere to leave a stale copy.

        The value goes through the same validation as the constructor, so a typo
        (``"enfroce"``) raises instead of quietly becoming not-enforce.
        """
        # `_resolve_mode(value, None)` reads "neither argument given" as the constructor
        # default, so `None` resolved to `enforce`. Every typo was refused and the one
        # value a config loader actually produces for a missing key silently switched a
        # calibrating gate into enforcement.
        if value is None:
            raise PolicyError("mode must be 'enforce' or 'observe', got None")
        self._enforcement = _resolve_mode(value, None)
        self._enforce = self._enforcement == "enforce"
        recorder = getattr(self, "_recorder", None)  # absent during __init__, by design
        if recorder is not None:
            recorder.enforced = self._enforce

    @property
    def mode(self) -> str:
        """The public spelling of :attr:`enforcement`."""
        return self.enforcement

    @mode.setter
    def mode(self, value: str) -> None:
        self.enforcement = value

    @property
    def policy(self) -> Policy:
        return self._policy

    @policy.setter
    def policy(self, policy: PolicySource) -> None:
        """Swap the ruleset, and make the swap actually take effect.

        ``Engine`` holds its own reference, so plain attribute assignment used to be a
        silent no-op: ``gate.policy = tightened`` read like a revocation and enforced
        the old ruleset forever. It also has to re-hash, because ``policy_hash`` is
        what ties an audit record to the ruleset that produced it — a stale hash is a
        record that names a policy which did not decide.
        """
        self._policy = _coerce_policy(policy)
        engine = getattr(self, "engine", None)
        if engine is not None:
            engine.policy = self._policy
        self._refresh_policy_hash()

    def _refresh_policy_hash(self) -> None:
        self._policy_hash = self._policy.content_hash()
        # The recorder stamps every row with these, so they are pushed rather than read
        # back: a record naming a hash that did not decide it is the one thing the trail
        # cannot survive, and that is exactly what a stale copy here would produce.
        self._recorder.policy_hash = self._policy_hash
        self._recorder.policy_version = self._policy.policy_version

    # ── coverage / "no silent bypass" ─────

    def declared_but_unwrapped(self) -> set[str]:
        """Tools the policy declares that this Gate has not wrapped."""
        return _coverage.declared_but_unwrapped(self)

    def ungated_tools(self, tools: Iterable[Any]) -> list[str]:
        """Which of ``tools`` this Gate does not mediate. See :mod:`histos.mediate.coverage`."""
        return _coverage.ungated_tools(self, tools)

    def coverage(self, tools: Iterable[Any]) -> dict[str, list[str]]:
        """The full mediation report for ``tools``. See :mod:`histos.mediate.coverage`."""
        return _coverage.coverage(self, tools)

    def _no_principal(self) -> GateDecision:
        return GateDecision(Effect.DENY, "no_principal", "no trusted principal set; identity must be bound out-of-band")

    def _apply_bindings(
        self,
        tool_name: str,
        active: Principal,
        call_args: dict[str, Any],
        rebound: list[str] | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> GateDecision | None:
        """Overwrite bound args with trusted principal attributes (Phase 0.1).

        The bound value is what the tool and every check see, so a hijacked model
        passing ``tenant_id="attacker"`` simply has it replaced. Fail closed if the
        principal lacks the attribute — never inject a missing/None trusted value.

        ``rebound`` collects the fields that were actually *changed*, and it exists
        because a rewrite is an authorization decision that used to leave no trace.
        A run where the gate silently redirected an SMS from the attacker's number to
        the caller's own recorded `effect=allow` and nothing else, so an auditor —
        and a measurement — could not tell it apart from a call the policy simply had
        no opinion about. Fields whose value already matched are not listed: nothing
        was overridden, and reporting one would inflate the count of interventions.

        The value itself never reaches the record. Only the field name does.
        """
        contract = self.engine.policy.contract_for(tool_name)
        if contract is None or not contract.bindings:
            return None
        # A caller that supplies `overrides` is asking for the rewrites rather than for
        # them to be applied — the gate does that so observe can evaluate the bound
        # arguments while executing the unbound ones. Everyone else, including the
        # conformance corpus, gets the straightforward thing: `call_args` comes back
        # bound.
        apply_in_place = overrides is None
        if overrides is None:
            overrides = {}
        for b in contract.bindings:
            if b.principal_attr not in active.attributes:
                return GateDecision(
                    Effect.DENY,
                    "arg_binding_unresolved",
                    f"principal is missing trusted attribute {b.principal_attr!r} for arg {b.field!r}",
                    field=b.field,
                )
            # Copied on the way out. `Principal` deep-copies on construction, which
            # stops the *caller* rewriting a bound identity; it does not stop the tool,
            # and a bind hands the tool the stored object itself. So an ordinary
            # `tenants.append(...)` inside a tool body edited the trust anchor that the
            # next call in the same request would be authorized against — the one value
            # in the library that must not be reachable from anything the model can
            # influence.
            # The same walk `Principal` snapshots with, and for the same reason twice
            # over. A bare `copy.deepcopy` here raised on any attribute holding an
            # uncopyable descendant — a lock, a session, an open file — so teaching the
            # *constructor* to tolerate one only moved the outage from construction to
            # call time, where it arrived as an uncaught TypeError out of the wrapper
            # with no audit record for a call the policy had already allowed.
            # `readonly=False`: the *anchor* is immutable, a *handout* is a plain copy.
            # The stored attribute is a ReadOnlyDict/ReadOnlyList so nobody holding the
            # Principal can edit a bound identity, but a tool mutating the argument it
            # was given harms nothing and refusing it would break ordinary tool bodies.
            trusted = _snapshot_value(active.attributes[b.principal_attr], readonly=False)
            if rebound is not None and (b.field not in call_args or call_args[b.field] != trusted):
                rebound.append(b.field)
            overrides[b.field] = trusted
        if apply_in_place:
            call_args.update(overrides)
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
        # The window is named because it is not in the policy: `rate_limit: 3` means
        # three calls per the LimitStore's window, which is a constructor argument and
        # not something the document can express, so a reader of the policy alone
        # cannot know what period they wrote down. Until the format carries it, the
        # decision does.
        detail = f" (window: {self.limits.window_seconds:g}s)" if raced == "rate_limit" else ""
        return GateDecision(Effect.DENY, raced, f"{raced} exceeded for {tool_name!r}{detail}")

    def _will_execute(self, decision: GateDecision) -> bool:
        """Whether the tool body actually runs given this decision and the mode."""
        return decision.effect is Effect.ALLOW or not self._enforce

    def _confirmed(self, decision: GateDecision, req: GateRequest, outcome: Any) -> GateDecision:
        """Turn a confirm callback's answer into a decision. Only ``True`` approves.

        This used to be a bare truthiness test, and truthiness is the wrong question to
        ask about an approval. `Callable[[GateRequest], Any]` is what hosts actually
        write against: a queue client returning a `Response` object, a store returning
        the approval record it found, an approvals UI returning the string `"denied"` —
        every one of those is truthy, and every one of them sent the money. The failure
        is silent and it is on the yes path, so nothing about it looks wrong until an
        auditor asks who approved a transfer.

        `False` and `None` deny, because a callback that says no and a callback that
        forgot to return are the same answer here. Anything else is the host wiring
        being wrong, which is a `confirm_error` denial rather than a guess.
        """
        if outcome is True:
            return GateDecision(Effect.ALLOW, "confirmed", f"{req.tool_name!r} confirmed")
        if outcome is False or outcome is None:
            return decision
        return GateDecision(
            Effect.DENY,
            "confirm_error",
            f"confirm callback for {req.tool_name!r} returned {type(outcome).__name__}, not a bool — "
            "an approval must be exactly True, because every other object a host might return "
            "(a response, a record, the string 'denied') is truthy",
        )

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
        # `protect()` refuses a lambda and points the caller here — and `"<lambda>"` is a
        # perfectly truthy string, so the very call its message recommends accepted one
        # and keyed the policy on a name every other lambda in the process shares.
        if name is None and tool_name == "<lambda>":
            raise PolicyError(
                "wrap() was handed a lambda, which has no stable name to key a policy on — every lambda "
                "in the process is called '<lambda>'. Pass name=... to say what this tool is."
            )

        # A streaming tool is refused here rather than wrapped. Calling one returns a
        # generator immediately, so the post-gate would scan the *iterator object* and
        # report `allow` while every value the tool actually yields — the canary, the
        # secret, the field the policy projects away — flows past untouched. Refusing
        # loudly at wrap time is the only honest option: a gate that silently inspects
        # nothing is worse than no gate, because the coverage report calls it covered.
        streaming = _streaming_kind(tool)
        if streaming is not None:
            raise PolicyError(
                f"tool {tool_name!r} is a {streaming} and cannot be gated: the output half of the gate "
                "can only inspect a materialised value. Wrap a function that returns the collected "
                "result, and gate that."
            )

        # And a tool that is already gated is refused for the mirror-image reason: the
        # symptoms of wrapping one twice all point somewhere else. Every limit is
        # consumed twice, so a `budget=2` runs out after one call and the operator
        # raises the budget; a `requires_confirmation` tool becomes permanently
        # unapprovable, because the outer gate spends the single-use approval and the
        # inner one then asks for another, so the operator drops the confirmation; and
        # the audit trail carries two `executed=True` records for one execution, so the
        # evidence overcounts. Each of those repairs ends with the caller less
        # protected than before, which is why this is loud rather than idempotent.
        # Every wrapper publishes `__gate_name__` already — the coverage check reads it
        # — so the question costs one attribute lookup.
        stamp = _any_gate_stamp(tool)
        if stamp is not None:
            raise PolicyError(
                f"tool {tool_name!r} is already gated (as {stamp!r}) and wrapping it again would consume "
                "every limit twice and make an approval unusable. Wrap the raw callable, or keep the "
                "wrapper you already have."
            )

        bound = _resolve_fixed_principal(fixed_principal, principal)
        run_async = is_async if is_async is not None else _detect_async(tool, tool_name)

        # Gate-scoped, not call-scoped. `protect()` refuses two same-named tools by
        # looking in a dict local to that one call, so building the tool set in two
        # groups — `g.protect(db_tools)` then `g.protect(api_tools)`, which is the "two
        # modules each defining `def delete(...)`" case its own comment names — walked
        # straight past it and enforced both callables against one contract.
        #
        # Keyed by name *and* by which half it is, because a dual-mode tool legitimately
        # gates two different callables under one name: a LangChain `StructuredTool`
        # carries `func` and `coroutine`, and both have to be wrapped or the tool is only
        # half mediated. Two sync `delete`s share a key and are refused; a sync/async
        # pair does not.
        key = (tool_name, run_async)
        previous = self._wrapped_targets.get(key)
        target = _wrap_identity(tool)
        if previous is not None and (held := previous()) is not None and not _same_tool(held, target):
            raise PolicyError(
                f"two different callables are being gated as {tool_name!r} on this Gate. One contract "
                "cannot describe two tools: pass name= to say which is which."
            )
        wrapper = self._wrap_async(tool, tool_name, bound) if run_async else self._wrap_sync(tool, tool_name, bound)
        # Recorded only now. It used to be recorded above `_detect_async`, which refuses
        # a sync wrapper around an async function — so after that refusal the Gate held
        # no wrapper for the tool while `declared_but_unwrapped()` reported none missing
        # and `coverage()` called it covered. A coverage report that is wrong in the
        # reassuring direction is the one failure it cannot have.
        self._wrapped_tools.add(tool_name)
        self._wrapped_targets[key] = _IdentityRef(target)
        self._register(wrapper)
        return wrapper

    def _register(self, wrapper: Any) -> None:
        """Remember a wrapper by identity, so :meth:`coverage` can be asked about objects.

        Dead references are dropped on the way in rather than by a callback: an ``id``
        the interpreter has already recycled would otherwise answer "yes, I produced
        that" for an entirely unrelated object, and a recycled-id false *positive* in
        this particular check is a silent all-clear.
        """
        self._wrappers = [ref for ref in self._wrappers if ref() is not None]
        with contextlib.suppress(TypeError):  # a wrapper that cannot be weak-referenced
            self._wrappers.append(weakref.ref(wrapper))

    def _wrap_sync(self, tool: Callable[..., Any], tool_name: str, bound: Principal | None) -> Callable[..., Any]:
        """The synchronous call path. See :mod:`histos.mediate.wrappers`."""
        return _wrappers._wrap_sync(self, tool, tool_name, bound)

    def _wrap_async(self, tool: Callable[..., Any], tool_name: str, bound: Principal | None) -> Callable[..., Any]:
        """The asynchronous call path. See :mod:`histos.mediate.wrappers`."""
        return _wrappers._wrap_async(self, tool, tool_name, bound)

    def protect(
        self,
        tool_objects: list[Callable[..., Any]],
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

        The honest limit on inference: it never writes a *contract* for a tool a role
        already grants. Such a tool keeps denying with ``unknown_tool``, because the one
        thing inference must not do is supply the declaration the grant is waiting for.

        ``review`` describes the policy as **authored**, not as inferred, so it can name
        a gap ``coverage`` reports as filled — a tool whose arg schema was guessed from a
        signature is still a tool nobody wrote a schema for. The two halves answer
        different questions: ``coverage`` says what is enforced now, ``review`` says what
        a human still owes the policy.
        """
        bound = _resolve_fixed_principal(fixed_principal, principal)
        result = ProtectResult()
        # The review describes the policy the HUMAN wrote, so it is read off a snapshot
        # taken before any inference. Reviewing the live policy afterwards made the
        # report erase its own worst finding: `role 'admin' grants unknown tool
        # 'delete_user'` came back clean, because protect() had just declared the tool
        # the warning was about. A report that answers for its own edits is worse than
        # no report.
        authored = replace(self.policy, tools=dict(self.policy.tools))
        # Inference accumulates here and is installed once, through the property setter,
        # rather than written into the live ruleset item by item. The Gate's policy is
        # read-only precisely so an in-place edit cannot take effect against a
        # `policy_hash` computed before it, and `protect()` must not be the one caller
        # that goes around that.
        tools: dict[str, ToolContract] = dict(self.policy.tools)
        for tool in tool_objects:
            tool_name = getattr(tool, "__name__", None)
            if not tool_name:
                raise PolicyError("cannot determine a tool name in protect(); wrap it individually with name=")
            # The name is the policy key, so two tools answering to one name is not a
            # collision to resolve — it is two different callables enforcing one
            # contract. `result.tools` kept the last, `coverage` listed the name twice
            # as ready, and the agent was handed a tool gated against somebody else's
            # rules. Two modules each defining `def delete(...)` is all it takes.
            if tool_name in result.tools:
                raise PolicyError(
                    f"protect() was handed two tools named {tool_name!r} "
                    f"({getattr(tool, '__qualname__', tool_name)!r} and one before it). The name is the "
                    "policy key, so one of them would be enforced against the other's contract. Wrap them "
                    "separately with Gate.wrap(tool, name=...) and give each its own name.",
                )
            if tool_name == "<lambda>":
                raise PolicyError(
                    "protect() was handed a lambda, which has no stable name to key a policy on. "
                    "Wrap it with Gate.wrap(tool, name=...)."
                )

            contract = self.policy.contract_for(tool_name)
            has_policy = contract is not None
            granted = any(tool_name in self.policy.allowed_tools(role) for role in self.policy.permissions)
            # An inferred schema is a convenience, never a grant, and never a stand-in
            # for one that can reject something. A signature with unannotated
            # parameters or `**kwargs` infers to a schema that accepts every argument
            # of every type; installing that where the policy had none replaced the
            # documented `unknown_tool` / `no_arg_schema` denial with a check that
            # cannot fail — a fail-open reached by the DEFAULT argument, while the
            # coverage report still said "needs-policy" about a tool that just ran.
            # So it is only installed when it actually constrains.
            #
            # And never for a tool that is already GRANTED but undeclared. Inferring a
            # schema fills a hole in a contract a human wrote; inferring the contract
            # itself writes the declaration the grant was waiting for, and `unknown_tool`
            # — the denial that makes "nothing is silently left ungated" true — became an
            # allow for a tool whose `tools:` entry someone had deleted or renamed. That
            # combination keeps denying until a human declares it.
            if contract is None and infer_missing and not granted:
                inferred = infer_contract(tool)
                if inferred.args is not None and _schema_constrains(inferred.args):
                    tools[tool_name] = inferred
            elif contract is not None and contract.args is None and infer_missing:
                schema = infer_schema(tool)
                if _schema_constrains(schema):
                    tools[tool_name] = replace(contract, args=schema)

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

        if tools != dict(self.policy.tools):
            self.policy = replace(self.policy, tools=tools)  # type: ignore[assignment]
        # The names go in explicitly because the snapshot is, correctly, blind to them:
        # a tool the policy never declared is not in `authored.tools`, so without this
        # the review would answer for three tools while the agent holds four.
        result.review = review_policy(authored, discovered=result.tools)
        return result

    # ── audit emit ───────────────────────────────────────────────────


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
    escalate: EscalationTier | None = None,
    mode: str | None = None,
    enforcement: str | None = None,
    name: str | None = None,
    audit_key: bytes | None = None,
    output_budget: int = _DEFAULT_OUTPUT_BUDGET,
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
        escalate=escalate,
        mode=mode,
        enforcement=enforcement,
        audit_key=audit_key,
        output_budget=output_budget,
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
    escalate: EscalationTier | None = None,
    mode: str | None = None,
    enforcement: str | None = None,
    audit_key: bytes | None = None,
    output_budget: int = _DEFAULT_OUTPUT_BUDGET,
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
        escalate=escalate,
        mode=mode,
        enforcement=enforcement,
        audit_key=audit_key,
        output_budget=output_budget,
        strict=strict,
    )
    return g.protect(tools, fixed_principal=fixed_principal, infer_missing=infer_missing)
