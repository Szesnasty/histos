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
materialised value, and a gate that silently skips it is worse than none.

**Identity is per-context, not per-thread-forever.** ``use_principal`` unbinds on
exit. Bare ``set_principal`` without :func:`reset_principal` leaves the identity
bound in *that* context — on a pooled worker thread the next task submitted to the
same worker inherits it. Use ``use_principal`` (or reset the token) in any pooled
or long-lived worker.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import os
import sys
import threading
import time
import warnings
import weakref
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
from histos.engine import Engine, EscalationTier, ResourceResolver, for_callback
from histos.errors import GateConfirmationRequired, GateDenied, PolicyError, ToolErrorRedacted
from histos.infer import infer_contract, infer_schema
from histos.limits import LimitStore
from histos.review import PolicyReview, review_policy
from histos.schema import Schema

# Anything `load_policy` accepts, plus an already-built Policy and None (which
# means "empty policy" — every call then denies by default).
PolicySource = Policy | str | Path | dict[str, Any] | None

# The trusted, request-scoped identity. Set by the host, never by the agent.
_current_principal: ContextVar[Principal | None] = ContextVar("histos_principal", default=None)


def set_principal(principal: Principal) -> Token[Principal | None]:
    """Bind the current trusted principal; returns a token for :func:`reset_principal`.

    The token is not optional bookkeeping. A context variable stays bound until it is
    reset, so on a pooled worker (``ThreadPoolExecutor``, a WSGI worker) an identity
    set and never reset is still bound when the *next* task lands on that worker, and
    that task runs as the previous caller. :func:`use_principal` resets on exit and is
    the path to reach for.
    """
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
        # A Gate owns its ruleset. `Policy` is frozen but its `tools`/`permissions`
        # dicts are not, so aliasing the caller's object meant one Gate's `protect()`
        # rewrote the ruleset of every other Gate holding it, and a grant added to the
        # dict after construction took effect against a `policy_hash` that no longer
        # described the policy that decided.
        return replace(
            policy,
            tools=dict(policy.tools),
            permissions=dict(policy.permissions),
            role_inherits=dict(policy.role_inherits),
        )
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


# ── unwrapping ─────────────────────────────────────────────────


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


# ── wrapper metadata (complete mediation) ────────────────────────────────

# What a framework actually reads off a tool. LangChain also infers an argument
# schema from the signature, which is pinned separately.
_WRAPPER_METADATA = ("__module__", "__name__", "__qualname__", "__doc__")


def _adopt_metadata(wrapper: Any, tool: Any, tool_name: str) -> None:
    """Give ``wrapper`` the tool's identity without giving away the tool itself.

    ``functools.wraps`` is the idiomatic way to do this and is exactly wrong for a
    security wrapper, on two counts. It publishes ``__wrapped__`` — a documented,
    public pointer at the *ungated* callable that ``inspect.unwrap``,
    ``inspect.signature(follow_wrapped=True)`` and every decorator-aware framework
    follow — and its ``WRAPPER_UPDATES`` step copies the target's whole instance
    ``__dict__``, so gating a callable object holding ``self.func = raw_tool``
    republishes the raw tool as ``wrapper.func``. Popping ``__wrapped__`` afterwards
    closes the first hole and not the second.

    So nothing is copied wholesale: the metadata attributes are set by name, and the
    signature is pinned explicitly because losing ``__wrapped__`` is what would
    otherwise cost a framework its inferred arg schema.
    """
    for attr in _WRAPPER_METADATA:
        value = getattr(tool, attr, None)
        if value is not None:
            setattr(wrapper, attr, value)
    if getattr(tool, "__name__", None) is None:
        # A partial or a callable object carries no __name__; the gate knows the name.
        wrapper.__name__ = tool_name
        wrapper.__qualname__ = tool_name
    with contextlib.suppress(TypeError, ValueError):  # a C callable has no signature
        wrapper.__signature__ = inspect.signature(tool)
    # Defence in depth at the one chokepoint every wrapping path funnels through: if a
    # later edit puts `functools.wraps` back above this call, the pointer it publishes
    # still does not survive.
    wrapper.__dict__.pop("__wrapped__", None)
    # Set last, so nothing above can overwrite it. This is the one attribute a caller
    # can interrogate on the *object* they are about to hand a framework, which is the
    # only way to catch a `protect()` result that was computed and then dropped — the
    # Gate records that `wrap()` was called, never what the caller did with the return
    # value. `guard_callable` copies it onto the adapter's own wrapper for the same
    # reason. It publishes a name, never a callable: nothing here is reachable through
    # it. See :meth:`Gate.ungated_tools`.
    wrapper.__gate_name__ = tool_name


# ── async / streaming detection ────────────────────────────────


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


def _streaming_kind(fn: Any) -> str | None:
    """``"generator"`` / ``"async generator"`` if calling ``fn`` yields, else ``None``."""
    # Same reason as `_is_coroutine_callable`: this needs the `__call__` *descriptor*
    # to ask whether it is a generator function, which `callable()` cannot answer.
    for candidate in (fn, _unwrap_target(fn), getattr(type(fn), "__call__", None)):  # noqa: B004
        if candidate is None:
            continue
        if inspect.isasyncgenfunction(candidate):
            return "async generator"
        if inspect.isgeneratorfunction(candidate):
            return "generator"
    return None


def _uninspectable_kind(result: Any) -> str | None:
    """What kind of un-post-gateable thing ``result`` is, if it is one.

    The post chain traverses str/bytes/dict/list/tuple/set. A coroutine, generator or
    async generator carries its payload *behind* an iteration the gate never performs,
    so every output control — canary redaction, projection, secret scanning — would
    report ``allow`` on content nothing inspected.
    """
    if inspect.isasyncgen(result):
        return "async generator"
    if inspect.isgenerator(result):
        return "generator"
    if inspect.isawaitable(result):
        return "coroutine"
    return None


def _is_control_flow(exc: BaseException) -> bool:
    """True for the ``BaseException``\\ s that are host control flow, not tool output.

    Substituting a redacted exception for one of these would turn a cancellation into
    a hang and a Ctrl-C into a silent no-op, so they always propagate as themselves.
    ``asyncio`` is looked up in ``sys.modules`` rather than imported: importing it
    costs most of this package's cold start, and no ``CancelledError`` instance can
    exist before something else has imported it.
    """
    if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
        return True
    asyncio = sys.modules.get("asyncio")
    return asyncio is not None and isinstance(exc, asyncio.CancelledError)


# ── asking an object whether it is gated ─────────────────────────────────

# Where a framework keeps the callable it will actually invoke. LangChain's
# `StructuredTool` splits sync and async across `func`/`coroutine`; a plain callable
# is itself. Kept to a short, named list rather than a search of `__dict__`: a probe
# that hunts for *any* attribute holding a gated callable would report "gated" for a
# tool object that merely stores one next to the ungated one it actually calls.
_TOOL_CALLABLE_ATTRS = ("func", "coroutine")


def _gate_stamp(tool: Any) -> str | None:
    """The tool name this object is gated under, or None if nothing here is gated."""
    for attr in (None, *_TOOL_CALLABLE_ATTRS):
        candidate = tool if attr is None else getattr(tool, attr, None)
        stamp = getattr(candidate, "__gate_name__", None)
        if isinstance(stamp, str):
            return stamp
    return None


def _exposed_name(tool: Any) -> str:
    """The name the agent sees this tool under.

    ``name`` first, because that is the framework's name for the tool and the one the
    model calls; ``__name__`` is the plain-callable case. A tool that answers to
    neither cannot be reported on at all, so it is refused rather than skipped —
    skipping is how an ungated tool ends up absent from the report that exists to find
    ungated tools.
    """
    for attr in ("name", "__name__"):
        value = getattr(tool, attr, None)
        if isinstance(value, str) and value:
            return value
    raise PolicyError(
        f"cannot determine the exposed name of {tool!r}: it has neither `name` nor `__name__`. "
        "Pass the tool objects the agent will be handed, or their names as strings."
    )


def _schema_constrains(schema: Schema) -> bool:
    """Whether an inferred schema can actually reject a call.

    A signature with unannotated parameters yields ``any``-typed fields and ``**kwargs``
    yields ``allow_extra``; either way the "schema" accepts every argument of every
    type. Standing that in for the ``no_arg_schema`` deny would replace a refusal with
    the appearance of validation.
    """
    if schema.allow_extra:
        return False
    return all(f.type != "any" for f in schema.fields.values())


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
        strict: bool = False,
    ) -> None:
        self.enforcement = _resolve_mode(mode, enforcement)
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
        )
        self.audit = audit if audit is not None else InMemoryAuditSink()
        self._enforce = self.enforcement == "enforce"
        self._confirm = confirm
        self._confirm_suspends = confirm_suspends
        # Per-Gate HMAC key so audit digests resist brute-forcing low-entropy args
        # . Pass a stable key to correlate digests across processes.
        self._audit_key = audit_key if audit_key is not None else os.urandom(32)
        self._decision_seq = 0
        self._seq_lock = threading.Lock()
        self._wrapped_tools: set[str] = set()
        # The wrappers this Gate handed back, by identity. Weak, so a Gate does not keep
        # every tool it ever wrapped alive, and identity-compared rather than hashed —
        # a framework's tool object is often an unhashable model instance.
        self._wrappers: list[weakref.ReferenceType[Any]] = []
        self._refresh_policy_hash()

    @property
    def mode(self) -> str:
        """The public spelling of :attr:`enforcement`."""
        return self.enforcement

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

    # ── coverage / "no silent bypass" ─────

    def declared_but_unwrapped(self) -> set[str]:
        """Tools the policy declares that were never actually wrapped."""
        return set(self.policy.tools) - self._wrapped_tools

    def _mediates(self, tool: Any, exposed_name: str) -> bool:
        """Whether a call to ``tool`` goes through this Gate's decision.

        Two questions, because neither answers the whole thing:

        * **identity** — is this object one *this* Gate produced? Exact, and the only
          form that separates "gated" from "gated by the strict gate CI is asserting
          against" when a process builds more than one.
        * **the stamp** — every wrapper carries ``__gate_name__``, and an adapter that
          re-wraps one (``guard_callable``) copies it onto the object it hands the
          framework. Identity cannot see through that extra layer; the stamp can. The
          exposed name has to match it: a tool published as ``wire_transfer`` whose
          callable was gated as ``read_balance`` is enforcing the wrong contract.

        A tool that answers neither is reported ungated. That direction is deliberate:
        a false alarm costs a CI run, a false all-clear costs the whole gate.
        """
        if any(ref() is tool for ref in self._wrappers):
            return True
        return _gate_stamp(tool) == exposed_name

    def ungated_tools(self, tools: Iterable[Any]) -> list[str]:
        """Names of the tools in ``tools`` whose execution this Gate does not mediate.

        The check :meth:`coverage` cannot make from names alone. ``protect()`` and
        ``wrap()`` return **new** objects and leave the originals alive, so a caller who
        drops the return value hands the agent the ungated tools while every name-based
        report stays green — the Gate knows ``wrap()`` was called and nothing about what
        the caller did with the result. Ask the objects instead::

            tools = protect_tools(tools, gate=g)      # ← keep the return value
            assert not g.ungated_tools(tools), "handed the framework ungated tools"

        Put that next to where the agent is constructed rather than in a lint step;
        the failure it catches is a missing assignment on the line above it.

        A string raises rather than passing: a name cannot answer this question, and a
        check that silently degrades to "clean" for the input somebody reaches for
        first is worse than no check.
        """
        ungated: list[str] = []
        for tool in tools:
            if isinstance(tool, str):
                raise PolicyError(
                    f"ungated_tools() needs the live tool objects, got the name {tool!r}. "
                    "A name cannot say whether the object the agent will be handed is the "
                    "wrapped one — that is the whole question. Use coverage() for names."
                )
            name = _exposed_name(tool)
            if not self._mediates(tool, name):
                ungated.append(name)
        return sorted(ungated)

    def coverage(self, tools: Iterable[Any]) -> dict[str, list[str]]:
        """Compare the tools exposed to the agent against the policy (Phase 0.1).

        Accepts the live tool objects **or** their names. The first three keys are the
        same question as ever, answered from names:

        ``covered`` — exposed and declared. ``undeclared`` — exposed to the agent but
        **not** in the policy: a silent gap (a forgotten tool the agent can call ungated
        at the framework layer). This is what ``histos coverage`` fails CI on.
        ``unwrapped`` — declared but never wrapped by this Gate.

        Two keys answer the question names cannot, and they are the reason to pass
        objects:

        ``ungated`` — exposed, and this Gate does not mediate it (see
        :meth:`ungated_tools`). This is what catches a discarded ``protect()`` result,
        where all three name-based keys report clean while every call runs unchecked.
        ``unchecked`` — passed as a name, so that question could not be asked at all.
        It exists so a name-based report cannot be *read* as an all-clear it never gave.
        """
        entries = list(tools)  # materialised: a generator would be consumed by the split
        names = [entry for entry in entries if isinstance(entry, str)]
        objects = [entry for entry in entries if not isinstance(entry, str)]
        exposed = set(names) | {_exposed_name(obj) for obj in objects}
        declared = set(self.policy.tools)
        return {
            "covered": sorted(exposed & declared),
            "undeclared": sorted(exposed - declared),
            "unwrapped": sorted(declared - self._wrapped_tools),
            "ungated": self.ungated_tools(objects),
            "unchecked": sorted(names),
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

        bound = _resolve_fixed_principal(fixed_principal, principal)
        self._wrapped_tools.add(tool_name)

        run_async = is_async if is_async is not None else _detect_async(tool, tool_name)
        wrapper = self._wrap_async(tool, tool_name, bound) if run_async else self._wrap_sync(tool, tool_name, bound)
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
                # Guarded exactly like the async path. An approvals UI that raises —
                # its queue is down, the operator's session expired — used to escape
                # the gate as its own exception, with no audit record for a call the
                # policy had already decided needed a human. Fail closed and record it.
                try:
                    outcome = self._confirm(for_callback(req))
                except self._confirm_suspends:
                    # The host is suspending the run, not failing. A checkpointing
                    # approval (LangGraph's `interrupt()`, a queue that parks the
                    # request) signals by raising, and turning that into a denial made
                    # the gate refuse the legitimate work it had just approved — the
                    # false positive this library names as its own worst outcome.
                    # Propagating is safe precisely because the tool has NOT run: a
                    # suspension is "no decision yet", never "allow".
                    raise
                except Exception as exc:  # noqa: BLE001 — a raising confirm fails closed
                    pre = GateDecision(Effect.DENY, "confirm_error", f"confirm callback raised: {exc!r}")
                else:
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
            if self._enforce and pre.effect is not Effect.ALLOW:
                # Deny-by-default over the *effect space*, not a list of the effects
                # that block. Written the other way round, an effect this branch has
                # not been taught — a member added to `Effect` later, or one a host
                # constructs itself — falls through to the tool body: a fail-open
                # reached by adding a value to an enum. ALLOW is the only word for yes.
                if pre.effect is Effect.REQUIRE_CONFIRMATION:
                    raise GateConfirmationRequired(pre)
                raise GateDenied(pre)

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

        _adopt_metadata(wrapped, tool, tool_name)
        return wrapped

    def _wrap_async(self, tool: Callable[..., Any], tool_name: str, bound: Principal | None) -> Callable[..., Any]:
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
                    outcome = self._confirm(for_callback(req))
                    if inspect.isawaitable(outcome):
                        outcome = await outcome
                except self._confirm_suspends:
                    # The host is suspending the run, not failing. A checkpointing
                    # approval (LangGraph's `interrupt()`, a queue that parks the
                    # request) signals by raising, and turning that into a denial made
                    # the gate refuse the legitimate work it had just approved — the
                    # false positive this library names as its own worst outcome.
                    # Propagating is safe precisely because the tool has NOT run: a
                    # suspension is "no decision yet", never "allow".
                    raise
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
            if self._enforce and pre.effect is not Effect.ALLOW:
                # Deny-by-default over the *effect space*, not a list of the effects
                # that block. Written the other way round, an effect this branch has
                # not been taught — a member added to `Effect` later, or one a host
                # constructs itself — falls through to the tool body: a fail-open
                # reached by adding a value to an enum. ALLOW is the only word for yes.
                if pre.effect is Effect.REQUIRE_CONFIRMATION:
                    raise GateConfirmationRequired(pre)
                raise GateDenied(pre)

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

        _adopt_metadata(wrapped, tool, tool_name)
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
            # An inferred schema is a convenience, never a grant, and never a stand-in
            # for one that can reject something. A signature with unannotated
            # parameters or `**kwargs` infers to a schema that accepts every argument
            # of every type; installing that where the policy had none replaced the
            # documented `unknown_tool` / `no_arg_schema` denial with a check that
            # cannot fail — a fail-open reached by the DEFAULT argument, while the
            # coverage report still said "needs-policy" about a tool that just ran.
            # So it is only installed when it actually constrains.
            if contract is None and infer_missing:
                inferred = infer_contract(tool)
                if inferred.args is not None and _schema_constrains(inferred.args):
                    self.policy.tools[tool_name] = inferred
            elif contract is not None and contract.args is None and infer_missing:
                schema = infer_schema(tool)
                if _schema_constrains(schema):
                    self.policy.tools[tool_name] = replace(contract, args=schema)

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
        # `+= 1` is a read-modify-write, so two threads sharing a Gate could stamp the
        # same `decision_id` on two different decisions — and `decision_id` is what an
        # investigator uses to say "this call, not that one". Cheap to make atomic.
        with self._seq_lock:
            self._decision_seq += 1
            decision_id = self._decision_seq
        record = AuditRecord(
            ts=time.time(),
            decision_id=decision_id,
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
    escalate: EscalationTier | None = None,
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
        escalate=escalate,
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
    escalate: EscalationTier | None = None,
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
        escalate=escalate,
        mode=mode,
        enforcement=enforcement,
        strict=strict,
    )
    return g.protect(tools, fixed_principal=fixed_principal, infer_missing=infer_missing)
