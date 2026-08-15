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
import inspect
import os
import sys
import threading
import time
import warnings
import weakref
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from histos._version import __version__
from histos.audit import AuditRecord, AuditSink, InMemoryAuditSink, digest_args
from histos.bundle import load_policy
from histos.content_rules import ContentRules
from histos.contracts import (
    Effect,
    GateDecision,
    GateRequest,
    Policy,
    Principal,
    ReadOnlyDict,
    ToolContract,
    _snapshot_value,
)
from histos.engine import _MAX_OUTPUT_SCAN_CHARS as _DEFAULT_OUTPUT_BUDGET
from histos.engine import Engine, EscalationTier, ResourceResolver, for_callback
from histos.errors import GateConfirmationRequired, GateDenied, PolicyError, ToolErrorRedacted
from histos.infer import infer_contract, infer_schema
from histos.limits import LimitStore
from histos.review import PolicyReview, review_policy
from histos.schema import Schema

# Anything `load_policy` accepts, plus an already-built Policy and None (which
# means "empty policy" — every call then denies by default).
PolicySource = Policy | str | Path | dict[str, Any] | None

# The request-scoped identity and its binding scope live in `histos.identity`.
# Imported rather than re-declared: the two ContextVars are process-wide singletons,
# and a second copy of either means `use_principal` binds one while the engine reads
# the other. `tests/test_characterisation.py` pins that they stay single.
from histos.identity import (  # noqa: E402 — a seam, kept beside what it replaced
    _current_principal,
)

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
        # Read-only, not merely copied. Copying stopped one Gate's `protect()` rewriting
        # another's ruleset; it did not stop `gate.policy.permissions[role] |= {...}`,
        # which the Engine sees immediately — it holds the same object — while every
        # subsequent audit record keeps naming the hash computed before the edit. A
        # record that attests a ruleset which did not decide is the one failure the
        # trail cannot survive, so the ruleset a Gate owns cannot be edited in place at
        # all. Swap it with `gate.policy = ...`, which re-hashes.
        #
        # One level was not deep enough. `ToolContract.args` hands out a `Schema`, which
        # is frozen, whose `.fields` is a plain mutable dict — so
        # `gate.policy.tools["wire"].args.fields["amount"] = Field(type="integer")`
        # removed a `maximum` from the live ruleset the engine consults on the next call
        # while `_policy_hash` still named the pre-edit hash. Identical end state to the
        # `|=` edit above, reached through the container the wrapper did not cover.
        return replace(
            policy,
            tools=ReadOnlyDict({name: _read_only_contract(c) for name, c in policy.tools.items()}),
            permissions=ReadOnlyDict(dict(policy.permissions)),
            role_inherits=ReadOnlyDict(dict(policy.role_inherits)),
        )
    return load_policy(policy)


def _read_only_contract(contract: ToolContract) -> ToolContract:
    """The same contract with its argument and return field maps made read-only."""
    args = _read_only_schema(contract.args)
    returns = _read_only_schema(contract.returns)
    if args is contract.args and returns is contract.returns:
        return contract
    return replace(contract, args=args, returns=returns)


def _read_only_schema(schema: Schema | None) -> Schema | None:
    if schema is None or isinstance(schema.fields, ReadOnlyDict):
        return schema
    return replace(schema, fields=ReadOnlyDict(dict(schema.fields)))


def _resolve_mode(mode: str | None, enforcement: str | None) -> str:
    """``mode`` is the public spelling; ``enforcement`` is the original kwarg."""
    if mode is not None and enforcement is not None and mode != enforcement:
        raise PolicyError(f"mode={mode!r} and enforcement={enforcement!r} disagree; pass one of them")
    resolved = mode if mode is not None else (enforcement if enforcement is not None else "enforce")
    if resolved not in ("enforce", "observe"):
        raise PolicyError(f"mode must be 'enforce'|'observe', got {resolved!r}")
    return resolved


def _resolve_fixed_principal(fixed_principal: Principal | None, principal: Principal | None) -> Principal | None:
    """Accept ``fixed_principal=``; refuse the ``principal=`` alias outright.

    ``principal=`` used to be accepted with a ``DeprecationWarning``, and that was the
    wrong instrument twice. The name reads like the per-request identity and does the
    opposite — it binds ONE identity for the lifetime of the wrapper, so on a
    multi-tenant server every caller runs as that identity, which is the single worst
    misconfiguration this library has. And the warning was invisible: Python filters
    ``DeprecationWarning`` outside ``__main__`` by default, and the ``stacklevel`` was
    counted for one entry point while three call this, so it pointed inside the
    library. "Your fail-closed default is off" is not a deprecation notice.

    Nothing is published yet, so there is no compatibility to keep. It raises.
    """
    if principal is None:
        return fixed_principal
    raise PolicyError(
        "`principal=` is gone. It bound ONE identity for the lifetime of the wrapper while reading like "
        "the per-request one, so on a server every caller ran as it. Use use_principal() per request, or "
        "fixed_principal= if you really do mean one identity for a script or worker.",
        code="removed_argument",
    )


# Tool identity, wrapper metadata and lazy-return inspection live beside this module.
from histos.inspection import (  # noqa: E402 — a seam, kept where the code used to be
    _close_quietly,
    _detect_async,
    _streaming_kind,
    _uninspectable_kind,
)
from histos.toolref import (  # noqa: E402
    _adopt_metadata,
    _IdentityRef,
    _wrap_identity,
)

# ── asking an object whether it is gated ─────────────────────────────────

# Where a framework keeps the callable it will actually invoke. LangChain's
# `StructuredTool` splits sync and async across `func`/`coroutine`; a plain callable
# is itself. Kept to a short, named list rather than a search of `__dict__`: a probe
# that hunts for *any* attribute holding a gated callable would report "gated" for a
# tool object that merely stores one next to the ungated one it actually calls.
_TOOL_CALLABLE_ATTRS = ("func", "coroutine")


class _Unnameable(Exception):
    """The binder cannot turn this call into named arguments, and says why.

    Raised out of `bind` rather than returned, because the two wrappers already have a
    path for "this call cannot be named" — `_refuse_unnameable`, which records the
    denial instead of raising an unaudited `TypeError`.
    """


def _positional_binder(tool: Callable[..., Any]) -> Callable[..., dict[str, Any]] | None:
    """A function mapping ``(*args, **kwargs)`` to a named dict, or None if that is impossible.

    The gate reasons about arguments by name: a schema names its fields, a ``bind``
    names the field it overwrites, the audit record lists ``arg_keys``. So a positional
    call used to be refused outright — ``PolicyError: must be called with keyword
    arguments only`` — which was fail-closed and technically defensible and wrong in
    practice, for four reasons at once. It is undocumented, so it lands as a runtime
    surprise on an ordinary ``my_tool("x")``. It fires in ``mode="observe"``, which is
    documented as blocking nothing and is exactly the step where a team is checking
    whether this library breaks their app. It emits no audit record, in a component
    whose trail claims to record every decision. And ``guard_callable`` catches only
    ``GateDenied``, so the refusal escapes the adapter into the agent loop as a raw
    exception instead of the non-coaching denial the adapter exists to return.

    Python already knows the mapping, so the gate asks it: bind the call the way the
    interpreter would and read the names back off. Resolved once at wrap time, because
    a tool whose arguments can never be named is a wiring problem the developer should
    hear about immediately, not on the first positional call in production.

    Returns None when there is no honest mapping — a C callable with no signature, or
    ``*args``, where several values share one parameter and no name distinguishes them.
    A positional call to one of those is still refused, and now audited.
    """
    try:
        # `inspect.signature(tool)`, not of its unwrap target. `_unwrap_target` is right
        # for async/streaming detection, where the innermost `__code__` is the question,
        # and wrong for naming arguments: for a `functools.partial` it hands back the
        # underlying function with the already-supplied parameters still in it, so every
        # positional argument is named one slot to the left. `partial(send, "sms")("+48111")`
        # was named `channel="+48111"`. `inspect.signature` accounts for a partial's
        # pre-bound arguments, bound methods, callable objects and classes already.
        signature = inspect.signature(tool)
    except (TypeError, ValueError):
        return None
    if any(p.kind is inspect.Parameter.VAR_POSITIONAL for p in signature.parameters.values()):
        return None

    var_keyword = next((p.name for p in signature.parameters.values() if p.kind is inspect.Parameter.VAR_KEYWORD), None)
    positional_only = any(p.kind is inspect.Parameter.POSITIONAL_ONLY for p in signature.parameters.values())

    def bind(*args: Any, **kwargs: Any) -> dict[str, Any]:
        # Not `apply_defaults()`: a default the caller did not pass is the tool's own
        # business, and materialising it here would put a value the model never sent
        # into the schema check, the audit record and the approval fingerprint.
        named = dict(signature.bind_partial(*args, **kwargs).arguments)
        # `bind_partial` nests everything that landed in `**kwargs` under the parameter's
        # own name. Flattened back, because `{"rest": {"tenant_id": ...}}` is not the
        # shape the schema, the bindings or the trail are written against.
        if var_keyword is not None:
            extras = named.pop(var_keyword, {})
            # PEP 570's stated purpose for `/` is that the parameter name becomes free
            # to reuse in `**kwargs`, so `def update(record_id, /, **fields)` legally
            # accepts `update(1, record_id=2)` — two distinct values. Flattening one
            # dict over the other silently kept the second and threw the trusted
            # positional away, where the raw call had raised a loud TypeError. The gate
            # names arguments; it cannot name these two apart, so it refuses.
            if extras.keys() & named.keys():
                collision = ", ".join(sorted(extras.keys() & named.keys()))
                raise _Unnameable(
                    f"{collision} arrives both positionally and in **{var_keyword}, and a gated call is "
                    "named — the two values cannot be told apart in the schema check, the audit record "
                    "or the approval fingerprint. Rename the keyword argument."
                )
            named.update(extras)
        return named

    def call(fn: Callable[..., Any], named: dict[str, Any]) -> Any:
        """Invoke ``fn`` with ``named``, routing positional-only parameters positionally.

        The gate reasons in names and the tool may not accept them: `def f(a, /, b)` —
        and every C or pybind11 callable exposing a `__text_signature__` — rejects
        `f(a=...)` with a TypeError. So the names are re-split through the same
        signature they came from on the way back out.
        """
        if not positional_only:
            return fn(**named)
        # Walked in declaration order: a positional-only parameter cannot be passed by
        # keyword at all, so `bind_partial(**named)` refuses it too and cannot be used
        # to re-split. Everything else stays a keyword, including a `bind` field the
        # signature does not name — the tool's own TypeError is a better error than one
        # invented here.
        rest = dict(named)
        positionals = [p for p in signature.parameters.values() if p.kind is inspect.Parameter.POSITIONAL_ONLY]
        # The last positional-only parameter the caller actually supplied. Stopping at
        # the *first* one missing was the bug this re-split exists to fix, reintroduced
        # one line down: `def f(a=1, b=2, /)` called as `f(b=9)` left `b` in `rest` and
        # handed it to the tool as a keyword, which a positional-only parameter cannot
        # accept. Everything up to the last supplied one goes positionally, and a hole
        # before it is filled from the signature's own default — it must have one, or
        # the call could not have been legal in the first place.
        supplied = [i for i, p in enumerate(positionals) if p.name in rest]
        ordered: list[Any] = []
        for parameter in positionals[: (supplied[-1] + 1) if supplied else 0]:
            if parameter.name in rest:
                ordered.append(rest.pop(parameter.name))
            elif parameter.default is not inspect.Parameter.empty:
                ordered.append(parameter.default)
            else:  # pragma: no cover — unreachable for a call the tool could accept
                raise _Unnameable(
                    f"positional-only parameter {parameter.name!r} has no value and no default, so the "
                    "gated call cannot be re-split into the positional form the tool requires."
                )
        return fn(*ordered, **rest)

    bind.call = call  # type: ignore[attr-defined]
    return bind


def _invoke(tool: Callable[..., Any], binder: Any, named: dict[str, Any]) -> Any:
    """Call ``tool`` with named arguments, however its signature wants to receive them."""
    call = getattr(binder, "call", None)
    return call(tool, named) if call is not None else tool(**named)


def _gate_stamp(tool: Any) -> str | None:
    """The tool name this object is gated under, or None if any way in is not gated.

    ``func`` and ``coroutine`` are not alternative spellings of one callable: on a
    LangChain ``StructuredTool`` they are the sync and async implementations, reached
    by ``invoke()`` and ``ainvoke()``. Returning the first stamp found therefore
    answered "gated" for a tool whose async half was wrapped and whose sync half was
    the raw function — and `ungated_tools()`, the assertion a host puts next to where
    it builds the agent, came back empty. Half a mediated tool is an ungated tool with
    a reassuring report attached, so every handle that is present has to agree.
    """
    handles = [getattr(tool, attr, None) for attr in _TOOL_CALLABLE_ATTRS]
    handles = [h for h in handles if callable(h)]
    if handles:
        stamps = {getattr(h, "__gate_name__", None) for h in handles}
        if len(stamps) == 1 and isinstance(next(iter(stamps)), str):
            return str(next(iter(stamps)))
        return None
    stamp = getattr(tool, "__gate_name__", None)
    return stamp if isinstance(stamp, str) else None


def _any_gate_stamp(tool: Any) -> str | None:
    """Any tool name this object is gated under — the question `wrap()` has to ask.

    `_gate_stamp` answers "gated, and every handle agrees", which is right for the
    coverage report: half a mediated tool is an ungated tool. It is a fail-open here,
    because it returns `None` both for "nothing is gated" and for "the handles
    disagree", and `wrap()` read the second as permission to wrap. A LangChain-shaped
    tool whose sync half was already wrapped therefore got its async half wrapped too,
    and every limit on the sync path was consumed twice — the exact harm the refusal
    beside this call exists to prevent.
    """
    candidates = [getattr(tool, attr, None) for attr in _TOOL_CALLABLE_ATTRS]
    stamps = [getattr(h, "__gate_name__", None) for h in candidates if callable(h)]
    stamps.append(getattr(tool, "__gate_name__", None))
    return next((s for s in stamps if isinstance(s, str)), None)


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
        output_budget: int = _DEFAULT_OUTPUT_BUDGET,
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
            output_budget=output_budget,
        )
        self.audit = audit if audit is not None else InMemoryAuditSink()
        self._confirm = confirm
        self._confirm_suspends = confirm_suspends
        # Per-Gate HMAC key so audit digests resist brute-forcing low-entropy args
        # . Pass a stable key to correlate digests across processes.
        self._audit_key = audit_key if audit_key is not None else os.urandom(32)
        self._decision_seq = 0
        self._seq_lock = threading.Lock()
        # Decisions this Gate could not record, whatever the sink was. `JSONLAuditSink`
        # counts its own, but `AuditSink` is a Protocol and a host's collector cannot be
        # made to — so the gap in the trail was legible only as a RuntimeWarning, which
        # is not something a monitor reads. Alarm on this instead.
        self.audit_failures = 0
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
        if previous is not None and previous() is not None and previous() != target:
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
        binder = _positional_binder(tool)

        def wrapped(*args: Any, **kwargs: Any) -> Any:
            started = time.perf_counter()
            active = bound or _current_principal.get()
            if args:
                if binder is None:
                    return self._refuse_unnameable(tool_name, kwargs, active, started, tool, args)
                try:
                    call_args = binder(*args, **kwargs)
                except _Unnameable as exc:
                    return self._refuse_unnameable(tool_name, kwargs, active, started, tool, args, str(exc))
            else:
                call_args = dict(kwargs)

            # No trusted identity → fail closed. Identity is never inferred.
            if active is None:
                decision = self._no_principal()
                self._emit(tool_name, call_args, decision, "pre", started, None, self._will_execute(decision))
                if self._enforce:
                    raise GateDenied(decision)
                return _invoke(tool, binder, call_args)

            rebound: list[str] = []
            overrides: dict[str, Any] = {}
            exec_source = dict(call_args)
            binding_denial = self._apply_bindings(tool_name, active, call_args, rebound, overrides)
            if binding_denial is not None:
                self._emit(
                    tool_name,
                    call_args,
                    binding_denial,
                    "pre",
                    started,
                    active,
                    self._will_execute(binding_denial),
                    rebound,
                )
                if self._enforce:
                    raise GateDenied(binding_denial)
                return _invoke(tool, binder, call_args)

            # Two dicts, because observe has to predict enforce and the two questions are
            # different. `checked_args` is what the policy is evaluated against and what
            # the trail records — always post-binding, so a dry run reports the decision
            # the real thing would make. `exec_args` is what the tool actually receives,
            # and only enforce rewrites that: observe is documented as changing nothing,
            # and a dry run whose side effects differ from the ungated app measures the
            # wrong thing. Deferring both was the first attempt, and it made observe
            # evaluate the model's unbound arguments — so it stopped predicting enforce
            # in both directions, which is the one thing observe is for.
            checked_args = {**call_args, **overrides}
            # Observe does not rewrite an argument the caller sent — that is the whole
            # point of it — but it does have to supply one the caller never sent at all.
            # A `bind` on a parameter the model is not expected to pass is the ordinary
            # shape (`def read(tenants): ...` with `tenants` bound from the principal),
            # and leaving it out meant observe invoked the tool with a missing argument
            # and raised a `TypeError` on a call enforce serves without complaint. A dry
            # run that breaks the app teaches the team to skip the dry run.
            supplied = {k: v for k, v in overrides.items() if k not in exec_source} if not self._enforce else {}
            exec_args = checked_args if self._enforce else {**exec_source, **supplied}
            call_args = checked_args

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
                    # Recorded before it leaves. The comment above says a raising
                    # confirm "used to escape the gate as its own exception, with no
                    # audit record for a call the policy had already decided needed a
                    # human" — and this branch reintroduced exactly that half: a call
                    # that reached the approval stage and parked produced no record at
                    # all, so the trail could not show that a human had been asked.
                    # `executed=False`, because a suspension is "no decision yet".
                    self._emit(
                        tool_name,
                        call_args,
                        GateDecision(
                            Effect.REQUIRE_CONFIRMATION,
                            "confirm_suspended",
                            f"{tool_name!r} parked awaiting an out-of-band approval",
                        ),
                        "pre",
                        started,
                        active,
                        False,
                        rebound,
                    )
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

            self._emit(tool_name, call_args, pre, "pre", started, active, self._will_execute(pre), rebound)
            if self._enforce and pre.effect is not Effect.ALLOW:
                # Deny-by-default over the *effect space*, not a list of the effects
                # that block. Written the other way round, an effect this branch has
                # not been taught — a member added to `Effect` later, or one a host
                # constructs itself — falls through to the tool body: a fail-open
                # reached by adding a value to an enum. ALLOW is the only word for yes.
                if pre.effect is Effect.REQUIRE_CONFIRMATION:
                    # The request travels with the pause. `req.args` is post-binding, and
                    # that is the only spelling an approval will match — see
                    # GateConfirmationRequired.
                    raise GateConfirmationRequired(pre, for_callback(req))
                raise GateDenied(pre)

            redacted: BaseException | None = None
            try:
                result = _invoke(tool, binder, exec_args)
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
        binder = _positional_binder(tool)

        async def wrapped(*args: Any, **kwargs: Any) -> Any:
            started = time.perf_counter()
            active = bound or _current_principal.get()
            if args:
                if binder is None:
                    outcome = self._refuse_unnameable(tool_name, kwargs, active, started, tool, args)
                    return await outcome if inspect.isawaitable(outcome) else outcome
                try:
                    call_args = binder(*args, **kwargs)
                except _Unnameable as exc:
                    outcome = self._refuse_unnameable(tool_name, kwargs, active, started, tool, args, str(exc))
                    return await outcome if inspect.isawaitable(outcome) else outcome
            else:
                call_args = dict(kwargs)

            if active is None:
                decision = self._no_principal()
                self._emit(tool_name, call_args, decision, "pre", started, None, self._will_execute(decision))
                if self._enforce:
                    raise GateDenied(decision)
                return await _invoke(tool, binder, call_args)

            rebound: list[str] = []
            overrides: dict[str, Any] = {}
            exec_source = dict(call_args)
            binding_denial = self._apply_bindings(tool_name, active, call_args, rebound, overrides)
            if binding_denial is not None:
                self._emit(
                    tool_name,
                    call_args,
                    binding_denial,
                    "pre",
                    started,
                    active,
                    self._will_execute(binding_denial),
                    rebound,
                )
                if self._enforce:
                    raise GateDenied(binding_denial)
                return await _invoke(tool, binder, call_args)

            # See the sync path: the policy is evaluated against the bound arguments in
            # both modes, and only enforce rewrites the ones the tool receives.
            checked_args = {**call_args, **overrides}
            # Observe does not rewrite an argument the caller sent — that is the whole
            # point of it — but it does have to supply one the caller never sent at all.
            # A `bind` on a parameter the model is not expected to pass is the ordinary
            # shape (`def read(tenants): ...` with `tenants` bound from the principal),
            # and leaving it out meant observe invoked the tool with a missing argument
            # and raised a `TypeError` on a call enforce serves without complaint. A dry
            # run that breaks the app teaches the team to skip the dry run.
            supplied = {k: v for k, v in overrides.items() if k not in exec_source} if not self._enforce else {}
            exec_args = checked_args if self._enforce else {**exec_source, **supplied}
            call_args = checked_args

            req = GateRequest(tool_name, call_args, active, phase="pre")
            pre = await self.engine.apre(req)

            if pre.effect is Effect.REQUIRE_CONFIRMATION and self._confirm is not None:
                try:
                    outcome = self._confirm(for_callback(req))
                    if inspect.isawaitable(outcome):
                        outcome = await outcome
                except self._confirm_suspends:
                    # Recorded before it leaves. The comment above says a raising
                    # confirm "used to escape the gate as its own exception, with no
                    # audit record for a call the policy had already decided needed a
                    # human" — and this branch reintroduced exactly that half: a call
                    # that reached the approval stage and parked produced no record at
                    # all, so the trail could not show that a human had been asked.
                    # `executed=False`, because a suspension is "no decision yet".
                    self._emit(
                        tool_name,
                        call_args,
                        GateDecision(
                            Effect.REQUIRE_CONFIRMATION,
                            "confirm_suspended",
                            f"{tool_name!r} parked awaiting an out-of-band approval",
                        ),
                        "pre",
                        started,
                        active,
                        False,
                        rebound,
                    )
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

            self._emit(tool_name, call_args, pre, "pre", started, active, self._will_execute(pre), rebound)
            if self._enforce and pre.effect is not Effect.ALLOW:
                # Deny-by-default over the *effect space*, not a list of the effects
                # that block. Written the other way round, an effect this branch has
                # not been taught — a member added to `Effect` later, or one a host
                # constructs itself — falls through to the tool body: a fail-open
                # reached by adding a value to an enum. ALLOW is the only word for yes.
                if pre.effect is Effect.REQUIRE_CONFIRMATION:
                    # The request travels with the pause. `req.args` is post-binding, and
                    # that is the only spelling an approval will match — see
                    # GateConfirmationRequired.
                    raise GateConfirmationRequired(pre, for_callback(req))
                raise GateDenied(pre)

            redacted: BaseException | None = None
            try:
                result = await _invoke(tool, binder, exec_args)
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
        lazy = _uninspectable_kind(result)
        if lazy is not None:
            return self._refuse_uninspectable(tool_name, call_args, active, started, result, lazy)
        post_req = GateRequest(tool_name, call_args, active, phase="post")
        post, final = self.engine.post(post_req, result)
        # The tool has already run by definition on the post phase.
        self._emit(tool_name, call_args, post, "post", started, active, True)
        if post.effect is Effect.DENY and self._enforce:
            raise GateDenied(post)
        # observe mode never modifies the result.
        return final if self._enforce else result

    def _refuse_unnameable(
        self,
        tool_name: str,
        kwargs: dict[str, Any],
        active: Principal | None,
        started: float,
        tool: Callable[..., Any],
        args: tuple[Any, ...],
        reason: str | None = None,
    ) -> Any:
        """Refuse a positional call the gate cannot turn into named arguments.

        Only reached for the two shapes where no honest mapping exists — ``*args``, and
        a callable with no introspectable signature — because for everything else
        :func:`_positional_binder` asks Python for the names. The gate cannot validate
        what it cannot name: a schema, a ``bind`` and the trail are all written against
        names, so allowing the call would skip all three.

        This used to be a bare ``PolicyError`` raised before anything was recorded,
        which made it the one refusal in the library that left no trace, and made it
        fire in ``observe`` mode, which is documented as blocking nothing. It is a
        decision now, so it is audited like one, and observe watches it rather than
        blocking on it — a dry run that breaks the app teaches the team to skip the dry
        run.
        """
        decision = GateDecision(
            Effect.DENY,
            "unnameable_args",
            reason
            or (
                f"{tool_name!r} was called with {len(args)} positional argument(s) and its parameters "
                "cannot be named (it takes *args, or exposes no signature), so the schema, the bindings "
                "and the audit trail have nothing to attach to. Call it with keyword arguments."
            ),
        )
        self._emit(tool_name, dict(kwargs), decision, "pre", started, active, self._will_execute(decision))
        if self._enforce:
            raise GateDenied(decision)
        return tool(*args, **kwargs)

    def _refuse_uninspectable(
        self,
        tool_name: str,
        call_args: dict[str, Any],
        active: Principal,
        started: float,
        result: Any,
        kind: str,
    ) -> Any:
        """Refuse a returned value whose payload is behind an iteration nothing performs.

        ``wrap`` refuses a generator *function*, but that asks the wrong object: a plain
        ``def search(q): return (row for row in rows)`` — or an async tool forced onto
        the sync path with ``is_async=False`` — looks ordinary at wrap time and only
        shows what it is here. The post chain then scanned the *iterator object* and
        reported ``allow`` with ``redactions: []``, so the canary, the secret and the
        projected-away field flowed to the model with a clean line in the log saying
        nothing was there.

        The honest limit, and the reason this reads as a denial of a value rather than
        of an action: the tool has already run, so nothing here can undo what it did.
        Refusing only stops the unscanned payload reaching the model.
        """
        decision = GateDecision(
            Effect.DENY,
            # its own published code, not `output_schema`: that one means the output was
            # read and did not match the declared return shape, and borrowing it here
            # said the opposite of what happened — nothing read this output at all — to
            # every dashboard and second implementation that groups by rule.
            "uninspectable_output",
            f"{tool_name!r} returned a {kind}: the output half of the gate can only inspect a "
            "materialised value, so nothing scanned it. Collect it first — `list(...)`, `dict(...)`, "
            "`bytes(...)` — and return that.",
        )
        # executed=True without argument: the tool body ran to completion.
        self._emit(tool_name, call_args, decision, "post", started, active, True)
        if not self._enforce:
            # observe mode never modifies the result, and closing it would modify it
            # more thoroughly than any redaction — the caller would get an exhausted
            # object where its data used to be.
            return result
        _close_quietly(result)
        raise GateDenied(decision)

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
        post, text = self.engine.post_exception(post_req, exc, mutate=self._enforce)
        # `post_exception` reads the exception's *text*, so an exception carrying its
        # payload as a lazy object — `raise ToolError(rows_iterator)` — is the raising
        # half of the same hole `_refuse_uninspectable` closes: `str(exc)` shows
        # `<generator object ...>`, nothing scans what the host will iterate out of
        # `exc.args`, and the record says allow. Each arg is asked the recursive
        # question, because `raise ToolError([rows])` hides the same object one level
        # down and a host draining `exc.args` finds it just as easily.
        lazy = next((kind for kind in map(_uninspectable_kind, exc.args) if kind is not None), None)
        if lazy is not None:
            post = GateDecision(
                Effect.DENY,
                "uninspectable_output",  # see `_refuse_uninspectable` on the code
                f"{tool_name!r} raised an error carrying a {lazy}: the output half of the gate can only "
                "inspect materialised text, so nothing scanned it.",
            )
        # The tool ran — it just ended by raising.
        self._emit(tool_name, call_args, post, "post", started, active, True)
        # observe mode records what it *would* have removed and changes nothing.
        if post.effect is Effect.ALLOW or not self._enforce:
            return exc
        if lazy is not None:
            # substituting the redacted exception is what drops the unscanned payload —
            # the original, and the object it holds, never reach the caller.
            for arg in exc.args:
                if _uninspectable_kind(arg) is not None:
                    _close_quietly(arg)
        return ToolErrorRedacted(post, type(exc).__name__, text)

    # ── protect the whole tool set ────────────────────

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

    def _emit(
        self,
        tool: str,
        args: dict[str, Any],
        decision: GateDecision,
        phase: str,
        started: float,
        principal: Principal | None,
        executed: bool,
        rebound: list[str] | None = None,
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
            rebound_args=sorted(rebound or ()),
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
        # The shipped sinks are total, and `AuditSink` is a Protocol, so a host's own
        # sink — a database write, an HTTP post to a collector — cannot be made to be.
        # `_emit` runs on the POST path too, after the tool body has produced its side
        # effect, so a sink that raises there does not prevent anything: it replaces a
        # completed call's result with the collector's traceback and throws the value
        # away. Reporting the sink is right; letting it take the call with it is not.
        # `failed` is read either side because the shipped sink is *total*: it absorbs
        # its own write errors, so the gate saw a clean return and could not count the
        # loss. That is the ordinary configuration, and it was the one where a host had
        # nothing to alarm on but a RuntimeWarning.
        before = getattr(self.audit, "failed", None)
        try:
            self.audit.record(record.to_dict())
        except Exception as exc:  # noqa: BLE001 — only `strict` may decide a call's fate
            self._sink_failed(exc, phase, executed)
        else:
            after = getattr(self.audit, "failed", None)
            if isinstance(before, int) and isinstance(after, int) and after > before:
                with self._seq_lock:
                    self.audit_failures += after - before

    def _sink_failed(self, exc: Exception, phase: str, executed: bool) -> None:
        """One rule for a sink that raised: only ``strict`` makes it fatal.

        Three separate things were wrong with catching it here and warning.

        *`strict` was inert.* `JSONLAuditSink(strict=True)` re-raises, and this was the
        only caller of `record()` in the library, so the blanket `except` caught the
        re-raise and turned it back into a warning. `strict=True` and `strict=False`
        behaved identically through `protect()`, `gate()` and `Gate` — every entry point
        the README teaches — while the sink's own warning text named `strict=True` as
        the remedy. It is honoured here now, on both phases, because "a lost record is
        worse than a failed call" is a statement about evidence, not about timing.

        *The justification was post-only.* "The side effect already happened, so raising
        prevents nothing" is true on POST and false on PRE, where the tool has not run
        and a raising sink is the only thing between an allowed call and an execution
        with no record of the decision. The default is still to continue — a collector
        outage should not stop an agent, and enforcement is unaffected either way, as
        the denial path never reaches the tool — but the message says which side of the
        call it is on instead of claiming the harmless one, and `audit_failures` counts
        it for a host that wants to alarm on the gap rather than parse warnings.

        *The warning could raise.* Under ``-W error`` — a perfectly ordinary CI setting
        — `warnings.warn` raises, so the "totality" the sink documents ended at this
        line: on POST the side effect stood, the record was lost *and* the caller got a
        RuntimeWarning instead of the value. A warning filter is a reporting choice, not
        a security one, so it does not get to decide a call. When the warning cannot be
        delivered the loss goes to stderr, which cannot be turned into an exception.
        """
        with self._seq_lock:
            self.audit_failures += 1
        if phase == "post":
            note = "the call had already run, so its side effect stands"
        elif executed:
            note = "the call is about to run with no record of the decision that allowed it"
        else:
            note = "the call was refused, and the refusal went unrecorded"
        message = (
            f"histos: the audit sink {type(self.audit).__name__} raised while recording this call "
            f"({phase} phase): {type(exc).__name__}: {exc}. This record is lost and {note}. "
            "Read Gate.audit_failures for the count, or give the sink strict=True to raise instead."
        )
        if getattr(self.audit, "strict", False):
            raise exc
        try:
            warnings.warn(message, RuntimeWarning, stacklevel=3)
        except Exception:  # noqa: BLE001 — `-W error` is a reporting choice, not a veto
            with contextlib.suppress(Exception):
                print(message, file=sys.stderr)


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
