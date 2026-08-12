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
import enum
import functools
import inspect
import itertools
import os
import sys
import threading
import time
import warnings
import weakref
from collections.abc import Callable, Iterable, Iterator
from contextvars import ContextVar, Token
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

# The trusted, request-scoped identity. Set by the host, never by the agent.
_current_principal: ContextVar[Principal | None] = ContextVar("histos_principal", default=None)

# The open `use_principal` scopes, as `(id(instance), token)` pairs, innermost last.
# In the Context rather than on the instance, because that is where a `Token` is valid:
# one may only be reset where it was created, so a stack held on a shared instance let
# two tasks pop each other's tokens and leave both bindings live. A tuple, not a list,
# so `set()` on it is a rebinding the Context owns and not a mutation every Context that
# inherited it can see.
_scope_tokens: ContextVar[tuple[tuple[int, Token[Principal | None]], ...]] = ContextVar(
    "histos_scope_tokens", default=()
)


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


# A generator frame does not get a context of its own in CPython: it runs in whichever
# context resumes it. So a `with use_principal(p):` that spans a `yield` binds `p` into
# the *consumer's* context for as long as the generator is suspended, and two suspended
# generators bound to different principals overwrite each other's binding — one request
# executing as another, from code that reads exactly like the documented usage.
_GENERATOR_FRAME = inspect.CO_GENERATOR | inspect.CO_ASYNC_GENERATOR


def _strict_drivers() -> frozenset[str]:
    """Source files whose frames drive a generator with strict enter/exit discipline.

    `contextlib` is the one the documentation recommends. pytest is here because a
    ``yield`` fixture is how a test suite scopes an identity, it is driven from
    ``_pytest.fixtures`` rather than through ``contextlib``, and refusing it errors out
    every test at setup — the first thing a team writes when they try the library.
    Looked up in ``sys.modules`` rather than imported: this costs nothing when pytest is
    not running, and a security library has no business importing a test framework.

    Anything else driving a setup/teardown generator by hand — a DI container of one's
    own, say — is still refused, and the refusal names the escape hatch.
    """
    files = {contextlib.__file__}
    for name in ("_pytest.fixtures", "_pytest.python"):
        path = getattr(sys.modules.get(name), "__file__", None)
        if path:
            files.add(path)
    return frozenset(files)


def _refuse_a_leaking_frame(caller: Any) -> None:
    """Refuse to open anywhere a binding would span somebody's ``yield``.

    Banning the frame *kind* outright was too broad: the two most ordinary ways to write
    a request scope — `@contextlib.contextmanager` and a generator-style test fixture —
    are generator frames, and under a strict driver the generator is bracketed in the
    consumer's own context, which is the safe case and the one to recommend. So the
    check asks who is driving.

    It has to keep asking. Looking one frame up was the first attempt and it re-opened
    the hole through the very spelling the refusal recommends: wrapping the producer in
    `@contextlib.contextmanager` satisfied a one-step check, while the `with` block
    still spanned the *consumer's* yields whenever that consumer was itself a generator.
    Two interleaved streams still ran as each other, now with nothing raised anywhere.
    So the whole resume chain is walked, and every generator in it has to be strictly
    driven before the first ordinary frame ends the question. `__exit__` carries the
    backstop for whatever this still cannot see — though not for this shape, where enter
    and exit both happen in the consumer's context and the reset succeeds.
    """
    frame, drivers = caller, None
    while frame is not None and frame.f_code.co_flags & _GENERATOR_FRAME:
        if drivers is None:
            drivers = _strict_drivers()
        driver = frame.f_back
        if driver is None or driver.f_code.co_filename not in drivers:
            where = (
                f"was opened inside the generator {frame.f_code.co_name!r}"
                if frame is caller
                else f"is held open across a `yield` of the generator {frame.f_code.co_name!r} consuming it"
            )
            raise PolicyError(
                f"use_principal() {where}. A generator has no context of its own — it runs in whichever "
                "context resumes it — so a binding that spans a `yield` leaks into the consumer and two "
                "interleaved streams run as each other. Wrap the generator in @contextlib.contextmanager, "
                "bind around whatever consumes it, or give the producer its own context with "
                "contextvars.copy_context().run(...)."
            )
        frame = driver.f_back


class use_principal:  # noqa: N801 — it is spelled and used as a function
    """Scope a trusted principal to a ``with`` block (e.g. one request).

    Refuses to open inside a generator or async generator, because there the scope it
    appears to create is not the scope it gets. Bind around the *consumer* of a stream
    instead, or give the producer its own context with
    ``contextvars.copy_context().run(...)`` (``asyncio.create_task`` and ``TaskGroup``
    already do this per task).

    A class rather than ``@contextmanager`` so that ``__enter__``'s caller is exactly
    one frame up: the check has to name the frame that wrote the ``with``, and through
    ``contextlib``'s own generator machinery that index is a guess.
    """

    __slots__ = ("_principal",)

    def __init__(self, principal: Principal) -> None:
        self._principal = principal

    def __enter__(self) -> None:
        _refuse_a_leaking_frame(sys._getframe(1))
        token = _current_principal.set(self._principal)
        _scope_tokens.set((*_scope_tokens.get(), (id(self), token)))
        return None

    def __exit__(self, *_exc: object) -> None:
        # The most recent entry *this Context* holds for *this instance*. A plain list on
        # the instance was the first attempt: it made a reused `scope = use_principal(p)`
        # work, and then broke worse than what it fixed. A `Token` may only be reset in
        # the Context that created it, so two tasks or two threads sharing one instance
        # pushed onto one LIFO list and, on any interleaving that was not perfectly
        # nested, each popped the other's token. contextvars refused it, both scopes
        # raised, and *neither* binding was ever reset — so on a pooled worker the
        # identity stayed live and every later task that landed there, with no principal
        # bound at all, executed gated write tools as the leaked one. Measured: four
        # unauthenticated tasks deleting four records as an admin.
        stack = _scope_tokens.get()
        for index in range(len(stack) - 1, -1, -1):
            if stack[index][0] == id(self):
                token = stack[index][1]
                _scope_tokens.set(stack[:index] + stack[index + 1 :])
                break
        else:
            return  # entered in another Context, which holds its own token and its own reset
        try:
            _current_principal.reset(token)
        except ValueError as exc:
            # contextvars refuses a token created in a different Context, which is
            # exactly the hazard the frame check above cannot always see: the block was
            # entered in one context and left in another, so the binding is still live
            # somewhere it was never scoped to. Loud, because the alternative is a
            # request running as somebody else.
            raise PolicyError(
                "use_principal() was entered in one context and left in another, so the identity it bound "
                "is still set where it was never scoped. This is what happens when the `with` block spans "
                "a `yield` in a generator the consumer drives. Bind around the consumer, or give the "
                "producer its own context with contextvars.copy_context().run(...)."
            ) from exc


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
        return replace(
            policy,
            tools=ReadOnlyDict(dict(policy.tools)),
            permissions=ReadOnlyDict(dict(policy.permissions)),
            role_inherits=ReadOnlyDict(dict(policy.role_inherits)),
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


# Exactly the containers `Engine._post` recurses through (dict keys *and* values, list,
# tuple, set, frozenset); everything else it reads as a leaf or hands back untouched.
# The lazy-output guard follows this set and no other, because the question it answers
# is "would the post chain have reached the payload", not "is this value iterable".
_POST_CONTAINERS = (dict, list, tuple, set, frozenset)

# Deep enough that no honest tool result reaches it — a search result nested 64
# containers deep is not a thing — and far below the interpreter's recursion limit,
# which the engine's own four traversals of the same structure would hit first.
_MAX_OUTPUT_DEPTH = 64

_LAZY_OWNED_BY_THE_RESULT = ("generator", "async generator", "coroutine")


def _defines(value: Any, method: str) -> bool:
    """Whether ``type(value)`` itself defines ``method`` — not its metaclass.

    `hasattr(type(value), "__iter__")` was the obvious spelling and it asks the wrong
    object: attribute lookup on a *class* falls through to the metaclass, and
    `enum.EnumType` defines `__iter__` so that `for c in Colour` works. So every enum
    member answered "iterable" while `iter(Colour.RED)` raises — and a single
    enum-valued field anywhere in an ordinary dict result refused the whole call, which
    is how a status field became a denial. Walking the instance MRO asks whether *this
    value* can be iterated, which is the actual question.
    """
    return any(method in klass.__dict__ for klass in type(value).__mro__)


# Exact type identity, not `isinstance`, so a subclass still takes the slow path. These
# are the leaves a real result is overwhelmingly made of, and none of them can hide a
# payload behind an iteration.
_INERT_LEAVES = frozenset({str, bytes, int, float, bool, type(None)})


def _lazy_leaf_kind(value: Any) -> str | None:
    """What kind of un-post-gateable thing a single value is, if it is one.

    Ordered for the common case. This runs on every leaf of every returned structure,
    in addition to the four traversals the engine already performs, and the predicate
    chain below is not cheap — `inspect.isawaitable` is an ABC check at roughly three
    times the cost of the others. Skipping it for the inert types took the walk over a
    10 000-row result from 48 ms to under 5.
    """
    if type(value) in _INERT_LEAVES:
        return None
    if inspect.isasyncgen(value):
        return "async generator"
    if inspect.isgenerator(value):
        return "generator"
    if inspect.isawaitable(value):
        return "coroutine"
    # asked of the *type*, because an instance attribute named `__next__` is not what
    # the interpreter iterates, and an opaque object that merely stores one is not an
    # iterator — refusing it would be a false positive on a value the post chain
    # already treats as an inert residual.
    if _defines(value, "__next__"):
        return "iterator"
    if isinstance(value, (str, bytes)):
        return None
    # An `enum.Flag` member is iterable in 3.11+ (iterating a composite yields its
    # constituents), so the MRO test above is right about it and refusing it is still
    # wrong: everything an enum member can hold was written at class-definition time,
    # so there is no tool output behind that iteration for anything to hide in.
    if isinstance(value, enum.Enum) and not any(
        "__iter__" in klass.__dict__ and klass.__module__ != "enum" for klass in type(value).__mro__
    ):
        # ...but only the iteration the enum machinery itself provides. A member class
        # that writes its own `__iter__` is an ordinary lazy wrapper that happens to
        # inherit from `Enum`, and the argument above says nothing about it: what it
        # yields can be anything, including tool output the post chain never sees.
        return None
    # an `__iter__`-only object hides its payload exactly as a generator does: this is
    # the ordinary lazy-result-wrapper idiom (`class Rows: def __iter__(self): yield ...`),
    # and so are `dict.values()`, `memoryview` and `deque` — none of them is an iterator,
    # all of them hand the post chain an object it walks straight past. Asked of the type
    # and of `__iter__` only: a `__getitem__`-only legacy sequence is left alone, because
    # every client object with subscript access defines one and refusing those would
    # refuse honest results to catch a shape nobody returns.
    if not _defines(value, "__iter__"):
        return None
    return f"{type(value).__name__} the post chain cannot traverse"


def _uninspectable_kind(result: Any, _depth: int = 0, _seen: set[int] | None = None) -> str | None:
    """What kind of un-post-gateable thing ``result`` holds, if it holds one.

    A coroutine, generator or async generator carries its payload *behind* an iteration
    the gate never performs, so every output control — canary redaction, projection,
    secret scanning — would report ``allow`` on content nothing inspected. Any other
    iterator hides its payload the same way — ``map``, ``filter``, ``iter([...])``, a
    file handle, a ``csv`` reader are all one ``next()`` away from content the gate has
    not read — and so does anything merely iterable that is not a container the post
    chain walks.

    This used to ask only the top-level value, which closed the shape nobody returns and
    left the shape everybody returns wide open: ``{"rows": (r for r in hits)}`` is the
    most ordinary MCP result there is, and the post chain walks into that dict, finds a
    generator object, scans its ``repr``-less self for canaries, finds none and reports
    ``allow`` with ``redactions: []`` while the caller drains the secret out of it. So
    the guard now walks the same containers the post chain walks, to the same leaves,
    and answers for the whole structure.
    """
    if isinstance(result, _POST_CONTAINERS):
        if _depth >= _MAX_OUTPUT_DEPTH:
            # refused rather than allowed: past this bound the guard stops being able to
            # say the payload was inspected, and "we did not look" is a denial.
            return "structure nested deeper than the output gate follows"
        seen = set() if _seen is None else _seen
        # a structure that refers to itself was already inspected on the way down;
        # descending again is the hang, not a second answer.
        if id(result) in seen:
            return None
        seen.add(id(result))
        try:
            children = itertools.chain(result.keys(), result.values()) if isinstance(result, dict) else result
            for child in children:
                kind = _uninspectable_kind(child, _depth + 1, seen)
                if kind is not None:
                    return kind
        except Exception:  # noqa: BLE001 — fail-closed
            # a container subclass whose iteration raises (a lazy `values()`, a mapping
            # mutated by another thread) is a container the guard did not finish reading,
            # and an unfinished read is not a clean bill of health. The engine answers
            # `internal_error` to the same failure one step later; answering it here keeps
            # the post record rather than letting the exception escape the wrapper.
            return "structure the output gate could not walk"
        return None
    kind = _lazy_leaf_kind(result)
    if kind is None or _depth == 0:
        return kind
    return f"structure containing a {kind}"


def _close_quietly(value: Any, _depth: int = 0, _seen: set[int] | None = None) -> None:
    """Close a value the gate is about to refuse, if it can be closed.

    Only ever called on something already denied, so nothing will consume it: a
    coroutine left to the collector is a ``RuntimeWarning`` pointing at the gate rather
    than at the tool that produced it, and an open generator holds its frame — and
    whatever that frame holds open — until it is collected. A ``close()`` that itself
    raises is the refused tool's cleanup failing, which must not replace the denial the
    caller needs to see.

    Inside a refused container it closes *less*: only the shapes whose sole owner is the
    structure being refused. A genexp or a coroutine is built for this one return value
    and nothing else can be holding it, but an iterator found at depth may be the tool's
    own long-lived file handle or database cursor sitting next to the rows — closing that
    breaks the tool's *next* call, which is a worse outcome than a frame collected late.
    """
    if isinstance(value, _POST_CONTAINERS):
        if _depth >= _MAX_OUTPUT_DEPTH:
            return
        seen = set() if _seen is None else _seen
        if id(value) in seen:
            return
        seen.add(id(value))
        # suppressed for the reason the whole function is best-effort: a container that
        # raises when walked is one of the things being refused, and its failure must not
        # replace the denial the caller needs to see.
        with contextlib.suppress(Exception):
            children = itertools.chain(value.keys(), value.values()) if isinstance(value, dict) else value
            for child in children:
                _close_quietly(child, _depth + 1, seen)
        return
    # Ownership, not depth. `_depth` is `0` at the top level and therefore falsy, so the
    # guard was skipped exactly where the value is most likely to be something the caller
    # still owns: a refused ORM page or an open cursor had `close()` called on it, tearing
    # down live state over a value the gate had merely declined to *inspect*. A generator,
    # coroutine or async generator is built for this one return and is the only shape safe
    # to close — which is all the docstring and SECURITY.md ever promised.
    if _lazy_leaf_kind(value) not in _LAZY_OWNED_BY_THE_RESULT:
        return
    closer = getattr(value, "close", None)
    if callable(closer):
        with contextlib.suppress(Exception):
            closer()


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
            trusted = _snapshot_value(active.attributes[b.principal_attr])
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
        target = _unwrap_target(tool)
        if previous is not None and previous is not target:
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
        self._wrapped_targets[key] = target
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
        post, text = self.engine.post_exception(post_req, exc)
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
        try:
            self.audit.record(record.to_dict())
        except Exception as exc:  # noqa: BLE001 — a sink must never decide a call's fate
            warnings.warn(
                f"histos: the audit sink {type(self.audit).__name__} raised while recording this call: "
                f"{type(exc).__name__}: {exc}. The call itself was unaffected, and this record is lost.",
                RuntimeWarning,
                stacklevel=2,
            )


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
        strict=strict,
    )
    return g.protect(tools, fixed_principal=fixed_principal, infer_missing=infer_missing)
