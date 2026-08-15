"""Whether a value can be looked at before it leaves, and whether a call is async.

Split out of `gate.py`. The post-gate can only redact what it can read, so a return that
defers its content — a generator, a coroutine, a lazily-decoding buffer — is the one
shape that reaches a caller without ever having been scanned. Recognising those is the
whole subject of this module, together with the detection that decides which wrapper a
tool gets in the first place.
"""

from __future__ import annotations

import contextlib
import enum
import inspect
import itertools
import sys
from collections.abc import Callable
from typing import Any

from histos.errors import PolicyError
from histos.mediate.toolref import _unwrap_target

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
