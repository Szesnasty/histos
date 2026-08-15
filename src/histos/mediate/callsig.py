"""Naming a call's arguments, and asking an object whether it is already gated.

Split out of `gate.py`. Every check downstream is keyed on argument *names*, so a
positional call has to be named before anything can decide about it — and a callable
that exposes no signature cannot be, which is a denial rather than a pass. The gate
stamps it leaves on a wrapper are here too: they are what `coverage()` reads and what
stops a tool being wrapped twice, and both questions are about the callable rather than
about the policy.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from histos.errors import PolicyError
from histos.policy.schema import Schema

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
