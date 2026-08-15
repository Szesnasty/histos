"""What a tool *is*, to a Gate: its identity, and the metadata a wrapper must carry.

Split out of `gate.py`. Two questions live here and they are easy to confuse, which is
how both of them were once answered wrong at the same time:

* **"is this the same tool?"** — asked when a name is claimed twice. Answered by
  :func:`_wrap_identity`, which is deliberately *not* object identity: a bound method is
  rebuilt on every attribute access, and two `functools.partial`s of one function are
  two different tools.
* **"is this thing already gated?"** — asked so a tool is never wrapped twice. Answered
  by the stamps a wrapper carries, which is also what `coverage()` reads.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import weakref
from collections.abc import Callable
from typing import Any

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


def _same_tool(a: Any, b: Any) -> bool:
    """Whether two wrap identities describe the same tool, without asking the host.

    The check was `previous != target`, which delegates the question to the tool object's
    own `__eq__` — and a great many tool objects have one. A Pydantic model, a dataclass,
    an ORM row, anything comparing by value: two genuinely different tools that happen to
    hold equal fields answer "same", and the collision that stops one contract enforcing
    two callables is waved through. The one case `==` was adopted for is a bound method,
    and that case is written out here instead.
    """
    if a is b:
        return True
    if inspect.ismethod(a) and inspect.ismethod(b):
        return a.__self__ is b.__self__ and a.__func__ is b.__func__
    if isinstance(a, tuple) and isinstance(b, tuple) and len(a) == len(b):
        # A partial's key: its target compared as a tool, its bound arguments by value.
        # The value comparison is guarded, because a bound argument may be a numpy array,
        # a DataFrame or a tensor, whose `__eq__` returns an array rather than a bool —
        # `bool()` on which raises, out of `Gate.wrap`, where a *decision* was owed. An
        # argument the gate cannot compare is not evidence that two tools are the same.
        if not _same_tool(a[0], b[0]):
            return False
        try:
            return bool(a[1:] == b[1:])
        except Exception:  # noqa: BLE001 — an uncomparable argument means "not the same"
            return False
    return False


def _wrap_identity(fn: Any) -> Any:
    """The value that answers "is this the same *tool*", which is not "the same object".

    `_unwrap_target` is the wrong identity for that question in both directions.

    A bound method is constructed fresh on every attribute access, so
    `repo.query is repo.query` is False — and re-protecting a tool set built by the same
    wiring function, which is the documented way to swap a ruleset (`gate.policy =
    tightened`, then re-wrap), was refused at load time with a message telling the caller
    to "pass name= to say which is which" when they had passed the only name there is.
    A false refusal at load time is an outage. Bound methods compare equal on
    `__self__`/`__func__`, so `==` answers it.

    In the other direction `_unwrap_target` follows `functools.partial.func`, so
    `partial(send, "sms")` and `partial(send, "email")` reduced to the same target and
    two genuinely different tools passed the check. The bound arguments are part of the
    tool, so they are part of the key.
    """
    if isinstance(fn, functools.partial):
        return (_unwrap_target(fn), fn.args, tuple(sorted(fn.keywords.items())))
    return _unwrap_target(fn)


class _IdentityRef:
    """A weak hold on a wrap identity, so a Gate does not keep every tool it ever saw.

    `_wrappers` is weak and says why in its own comment; `_wrapped_targets` was added
    beside it holding the same objects *strongly* and never pruned, which quietly undid
    that. A long-lived Gate wrapping per-request or per-tenant closures — a factory-built
    tool set, an MCP session's tools — then retained every closure and everything it
    captured for the life of the process.

    A dead reference reads as "no previous target", and that is the right answer rather
    than a hole. The wrapper this Gate handed back closes over the tool, so as long as
    the caller holds the wrapper — which they must, since it is the only way to call the
    tool — the target is alive and the collision is still refused. A target that has
    been collected is one whose wrapper was thrown away: unreachable, uncallable, and
    nothing another tool can collide with. Both module-level functions and discarded
    lambdas-with-a-kept-wrapper are still refused; only the fully discarded one relaxes.
    """

    __slots__ = ("_key", "_ref")

    def __init__(self, identity: Any) -> None:
        self._key: Any = None
        self._ref: Any = None
        if isinstance(identity, tuple):
            # A partial's key: hold the callable weakly, the bound arguments by value.
            target, *rest = identity
            self._ref = self._weaken(target)
            self._key = tuple(rest)
        else:
            self._ref = self._weaken(identity)

    @staticmethod
    def _weaken(target: Any) -> Any:
        # `WeakMethod` for a bound method, because a plain `weakref.ref` to one is dead
        # on arrival: `repo.query` builds a new bound-method object per access and it is
        # collected the moment this returns. `WeakMethod` holds `__self__` weakly and
        # `__func__` strongly and rebuilds the binding, which is the thing whose lifetime
        # actually matters.
        if inspect.ismethod(target):
            try:
                return weakref.WeakMethod(target)
            except TypeError:  # pragma: no cover - a method on a non-weakrefable object
                pass
        try:
            return weakref.ref(target)
        except TypeError:
            # Not weak-referenceable — a builtin, a C callable. Those are module-level
            # and immortal in practice, so a strong reference retains nothing that was
            # going to be collected anyway.
            return lambda _target=target: _target

    def __call__(self) -> Any:
        target = self._ref()
        if target is None:
            return None
        return (target, *self._key) if self._key is not None else target


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
