"""The trusted, request-scoped identity, and the scope that binds it.

Split out of `gate.py`, which had grown past two thousand lines — a size at which
"what else touches this?" stops being answerable by reading, and that question is
exactly the one every recent defect turned on.

The two `ContextVar`s below are **process-wide singletons and must stay that way**.
`use_principal` writes them and the engine reads them, so a second copy — the ordinary
consequence of a careless module split — would mean every call runs unauthenticated
while every test of either module still passes. `tests/test_characterisation.py` pins
that they are one object each; do not re-declare them anywhere.
"""

from __future__ import annotations

import contextlib
import inspect
import sys
from contextvars import ContextVar, Token
from typing import Any

from histos.errors import PolicyError
from histos.policy.contracts import Principal

# The trusted, request-scoped identity. Set by the host, never by the agent.
_current_principal: ContextVar[Principal | None] = ContextVar("histos_principal", default=None)

# The open `use_principal` scopes, as `(id(instance), token)` pairs, innermost last.
# In the Context rather than on the instance, because that is where a `Token` is valid:
# one may only be reset where it was created, so a stack held on a shared instance let
# two tasks pop each other's tokens and leave both bindings live. A tuple, not a list,
# so `set()` on it is a rebinding the Context owns and not a mutation every Context that
# inherited it can see.
# Keyed by the *instance*, not by `id(self)`. An entry holding only an address holds no
# reference to the object, so a scope entered and never exited leaves an entry whose
# object is freed — and CPython hands the very next `use_principal(...)` that same
# address, because `__slots__` makes them all one size. `__exit__` then matched on the
# recycled address and reset a token belonging to a scope that had nothing to do with
# it. Holding the instance costs one reference per open scope and makes the key
# un-reusable by construction.
_scope_tokens: ContextVar[tuple[tuple[Any, Token[Principal | None]], ...]] = ContextVar(
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

    The async twin is here for the same reason and was missed the first time. An
    ``async def`` yield fixture is not driven by ``_pytest.fixtures``: pytest-asyncio
    drives it from its plugin, and anyio from its event-loop backend. So the identical
    fixture, written ``async``, errored out every test at setup — and the workaround the
    refusal recommends was refused with it, leaving an async suite nothing to write. The
    shape was measured: same Context, both halves in it, nothing left bound afterwards.

    The async runners are matched by ``(file, function)`` rather than by file alone.
    ``anyio/_backends/_asyncio.py`` holds the fixture runner *and* the task-group
    implementation, and a user's own task group driving a generator by hand is exactly
    the interleaving this check exists to refuse — so the file is not a blanket excuse,
    only the frame that brackets a fixture is.

    Anything else driving a setup/teardown generator by hand — a DI container of one's
    own, say — is still refused, and the refusal names the escape hatch.
    """
    files = {contextlib.__file__}
    for name in ("_pytest.fixtures", "_pytest.python", "pytest_asyncio.plugin", "anyio.pytest_plugin"):
        path = getattr(sys.modules.get(name), "__file__", None)
        if path:
            files.add(path)
    return frozenset(files)


# Frames that bracket an async fixture, named exactly, for modules whose file also holds
# machinery that must stay refused. See `_strict_drivers`.
_STRICT_DRIVER_FRAMES: tuple[tuple[str, str], ...] = (
    ("anyio._backends._asyncio", "_run_tests_and_fixtures"),
    ("anyio._backends._trio", "_run_tests_and_fixtures"),
)


def _is_strict_driver(frame: Any, drivers: frozenset[str]) -> bool:
    """Whether this frame is one of the drivers that bracket a generator strictly."""
    if frame.f_code.co_filename in drivers:
        return True
    for module, function in _STRICT_DRIVER_FRAMES:
        if frame.f_code.co_name != function:
            continue
        path = getattr(sys.modules.get(module), "__file__", None)
        if path and frame.f_code.co_filename == path:
            return True
    return False


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
        if driver is None or not _is_strict_driver(driver, drivers):
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
        # Every consecutive driver frame, not one. `ExitStack.enter_context` sits
        # between `_GeneratorContextManager.__enter__` and the code that wrote the
        # `with`, and it lives in contextlib too — so a single `f_back` landed on it,
        # found an ordinary frame, and ended the walk one hop short of the consumer.
        # `with ExitStack() as s: s.enter_context(request_scope(p)); yield` was therefore
        # accepted, and measured doing exactly what the plain spelling is refused for:
        # alice's second row executing as bob, with nothing raised anywhere. The
        # `AsyncExitStack` twin behaved identically.
        while driver is not None and _is_strict_driver(driver, drivers):
            driver = driver.f_back
        frame = driver


class use_principal:  # noqa: N801 — it is spelled and used as a function
    """Scope a trusted principal to a ``with`` block (e.g. one request).

    Refuses to open inside a generator or async generator, because there the scope it
    appears to create is not the scope it gets. Bind around the *consumer* of a stream
    instead, or give the producer its own context with
    ``contextvars.copy_context().run(...)`` (``asyncio.create_task`` and ``TaskGroup``
    already do this per task).

    The refusal is **best-effort**, and SECURITY.md says where it stops. It works by
    reading the call stack, so it sees the literal spelling, `@contextmanager`
    producers, `ExitStack`, and a subclass that does not override ``__enter__`` — but a
    hand-written object that takes this context manager in an ``__enter__`` of its own
    and releases it later interposes an ordinary frame, and at enter time the stack
    cannot tell that frame from one that wrote the ``with`` itself. Do not wrap this in
    a scope object of your own inside a producer.

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
        _scope_tokens.set((*_scope_tokens.get(), (self, token)))
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
            if stack[index][0] is self:
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
