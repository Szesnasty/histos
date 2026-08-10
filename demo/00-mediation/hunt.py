"""Is the gate actually the only way in?

Every claim the other demos make rests on one assumption: that a tool handed to a
framework can only be reached through the gate. `SECURITY.md` says complete
mediation is a property of the adapter, not of the library — so this is the file
that checks whether the adapter earns that.

Nothing here involves a model. It reaches for the tool the way *code* can: the
core wrappers (`gate`, `Gate.wrap`, `protect`), every public entry point LangChain
exposes, the private ones underneath them, the async paths, the attributes a caller
can read off the object, LangGraph's own executor — and then a search that stops
enumerating and simply walks the object graph looking for the ungated callable.

    python hunt.py

Two observables decide every row, and only two: did the tool body run (`CALLS`),
and did the wrapper record a decision (`AUDIT`, or the control's own counter). The
exception type is never the verdict. An earlier version of this file scored a
framework `TypeError` as GATED, which credits the gate for a call that never
reached it — so a signature change in LangChain would have turned a real bypass
into a green row.

    GATED    the wrapper recorded a decision and the body did not run
    REACHED  the body ran without a decision behind it
    N/A      the path does not exist on this object
    ERROR    the call failed before the wrapper was consulted; it proves nothing

REACHED is a bypass in sections A and B and nowhere else. Sections C, D and E
exist because the honest answer to the title question is not "yes": C and D are
paths that reach the body and *cannot* be closed by an in-process library, and
printing them next to the mediated rows is the only way a reader can tell the two
apart. E is the control — the same probes against the wrapper a competent team
writes by hand — which is what turns section A's `N/A` rows from an absence into
a measured difference.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import copy
import functools
import gc
import inspect
import operator
import pickle
import sys
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AIMessage, AnyMessage
from langchain_core.tools import StructuredTool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from histos import (
    Gate,
    InMemoryAuditSink,
    Policy,
    Principal,
    Schema,
    ToolContract,
    gate,
    protect,
    use_principal,
)
from histos.integrations.langchain import protect_tools

# A tool that records every time its body runs. If the counter moves without a
# decision behind it, something got past.
CALLS: list[dict[str, Any]] = []

# Every Gate in this file shares one sink, so "did the gate decide?" is a single
# integer comparison no matter which wrapper the row is probing.
AUDIT = InMemoryAuditSink()

# The control in section E keeps its own counter, because it is not a Gate and must
# not be scored as one.
NAIVE_REFUSALS = [0]


def wire_transfer(amount: int, to_account: str) -> dict[str, Any]:
    """Move money. The only tool in this harness, so any execution is unambiguous."""
    CALLS.append({"amount": amount, "to_account": to_account})
    return {"moved": amount, "to": to_account}


POLICY = Policy(
    tools={
        "wire_transfer": ToolContract(
            name="wire_transfer",
            args=Schema({}),  # no argument is declared, so *every* call must be refused
            access="write",
        )
    },
    permissions={"clerk": frozenset({"wire_transfer"})},
)

CLERK = Principal(role="clerk", identity="svc:hunt")
ARGS = {"amount": 1_000_000, "to_account": "attacker"}

GATED, REACHED, ABSENT, ERROR = "GATED", "REACHED", "N/A", "ERROR"


class GraphState(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]


class PathAbsent(Exception):
    """A probe raises this when the path it tests does not exist on this object.

    Explicit, because "the attribute is missing" and "the call blew up" are different
    findings and only one of them is a reason to stop looking.
    """


@dataclass
class Result:
    path: str
    outcome: str
    detail: str = ""


def _audit_decisions() -> int:
    return len(AUDIT.entries)


def _naive_decisions() -> int:
    return NAIVE_REFUSALS[0]


def _attempt(
    path: str,
    call: Callable[[], Any],
    *,
    decisions: Callable[[], int] = _audit_decisions,
) -> Result:
    """Run one entry point and decide what it proves.

    The policy declares `wire_transfer` with an empty argument schema, so a call that
    reaches the gate can only ever be refused. If the body runs anyway, the gate was
    not on the path. And if neither happens, the row proves nothing and must not be
    scored as a win — which is what `ERROR` is for.

    `decisions` is a parameter so the section E control can be scored on its own
    refusal counter rather than borrowing the Gate's audit trail.
    """
    calls, decided_before = len(CALLS), decisions()
    failure: BaseException | None = None
    try:
        call()
    except PathAbsent as exc:
        return Result(path, ABSENT, str(exc)[:70])
    except Exception as exc:
        failure = exc

    ran, decided = len(CALLS) > calls, decisions() > decided_before
    raised = f"{type(failure).__name__}: {str(failure)[:58]}" if failure else "returned without raising"

    if ran:
        # A decision plus an execution would mean the wrapper allowed the call, which
        # this policy cannot do — so it is as much a finding as no decision at all.
        return Result(path, REACHED, "a decision was recorded and the body ran anyway" if decided else raised)
    if decided:
        return Result(path, GATED, raised)
    if isinstance(failure, AttributeError | PathAbsent):
        return Result(path, ABSENT, raised)
    return Result(path, ERROR, raised)


# ── reaching for the raw callable through the object graph ───────────────


_HANDLE_ATTRS = ("func", "coroutine", "_run", "_arun", "__wrapped__", "__func__", "__self__")


@dataclass(frozen=True)
class Step:
    """One dereference: how it reads, and how to actually perform it.

    Carrying the accessor rather than re-parsing a dotted string is not tidiness. The
    previous version built a path like `.__closure__[0].cell_contents` and then split
    it on `.`, so every search row died with `AttributeError: 'function' object has no
    attribute 'cell_contents'` — and `_attempt` filed that as `N/A`, "the path does not
    exist". The path existed. Four rows of this hunt reported a clean result because
    the probe crashed on its own path string.
    """

    label: str
    get: Callable[[Any], Any]


def _children(obj: Any) -> Iterator[tuple[Step, Any]]:
    """The ways one object hands you another, without leaving the object.

    Deliberately excludes `__globals__` and the `gc` module: those reach the whole
    process and would find the raw function from *any* starting point, which says
    nothing about mediation. They are probed separately, in section D.
    """
    for attr in _HANDLE_ATTRS:
        try:
            child = getattr(obj, attr, None)
        except Exception:  # a pydantic model can raise on attribute access
            continue
        if child is not None:
            yield Step(f".{attr}", operator.attrgetter(attr)), child

    for index, cell in enumerate(getattr(obj, "__closure__", None) or ()):
        try:
            contents = cell.cell_contents
        except ValueError:  # an empty cell, from a recursive definition
            continue
        yield Step(f".__closure__[{index}].cell_contents", _cell_getter(index)), contents

    if isinstance(obj, functools.partial):
        yield Step(".func", operator.attrgetter("func")), obj.func
        for index, arg in enumerate(obj.args):
            yield Step(f".args[{index}]", _item_getter(index)), arg
        for key, value in obj.keywords.items():
            yield Step(f".keywords[{key!r}]", _keyword_getter(key)), value


def _cell_getter(index: int) -> Callable[[Any], Any]:
    return lambda obj: obj.__closure__[index].cell_contents


def _item_getter(index: int) -> Callable[[Any], Any]:
    return lambda obj: obj.args[index]


def _keyword_getter(key: str) -> Callable[[Any], Any]:
    return lambda obj: obj.keywords[key]


def _find_raw(root: Any, *, max_nodes: int = 4096) -> list[Step] | None:
    """Breadth-first search from a wrapped object for `wire_transfer` itself.

    This is the point of the file. Enumerating entry points by hand is how an earlier
    version missed one: it followed `tool.func.__closure__[0].cell_contents` and
    stopped, one dereference short of that cell's own `__wrapped__`. A search measures
    reachability instead of a hop count, so a survivor at depth four is found by the
    same code that found the one at depth two.
    """
    queue: list[tuple[list[Step], Any]] = [([], root)]
    seen: set[int] = {id(root)}
    while queue and len(seen) < max_nodes:
        path, obj = queue.pop(0)
        for step, child in _children(obj):
            if child is wire_transfer:
                return [*path, step]
            if id(child) in seen:
                continue
            seen.add(id(child))
            queue.append(([*path, step], child))
    return None


FOUND_PATHS: dict[str, str] = {}


def _call_found(root: Any, root_name: str) -> Any:
    """Search from `root`, and if the raw callable is reachable, re-walk and *call* it.

    Reporting a path is an assertion about the object graph; walking it a second time
    from the accessors and checking the identity of what comes out is what makes the
    printed path evidence rather than a claim.
    """
    steps = _find_raw(root)
    if steps is None:
        raise PathAbsent(f"no path from {root_name} to the ungated callable")

    found = root
    for step in steps:
        found = step.get(found)
    rendered = root_name + "".join(step.label for step in steps)
    if found is not wire_transfer:
        raise PathAbsent(f"{rendered} did not re-walk to the raw callable")

    FOUND_PATHS[root_name] = rendered
    return found(**ARGS)


# ── the probes that need more than an expression ─────────────────────────


def _unwrap(fn: Any) -> Any:
    """`inspect.unwrap` — what every decorator-unwrapping helper in the ecosystem does."""
    target = inspect.unwrap(fn)
    if target is fn:
        raise PathAbsent("inspect.unwrap found nothing to unwrap")
    return target


def _wrapped_of(fn: Any) -> Any:
    found = getattr(fn, "__wrapped__", None)
    if found is None:
        raise PathAbsent("no __wrapped__ on this object")
    return found


def _first_closure_cell(fn: Any) -> Any:
    for cell in getattr(fn, "__closure__", None) or ():
        candidate = cell.cell_contents
        if callable(candidate) and getattr(candidate, "__name__", "") == "wire_transfer":
            return candidate
    raise PathAbsent("no wrapped callable found in the closure")


def _from_globals(fn: Any) -> Any:
    """The module dictionary the wrapper itself closes over."""
    found = getattr(fn, "__globals__", {}).get("wire_transfer")
    if found is None:
        raise PathAbsent("the wrapper's module does not define wire_transfer")
    return found


def _unpickled(fn: Any) -> Any:
    """A round trip through pickle, which resolves a function by `__module__.__qualname__`.

    The wrapper adopts both, so this asks whether a wrapper that *claims* to be
    `wire_transfer` can be exchanged for the real one by a task queue, a process pool,
    or anything else that sends a tool across a boundary.
    """
    try:
        return pickle.loads(pickle.dumps(fn))
    except Exception as exc:
        raise PathAbsent(f"pickle refuses: {str(exc)[:56]}") from exc


def _in_thread(fn: Callable[[], Any], *, carry_context: bool) -> Any:
    """Run `fn` on another thread and re-raise what it raised.

    A `ContextVar` does not cross a thread boundary unless the caller carries it, so
    this asks the question a background worker asks: with no identity bound, does the
    gate fail closed, or does it fail open?
    """
    context = contextvars.copy_context() if carry_context else None
    outcome: list[tuple[str, Any]] = []

    def run() -> None:
        try:
            outcome.append(("ok", context.run(fn) if context else fn()))
        except BaseException as exc:  # noqa: BLE001 — re-raised on the calling thread
            outcome.append(("raised", exc))

    worker = threading.Thread(target=run)
    worker.start()
    worker.join()
    kind, value = outcome[0]
    if kind == "raised":
        raise value
    return value


def _rehosted(tool: Any) -> Any:
    """The same gated callable, inside a different tool class.

    A subclass is the obvious way to try to shed a wrapper, and it does not work here
    for a structural reason worth stating: the adapter gates the *callable*, so
    re-hosting it changes the object that holds it and not what running it does.
    """

    class Rehosted(StructuredTool):
        pass

    return Rehosted(
        name=tool.name,
        description=tool.description,
        func=tool.func,
        args_schema=tool.args_schema,
    )


def _through_tool_node(tool: Any, args: dict[str, Any]) -> Any:
    """LangGraph's own executor, driven from a compiled graph — the way it really runs."""
    builder = StateGraph(GraphState)
    builder.add_node("tools", ToolNode([tool]))
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    graph = builder.compile()

    call = AIMessage(
        content="",
        tool_calls=[{"name": "wire_transfer", "args": args, "id": "hunt-1", "type": "tool_call"}],
    )
    return graph.invoke({"messages": [call]})


def _monkeypatched(tool: Any) -> Any:
    """Overwrite the gated callable on a copy of the tool, then use the tool normally."""
    clone = copy.deepcopy(tool)
    clone.func = wire_transfer
    return clone.invoke(ARGS)


def _by_scanning_the_heap() -> Any:
    """`gc.get_objects()` enumerates every live object, including the ungated one."""
    for obj in gc.get_objects():
        if obj is wire_transfer:
            return obj(**ARGS)
    raise PathAbsent("not found on the heap")  # pragma: no cover - it is always there


def _no_coroutine() -> None:
    raise PathAbsent("a sync tool has no coroutine")


def naive_guard(fn: Callable[..., Any]) -> Callable[..., Any]:
    """The control: the same wrapper, written the way the tutorials write it.

    `functools.wraps` is the idiomatic, correct-looking choice, and it is what makes
    section E's rows differ from section A's. It refuses every call, exactly as this
    policy does, so the only thing the two wrappers can differ on is what they leak.
    """

    @functools.wraps(fn)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        NAIVE_REFUSALS[0] += 1
        raise RuntimeError("naive guard: denied")

    return wrapped


# ── the suites ───────────────────────────────────────────────────────────


def core_products() -> dict[str, Any]:
    """The three things the library itself hands back, with no framework involved.

    These were absent from this hunt for its whole life, which is how a live
    `__wrapped__` pointer on `Gate.wrap`'s product survived a demo written to find
    exactly that. The adapter is not the only thing people call.
    """
    return {
        "gate(fn, policy=…)": gate(wire_transfer, policy=POLICY, audit=AUDIT),
        "Gate(policy).wrap(fn)": Gate(POLICY, audit=AUDIT).wrap(wire_transfer),
        "protect([fn]).tools[…]": protect([wire_transfer], policy=POLICY, audit=AUDIT).tools["wire_transfer"],
    }


def core_wrappers(products: dict[str, Any]) -> list[Result]:
    """Call each product, then ask it for its target the two ways the ecosystem asks."""
    results: list[Result] = []
    for name, guarded in products.items():
        results.append(_attempt(f"{name}(**args)", lambda g=guarded: g(**ARGS)))
        results.append(_attempt(f"{name}.__wrapped__(**args)", lambda g=guarded: _wrapped_of(g)(**ARGS)))
        results.append(_attempt(f"inspect.unwrap({name})(**args)", lambda g=guarded: _unwrap(g)(**ARGS)))
    return results


def adapter_surface(tool: Any) -> list[Result]:
    """The LangChain `StructuredTool` that `protect_tools` hands the framework."""
    return [
        # ── the documented ways ──────────────────────────────────────────
        _attempt("tool.invoke(args)", lambda: tool.invoke(ARGS)),
        _attempt("tool.run(args)", lambda: tool.run(ARGS)),
        _attempt("await tool.ainvoke(args)", lambda: asyncio.run(tool.ainvoke(ARGS))),
        _attempt("await tool.arun(args)", lambda: asyncio.run(tool.arun(ARGS))),
        # ── the private ones underneath. `config` is required by this LangChain, and
        #    omitting it used to raise a TypeError the old scorer credited as GATED ──
        _attempt("tool._run(**args, config={})", lambda: tool._run(**ARGS, config={})),
        _attempt("await tool._arun(**args, config={})", lambda: asyncio.run(tool._arun(**ARGS, config={}))),
        _attempt("tool._run.__func__(tool, …)", lambda: tool._run.__func__(tool, **ARGS, config={})),
        # ── attributes a caller can simply read ──────────────────────────
        _attempt("tool.func(**args)", lambda: tool.func(**ARGS)),
        _attempt(
            "tool.coroutine(**args)",
            lambda: asyncio.run(tool.coroutine(**ARGS)) if tool.coroutine else _no_coroutine(),
        ),
        _attempt("tool.func.__wrapped__(**args)", lambda: _wrapped_of(tool.func)(**ARGS)),
        _attempt("inspect.unwrap(tool.func)(**args)", lambda: _unwrap(tool.func)(**ARGS)),
        _attempt("tool.func.__globals__['wire_transfer']", lambda: _from_globals(tool.func)(**ARGS)),
        # ── the naive one-hop closure probe, kept because it is what people write ──
        _attempt("closure of tool.func", lambda: _first_closure_cell(tool.func)(**ARGS)),
        _attempt(
            "inspect.unwrap(closure of tool.func)",
            lambda: _unwrap(_first_closure_cell(tool.func))(**ARGS),
        ),
        # ── ways of moving the callable somewhere else ───────────────────
        _attempt("functools.partial(tool.func)(**args)", lambda: functools.partial(tool.func)(**ARGS)),
        _attempt("copy.deepcopy(tool).invoke(args)", lambda: copy.deepcopy(tool).invoke(ARGS)),
        _attempt("pickle round trip of tool.func", lambda: _unpickled(tool.func)(**ARGS)),
        _attempt("subclass re-hosting tool.func", lambda: _rehosted(tool).invoke(ARGS)),
        # ── another thread, and another thread with the context carried ──
        _attempt("threading.Thread → tool.invoke", lambda: _in_thread(lambda: tool.invoke(ARGS), carry_context=False)),
        _attempt(
            "threading.Thread with copy_context()",
            lambda: _in_thread(lambda: tool.invoke(ARGS), carry_context=True),
        ),
        _attempt("asyncio.to_thread(tool.invoke)", lambda: asyncio.run(asyncio.to_thread(tool.invoke, ARGS))),
        # ── LangGraph's own executor ─────────────────────────────────────
        _attempt("langgraph ToolNode", lambda: _through_tool_node(tool, ARGS)),
    ]


def searches(roots: dict[str, Any]) -> list[Result]:
    """Walk the object graph from each wrapped object and call whatever it finds.

    Every row here reaches the tool body, and the reason is the same one every time:
    a Python wrapper closes over the callable it wraps, and CPython publishes closure
    cells. There is no version of `guard_callable` that does not hold a reference to
    its target, and no attribute on a Python object that code in the same process
    cannot read. This is the floor, and it is worth measuring rather than omitting.
    """
    results: list[Result] = []
    for name, root in roots.items():
        found = _attempt(f"search from {name}", lambda r=root, n=name: _call_found(r, n))
        results.append(Result(found.path, found.outcome, FOUND_PATHS.get(name, found.detail)))
    return results


def boundary(tool: Any, raw: Any) -> list[Result]:
    """Paths that start somewhere other than the wrapped object.

    None of these is a mediation failure: they are the documented edge of what an
    in-process library can promise. histos gates the objects it was handed; it does
    not sandbox the interpreter.
    """
    return [
        _attempt("the original, unwrapped tool", lambda: raw.invoke(ARGS)),
        _attempt("the plain function", lambda: wire_transfer(**ARGS)),
        _attempt(
            "sys.modules[__main__].wire_transfer",
            lambda: sys.modules[wire_transfer.__module__].wire_transfer(**ARGS),
        ),
        _attempt("monkeypatch tool.func, then invoke", lambda: _monkeypatched(tool)),
        _attempt("gc.get_objects() heap scan", _by_scanning_the_heap),
    ]


def control() -> list[Result]:
    """The same probes against a textbook `functools.wraps` wrapper.

    Without this section, section A's `N/A` rows are an absence and prove nothing: a
    reader cannot tell "the pointer was removed" from "nothing would have been there
    anyway". Run side by side, the difference is two rows, and two rows is the honest
    size of what removing `__wrapped__` buys.
    """
    naive = naive_guard(wire_transfer)
    scored = functools.partial(_attempt, decisions=_naive_decisions)
    results = [
        scored("functools.wraps guard(**args)", lambda: naive(**ARGS)),
        scored("functools.wraps guard.__wrapped__(**args)", lambda: _wrapped_of(naive)(**ARGS)),
        scored("inspect.unwrap(functools.wraps guard)(**args)", lambda: _unwrap(naive)(**ARGS)),
    ]
    found = scored("search from functools.wraps guard", lambda: _call_found(naive, "naive"))
    results.append(Result(found.path, found.outcome, FOUND_PATHS.get("naive", found.detail)))
    return results


def footgun() -> list[str]:
    """The mistake `README.md` warns about, and what actually catches it.

    `protect_tools()` returns new objects; a caller who drops the return value keeps
    handing the framework the ungated originals. This runs that mistake and reports
    what each available check says about it, because the README used to name a check
    that cannot see it.
    """
    tools = [StructuredTool.from_function(wire_transfer, name="wire_transfer", description="Move money.")]
    guard = Gate(POLICY, audit=AUDIT)
    protect_tools(tools, gate=guard, on_denied="raise")  # ← the return value is dropped

    coverage = guard.coverage([t.name for t in tools])
    before = len(CALLS)
    # The point of this call is whether the body ran, not how it ended.
    with use_principal(CLERK), contextlib.suppress(Exception):
        tools[0].invoke(ARGS)
    return [
        f"gate.coverage([...])           {coverage}",
        f"gate.declared_but_unwrapped()  {guard.declared_but_unwrapped() or 'set()'}",
        f"ungated_tools([...])           {ungated_tools(tools)}",
        f"the body ran anyway            {len(CALLS) > before}",
    ]


def ungated_tools(tools: list[Any]) -> list[str]:
    """Names of tools whose execution is not the gate's, asked of the objects themselves.

    `guard_callable` stamps `__gate_name__` on the callable it returns, so this reads
    the tools a framework is actually about to be handed. A Gate cannot answer this:
    it records a name when `wrap()` is called and never sees what the caller did with
    the result.
    """
    return [t.name for t in tools if getattr(getattr(t, "func", None), "__gate_name__", None) != t.name]


# ── output ───────────────────────────────────────────────────────────────


MARKS = {GATED: "✓", REACHED: "✗", ABSENT: "·", ERROR: "!"}


def _table(title: str, note: str, results: list[Result], width: int) -> None:
    print(f"\n{title}")
    print(f"  {note}\n")
    for r in results:
        print(f"  {r.path:<{width}}  {MARKS[r.outcome]} {r.outcome:<8} {r.detail}")


def _tally(results: list[Result]) -> str:
    counts = {name: sum(1 for r in results if r.outcome == name) for name in (GATED, ABSENT, ERROR, REACHED)}
    return ", ".join(f"{count} {name.lower()}" for name, count in counts.items())


def _ran_during(section: Callable[[], list[Result]]) -> tuple[list[Result], int]:
    """Run a section and report how many times the tool body executed inside it."""
    before = len(CALLS)
    results = section()
    return results, len(CALLS) - before


def main() -> int:
    raw = StructuredTool.from_function(wire_transfer, name="wire_transfer", description="Move money.")
    (tool,) = protect_tools([raw], gate=Gate(POLICY, audit=AUDIT), on_denied="raise")
    products = core_products()

    with use_principal(CLERK):
        core, core_ran = _ran_during(lambda: core_wrappers(products))
        adapter, adapter_ran = _ran_during(lambda: adapter_surface(tool))
        found, found_ran = _ran_during(lambda: searches({**products, "tool": tool}))
        edge, edge_ran = _ran_during(lambda: boundary(tool, raw))
        naive, naive_ran = _ran_during(control)

    mediated = core + adapter
    width = max(len(r.path) for r in mediated + found + edge + naive)

    _table(
        "A. the library's own wrappers",
        "no framework involved — these are what `gate`/`protect` return",
        core,
        width,
    )
    _table("B. the LangChain tool the adapter hands the framework", "plus LangGraph's executor", adapter, width)
    _table(
        "C. searching the wrapped object for the callable inside it",
        "starts at the gated object and reaches the body — the floor, not a regression",
        found,
        width,
    )
    _table(
        "D. paths that start somewhere else in the process",
        "not mediation failures — the documented edge of an in-process library",
        edge,
        width,
    )
    _table(
        "E. control: the same wrapper written with functools.wraps",
        "what section A's `N/A` rows are measured against",
        naive,
        width,
    )

    bypasses = [r for r in mediated if r.outcome == REACHED]
    errors = [r for r in mediated if r.outcome == ERROR]

    print(f"\nA + B — {len(mediated)} enumerated entry points: {_tally(mediated)}")
    print(f"  executions of the tool body inside A + B: {core_ran + adapter_ran}")
    if bypasses:
        print(f"  ✗ {len(bypasses)} reached the tool body with no decision behind it:")
        for r in bypasses:
            print(f"      {r.path}  {r.detail}")
    else:
        print("  ✓ none reached the tool body without a decision behind it")
    if errors:
        print(f"  ! {len(errors)} proved nothing (failed before the gate was consulted)")

    print(f"\nC — {len(found)} object-graph searches: {_tally(found)} ({found_ran} executions)")
    print("  every wrapper here holds its target in a closure cell, and CPython publishes those.")
    print("  removing `__wrapped__` closes the *automatic* unwrappers; it cannot close this.")
    print(f"\nD — {len(edge)} paths from elsewhere in the process: {_tally(edge)} ({edge_ran} executions)")
    print(f"E — control, {len(naive)} rows: {_tally(naive)} ({naive_ran} executions)")
    print(f"  the same three probes against histos' own wrappers: {_tally(core[1:3] + found[:1])}")

    print("\nF. the missing-assignment footgun")
    print("  `protect_tools(tools, gate=g)` with the result dropped\n")
    for line in footgun():
        print(f"  {line}")

    return 1 if bypasses or errors else 0


if __name__ == "__main__":
    sys.exit(main())
