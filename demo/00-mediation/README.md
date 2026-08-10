# Is the gate actually the only way in?

Every claim the other demos make rests on one assumption: a tool handed to a
framework can only be reached **through** the gate. `SECURITY.md` says complete
mediation is a property of the adapter rather than of the library, and
`roadmap.md` asks the question directly — *is there any tool-execution path that
bypasses the gate?* This is the file that answers it, and the honest answer is
"yes, three of them, and here is exactly which".

No model is involved. `hunt.py` reaches for the tool the way *code* can: the three
things the library itself hands back (`gate`, `Gate.wrap`, `protect`), every public
entry point LangChain exposes, the private ones underneath, the async paths, the
attributes a caller can read straight off the object, LangGraph's own executor —
and then a breadth-first search that stops enumerating and simply walks the object
graph looking for the ungated callable.

```bash
# `demo/README.md` sets up one virtualenv and symlinks it here; or make your own:
#   python3.13 -m venv .venv && .venv/bin/pip install -r requirements.txt -e ../..
.venv/bin/python hunt.py
```

No Ollama, no model, about a second. Exit 0 if nothing in sections A or B reached
the tool body.

The trick that makes the answer unambiguous: the policy declares `wire_transfer`
with an **empty argument schema**, so a call that reaches the gate can only ever be
refused. Two observables decide every row and only two — did the tool body run
(`CALLS`), and did the wrapper record a decision (`AUDIT`). The exception type is
never the verdict.

| | meaning |
|---|---|
| `✓ GATED` | the wrapper recorded a decision and the body did not run |
| `✗ REACHED` | the body ran with no decision behind it |
| `· N/A` | the path does not exist on this object |
| `! ERROR` | the call failed before the wrapper was consulted; it proves nothing |

`ERROR` exists because of a bug this harness used to have. It scored *any*
exception as GATED, so `tool._run(**args)` raising `TypeError: missing 1 required
keyword-only argument: 'config'` counted as a win — the gate was credited for a
call that never reached it, and a LangChain signature change would have turned a
real bypass into a green row. Those rows now pass `config={}` and are genuinely
exercised.

## Result

31 enumerated entry points, run against the current tree:

```
A + B — 31 enumerated entry points: 19 gated, 12 n/a, 0 error, 0 reached
  executions of the tool body inside A + B: 0
  ✓ none reached the tool body without a decision behind it
```

**19 gated, 12 not applicable, 0 reached.** The 12 `N/A` rows are not wins and are
not counted as any; they are paths that do not exist on the object. Nine of the
twelve are `__wrapped__` / `inspect.unwrap` rows, and section E is what turns those
nine from an absence into a measurement.

<details>
<summary>A. the library's own wrappers — no framework involved</summary>

```
gate(fn, policy=…)(**args)                      ✓ GATED
gate(fn, policy=…).__wrapped__(**args)          · N/A     no __wrapped__ on this object
inspect.unwrap(gate(fn, policy=…))(**args)      · N/A     inspect.unwrap found nothing to unwrap
Gate(policy).wrap(fn)(**args)                   ✓ GATED
Gate(policy).wrap(fn).__wrapped__(**args)       · N/A
inspect.unwrap(Gate(policy).wrap(fn))(**args)   · N/A
protect([fn]).tools[…](**args)                  ✓ GATED
protect([fn]).tools[…].__wrapped__(**args)      · N/A
inspect.unwrap(protect([fn]).tools[…])(**args)  · N/A
```

This section did not exist for most of this file's life, and its absence is how a
live `__wrapped__` pointer on `Gate.wrap`'s product survived a demo written to find
exactly that. The hunt only probed the LangChain `StructuredTool`; `gate()` and
`Gate.wrap()` are what most callers actually touch.

</details>

<details>
<summary>B. the LangChain tool the adapter hands the framework</summary>

```
tool.invoke(args)                               ✓ GATED
tool.run(args)                                  ✓ GATED
await tool.ainvoke(args)                        ✓ GATED
await tool.arun(args)                           ✓ GATED
tool._run(**args, config={})                    ✓ GATED
await tool._arun(**args, config={})             ✓ GATED
tool._run.__func__(tool, …)                     ✓ GATED
tool.func(**args)                               ✓ GATED
tool.coroutine(**args)                          · N/A     a sync tool has no coroutine
tool.func.__wrapped__(**args)                   · N/A     no __wrapped__ on this object
inspect.unwrap(tool.func)(**args)               · N/A     inspect.unwrap found nothing to unwrap
tool.func.__globals__['wire_transfer']          · N/A     the wrapper's module does not define wire_transfer
closure of tool.func                            ✓ GATED
inspect.unwrap(closure of tool.func)            · N/A
functools.partial(tool.func)(**args)            ✓ GATED
copy.deepcopy(tool).invoke(args)                ✓ GATED
pickle round trip of tool.func                  · N/A     pickle refuses
subclass re-hosting tool.func                   ✓ GATED
threading.Thread → tool.invoke                  ✓ GATED   [no_principal]
threading.Thread with copy_context()            ✓ GATED
asyncio.to_thread(tool.invoke)                  ✓ GATED
langgraph ToolNode                              ✓ GATED
```

Two rows are worth reading twice. `threading.Thread → tool.invoke` is denied
`[no_principal]` and every other row is denied `[arg_schema]`: a `ContextVar` does
not cross a thread boundary, and with no identity bound the gate fails **closed**
rather than open. And `pickle round trip of tool.func` is `N/A` for a load-bearing
reason — the wrapper adopts the target's `__qualname__`, so `pickle` looks up
`__main__.wire_transfer`, finds an object that is not the wrapper, and refuses
rather than silently handing a task queue the ungated function.

</details>

## The three things that do reach the tool

They are printed, not omitted, because a hunt that only prints its wins is a
brochure.

### C. the callable is inside the wrapper, and CPython publishes closure cells

```
search from gate(fn, policy=…)      ✗ REACHED  gate(fn, policy=…).__closure__[2].cell_contents
search from Gate(policy).wrap(fn)   ✗ REACHED  Gate(policy).wrap(fn).__closure__[2].cell_contents
search from protect([fn]).tools[…]  ✗ REACHED  protect([fn]).tools[…].__closure__[2].cell_contents
search from tool                    ✗ REACHED  tool.func.__closure__[0].cell_contents.__closure__[2].cell_contents
```

Four of four. The search finds the path, re-walks it from the accessors, checks
that what comes out **is** the raw function, and calls it — so each path above is
evidence rather than a claim.

This is the floor, and no version of `guard_callable` clears it. A Python wrapper
must hold a reference to what it wraps, and every way of holding it is readable:
a closure cell, an instance attribute, a name-mangled slot, a module-level
registry. `histos` gates objects; it does not sandbox the interpreter.

What removing `__wrapped__` bought is therefore narrower than "the callable is
unreachable", and section E measures it exactly: the *automatic* unwrappers stop
working. `inspect.unwrap`, `inspect.signature(follow_wrapped=True)`, pytest's
fixture machinery, DI containers and every decorator-aware framework follow
`__wrapped__` and nothing follows `__closure__`. The difference between an
accidental bypass and a deliberate one is the whole difference here, and it is
worth having — but it is not the difference the previous version of this README
claimed.

> Note: `closure of tool.func` in section B is `✓ GATED` and `search from tool` is
> `✗ REACHED`, and both are correct. The section B probe is the naive one-hop walk
> — it takes the first closure cell holding something named `wire_transfer`, which
> is the *gate's own* wrapper, because `_adopt_metadata` gave it that name. The
> search keeps going. A depth-limited probe reporting a clean result is exactly the
> failure mode that hid this for as long as it was hidden.

### D. paths that start somewhere else in the process

```
the original, unwrapped tool         ✗ REACHED
the plain function                   ✗ REACHED
sys.modules[__main__].wire_transfer  ✗ REACHED
monkeypatch tool.func, then invoke   ✗ REACHED
gc.get_objects() heap scan           ✗ REACHED
```

Five of five, and none is a mediation failure: **you can always call a function you
did not gate.** That is documented, not discovered. They are in the output so that
a reader can tell which rows the library is answerable for.

### E. the control — the same wrapper, written the way the tutorials write it

Without this section, the nine `__wrapped__` / `inspect.unwrap` rows in A and B are
an absence and prove nothing: a reader cannot distinguish "the pointer was removed"
from "nothing would have been there anyway". So `hunt.py` builds the honest
baseline — a wrapper that
refuses every call exactly as this policy does, written with `functools.wraps` —
and runs the same probes:

| probe | `functools.wraps` guard | histos' `gate()` |
|---|---|---|
| call it | `✓ GATED` | `✓ GATED` |
| `.__wrapped__(**args)` | `✗ REACHED` | `· N/A` |
| `inspect.unwrap(…)(**args)` | `✗ REACHED` | `· N/A` |
| object-graph search | `✗ REACHED` (`naive.__wrapped__`, one hop) | `✗ REACHED` (`.__closure__[2].cell_contents`, one hop) |

**The delta is two rows out of four.** That is the entire measured value of
`_adopt_metadata` over `functools.wraps` on this axis, and it is worth stating
plainly rather than dressing up: the ecosystem's automatic unwrappers no longer
find the ungated callable, and a person who types `.__closure__` still does. The
last row is also the honest deflation — the control's raw function is one
dereference away either way; only the *name of the attribute* changed.

## The footgun, and what actually catches it

`protect_tools()` returns **new** objects and leaves the originals alive:

```python
tools = [book, cancel, refund]
protect_tools(tools, gate=gate)           # ← protects nothing
tools = protect_tools(tools, gate=gate)   # ← protects everything
```

A missing assignment is a silent, total loss of enforcement, and nothing raises.
An earlier version of this README said `Gate.coverage()` is what catches it. **It
does not**, and section F of the hunt runs the mistake to prove it:

```
gate.coverage([...])           {'covered': ['wire_transfer'], 'undeclared': [], 'unwrapped': []}
gate.declared_but_unwrapped()  set()
ungated_tools([...])           ['wire_transfer']
the body ran anyway            True
```

Coverage reports **clean** while the ungated body executes. The reason is
structural: `Gate.wrap()` records the tool's name in `self._wrapped_tools` when it
is called, and `coverage()` diffs names against the policy. Whether the caller kept
the returned object is not a fact the Gate has. `histos coverage` on the CLI is no
better — it diffs the policy against a comma-separated `--tools` string and never
looks at an object at all.

What does work is asking the **objects you are about to hand the framework**, since
`guard_callable` stamps `__gate_name__` on the callable it returns:

```python
def ungated_tools(tools):
    return [t.name for t in tools
            if getattr(getattr(t, "func", None), "__gate_name__", None) != t.name]

assert not ungated_tools(tools), f"handed the framework ungated tools: {ungated_tools(tools)}"
```

That is the assertion to put in CI, next to the agent construction and not in a
separate lint step. `Gate.coverage()` answers a different and still useful question
— *is every tool the agent can see declared in the policy?* — and it is the right
CI gate for **that**. It is not a check that enforcement was installed.

## What this does not prove

The hunt covers LangChain's `StructuredTool` and LangGraph's `ToolNode` at the
versions in `requirements.txt`. It says nothing about other frameworks, and nothing
about a future LangChain release adding an execution path. It is a test, not a
theorem — which is the argument for it living here and being run rather than being
a paragraph in a document.

The exit code is 1 if any row in A or B reaches the body or errors before the gate,
and 0 otherwise. Sections C, D and E do not affect it: they reach the body by
construction, and a harness that failed on them would fail forever and be ignored
within a week.
