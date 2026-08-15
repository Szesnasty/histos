"""Complete mediation, asked as a question a host can answer before shipping.

Split out of `gate.py`. Every guarantee this library makes is conditional on one thing
it cannot enforce from inside: that the agent has no path to a tool that was not
wrapped. A gate around nine of ten tools protects nine of ten tools, and the tenth is
where the call goes.

So the check is a *report*, not an assertion — a host runs it in CI against the exact
list it is about to register with the framework. Plain functions taking the gate rather
than methods on it: they read three attributes and decide nothing, which is the shape
that can be tested against a stub and read without the eleven hundred lines beside it.

The one failure this must never have is being wrong in the reassuring direction, which
is why an object it cannot identify counts as *not* mediated.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from histos.errors import PolicyError
from histos.mediate.callsig import _exposed_name, _gate_stamp


def declared_but_unwrapped(gate: Any) -> set[str]:
    """Tools the policy declares that were never actually wrapped."""
    return set(gate.policy.tools) - gate._wrapped_tools


def _mediates(gate: Any, tool: Any, exposed_name: str) -> bool:
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
    if any(ref() is tool for ref in gate._wrappers):
        return True
    return _gate_stamp(tool) == exposed_name


def ungated_tools(gate: Any, tools: Iterable[Any]) -> list[str]:
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
        if not _mediates(gate, tool, name):
            ungated.append(name)
    return sorted(ungated)


def coverage(gate: Any, tools: Iterable[Any]) -> dict[str, list[str]]:
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
    declared = set(gate.policy.tools)
    return {
        "covered": sorted(exposed & declared),
        "undeclared": sorted(exposed - declared),
        "unwrapped": sorted(declared - gate._wrapped_tools),
        "ungated": ungated_tools(gate, objects),
        "unchecked": sorted(names),
    }


# ── shared per-call steps (identical on the sync and async paths) ──
