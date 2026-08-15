"""Complete mediation: no wrapping path may publish a route to the ungated tool.

`functools.wraps` sets `__wrapped__` to the callable being wrapped. On an ordinary
decorator that is a convenience; on a security wrapper it is a public, documented
pointer at the thing being protected, and `inspect.unwrap`,
`inspect.signature(follow_wrapped=True)` and every decorator-aware framework follow it
without being asked.

This was fixed once, in the LangChain adapter only. The core paths — `gate()`,
`Gate.wrap()`, `protect()`, sync and async — kept publishing it, so the documented
one-liner in the README shipped the bypass the repository described as closed. These
tests exist so the next refactor cannot quietly reopen it on *any* path.

The policy below declares each tool with an EMPTY argument schema, so a gated call can
only ever be refused. If the tool body runs, the gate was not on the path.
"""

from __future__ import annotations

import asyncio
import copy
import functools
import gc
import inspect

import pytest

from histos import Field, Gate, Policy, Principal, Schema, ToolContract, gate, protect, use_principal
from histos.errors import GateDenied, PolicyError
from histos.integrations.base import guard_callable

CALLS: list[int] = []


def transfer(amount: int) -> str:
    """Move money."""
    CALLS.append(amount)
    return "moved"


async def atransfer(amount: int) -> str:
    """Move money, asynchronously."""
    CALLS.append(amount)
    return "moved"


class CallableTool:
    """A callable object holding its target — the shape `WRAPPER_UPDATES` leaks."""

    __name__ = "transfer"

    def __init__(self) -> None:
        self.func = transfer

    def __call__(self, amount: int) -> str:
        return self.func(amount=amount)


def _policy() -> Policy:
    return Policy(
        tools={name: ToolContract(name=name, args=Schema({}), access="write") for name in ("transfer", "atransfer")},
        permissions={"clerk": frozenset({"transfer", "atransfer"})},
    )


CLERK = Principal(role="clerk", identity="svc-1")


@pytest.fixture(autouse=True)
def _clear() -> None:
    CALLS.clear()


def _sync_wrappings() -> dict[str, object]:
    """Every documented way to gate a plain sync callable."""
    return {
        "gate()": gate(transfer, policy=_policy()),
        "Gate.wrap()": Gate(_policy()).wrap(transfer),
        "protect()": protect([transfer], policy=_policy()).tools["transfer"],
        "guard_callable()": guard_callable(transfer, name="transfer", gate=Gate(_policy()), on_denied="raise"),
        "partial": Gate(_policy()).wrap(functools.partial(transfer), name="transfer"),
        "callable object": Gate(_policy()).wrap(CallableTool(), name="transfer"),
        "decorated": Gate(_policy()).wrap(functools.wraps(transfer)(lambda **kw: transfer(**kw)), name="transfer"),
    }


# ── the pointer itself ───────────────────────────────────────────────────


@pytest.mark.parametrize("label", list(_sync_wrappings()))
def test_no_sync_wrapping_publishes_the_ungated_callable(label: str) -> None:
    guarded = _sync_wrappings()[label]
    assert not hasattr(guarded, "__wrapped__"), f"{label} leaks the ungated callable as __wrapped__"
    assert inspect.unwrap(guarded) is guarded, f"{label} is unwrappable back to the raw tool"
    assert transfer not in vars(guarded).values(), f"{label} republishes the raw tool in its __dict__"


def test_the_async_wrapping_does_not_publish_it_either() -> None:
    guarded = gate(atransfer, policy=_policy())
    assert not hasattr(guarded, "__wrapped__")
    assert inspect.unwrap(guarded) is guarded


def test_no_automatic_unwrapping_protocol_reaches_the_tool() -> None:
    """The line this library actually defends, stated precisely.

    A wrapper has to hold the callable it wraps — that reference lives in a closure
    cell and no design removes it. So ``__closure__`` traversal is **not** in scope:
    reaching it means in-process code deliberately walking cell contents, which is the
    malicious-developer / compromised-dependency case ``SECURITY.md`` excludes by name.

    ``__wrapped__`` is a different thing and that is the whole point of the fix. It is
    a *published protocol*: ordinary, well-behaved framework code follows it
    automatically, without anyone attacking anything, so leaking it turned a routine
    ``inspect.unwrap`` into a silent bypass. What must hold is that no automatic
    protocol — and no attribute a caller can simply read — yields the raw tool.
    """
    for label, guarded in _sync_wrappings().items():
        assert inspect.unwrap(guarded) is guarded, f"{label}: inspect.unwrap reaches the tool"
        assert inspect.signature(guarded, follow_wrapped=True) is not None
        reachable = {id(v) for v in vars(guarded).values()}
        assert id(transfer) not in reachable, f"{label}: the tool is readable off the wrapper"


# ── and the pointer must not be executable ───────────────────────────────


@pytest.mark.parametrize("label", list(_sync_wrappings()))
def test_no_reach_around_executes_the_tool_body(label: str) -> None:
    guarded = _sync_wrappings()[label]
    with use_principal(CLERK):
        with pytest.raises(GateDenied):
            guarded(amount=1)
        for route in (getattr(guarded, "__wrapped__", None), inspect.unwrap(guarded) if guarded else None):
            if route is None or route is guarded:
                continue
            with pytest.raises(Exception):  # noqa: B017 — any refusal will do; execution will not
                route(amount=999)
    assert CALLS == [], f"{label}: the tool body ran despite the policy declaring no arguments"


def test_deepcopy_and_gc_do_not_hand_back_the_raw_tool() -> None:
    guarded = gate(transfer, policy=_policy())
    assert not hasattr(copy.deepcopy(guarded), "__wrapped__")
    gc.collect()
    assert all(r is not transfer for r in gc.get_referents(guarded))


# ── what removing the pointer must NOT cost ──────────────────────────────


def test_the_metadata_frameworks_read_survives() -> None:
    """LangChain infers an argument schema from the signature when none is supplied."""
    guarded = gate(transfer, policy=_policy())
    assert guarded.__name__ == "transfer"
    assert guarded.__doc__ == "Move money."
    assert guarded.__module__ == transfer.__module__
    assert str(inspect.signature(guarded)) == str(inspect.signature(transfer))


def test_a_partial_or_callable_object_still_gets_a_name() -> None:
    guarded = Gate(_policy()).wrap(CallableTool(), name="transfer")
    assert guarded.__name__ == "transfer"


# ── streaming tools are refused, not silently half-gated ─────────────────


def test_a_generator_tool_is_refused_at_wrap_time() -> None:
    def streaming(amount: int):
        yield amount

    with pytest.raises(PolicyError, match="generator"):
        gate(streaming, policy=_policy(), name="transfer")


def test_an_async_generator_tool_is_refused_at_wrap_time() -> None:
    async def streaming(amount: int):
        yield amount

    with pytest.raises(PolicyError, match="async generator"):
        gate(streaming, policy=_policy(), name="transfer")


# ── swapping the ruleset must actually take effect ───────────────────────


def test_assigning_a_new_policy_is_enforced_not_ignored() -> None:
    """`gate.policy = tightened` read like a revocation and enforced the old ruleset."""
    g = Gate(_policy())
    guarded = g.wrap(transfer)
    g.policy = Policy(
        tools={"transfer": ToolContract(name="transfer", args=Schema({}), access="write")},
        permissions={},  # the grant is revoked
    )
    with use_principal(CLERK), pytest.raises(GateDenied) as exc:
        guarded(amount=1)
    assert exc.value.decision.rule == "rbac"


def test_a_gate_does_not_rewrite_the_caller_s_policy() -> None:
    """`protect()` used to mutate a shared Policy, flipping authorization elsewhere."""

    def undeclared(note: str) -> None:  # an undeclared tool forces inference
        return None

    shared = _policy()
    before = shared.content_hash()
    protect([transfer, undeclared], policy=shared)
    assert shared.content_hash() == before, "protect() mutated the caller's policy in place"


def test_protect_refuses_a_lambda_rather_than_keying_a_policy_on_its_name() -> None:
    with pytest.raises(PolicyError, match="lambda"):
        protect([lambda **kw: None], policy=_policy())  # noqa: E731 — the point is the name


def test_protect_refuses_two_tools_that_answer_to_one_name() -> None:
    def make() -> object:
        def delete(target: str) -> None:
            return None

        return delete

    with pytest.raises(PolicyError, match="two tools named"):
        protect([make(), make()], policy=_policy())


def test_async_reach_around_does_not_execute_either() -> None:
    guarded = gate(atransfer, policy=_policy())
    with use_principal(CLERK):
        with pytest.raises(GateDenied):
            asyncio.run(guarded(amount=1))
    assert CALLS == []


# ── the callbacks a host provides must not be able to open the gate ──────


def test_a_raising_sync_confirm_fails_closed_and_is_audited() -> None:
    """The async path guarded this; the sync path did not, so a confirm callback that
    raised — its queue down, the operator's session expired — escaped as its own
    exception, and the call the policy had just said needed a human left no record."""
    from histos.trail.audit import InMemoryAuditSink

    def boom(_req):
        raise RuntimeError("approvals queue is down")

    policy = Policy(
        tools={
            "transfer": ToolContract(
                name="transfer",
                args=Schema({"amount": Field(type="integer")}),
                access="write",
                requires_confirmation=True,
            )
        },
        permissions={"clerk": frozenset({"transfer"})},
    )
    sink = InMemoryAuditSink()
    guarded = Gate(policy, confirm=boom, audit=sink).wrap(transfer)

    with use_principal(CLERK), pytest.raises(GateDenied) as exc:
        guarded(amount=1)
    assert exc.value.decision.rule == "confirm_error"
    assert CALLS == []
    assert [r for r in sink.entries if r["rule"] == "confirm_error"], "the denial left no audit record"


def test_confirm_cannot_mutate_the_arguments_the_tool_receives() -> None:
    """`confirm` used to be handed the very dict the gate then splats into the tool, so
    a well-meant normalisation in an approvals UI landed in the executed call after
    every check had already passed."""
    seen: list[dict] = []

    def meddle(req):
        seen.append(dict(req.args))
        req.args["amount"] = 999_999  # an approvals UI "normalising" the value
        return True

    policy = Policy(
        tools={
            "transfer": ToolContract(
                name="transfer",
                args=Schema({"amount": Field(type="integer")}),
                access="write",
                requires_confirmation=True,
            )
        },
        permissions={"clerk": frozenset({"transfer"})},
    )
    guarded = Gate(policy, confirm=meddle).wrap(transfer)
    with use_principal(CLERK):
        guarded(amount=1)
    assert seen == [{"amount": 1}]
    assert CALLS == [1], f"the mutated value reached the tool: {CALLS}"


def test_concurrent_calls_get_distinct_decision_ids() -> None:
    """`decision_id` is how an investigator says 'this call, not that one'."""
    from concurrent.futures import ThreadPoolExecutor

    from histos.trail.audit import InMemoryAuditSink

    policy = Policy(
        tools={
            "transfer": ToolContract(name="transfer", args=Schema({"amount": Field(type="integer")}), access="write")
        },
        permissions={"clerk": frozenset({"transfer"})},
    )
    sink = InMemoryAuditSink()
    guarded = Gate(policy, audit=sink).wrap(transfer)

    def call(i: int) -> None:
        with use_principal(CLERK):
            guarded(amount=i)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(call, range(200)))

    ids = [r["decision_id"] for r in sink.entries]
    assert len(ids) == len(set(ids)), "two decisions were stamped with the same decision_id"
