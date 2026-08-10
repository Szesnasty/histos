"""Async support — the detection matrix and the awaited seams.

The engine stays synchronous; only the *wrapper* gains an async path, plus the two
places that genuinely do IO: the `resource_resolver` and the `confirm` callback.
The detection matrix is the point of this file — it is the first place a user hits
a weird runtime bug, so every shape gets its own case, and an ambiguous shape must
fail LOUD at wrap time rather than silently pick a path.

`asyncio.run` is used directly so the suite needs no async plugin.
"""

from __future__ import annotations

import asyncio
import functools

import pytest

from histos import (
    Constraint,
    Field,
    Gate,
    GateConfirmationRequired,
    GateDenied,
    InMemoryAuditSink,
    Policy,
    PolicyError,
    Principal,
    Schema,
    ToolContract,
    gate,
    use_principal,
)


def _echo_policy(**tool_kwargs) -> Policy:
    return Policy(
        tools={"echo": ToolContract(name="echo", args=Schema({"x": Field(type="integer")}), **tool_kwargs)},
        permissions={"r": frozenset({"echo"})},
    )


async def echo(x: int) -> int:
    return x


def sync_echo(x: int) -> int:
    return x


# ── detection matrix ─────────────────────────────────────────────────────


def test_plain_async_function_gets_an_async_wrapper():
    safe = gate(echo, policy=_echo_policy())
    with use_principal(Principal(role="r")):
        assert asyncio.run(safe(x=7)) == 7


def test_decorated_async_function_is_detected():
    def logged(fn):
        @functools.wraps(fn)
        async def inner(**kwargs):
            return await fn(**kwargs)

        return inner

    safe = gate(logged(echo), policy=_echo_policy())
    with use_principal(Principal(role="r")):
        assert asyncio.run(safe(x=3)) == 3


def test_partial_over_async_is_detected():
    safe = gate(functools.partial(echo), policy=_echo_policy(), name="echo")
    with use_principal(Principal(role="r")):
        assert asyncio.run(safe(x=4)) == 4


def test_partial_over_sync_stays_sync():
    safe = gate(functools.partial(sync_echo), policy=_echo_policy(), name="echo")
    with use_principal(Principal(role="r")):
        assert safe(x=5) == 5


def test_callable_object_with_async_call_is_detected():
    class AsyncTool:
        async def __call__(self, x: int) -> int:
            return x * 2

    safe = gate(AsyncTool(), policy=_echo_policy(), name="echo")
    with use_principal(Principal(role="r")):
        assert asyncio.run(safe(x=6)) == 12


def test_callable_object_with_sync_call_stays_sync():
    class SyncTool:
        def __call__(self, x: int) -> int:
            return x * 2

    safe = gate(SyncTool(), policy=_echo_policy(), name="echo")
    with use_principal(Principal(role="r")):
        assert safe(x=6) == 12


def test_sync_wrapper_over_async_fails_loud_at_wrap_time():
    """The genuinely ambiguous shape: guessing either never awaits or awaits a value."""

    def leaky(fn):
        @functools.wraps(fn)  # sets __wrapped__, so the async target is visible
        def inner(**kwargs):
            return fn(**kwargs)  # returns a coroutine from a sync function

        return inner

    with pytest.raises(PolicyError) as exc:
        gate(leaky(echo), policy=_echo_policy())
    assert "cannot tell whether tool" in str(exc.value)
    assert "is_async=" in str(exc.value)


def test_is_async_override_resolves_the_ambiguous_case():
    def leaky(fn):
        @functools.wraps(fn)
        def inner(**kwargs):
            return fn(**kwargs)

        return inner

    safe = gate(leaky(echo), policy=_echo_policy(), is_async=True)
    with use_principal(Principal(role="r")):
        assert asyncio.run(safe(x=9)) == 9


# ── the gate still gates on the async path ───────────────────────────────


def test_async_denial_blocks_before_the_side_effect():
    ran = []

    async def echo(x: int) -> int:  # noqa: F811 — a local tool with a side effect
        ran.append(x)
        return x

    safe = gate(echo, policy=_echo_policy())
    with use_principal(Principal(role="nobody")), pytest.raises(GateDenied) as exc:
        asyncio.run(safe(x=1))
    assert exc.value.decision.rule == "rbac"
    assert ran == []


def test_async_missing_principal_fails_closed():
    safe = gate(echo, policy=_echo_policy())
    with pytest.raises(GateDenied) as exc:
        asyncio.run(safe(x=1))
    assert exc.value.decision.rule == "no_principal"


def test_async_positional_arguments_are_rejected():
    safe = gate(echo, policy=_echo_policy())
    with use_principal(Principal(role="r")), pytest.raises(PolicyError):
        asyncio.run(safe(1))


def test_async_arg_schema_is_enforced():
    safe = gate(echo, policy=_echo_policy())
    with use_principal(Principal(role="r")), pytest.raises(GateDenied) as exc:
        asyncio.run(safe(x="not-an-int"))
    assert exc.value.decision.rule == "arg_schema"


def test_async_limits_are_consumed():
    safe = gate(echo, policy=_echo_policy(budget=1))
    with use_principal(Principal(role="r", identity="u1")):
        assert asyncio.run(safe(x=1)) == 1
        with pytest.raises(GateDenied) as exc:
            asyncio.run(safe(x=2))
    assert exc.value.decision.rule == "budget"


def test_async_post_gate_redacts():
    policy = Policy(
        tools={
            "fetch": ToolContract(
                name="fetch",
                args=Schema({}),
                returns=Schema({"total": Field(type="number"), "email": Field(type="string", sensitive="pii")}),
            )
        },
        permissions={"r": frozenset({"fetch"})},
    )

    async def fetch():
        return {"total": 1.0, "email": "a@b.com"}

    safe = gate(fetch, policy=policy)
    with use_principal(Principal(role="r")):
        out = asyncio.run(safe())
    assert out == {"total": 1.0, "email": "[REDACTED]"}


# ── the awaited seams: resolver and confirm ──────────────────────────────

_OWNERS = {"ORD-1": "acme", "ORD-2": "globex"}


def _owned_policy() -> Policy:
    return Policy(
        tools={
            "read_order": ToolContract(
                name="read_order",
                args=Schema({"order_id": Field(type="string")}),
                constraints=(Constraint.owns("tenant_id"),),
            )
        },
        permissions={"r": frozenset({"read_order"})},
    )


async def read_order(order_id: str) -> dict:
    return {"order_id": order_id}


def test_async_resource_resolver_is_awaited():
    async def resolver(tool, args):
        await asyncio.sleep(0)  # a real resolver does IO here
        return {"tenant_id": _OWNERS.get(args["order_id"], "<unknown>")}

    g = Gate(_owned_policy(), resource_resolver=resolver)
    safe = g.wrap(read_order)
    acme = Principal(role="r", attributes={"tenant_id": "acme"})

    with use_principal(acme):
        assert asyncio.run(safe(order_id="ORD-1")) == {"order_id": "ORD-1"}
        with pytest.raises(GateDenied) as exc:
            asyncio.run(safe(order_id="ORD-2"))  # someone else's order
    assert exc.value.decision.rule == "resource_constraint"


def test_sync_resolver_still_works_on_the_async_path():
    def resolver(tool, args):
        return {"tenant_id": _OWNERS.get(args["order_id"], "<unknown>")}

    safe = Gate(_owned_policy(), resource_resolver=resolver).wrap(read_order)
    with use_principal(Principal(role="r", attributes={"tenant_id": "acme"})):
        assert asyncio.run(safe(order_id="ORD-1")) == {"order_id": "ORD-1"}


def test_async_resolver_on_a_sync_tool_fails_closed_with_a_clear_reason():
    """Comparing a coroutine to a principal attribute must not read as a mismatch."""

    async def resolver(tool, args):
        return {"tenant_id": "acme"}

    def read_order(order_id: str) -> dict:  # noqa: F811 — deliberately sync
        return {"order_id": order_id}

    safe = Gate(_owned_policy(), resource_resolver=resolver).wrap(read_order)
    with use_principal(Principal(role="r", attributes={"tenant_id": "acme"})):
        with pytest.raises(GateDenied) as exc:
            safe(order_id="ORD-1")
    assert exc.value.decision.rule == "resolver_error"
    assert "async" in exc.value.decision.reason


def test_resolver_not_found_is_distinct_on_the_async_path():
    from histos import ResourceNotFound

    async def resolver(tool, args):
        raise ResourceNotFound("no such order")

    safe = Gate(_owned_policy(), resource_resolver=resolver).wrap(read_order)
    with use_principal(Principal(role="r", attributes={"tenant_id": "acme"})):
        with pytest.raises(GateDenied) as exc:
            asyncio.run(safe(order_id="ORD-9"))
    assert exc.value.decision.rule == "resource_not_found"


def test_async_confirm_callback_is_awaited():
    policy = _echo_policy(requires_confirmation=True)
    approved = {"value": False}

    async def confirm(req):
        await asyncio.sleep(0)
        return approved["value"]

    safe = Gate(policy, confirm=confirm).wrap(echo)
    with use_principal(Principal(role="r")):
        with pytest.raises(GateConfirmationRequired):
            asyncio.run(safe(x=1))
        approved["value"] = True
        assert asyncio.run(safe(x=1)) == 1


def test_async_confirm_on_a_sync_tool_fails_closed():
    async def confirm(req):
        return True

    safe = Gate(_echo_policy(requires_confirmation=True), confirm=confirm).wrap(sync_echo, name="echo")
    with use_principal(Principal(role="r")):
        with pytest.raises(GateDenied) as exc:
            safe(x=1)
    assert exc.value.decision.rule == "confirm_error"


def test_raising_confirm_fails_closed_on_the_async_path():
    def confirm(req):
        raise RuntimeError("approval service down")

    sink = InMemoryAuditSink()
    safe = Gate(_echo_policy(requires_confirmation=True), confirm=confirm, audit=sink).wrap(echo)
    with use_principal(Principal(role="r")):
        with pytest.raises(GateDenied) as exc:
            asyncio.run(safe(x=1))
    assert exc.value.decision.rule == "confirm_error"
    assert sink.denied[0]["executed"] is False


def test_async_observe_mode_executes_but_records_the_denial():
    sink = InMemoryAuditSink()
    ran = []

    async def echo(x: int) -> int:  # noqa: F811
        ran.append(x)
        return x

    safe = Gate(_echo_policy(), audit=sink, mode="observe").wrap(echo)
    with use_principal(Principal(role="nobody")):
        assert asyncio.run(safe(x=1)) == 1  # not blocked
    assert ran == [1]
    pre = [e for e in sink.entries if e["phase"] == "pre"][0]
    assert (pre["effect"], pre["enforced"], pre["executed"]) == ("deny", False, True)
