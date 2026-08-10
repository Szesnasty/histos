"""protect() — wrap the whole tool set, infer missing schemas, report coverage."""

from __future__ import annotations

import pytest

from histos import Field, Gate, GateDenied, Policy, Principal, Schema, ToolContract, use_principal


def tool_a(x: int):  # full contract + grant → ready
    return x


def tool_b(y: int):  # contract exists but no role grants it → needs-grant
    return y


def tool_c(z: int):  # no contract at all → needs-policy (schema inferred)
    return z


def tool_d(w: int):  # contract with no arg schema + grant → schema inferred, becomes usable
    return w


def _policy() -> Policy:
    return Policy(
        tools={
            "tool_a": ToolContract(name="tool_a", args=Schema({"x": Field(type="integer")})),
            "tool_b": ToolContract(name="tool_b", args=Schema({"y": Field(type="integer")})),
            "tool_d": ToolContract(name="tool_d", args=None),
        },
        permissions={"r": frozenset({"tool_a", "tool_d"})},
    )


def test_coverage_report_classifies_each_tool():
    g = Gate(_policy())
    result = g.protect([tool_a, tool_b, tool_c, tool_d])
    status = {r["tool"]: r["status"] for r in result.report}
    assert status["tool_a"] == "ready"
    assert status["tool_b"] == "needs-grant"
    assert status["tool_c"] == "needs-policy"
    assert status["tool_d"] == "ready"  # had a grant; schema inferred
    assert "2/4" in result.summary() or "tools fully covered" in result.summary()


def test_inferred_schema_is_enforced_after_protect():
    g = Gate(_policy())
    result = g.protect([tool_d])
    safe = result.tools["tool_d"]
    with use_principal(Principal(role="r")):
        assert safe(w=5) == 5
        with pytest.raises(GateDenied) as exc:
            safe(w="not-an-int")  # inferred integer schema rejects this
    assert exc.value.decision.rule == "arg_schema"


def test_tool_without_policy_denies_by_default_even_after_protect():
    g = Gate(_policy())
    result = g.protect([tool_c])
    safe = result.tools["tool_c"]
    with use_principal(Principal(role="r")), pytest.raises(GateDenied) as exc:
        safe(z=1)  # inferred schema, but no RBAC grant → denied
    assert exc.value.decision.rule == "rbac"


# ── complete mediation: the guard must not publish a way around itself ────


def test_guard_does_not_expose_the_ungated_callable():
    """`functools.wraps` sets `__wrapped__` to the original function.

    On an ordinary decorator that is a convenience. On a security wrapper it is a
    public pointer to the thing being protected, and a mediation hunt found it
    reachable as `tool.func.__wrapped__(...)`. It is removed deliberately, so this
    test is the thing that stops it coming back with the next refactor.
    """
    from histos.integrations.base import guard_callable

    calls: list[int] = []

    def transfer(amount: int) -> str:
        calls.append(amount)
        return "moved"

    policy = Policy(
        tools={"transfer": ToolContract(name="transfer", args=Schema({}), access="write")},
        permissions={"clerk": frozenset({"transfer"})},
    )
    guarded = guard_callable(transfer, name="transfer", gate=Gate(policy), on_denied="raise")

    assert not hasattr(guarded, "__wrapped__"), "the guard leaks the ungated callable"
    with use_principal(Principal(role="clerk", identity="svc-1")), pytest.raises(GateDenied):
        guarded(amount=1)
    assert calls == [], "the tool body ran despite the policy declaring no arguments"


def test_guard_keeps_the_metadata_frameworks_read():
    """Removing `__wrapped__` must not cost the name, the doc or the signature —
    LangChain infers an argument schema from the signature when none is supplied."""
    import inspect

    from histos.integrations.base import guard_callable

    def transfer(amount: int, to_account: str) -> str:
        """Move money."""
        return "moved"

    policy = Policy(
        tools={"transfer": ToolContract(name="transfer", args=Schema({}), access="write")},
        permissions={"clerk": frozenset({"transfer"})},
    )
    guarded = guard_callable(transfer, name="transfer", gate=Gate(policy))

    assert guarded.__name__ == "transfer"
    assert guarded.__doc__ == "Move money."
    assert list(inspect.signature(guarded).parameters) == ["amount", "to_account"]
