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
