"""Rate-window and budget limits, with a deterministic clock."""

from __future__ import annotations

import pytest
from conftest import FakeClock

from histos import Gate, GateDenied, LimitStore, Policy, Principal, Schema, ToolContract, use_principal


def _wrap(tool, *, rate_limit=None, budget=None, clock=None):
    policy = Policy(
        tools={"ping": ToolContract(name="ping", args=Schema({}), rate_limit=rate_limit, budget=budget)},
        permissions={"r": frozenset({"ping"})},
    )
    limits = LimitStore(window_seconds=60.0, time_fn=clock) if clock else LimitStore(window_seconds=60.0)
    return Gate(policy, limits=limits).wrap(tool, name="ping")


def test_rate_limit_blocks_within_window():
    clock = FakeClock()

    def ping():
        return "pong"

    safe = _wrap(ping, rate_limit=2, clock=clock)
    with use_principal(Principal(role="r", identity="u1")):
        assert safe() == "pong"
        assert safe() == "pong"
        with pytest.raises(GateDenied) as exc:
            safe()
    assert exc.value.decision.rule == "rate_limit"


def test_rate_limit_recovers_after_window():
    clock = FakeClock()

    def ping():
        return "pong"

    safe = _wrap(ping, rate_limit=1, clock=clock)
    with use_principal(Principal(role="r", identity="u1")):
        assert safe() == "pong"
        clock.tick(120)  # window passed
        assert safe() == "pong"


def test_budget_is_absolute():
    def ping():
        return "pong"

    safe = _wrap(ping, budget=1)
    with use_principal(Principal(role="r", identity="u1")):
        assert safe() == "pong"
        with pytest.raises(GateDenied) as exc:
            safe()
    assert exc.value.decision.rule == "budget"


def test_denied_call_does_not_burn_budget():
    """A call denied by RBAC must not consume a limit slot."""

    def ping():
        return "pong"

    policy = Policy(
        tools={"ping": ToolContract(name="ping", args=Schema({}), budget=1)},
        permissions={"r": frozenset({"ping"})},
    )
    limits = LimitStore()
    g = Gate(policy, limits=limits)
    safe = g.wrap(ping, name="ping")

    with use_principal(Principal(role="nobody")):  # denied, should not consume
        with pytest.raises(GateDenied):
            safe()
    with use_principal(Principal(role="r", identity="u1")):
        assert safe() == "pong"  # budget still available
