"""Definition of done, first slice. One test per acceptance criterion."""

from __future__ import annotations

import pytest

from histos import (
    Gate,
    GateDenied,
    InMemoryAuditSink,
    Policy,
    Principal,
    ToolContract,
    gate,
    use_principal,
)


def test_one_wrapping_call_protects_a_tool(sample_policy):
    """A single wrapping call yields a protected tool (integration cost = 1 line)."""
    calls = []

    def get_order(order_id):
        calls.append(order_id)
        return {"total": 9.99, "email": "a@b.com"}

    safe = gate(get_order, policy=sample_policy)
    with use_principal(Principal(role="viewer", identity="u1")):
        result = safe(order_id=1)
    assert calls == [1]
    # returns.email is PII and viewer may not see it → redacted post-gate
    assert result["email"] == "[REDACTED]"
    assert result["total"] == 9.99


def test_no_policy_denies_by_default():
    """Wrapping with no policy denies every call."""

    def anything(x):
        return x

    safe = gate(anything, policy=None)
    with use_principal(Principal(role="anyone")), pytest.raises(GateDenied) as exc:
        safe(x=1)
    assert exc.value.decision.rule == "unknown_tool"


def test_incomplete_policy_fails_closed_with_reason():
    """A gated tool with no arg schema fails closed and says why."""
    policy = Policy(
        tools={"t": ToolContract(name="t", args=None)},
        permissions={"r": frozenset({"t"})},
    )

    def t(x):
        return x

    safe = gate(t, policy=policy)
    with use_principal(Principal(role="r")), pytest.raises(GateDenied) as exc:
        safe(x=1)
    assert exc.value.decision.rule == "no_arg_schema"
    assert "arg schema" in exc.value.decision.reason


def test_destructive_action_is_blocked_before_side_effect(sample_policy):
    """The destructive tool must not run when the gate denies it."""
    deleted = []

    def delete_invoice(invoice_id):
        deleted.append(invoice_id)  # the irreversible side effect
        return {"ok": True}

    safe = gate(delete_invoice, policy=sample_policy)
    # 'viewer' has no grant for delete_invoice → blocked pre-execution.
    with use_principal(Principal(role="viewer", attributes={"tenant_id": "acme"})):
        with pytest.raises(GateDenied) as exc:
            safe(invoice_id=99)
    assert exc.value.decision.rule == "rbac"
    assert deleted == []  # side effect never happened


def test_planted_canary_caught_deterministically_on_post_gate(sample_policy):
    """A verbatim canary in a tool's output is redacted on the post-gate."""
    sink = InMemoryAuditSink()

    def get_order(order_id):
        return {"total": 1.0, "email": "x@y.com", "note": "leak CANARY-7f3a-SECRET here"}

    g = Gate(sample_policy, audit=sink)
    safe = g.wrap(get_order)
    with use_principal(Principal(role="viewer")):
        result = safe(order_id=1)
    assert "CANARY-7f3a-SECRET" not in str(result)
    assert "[REDACTED-CANARY]" in result["note"]
    post = [e for e in sink.entries if e["phase"] == "post"][0]
    assert post["effect"] == "redact"
    assert any("canary:" in r for r in post["redactions"])


def test_works_with_zero_infrastructure(sample_policy):
    """No proxy, no DB, no network — a plain in-process call."""

    def get_order(order_id):
        return {"total": 5.0}

    safe = gate(get_order, policy=sample_policy)
    with use_principal(Principal(role="admin")):
        assert safe(order_id=1)["total"] == 5.0


def test_every_decision_is_audited(sample_policy):
    """Allowed and denied calls both produce an audit record."""
    sink = InMemoryAuditSink()
    g = Gate(sample_policy, audit=sink)

    def get_order(order_id):
        return {"total": 1.0}

    safe = g.wrap(get_order)
    with use_principal(Principal(role="viewer")):
        safe(order_id=1)  # allowed → pre + post records
    with use_principal(Principal(role="nobody")), pytest.raises(GateDenied):
        safe(order_id=2)  # denied → pre record

    assert len(sink.denied) == 1
    assert sink.denied[0]["rule"] == "rbac"
    # decision_ids are unique and monotonic
    ids = [e["decision_id"] for e in sink.entries]
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)


def test_missing_principal_fails_closed(sample_policy):
    """No trusted identity in context → deny, never guess."""

    def get_order(order_id):
        return {"total": 1.0}

    safe = gate(get_order, policy=sample_policy)
    with pytest.raises(GateDenied) as exc:
        safe(order_id=1)  # no use_principal(...)
    assert exc.value.decision.rule == "no_principal"


def test_positional_arguments_are_rejected(sample_policy):
    """Gated tools are keyword-only so the gate always sees named args."""
    from histos import PolicyError

    def get_order(order_id):
        return {"total": 1.0}

    safe = gate(get_order, policy=sample_policy)
    with use_principal(Principal(role="viewer")), pytest.raises(PolicyError):
        safe(1)
