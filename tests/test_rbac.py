"""RBAC allow-list: deny-by-default and role inheritance."""

from __future__ import annotations

import pytest

from histos import Gate, GateDenied, Principal, use_principal


def _order_tool():
    def get_order(order_id):
        return {"total": 1.0}

    return get_order


def test_role_with_grant_is_allowed(sample_policy):
    safe = Gate(sample_policy).wrap(_order_tool())
    with use_principal(Principal(role="viewer")):
        assert safe(order_id=1) == {"total": 1.0}


def test_role_without_grant_is_denied(sample_policy):
    safe = Gate(sample_policy).wrap(_order_tool())
    with use_principal(Principal(role="billing")):  # billing may delete_invoice, not get_order
        with pytest.raises(GateDenied) as exc:
            safe(order_id=1)
    assert exc.value.decision.rule == "rbac"


def test_unknown_role_is_denied(sample_policy):
    safe = Gate(sample_policy).wrap(_order_tool())
    with use_principal(Principal(role="ghost")), pytest.raises(GateDenied):
        safe(order_id=1)


def test_inherited_grant_is_allowed(sample_policy, sample_resolver):
    """admin inherits billing → admin may call delete_invoice."""

    def delete_invoice(invoice_id):
        return {"ok": True}

    safe = Gate(sample_policy, resource_resolver=sample_resolver).wrap(delete_invoice)
    with use_principal(Principal(role="admin", attributes={"tenant_id": "acme"})):
        assert safe(invoice_id=1) == {"ok": True}


def test_inheritance_cycles_do_not_hang():
    from histos import Field, Policy, Schema, ToolContract

    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({"x": Field(type="integer")}))},
        permissions={"a": frozenset(), "b": frozenset({"t"})},
        role_inherits={"a": "b", "b": "a"},  # cycle
    )
    assert policy.allowed_tools("a") == frozenset({"t"})
