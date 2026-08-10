"""Policy bundle: load / merge / round-trip, and the import→protect join."""

from __future__ import annotations

import pytest

from histos import (
    Gate,
    GateDenied,
    Principal,
    contracts_from_mcp,
    dump_bundle,
    load_bundle,
    load_bundle_json,
    load_bundle_yaml,
    merge_contracts,
    use_principal,
)

BUNDLE = {
    "version": "1",
    "policy_id": "acme",
    "canaries": ["CANARY-1"],
    "tools": {
        "delete_invoice": {
            "access": "write",
            "sensitivity": "critical",
            "args": {"invoice_id": {"type": "string"}, "tenant_id": {"type": "string"}},
            "rate_limit": 5,
            "confirmation": {"required": True},
            "resource": {"owns": "tenant_id"},
        },
        "get_invoice": {"access": "read", "args": {"invoice_id": {"type": "string"}}},
    },
    "roles": {
        "support": {"allow": ["get_invoice"]},
        "billing": {"inherits": "support", "allow": ["delete_invoice"]},
    },
}


def test_load_bundle_builds_policy():
    policy = load_bundle(BUNDLE)
    assert set(policy.tools) == {"delete_invoice", "get_invoice"}
    assert policy.tools["delete_invoice"].access == "write"
    assert policy.tools["delete_invoice"].rate_limit == 5
    assert policy.tools["delete_invoice"].requires_confirmation is True
    assert len(policy.tools["delete_invoice"].constraints) == 1
    assert policy.canaries == frozenset({"CANARY-1"})
    # inheritance: billing inherits support's get_invoice + its own delete_invoice
    assert policy.allowed_tools("billing") == frozenset({"get_invoice", "delete_invoice"})


def test_roundtrip_preserves_content_hash():
    policy = load_bundle(BUNDLE)
    again = load_bundle(dump_bundle(policy))
    assert policy.content_hash() == again.content_hash()


def test_json_and_yaml_loaders_agree():
    import json

    from_json = load_bundle_json(json.dumps(BUNDLE))
    yaml_text = """
version: '1'
tools:
  get_invoice:
    access: read
    args: {invoice_id: {type: string}}
roles:
  support: {allow: [get_invoice]}
"""
    from_yaml = load_bundle_yaml(yaml_text)
    assert "get_invoice" in from_json.tools
    assert "get_invoice" in from_yaml.tools


def test_merge_contracts_fills_shape_keeps_authz():
    """Authz from the bundle, arg/return shape from the imported MCP schema."""
    bundle = {
        "version": "1",
        "tools": {"delete_invoice": {"access": "write"}},  # authz only, no args
        "roles": {"billing": {"allow": ["delete_invoice"]}},
    }
    policy = load_bundle(bundle)
    assert policy.tools["delete_invoice"].args is None  # shape missing

    contracts = contracts_from_mcp(
        [
            {
                "name": "delete_invoice",
                "inputSchema": {
                    "type": "object",
                    "properties": {"invoice_id": {"type": "string"}},
                    "required": ["invoice_id"],
                },
            }
        ]
    )
    merged = merge_contracts(policy, contracts)
    # shape now present, authz (access=write, grant) preserved
    assert merged.tools["delete_invoice"].args is not None
    assert merged.tools["delete_invoice"].access == "write"

    def delete_invoice(invoice_id):
        return {"ok": True}

    safe = Gate(merged).wrap(delete_invoice)
    with use_principal(Principal(role="billing")):
        assert safe(invoice_id="x") == {"ok": True}
        with pytest.raises(GateDenied) as exc:
            safe(invoice_id=123)  # inferred string schema rejects an int
    assert exc.value.decision.rule == "arg_schema"


def test_merge_adds_discovered_tool_but_denies_without_grant():
    policy = load_bundle({"version": "1", "tools": {}, "roles": {"r": {"allow": []}}})
    contracts = contracts_from_mcp([{"name": "mystery", "inputSchema": {"type": "object", "properties": {}}}])
    merged = merge_contracts(policy, contracts)
    assert "mystery" in merged.tools  # discovered

    def mystery():
        return "hi"

    safe = Gate(merged).wrap(mystery)
    with use_principal(Principal(role="r")):
        with pytest.raises(GateDenied) as exc:
            safe()
    assert exc.value.decision.rule == "rbac"  # no grant → denied by default
