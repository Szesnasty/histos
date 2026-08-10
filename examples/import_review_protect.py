"""Import → review → protect — the recommended way in.

Run with `python examples/import_review_protect.py`.

The two layers stay separate:
  * tool *shapes* are imported from a standard format (here: MCP tool defs) — no
    re-typing of what already exists in the app;
  * *authorization* (roles, permissions, resource constraints, limits, canaries)
    is authored in the Histos policy bundle.

They are merged, reviewed, and only then enforced.
"""

from __future__ import annotations

from histos import (
    Gate,
    GateDenied,
    Principal,
    contracts_from_mcp,
    load_bundle,
    merge_contracts,
    review_policy,
    use_principal,
)

# ── layer 1: tool shapes discovered from the app (MCP tool definitions) ──
mcp_tools = [
    {
        "name": "get_invoice",
        "inputSchema": {"type": "object", "properties": {"invoice_id": {"type": "string"}}, "required": ["invoice_id"]},
        "outputSchema": {
            "type": "object",
            "properties": {"total": {"type": "number"}, "email": {"type": "string", "x-sensitive": "pii"}},
        },
    },
    {
        "name": "delete_invoice",
        "inputSchema": {
            "type": "object",
            "properties": {"invoice_id": {"type": "string"}, "tenant_id": {"type": "string"}},
            "required": ["invoice_id", "tenant_id"],
        },
    },
]

# ── layer 2: authorization, authored as a Histos policy bundle ────
bundle = {
    "version": "1",
    "policy_id": "acme-billing",
    "canaries": ["CANARY-7f3a-SECRET"],
    "tools": {
        "delete_invoice": {
            "access": "write",
            "sensitivity": "critical",
            "rate_limit": 5,
            "resource": {"owns": "tenant_id"},
        },
    },
    "roles": {
        "support_agent": {"allow": ["get_invoice"]},
        "billing_admin": {"inherits": "support_agent", "allow": ["delete_invoice"]},
    },
}


def main() -> None:
    # import → merge
    contracts = contracts_from_mcp(mcp_tools)
    policy = merge_contracts(load_bundle(bundle), contracts)

    # review — what to read before turning enforcement on
    print("── review ──")
    print(review_policy(policy).render())
    print(f"\npolicy hash: {policy.content_hash()}")

    # protect
    def get_invoice(invoice_id):
        return {"total": 12.5, "email": "customer@example.com"}

    def delete_invoice(invoice_id, tenant_id):
        return {"success": True, "audit": "internal CANARY-7f3a-SECRET"}

    # The trusted resource store. `resource: {owns: tenant_id}` in the bundle above
    # means the gate asks THIS who owns the invoice — never the caller.
    owners = {"inv-1": "acme", "inv-9": "acme", "inv-77": "rival"}

    def resolve(tool, args):
        return {"tenant_id": owners.get(args["invoice_id"], "<unknown>")}

    g = Gate(policy, resource_resolver=resolve)
    safe_get = g.wrap(get_invoice)
    safe_delete = g.wrap(delete_invoice)

    print("\n── enforce ──")
    with use_principal(Principal(role="support_agent", identity="a1", attributes={"tenant_id": "acme"})):
        print("support get_invoice:", safe_get(invoice_id="inv-1"))  # PII redacted
        try:
            safe_delete(invoice_id="inv-9", tenant_id="acme")
        except GateDenied as exc:
            print("support delete_invoice ->", exc.decision.explain())

    with use_principal(Principal(role="billing_admin", identity="a2", attributes={"tenant_id": "acme"})):
        print("billing delete (own tenant):", safe_delete(invoice_id="inv-9", tenant_id="acme"))  # canary redacted
        try:
            safe_delete(invoice_id="inv-77", tenant_id="acme")  # someone else's invoice
        except GateDenied as exc:
            print("billing delete (cross-tenant) ->", exc.decision.explain())


if __name__ == "__main__":
    main()
