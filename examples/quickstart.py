"""Zero-infrastructure demo: run with `python examples/quickstart.py`.

No proxy, no database, no network, no models — just an in-process policy that
bounds what a (possibly manipulated) agent can do. Demonstrates:

  * RBAC deny-by-default
  * resource-aware authorization (tenant scoping)
  * a verbatim canary redacted on the way out
  * observe (dry-run) mode
  * the audit trail (including denied attempts)
"""

from __future__ import annotations

from histos import (
    Constraint,
    Field,
    Gate,
    GateDenied,
    InMemoryAuditSink,
    Policy,
    Principal,
    Schema,
    Sensitivity,
    ToolContract,
    use_principal,
)


# ── the tools an agent can call ──────────────────────────────────────────
def get_order(order_id: int):
    return {"order_id": order_id, "total": 42.0, "email": "customer@example.com"}


def delete_invoice(invoice_id: int):
    # Pretend this irreversibly deletes something.
    return {"deleted": invoice_id, "note": "internal token CANARY-7f3a-SECRET"}


# The trusted resource store. Row-level authorization reads ownership from HERE —
# never from an argument the (possibly hijacked) model supplied.
_INVOICES = {9: {"tenant_id": "acme"}, 77: {"tenant_id": "rival"}}


def resolve_invoice(tool: str, args: dict) -> dict:
    return _INVOICES.get(args["invoice_id"], {})


# ── the policy (this is the whole security configuration) ────────────────
policy = Policy(
    tools={
        "get_order": ToolContract(
            name="get_order",
            args=Schema({"order_id": Field(type="integer")}),
            returns=Schema({"total": Field(type="number"), "email": Field(type="string", sensitive="pii")}),
        ),
        "delete_invoice": ToolContract(
            name="delete_invoice",
            args=Schema({"invoice_id": Field(type="integer")}),
            access="write",
            sensitivity=Sensitivity.CRITICAL,
            # Row-level authz: the resolver looks the invoice up and returns its REAL
            # owner, which is compared to the principal. Not a caller-declared value.
            constraints=(Constraint.owns("tenant_id"),),
        ),
    },
    permissions={"support": frozenset({"get_order"}), "billing": frozenset({"delete_invoice"})},
    canaries=frozenset({"CANARY-7f3a-SECRET"}),
    policy_version="1",
)


def main() -> None:
    audit = InMemoryAuditSink()
    g = Gate(policy, audit=audit, resource_resolver=resolve_invoice)
    safe_get = g.wrap(get_order)
    safe_delete = g.wrap(delete_invoice)

    print("policy hash:", policy.content_hash())
    print()

    support = Principal(role="support", identity="agent-1", attributes={"tenant_id": "acme"})
    billing = Principal(role="billing", identity="agent-2", attributes={"tenant_id": "acme"})

    with use_principal(support):
        # PII in the return is redacted for a role that may not see it.
        print("support get_order:", safe_get(order_id=1))
        # support has no grant for delete_invoice → blocked before any side effect.
        try:
            safe_delete(invoice_id=9)
        except GateDenied as exc:
            print("support delete_invoice ->", exc.decision.explain())

    with use_principal(billing):
        # allowed within own tenant; the canary in the output is redacted.
        print("billing delete_invoice (own tenant):", safe_delete(invoice_id=9))
        # cross-tenant delete denied by the resource constraint.
        try:
            safe_delete(invoice_id=77)  # someone else's invoice
        except GateDenied as exc:
            print("billing delete_invoice (cross-tenant) ->", exc.decision.explain())

    # observe mode: log what WOULD happen, block nothing (great for calibration).
    observed = InMemoryAuditSink()
    dry = Gate(policy, audit=observed, mode="observe", resource_resolver=resolve_invoice).wrap(delete_invoice)
    with use_principal(support):
        dry(invoice_id=77)  # would be denied under enforce
    would_block = [e for e in observed.entries if e["effect"] == "deny"]
    print(f"\nobserve mode: {len(would_block)} call(s) would have been blocked (none actually were)")

    print("\n── audit trail (the 'prove it' artifact) ──")
    for e in audit.entries:
        print(f"  #{e['decision_id']:<2} {e['phase']:<4} {e['tool']:<15} {e['effect']:<7} {e['rule']}")

    denied = audit.denied
    print(f"\n{len(denied)} unauthorised attempt(s) blocked and recorded.")


if __name__ == "__main__":
    main()
