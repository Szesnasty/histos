"""Killer demo (Phase 0.1) — the composite, not one check.

A *hijacked* support agent runs makeRefund through the whole PRE/POST chain. RBAC is
one of many bars; the point is that the agent's real capability stays bounded by code
it does not control — and a secret the backend leaks never reaches the model.

Run it::  python examples/makeRefund_demo.py
"""

from __future__ import annotations

from histos import (
    ApprovalStore,
    Binding,
    Constraint,
    Field,
    Gate,
    GateConfirmationRequired,
    GateDenied,
    Policy,
    Principal,
    Schema,
    ToolContract,
    request_fingerprint,
    use_principal,
)

# Which tenant each order really belongs to (the trusted resource store).
_ORDERS = {"ORD-1": "acme", "ORD-OTHER": "globex"}


def _resolver(tool: str, args: dict) -> dict:
    return {"tenant_id": _ORDERS.get(args.get("order_id"), "<unknown>")}


def make_refund(order_id: str, amount: int, tenant_id: str) -> dict:
    # The backend accidentally returns a card + an internal token alongside the status.
    return {"status": "refunded", "card": "4111111111111111", "internal_token": "tok_live_secret"}


def build_gate() -> tuple[Gate, ApprovalStore]:
    policy = Policy(
        tools={
            "make_refund": ToolContract(
                name="make_refund",
                args=Schema(
                    {
                        "order_id": Field(type="string"),
                        "amount": Field(type="integer", minimum=1, maximum=500),
                        "tenant_id": Field(type="string"),
                    }
                ),
                returns=Schema({"status": Field(type="string")}),
                access="write",
                # inject the trusted tenant — the model cannot control it
                bindings=(Binding("tenant_id", "tenant_id"),),
                # authorize on the REAL owner of the order (resolved), not a self-declared arg
                constraints=(Constraint.owns("tenant_id"),),
                requires_confirmation=True,
                project_output=True,  # drop card / internal_token — only `status` egresses
            )
        },
        permissions={"support": frozenset({"make_refund"})},
    )
    approvals = ApprovalStore(policy)
    gate = Gate(policy, resource_resolver=_resolver, confirm=approvals.as_confirm())
    return gate, approvals


def run() -> list[tuple[str, str]]:
    """Run the scenario and return (label, outcome) pairs (used by the test)."""
    gate, approvals = build_gate()
    safe = gate.wrap(make_refund)
    support = Principal(role="support", identity="support-42", attributes={"tenant_id": "acme"})
    results: list[tuple[str, str]] = []

    with use_principal(support):
        # 1. Hijacked: drain a huge refund, spoofing the tenant.
        try:
            safe(order_id="ORD-1", amount=10_000, tenant_id="attacker")
            results.append(("huge refund", "ALLOWED?!"))
        except GateDenied as d:
            results.append(("huge refund", f"{d.decision.rule} → {d.public_reason}"))

        # 2. Reasonable amount, still spoofing the tenant → tenant is overwritten,
        #    amount ok, order really is theirs → high-risk write needs confirmation.
        try:
            safe(order_id="ORD-1", amount=400, tenant_id="attacker")
            results.append(("await confirm", "ALLOWED without confirm?!"))
        except GateConfirmationRequired as d:
            results.append(("await confirm", d.public_reason))

        # 3. A human approves the EXACT (bound) action out-of-band, then it runs —
        #    and the leaked card/token are stripped before the model sees the result.
        approvals.grant(
            request_fingerprint("make_refund", {"order_id": "ORD-1", "amount": 400, "tenant_id": "acme"}, support)
        )
        out = safe(order_id="ORD-1", amount=400, tenant_id="attacker")
        results.append(("approved+run", f"model sees {out}"))

        # 4. Try to refund another tenant's order → resource ownership fails.
        try:
            safe(order_id="ORD-OTHER", amount=100, tenant_id="acme")
            results.append(("cross-tenant", "ALLOWED?!"))
        except GateDenied as d:
            results.append(("cross-tenant", f"{d.decision.rule} → {d.public_reason}"))

    return results


def main() -> None:  # pragma: no cover
    print("Histos — makeRefund composite demo (a hijacked agent, bounded)\n")
    for label, outcome in run():
        print(f"  {label:16} {outcome}")
    print("\nRBAC passed every time. The refund was still bounded by value, ownership,")
    print("out-of-band confirmation, and output redaction — none of which the model controls.")


if __name__ == "__main__":  # pragma: no cover
    main()
