"""Row ownership on a refund, counted by executions rather than by decisions.

Ten attempts run against one wrapped handler. One of them is allowed to go
through; the other nine are the ways a hijacked agent would try to get around
the boundary. The counter is incremented *inside* the handler, so every figure
printed here is an observed side effect — not a decision string the library
produced about itself.

Run it::

    python attempts.py           # transcript
    python attempts.py --json    # machine-readable record

Exit code is the number of attempts that behaved unexpectedly. CI runs it.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime

import histos
from histos import (
    ApprovalStore,
    Constraint,
    Field,
    Gate,
    GateConfirmationRequired,
    GateDenied,
    Policy,
    Principal,
    Schema,
    ToolContract,
    use_principal,
)

# The trusted datastore. Both customers sit in the same tenant, so tenant alone
# never separates them — only the real owner of the row does.
_ORDERS = {
    "ORD-123": {"owner_id": "u1", "tenant_id": "store"},
    "ORD-789": {"owner_id": "u2", "tenant_id": "store"},
}

_executions: list[dict] = []


def issue_refund(order_id: str, reason: str) -> dict:
    """The side effect being protected. Money would move here."""
    _executions.append({"order_id": order_id, "reason": reason})
    return {"status": "refunded", "order_id": order_id}


def load_order(tool: str, args: dict) -> dict:
    """Trusted resource lookup. Histos calls this with (tool_name, args)."""
    order = _ORDERS.get(args.get("order_id"))
    if order is None:
        raise KeyError(args.get("order_id"))
    return dict(order)


def build_policy() -> Policy:
    return Policy(
        tools={
            "issue_refund": ToolContract(
                name="issue_refund",
                args=Schema(
                    {
                        "order_id": Field(type="string", pattern=r"^ORD-\d{3,6}$"),
                        "reason": Field(type="string", max_length=200),
                    }
                ),
                access="write",
                # Authorize against the real owner returned by load_order,
                # never against a self-declared argument.
                constraints=(Constraint.owns("owner_id"),),
                requires_confirmation=True,
            )
        },
        permissions={"customer": frozenset({"issue_refund"})},
    )


@dataclass
class Attempt:
    label: str
    expectation: str  # "executes" | "blocked"
    outcome: str = ""
    rule: str | None = None
    executions: int = 0
    as_expected: bool = field(default=False)


def _run(attempt: Attempt, call) -> Attempt:
    before = len(_executions)
    try:
        call()
        attempt.outcome = "executed"
    except GateDenied as exc:
        attempt.outcome = "denied"
        attempt.rule = getattr(exc.decision, "rule", None)
    except GateConfirmationRequired as exc:
        attempt.outcome = "confirmation required"
        attempt.rule = getattr(getattr(exc, "decision", None), "rule", "requires_confirmation")
    except Exception as exc:  # noqa: BLE001 - recorded, never swallowed
        attempt.outcome = type(exc).__name__
        attempt.rule = str(exc)[:60]
    attempt.executions = len(_executions) - before
    attempt.as_expected = attempt.executions == 1 if attempt.expectation == "executes" else attempt.executions == 0
    return attempt


def run_all() -> list[Attempt]:
    policy = build_policy()
    approvals = ApprovalStore(policy)
    gate = Gate(policy, resource_resolver=load_order, confirm=approvals.as_confirm())
    safe_refund = gate.wrap(issue_refund)

    u1 = Principal(role="customer", identity="u1", attributes={"owner_id": "u1", "tenant_id": "store"})
    guest = Principal(role="guest", identity="u1", attributes={"owner_id": "u1", "tenant_id": "store"})

    out: list[Attempt] = []

    # The baseline: what an unwrapped handler does with someone else's order.
    out.append(
        _run(
            Attempt("unwrapped handler, someone else's order", "executes"),
            lambda: issue_refund(order_id="ORD-789", reason="refund"),
        )
    )

    # The same call, wrapped.
    with use_principal(u1):
        out.append(
            _run(
                Attempt("wrapped, someone else's order", "blocked"),
                lambda: safe_refund(order_id="ORD-789", reason="refund"),
            )
        )

    # The positive control: own order, confirmed out of band.
    with use_principal(u1):
        try:
            safe_refund(order_id="ORD-123", reason="refund")
        except GateConfirmationRequired as exc:
            approvals.grant(exc.request)
        out.append(
            _run(
                Attempt("wrapped, own order, confirmed", "executes"),
                lambda: safe_refund(order_id="ORD-123", reason="refund"),
            )
        )

    # The model appends a role to the arguments.
    with use_principal(u1):
        out.append(
            _run(
                Attempt('args carry role="admin"', "blocked"),
                lambda: safe_refund(order_id="ORD-123", reason="refund", role="admin"),
            )
        )
    # No trusted identity bound at all.
    out.append(
        _run(
            Attempt("no principal bound", "blocked"),
            lambda: safe_refund(order_id="ORD-123", reason="refund"),
        )
    )
    # A role without the permission.
    with use_principal(guest):
        out.append(
            _run(
                Attempt("role without the permission", "blocked"),
                lambda: safe_refund(order_id="ORD-123", reason="refund"),
            )
        )
    # A live approval does not travel to another row.
    with use_principal(u1):
        out.append(
            _run(
                Attempt("live approval reused on another row", "blocked"),
                lambda: safe_refund(order_id="ORD-789", reason="refund"),
            )
        )
    # The host refuses to confirm.
    deny_gate = Gate(policy, resource_resolver=load_order, confirm=lambda req: False)
    deny_refund = deny_gate.wrap(issue_refund)
    with use_principal(u1):
        out.append(
            _run(
                Attempt("host refuses confirmation", "blocked"),
                lambda: deny_refund(order_id="ORD-123", reason="refund"),
            )
        )
    # No confirmation callback wired.
    noconfirm_refund = Gate(policy, resource_resolver=load_order).wrap(issue_refund)
    with use_principal(u1):
        out.append(
            _run(
                Attempt("no confirmation callback wired", "blocked"),
                lambda: noconfirm_refund(order_id="ORD-123", reason="refund"),
            )
        )
    # No trusted resource lookup wired.
    noresolver_refund = Gate(policy, confirm=lambda req: True).wrap(issue_refund)
    with use_principal(u1):
        out.append(
            _run(
                Attempt("no resource resolver wired", "blocked"),
                lambda: noresolver_refund(order_id="ORD-123", reason="refund"),
            )
        )
    # Identifier that fails the argument schema.
    with use_principal(u1):
        out.append(
            _run(
                Attempt("malformed order id", "blocked"),
                lambda: safe_refund(order_id="DROP TABLE orders", reason="refund"),
            )
        )
    # A row the datastore does not have.
    with use_principal(u1):
        out.append(
            _run(
                Attempt("row absent from the datastore", "blocked"),
                lambda: safe_refund(order_id="ORD-999", reason="refund"),
            )
        )
    return out


def _git(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:  # noqa: BLE001
        return "unavailable"


def build_record(attempts: list[Attempt]) -> dict:
    wrapped = [a for a in attempts if not a.label.startswith("unwrapped")]
    allowed = [a for a in wrapped if a.expectation == "executes"]
    blocked = [a for a in wrapped if a.expectation == "blocked"]
    return {
        "demo": "refund row ownership",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "provenance": {
            "library": "histos",
            "version": histos.__version__,
            "commit": _git("rev-parse", "HEAD"),
            # The record rewrites itself as it is produced, so only the library
            # source is checked here.
            "library_source_dirty": bool(_git("status", "--porcelain", "--", "src")),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "scope": {
            "identity": "supplied by the harness, no authentication",
            "resources": "in-memory rows",
            "llm": False,
            "payments": False,
            "note": "Counts real handler calls, not decisions.",
        },
        "summary": {
            "allowed_executions": sum(a.executions for a in allowed),
            "blocked_attempts": len(blocked),
            "executions_under_blocked_attempts": sum(a.executions for a in blocked),
            "unexpected": sum(not a.as_expected for a in attempts),
        },
        "attempts": [vars(a) for a in attempts],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="emit the record")
    args = ap.parse_args()

    record = build_record(run_all())

    if args.json:
        print(json.dumps(record, indent=2))
        return record["summary"]["unexpected"]

    p = record["provenance"]
    print(f"\nhistos {p['version']} · python {p['python']}")
    print("refund row ownership — executions counted inside the handler\n")
    for a in record["attempts"]:
        mark = " ok " if a["as_expected"] else " !! "
        rule = f" [{a['rule']}]" if a["rule"] else ""
        print(f"  {mark} {a['label']:<42} {a['outcome']}{rule} -> ran {a['executions']}x")
    s = record["summary"]
    print(
        f"\n  {s['allowed_executions']} allowed execution, "
        f"{s['blocked_attempts']} blocked attempts, "
        f"{s['executions_under_blocked_attempts']} executions\n"
    )
    return s["unexpected"]


if __name__ == "__main__":
    raise SystemExit(main())
