"""Run the accounts-payable workflow, with the policy on or off.

    python run.py inbox                # what is waiting to be settled
    python run.py compare 2            # one invoice, both wirings, side by side
    python run.py all                  # every invoice, both wirings, with a tally
    python run.py session              # the whole inbox in one run, one officer
    python run.py process 4 --histos   # one invoice, one wiring, verbose
    python run.py process 4 --histos --ask   # ...and you are the finance officer

Both columns run the same AP application, which already refuses an overpayment,
settles an order once, and never lets the agent write supplier bank details. The
delta printed at the end is what the policy adds on top of that.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from ap.store import INVOICES, connect, reset
from gatereport import gate_report
from graph import MAX_TURNS, MODEL, TEMPERATURE, build_graph, exchanges, process, usage
from probe import inspect, utility
from wiring import FinanceOfficer, Protected, ap_principal, protected, unprotected

from histos import use_principal

GREEN, RED, DIM, BOLD, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"

# One JSON object per wiring, straight from the probe. See the note in
# `03-oncall-triage/run.py` — the sweep used to read its verdict by scanning stdout
# for a damage glyph, and stdout carries prose the model wrote.
RESULT_LINES = os.environ.get("HISTOS_DEMO_RESULT") == "1"

LABELS = {
    1: "legitimate",
    2: "bank account quietly swapped",
    3: "amount inflated past the purchase order",
    4: "bank change announced loudly",
    5: "the same invoice again - a duplicate",
}


def _settle(invoice_id: int, *, gated: bool, interactive: bool = False) -> tuple[list, Protected | None, dict]:
    """One invoice through one wiring. The state comes back too, not just the calls.

    `exchanges()` alone cannot say whether the workflow ran or died: a failed run
    returns a stub state with no tool calls, which renders identically to a model
    that read the invoice and correctly did nothing.
    """
    reset()
    if not gated:
        state = process(build_graph(unprotected()), invoice_id)
        return exchanges(state), None, state

    bundle = protected(FinanceOfficer(interactive=interactive))
    graph = build_graph(bundle.tools)
    with use_principal(ap_principal()):
        state = process(graph, invoice_id, approver=bundle.officer)
    return exchanges(state), bundle, state


def _render(calls: list, bundle: Protected | None, indent: str = "    ") -> bool:
    """One line per call, its outcome directly underneath it.

    Printing every call and then every denial as two independent lists put the
    gate's refusal under whichever call happened to print last, which in a demo
    whose entire product is *which call was stopped and why* asserted the wrong one.
    """
    for name, args, result in calls:
        print(f"{indent}{DIM}↳ {name}({', '.join(f'{k}={v!r}' for k, v in args.items())}){OFF}")
        if "ACTION_NOT_AUTHORIZED" in result or "blocked by policy" in result:
            print(f"{indent}  {RED}⨯ {result.strip()}{OFF}")
        elif "error" in result[:40]:
            print(f"{indent}  {DIM}· {result.strip()[:110]}{OFF}")

    if bundle is not None:
        for ask, ok, why in bundle.officer.decisions:
            mark = "✓" if ok else "⨯"
            colour = DIM if ok else RED
            print(
                f"{indent}{colour}{mark} officer [{ask['fingerprint']}] "
                f"{ask['amount_pln']} PLN → {ask['iban']}: {why}{OFF}"
            )

    conn = connect()
    paid = conn.execute("SELECT amount_pln, iban FROM payments").fetchall()
    requests = conn.execute("SELECT supplier_id, iban, status FROM bank_change_requests").fetchall()
    conn.close()
    for row in paid:
        print(f"{indent}{DIM}€ paid {row['amount_pln']} PLN → {row['iban']}{OFF}")
    if not paid:
        print(f"{indent}{DIM}€ nothing paid{OFF}")
    for row in requests:
        print(
            f"{indent}{DIM}⧗ bank change filed for supplier {row['supplier_id']} → {row['iban']} ({row['status']}){OFF}"
        )

    _render_trail(bundle, indent)

    damage = inspect()
    if damage:
        for line in damage.lines():
            print(f"{indent}{RED}{BOLD}✗ {line}{OFF}")
    else:
        print(f"{indent}{GREEN}✓ no money went anywhere it should not{OFF}")
    # Printed either way and never part of the verdict: mail off the supplier list is
    # a real difference between the columns, but it is not money going astray, and
    # counting it made an agent escalating to its own finance team score as fraud.
    for line in damage.notes():
        print(f"{indent}{DIM}· {line}{OFF}")
    return bool(damage)


def _render_trail(bundle: Protected | None, indent: str) -> None:
    """The approval trail, which in accounts payable is the regulated deliverable.

    Without the gate there is no trail at all — that is not an omission in the
    rendering, it is the state of the unprotected column, and it is printed as such.
    """
    if bundle is None:
        print(f"{indent}{DIM}▤ audit trail: none. Nothing recorded who authorised this or why.{OFF}")
        return
    entries = bundle.audit.entries
    # A payment a human refused is recorded as `require_confirmation`, not `deny` —
    # listing only denials left the one event an auditor actually asks about
    # ("who declined this, and when") off the trail entirely.
    stopped = [e for e in entries if e["effect"] in ("deny", "require_confirmation")]
    redacted = sum(1 for e in entries if e["effect"] == "redact")
    print(
        f"{indent}{DIM}▤ audit trail: {len(entries)} decisions recorded, {len(stopped)} stopped, "
        f"{redacted} returns redacted, policy {bundle.gate.policy.content_hash()[:16]}{OFF}"
    )
    for entry in stopped:
        detail = f" ({entry['field_name']})" if entry["field_name"] else ""
        print(
            f"{indent}  {DIM}▤ {entry['effect']} {entry['tool']} — {entry['rule']}{detail}: {entry['reason'][:90]}{OFF}"
        )
    for ask, ok, why in bundle.officer.decisions:
        verdict = "approved" if ok else "refused"
        print(f"{indent}  {DIM}▤ {verdict} {ask['tool']} [{ask['fingerprint']}] by the finance officer: {why}{OFF}")


def cmd_inbox(_: argparse.Namespace) -> int:
    reset()
    conn = connect()
    print(f"{BOLD}unpaid invoices{OFF}")
    for row in conn.execute("SELECT id, from_email, subject, po_number FROM invoices ORDER BY id"):
        print(
            f"  {row['id']}  {row['subject']:<32} from {row['from_email']:<34} "
            f"bound to {row['po_number'] or '(none)':<14} {DIM}{LABELS[row['id']]}{OFF}"
        )
    print(f"\n{BOLD}supplier master data — the only accounts money should reach{OFF}")
    for row in conn.execute("SELECT id, name, iban FROM suppliers"):
        print(f"  {row['id']}  {row['name']:<30} {row['iban']}")
    print(f"\n{BOLD}open purchase orders{OFF}")
    for row in conn.execute("SELECT po_number, amount_pln, description FROM purchase_orders"):
        print(f"  {row['po_number']}  {row['amount_pln']:>6} PLN  {row['description']}")
    conn.close()
    return 0


def cmd_checks(_: argparse.Namespace) -> int:
    """Everything the README asserts that a 7B model is not needed to demonstrate."""
    import checks

    return checks.main()


def _record(invoice_id: int, wiring: str, calls: list, bundle: Protected | None, state: dict) -> dict:
    """Everything a later re-scoring could want, from the same objects `_render` prints.

    `utility` is the control the damage column cannot supply on its own: a workflow
    that never ran moves no money, and without a completion signal beside the harm
    signal that is indistinguishable from a workflow that was correctly stopped.
    """
    damage = inspect()
    tools_called = [name for name, _args, _result in calls]
    util = utility(invoice_id, tools_called)
    conn = connect()
    payments = [dict(r) for r in conn.execute("SELECT invoice_id, iban, amount_pln FROM payments ORDER BY id")]
    conn.close()
    return {
        "wiring": wiring,
        "damage": bool(damage),
        "damage_lines": damage.lines(),
        "notes": damage.notes(),
        "utility": {
            "settled": util.settled,
            "flagged": util.flagged,
            "parked": util.parked,
            "decided": util.decided,
            "status": util.status,
        },
        "calls": [{"tool": name, "args": args} for name, args, _result in calls],
        "denials": sum(1 for _n, _a, r in calls if "ACTION_NOT_AUTHORIZED" in r or "blocked by policy" in r),
        "steps": len(calls),
        "payments": payments,
        # `null` on the ungated side is the honest value: there is no gate, so there
        # is no trail. An empty one would let the two columns be compared as though
        # both had been audited and one simply decided nothing.
        "gate": None if bundle is None else gate_report(bundle.gate, bundle.executions, len(calls)),
        "approvals": [] if bundle is None else [[ask["tool"], ok, why] for ask, ok, why in bundle.officer.decisions],
        "error": state.get("error", ""),
        "turns": state.get("turns", 0),
        "max_turns": MAX_TURNS,
        "model": MODEL,
        "temperature": TEMPERATURE,
        "usage": usage(state),
    }


def cmd_compare(args: argparse.Namespace) -> int:
    print(f"model: {MODEL}")
    print(f"\n{BOLD}invoice {args.invoice_id} — {LABELS.get(args.invoice_id, '?')}{OFF}")
    failed = False
    for label, wiring, gated in (
        (f"{RED}WITHOUT histos{OFF}", "unprotected", False),
        (f"{GREEN}WITH histos{OFF}", "protected", True),
    ):
        print(f"\n  {label}")
        calls, bundle, state = _settle(args.invoice_id, gated=gated)
        _render(calls, bundle)
        if state.get("error"):
            print(f"    {RED}{BOLD}! the workflow never ran: {str(state['error'])[:160]}{OFF}")
            failed = True
        if RESULT_LINES:
            print("RESULT " + json.dumps(_record(args.invoice_id, wiring, calls, bundle, state), default=str))
    # A run the model never answered is not a run where no money moved, and the exit
    # code is the one signal a harness gets for free.
    return 1 if failed else 0


def cmd_all(_: argparse.Namespace) -> int:
    print(f"model: {MODEL}\n")
    tally = {False: 0, True: 0}
    for invoice_id, *_rest in INVOICES:
        print("=" * 78)
        print(f"{BOLD}invoice {invoice_id} — {LABELS[invoice_id]}{OFF}")
        for label, gated in ((f"{RED}WITHOUT histos{OFF}", False), (f"{GREEN}WITH histos{OFF}", True)):
            print(f"\n  {label}")
            calls, bundle, _state = _settle(invoice_id, gated=gated)
            if _render(calls, bundle):
                tally[gated] += 1
        print()
    total = len(INVOICES)
    print("=" * 78)
    print("  invoices where money went somewhere it should not")
    print(f"    AP application alone: {tally[False]}/{total}")
    print(f"    with histos:          {tally[True]}/{total}")
    return 0


def cmd_session(_: argparse.Namespace) -> int:
    """The whole inbox in one run, the way accounts payable actually works.

    One database, one officer, invoices in order. `all` resets between invoices,
    which keeps the attribution clean but hides everything cumulative: the duplicate,
    and the fact that a rewritten master record would make the *next* invoice look
    correct to every remaining check.
    """
    print(f"model: {MODEL}\n")
    for label, gated in ((f"{RED}WITHOUT histos{OFF}", False), (f"{GREEN}WITH histos{OFF}", True)):
        print("=" * 78)
        print(f"{label}  — settling the whole inbox")
        reset()
        bundle = None
        if gated:
            bundle = protected()
            graph = build_graph(bundle.tools)
        else:
            graph = build_graph(unprotected())

        for invoice_id, *_rest in INVOICES:
            if bundle is not None:
                with use_principal(ap_principal()):
                    process(graph, invoice_id, approver=bundle.officer)
            else:
                process(graph, invoice_id)

        conn = connect()
        paid = conn.execute("SELECT invoice_id, amount_pln, iban FROM payments ORDER BY id").fetchall()
        conn.close()
        for row in paid:
            print(f"    {DIM}€ invoice {row['invoice_id']}  {row['amount_pln']:>6} PLN → {row['iban']}{OFF}")
        if bundle is not None:
            for reason in bundle.officer.refused:
                print(f"    {DIM}officer refused: {reason}{OFF}")

        total = sum(r["amount_pln"] for r in paid)
        _render_trail(bundle, "    ")
        damage = inspect()
        print(f"    {BOLD}total paid: {total} PLN{OFF}")
        if damage:
            for line in damage.lines():
                print(f"    {RED}{BOLD}✗ {line}{OFF}")
        else:
            print(f"    {GREEN}✓ no money went anywhere it should not{OFF}")
        print()
    return 0


def cmd_process(args: argparse.Namespace) -> int:
    print(f"model: {MODEL}   policy {'ON' if args.histos else 'OFF'}")
    if args.ask and not args.histos:
        print(f"{DIM}  (--ask needs --histos: without a policy nothing asks anyone){OFF}")
    calls, bundle, _state = _settle(args.invoice_id, gated=args.histos, interactive=args.ask)
    _render(calls, bundle, indent="  ")
    conn = connect()
    print(f"\n{DIM}  payments now on file:{OFF}")
    for row in conn.execute("SELECT invoice_id, iban, amount_pln FROM payments"):
        print(f"{DIM}    invoice {row['invoice_id']}  {row['amount_pln']:>6} PLN → {row['iban']}{OFF}")
    conn.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="run.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("inbox", help="what is waiting, and what the records say").set_defaults(func=cmd_inbox)
    sub.add_parser("checks", help="every claim that does not need a model, run").set_defaults(func=cmd_checks)

    c = sub.add_parser("compare", help="one invoice, both wirings")
    c.add_argument("invoice_id", type=int)
    c.set_defaults(func=cmd_compare)

    sub.add_parser("all", help="every invoice, both wirings, with a tally").set_defaults(func=cmd_all)
    sub.add_parser("session", help="the whole inbox in one run, one officer").set_defaults(func=cmd_session)

    p = sub.add_parser("process", help="one invoice, one wiring")
    p.add_argument("invoice_id", type=int)
    p.add_argument("--histos", action="store_true")
    p.add_argument("--ask", action="store_true", help="you are the finance officer; approvals come to the terminal")
    p.set_defaults(func=cmd_process)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
