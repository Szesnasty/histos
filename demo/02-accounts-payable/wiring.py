"""The same workflow, twice: as a competent AP team already has it, and behind a policy.

`unprotected()` is not a straw man. It is the AP application with the controls a
2026 finance function genuinely runs — the agent has no write access to supplier
bank details, two-way matching refuses a payment larger than its order, and an
order is settled once. Those live in `ap/tools.py` and they are in **both**
columns. The delta this demo reports is only what histos adds *on top of* that.

The resolver is the interesting half of the policy. A policy file can say *"the
payee must match the supplier master record"*, but only the application knows how
to work out whether it does — which purchase order this invoice belongs to, which
supplier that is, and what account is on file for them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ap import tools as ap_tools
from ap.store import connect
from gatereport import Executions
from langchain_core.tools import StructuredTool
from langgraph.errors import GraphInterrupt
from langgraph.types import interrupt

from histos import Gate, Principal, load_policy
from histos.integrations.langchain import protect_tools
from histos.mediate.approvals import fingerprint_of
from histos.trail.audit import InMemoryAuditSink

POLICY_PATH = Path(__file__).resolve().parent / "security.policy.yaml"


def _as_langchain_tools(functions: list[Any]) -> list[StructuredTool]:
    return [
        StructuredTool.from_function(fn, name=fn.__name__, description=(fn.__doc__ or "").strip()) for fn in functions
    ]


def unprotected() -> list[StructuredTool]:
    """The AP functions the workflow is given, with no policy anywhere."""
    return _as_langchain_tools(ap_tools.ALL_TOOLS)


# ── the half a policy file cannot contain ────────────────────────────────


def purchase_order_for(invoice_id: Any) -> tuple[str, int, int] | None:
    """`(po_number, supplier_id, agreed_amount)` for the order this invoice is bound to.

    One lookup, deliberately shared. The resolver, the finance officer and the
    briefing are different *controls* and all are worth having — but "which order is
    this, and what did we agree" is one *fact*, and answering it three times is how
    three controls end up validating three different orders.

    The order number is read from the `po_number` column, not parsed out of the
    email here. Ingestion extracted it once and stored it (`ap/store.py`). That does
    not make it trustworthy — a sender writes their own reference either way — but
    it means an email that names two orders binds to neither and is refused, instead
    of every control re-parsing the text and each landing on a different answer.
    """
    if invoice_id is None:
        return None
    conn = connect()
    try:
        invoice = conn.execute("SELECT po_number FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
        if invoice is None or invoice["po_number"] is None:
            return None
        po = conn.execute(
            "SELECT supplier_id, amount_pln FROM purchase_orders WHERE po_number = ?", (invoice["po_number"],)
        ).fetchone()
        return (invoice["po_number"], int(po["supplier_id"]), int(po["amount_pln"])) if po else None
    finally:
        conn.close()


def _supplier_domains() -> set[str]:
    """The domains the company actually buys from, read from the supplier master.

    This used to be a regex in the policy file naming three brands. That is the
    supplier master maintained a second time, by hand, in a file nobody updates when
    procurement onboards a vendor — and the failure mode is silent: correspondence
    with a real supplier starts bouncing, so somebody widens the pattern.
    """
    conn = connect()
    try:
        return {row["email"].rsplit("@", 1)[-1].lower() for row in conn.execute("SELECT email FROM suppliers")}
    finally:
        conn.close()


def resolve_resource(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Work out, from the company's own records, whether this call is the right one.

    Returns facts about the resource being touched, never a restatement of the
    arguments. Every value here is read from a company table; the invoice body is
    never consulted, because it is the thing under suspicion.
    """
    if tool_name == "schedule_payment":
        order = purchase_order_for(args.get("invoice_id"))
        if order is None:
            # An invoice with no single order behind it cannot be validated against
            # anything, so both facts are false and the payment fails closed.
            return {"payee_matches_supplier_record": False, "amount_matches_purchase_order": False}
        _po_number, supplier_id, agreed = order
        conn = connect()
        try:
            supplier = conn.execute("SELECT iban FROM suppliers WHERE id = ?", (supplier_id,)).fetchone()
        finally:
            conn.close()
        return {
            "payee_matches_supplier_record": bool(supplier) and args.get("iban") == supplier["iban"],
            "amount_matches_purchase_order": int(args.get("amount_pln", -1)) == agreed,
        }

    if tool_name == "send_email":
        recipient = str(args.get("to", ""))
        domain = recipient.rsplit("@", 1)[-1].lower() if "@" in recipient else ""
        return {"recipient_domain_on_file": domain in _supplier_domains()}

    return {}


# ── the human the policy asks for ────────────────────────────────────────


@dataclass(frozen=True)
class ApprovalAsk:
    """What a human is shown when the gate stops for confirmation.

    Built from the `GateRequest` — the tool, its arguments and the principal — plus
    the facts the company's own records give about them. The fingerprint is the
    gate's own binding: an approval is for this tool, these exact arguments, this
    principal. It cannot be replayed for a different account.
    """

    tool: str
    fingerprint: str
    invoice_id: int | None
    amount_pln: int | None
    iban: str | None
    po_number: str | None
    agreed_pln: int | None

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _ask_from(request: Any) -> dict[str, Any]:
    args = dict(request.args)
    order = purchase_order_for(args.get("invoice_id"))
    return ApprovalAsk(
        tool=request.tool_name,
        fingerprint=fingerprint_of(request)[:16],
        invoice_id=args.get("invoice_id"),
        amount_pln=args.get("amount_pln"),
        iban=args.get("iban"),
        po_number=order[0] if order else None,
        agreed_pln=order[2] if order else None,
    ).as_dict()


def suspend_for_approval(request: Any) -> bool:
    """The gate's confirmation callback: suspend the graph and wait for a person.

    This is the seam between the two halves. `interrupt()` is LangGraph's own
    human-in-the-loop primitive — it checkpoints the run and raises out to the
    caller, who resumes with `Command(resume=...)`. Putting it *here*, inside the
    gate's confirmation hook, rather than on an edge in `graph.py`, is the whole
    argument of this demo in one function:

    * the model calls `schedule_payment` on whichever pass through `act` it chooses,
      so there is no edge to attach an approval to without re-implementing "is this
      call a payment?" in graph code — which is the policy, written twice;
    * the gate has already run RBAC, the argument schema and `resource.where` before
      it gets here, so the human is asked only about calls that were otherwise
      allowed, and is shown what the records say rather than what the email says;
    * the callback is host code. It is not a tool. An injected agent cannot call it,
      and cannot self-approve.

    On resume LangGraph re-enters the `act` node, the gate re-decides, and this
    callback is reached a second time — where `interrupt()` returns the answer
    instead of raising. The gate's rate limit and budget are consumed *after* the
    callback returns, so nothing is double-counted.
    """
    return bool(interrupt(_ask_from(request)))


class FinanceOfficer:
    """An honest model of what a finance officer actually checks.

    The first version of this class granted its own approval inside the callback and
    then consumed it, which is `confirm=lambda req: True` wearing a costume.
    `SECURITY.md` names that exact trap, so it was wrong on the demo's own terms.

    This one refuses. It approves a payment when the amount matches the purchase
    order sitting on the desk — the check a finance officer genuinely performs — and
    **does not verify the account number**, because that is the check humans famously
    skip and the reason business email compromise works at all. The account is
    checked by `resource.where`, in code, before the human is ever asked.

    `settled_orders` is a second, independent duplicate catch. `schedule_payment`
    already closes a purchase order when it pays it, so the *baseline* refuses a
    duplicate too and this officer is not what saves the money. It is kept because
    two people who each independently remember is how AP actually works, and removed
    from the scoreboard because it is not a histos win.
    """

    def __init__(self, *, rubber_stamp: bool = False, interactive: bool = False) -> None:
        self.rubber_stamp = rubber_stamp
        self.interactive = interactive
        self.asked: list[dict[str, Any]] = []
        self.decisions: list[tuple[dict[str, Any], bool, str]] = []
        self.settled_orders: set[str] = set()

    @property
    def refused(self) -> list[str]:
        return [why for _ask, ok, why in self.decisions if not ok]

    @property
    def approved(self) -> list[str]:
        return [why for _ask, ok, why in self.decisions if ok]

    def __call__(self, ask: dict[str, Any]) -> bool:
        self.asked.append(ask)
        ok, why = self._judge(ask)
        self.decisions.append((ask, ok, why))
        return ok

    def _judge(self, ask: dict[str, Any]) -> tuple[bool, str]:
        if self.interactive:
            print(
                f"\n    approval requested: {ask['tool']}  invoice {ask['invoice_id']}  "
                f"{ask['amount_pln']} PLN → {ask['iban']}"
                f"\n    our records: {ask['po_number']} agreed at {ask['agreed_pln']} PLN"
                f"\n    request fingerprint {ask['fingerprint']}"
            )
            answer = input("    approve? [y/N] ").strip().lower() == "y"
            return answer, "approved at the terminal" if answer else "refused at the terminal"
        if self.rubber_stamp:
            return True, "rubber stamp"

        if ask.get("agreed_pln") is None:
            return False, "no purchase order I can match this to"
        if int(ask.get("amount_pln") or 0) != int(ask["agreed_pln"]):
            return False, f"{ask['amount_pln']} PLN against an order of {ask['agreed_pln']} — not what was agreed"
        if ask["po_number"] in self.settled_orders:
            return False, f"{ask['po_number']} was already approved earlier today — this is a duplicate"
        self.settled_orders.add(ask["po_number"])
        return True, f"{ask['amount_pln']} PLN matches {ask['po_number']}"


@dataclass
class Protected:
    """Everything the protected wiring hands back: the tools, the human, the trail."""

    tools: list[StructuredTool]
    officer: FinanceOfficer
    gate: Gate
    audit: InMemoryAuditSink
    #: Counts tool bodies that actually ran, wrapped *inside* the gate so anything
    #: reaching a function is counted whichever path it took.
    executions: Executions = field(default_factory=Executions)

    def denials(self) -> list[dict[str, Any]]:
        return [e for e in self.audit.entries if e["effect"] == "deny"]

    def __iter__(self):  # so `tools, officer = protected()` still reads naturally
        return iter((self.tools, self.officer))


def protected(officer: FinanceOfficer | None = None) -> Protected:
    """The same functions, gated, with the human the policy inserts.

    The audit sink is not decoration. In accounts payable the approval trail *is*
    the regulated deliverable — an auditor asks who authorised a payment and on what
    basis, and "the model decided" is not an answer. The gate records every decision
    it makes, allow and deny alike, with the rule that fired and the hash of the
    policy that produced it.
    """
    officer = officer or FinanceOfficer()
    audit = InMemoryAuditSink()
    gate = Gate(
        load_policy(POLICY_PATH),
        resource_resolver=resolve_resource,
        confirm=suspend_for_approval,
        # `interrupt()` signals by RAISING, which is how LangGraph checkpoints a run
        # and hands control back. The gate treats a raising `confirm` as fail-closed —
        # correct for an approvals queue that is down, wrong for one that is merely
        # asking — so the host says which exception means "suspended, nothing ran".
        confirm_suspends=(GraphInterrupt,),
        audit=audit,
    )
    executions = Executions()
    counted = _as_langchain_tools(executions.wrap_all(ap_tools.ALL_TOOLS))
    return Protected(protect_tools(counted, gate=gate), officer, gate, audit, executions)


def ap_principal() -> Principal:
    """The workflow's own identity, bound by the host — not by anything it reads."""
    return Principal(role="ap_agent", identity="svc:ap-workflow")
