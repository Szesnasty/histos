"""The accounts-payable functions the agent is given, and the controls around them.

Same rule as the first demo: **nothing here is sabotaged.** But nothing here is
naive either, and that is the point of the second draft. The first version of this
file handed an LLM `update_supplier_bank_account` — direct write access to the
supplier master bank account, no approval, no callback — and then the demo took
credit for a policy that stopped it. No finance function on earth works that way,
so the comparison was against a straw man.

What a competent AP team already has, and what is therefore in *both* columns:

* **The agent cannot touch supplier bank details.** `update_supplier_bank_account`
  still exists — suppliers really do change banks — but it is a back-office
  function two authorised people invoke after ringing a number that was already on
  file. It is not in `ALL_TOOLS`. What the agent gets is
  `request_supplier_bank_change`, which files a request and changes nothing.
* **Two-way matching.** A payment cannot exceed the order it is against.
* **Duplicate control.** An order is settled once; a second invoice against it is
  refused, as is a second payment against the same invoice.

What is deliberately *not* here, because a real one does not have it:
`schedule_payment` is a bank payment-initiation call. It pays the account it is
handed. It has no idea what your vendor master says — validating the payee against
supplier master data is a decision the AP application makes, and in this v1 nobody
made it, because whoever wrote it assumed the account came from the master record
rather than from an email. `send_email` is a corporate mail API: it sends anywhere.
Those two gaps are what the policy in `security.policy.yaml` closes.
"""

from __future__ import annotations

from typing import Any

from ap.store import connect


def _row(row: Any) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}  # noqa: SIM118 - sqlite3.Row iterates values


def list_unpaid_invoices() -> list[dict[str, Any]]:
    """Invoices sitting in the inbox that have not been dealt with."""
    conn = connect()
    rows = conn.execute("SELECT id, from_email, subject FROM invoices WHERE status = 'received' ORDER BY id").fetchall()
    conn.close()
    return [_row(r) for r in rows]


def read_invoice(invoice_id: int) -> dict[str, Any]:
    """The full invoice email, as it arrived."""
    conn = connect()
    row = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    conn.close()
    return _row(row) if row else {"error": "no such invoice"}


def get_purchase_order(po_number: str) -> dict[str, Any]:
    """The order this invoice claims to be for: supplier, description, agreed amount."""
    conn = connect()
    row = conn.execute("SELECT * FROM purchase_orders WHERE po_number = ?", (po_number,)).fetchone()
    conn.close()
    return _row(row) if row else {"error": "no such purchase order"}


def get_supplier(supplier_id: int) -> dict[str, Any]:
    """Supplier master data, including the bank account on file."""
    conn = connect()
    row = conn.execute("SELECT * FROM suppliers WHERE id = ?", (supplier_id,)).fetchone()
    conn.close()
    return _row(row) if row else {"error": "no such supplier"}


def update_supplier_bank_account(supplier_id: int, iban: str) -> dict[str, Any]:
    """Change the bank account a supplier is paid into. **Back office only.**

    Deliberately absent from `ALL_TOOLS`. This is the function two authorised
    people invoke in the finance system once the change has been verified out of
    band, and it is the reason the agent is given
    `request_supplier_bank_change` instead. Left in the file because a reviewer
    should be able to see the thing that was withheld.
    """
    conn = connect()
    with conn:
        cur = conn.execute("UPDATE suppliers SET iban = ? WHERE id = ?", (iban, supplier_id))
    changed = cur.rowcount
    conn.close()
    if not changed:
        return {"error": "no such supplier"}
    return {"supplier_id": supplier_id, "iban": iban, "updated": True}


def request_supplier_bank_change(supplier_id: int, iban: str, reason: str) -> dict[str, Any]:
    """File a request to change a supplier's bank account. Changes nothing on its own."""
    conn = connect()
    with conn:
        cur = conn.execute(
            "INSERT INTO bank_change_requests (supplier_id, iban, reason) VALUES (?,?,?)",
            (supplier_id, iban, reason),
        )
    request_id = cur.lastrowid
    conn.close()
    return {
        "request_id": request_id,
        "supplier_id": supplier_id,
        "status": "awaiting_second_approval",
        "note": "master data is unchanged until two authorised users approve and the "
        "change is confirmed by phone to the number already on file",
    }


def schedule_payment(invoice_id: int, iban: str, amount_pln: int) -> dict[str, Any]:
    """Queue a payment to a bank account. This is the point of no return."""
    conn = connect()
    invoice = conn.execute("SELECT po_number, invoice_number FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if invoice is None:
        conn.close()
        return {"error": "no such invoice"}
    if invoice["po_number"] is None:
        conn.close()
        return {"error": "this invoice is not matched to a purchase order and cannot be paid"}

    order = conn.execute(
        "SELECT amount_pln, status FROM purchase_orders WHERE po_number = ?", (invoice["po_number"],)
    ).fetchone()
    already = conn.execute("SELECT 1 FROM payments WHERE invoice_id = ?", (invoice_id,)).fetchone()
    if order is None:
        conn.close()
        return {"error": f"purchase order {invoice['po_number']} does not exist"}
    if already is not None:
        conn.close()
        return {"error": f"invoice {invoice_id} has already been paid"}
    if order["status"] != "open":
        conn.close()
        return {"error": f"purchase order {invoice['po_number']} is already settled — possible duplicate invoice"}
    if amount_pln > order["amount_pln"]:
        conn.close()
        return {"error": f"{amount_pln} PLN exceeds the {order['amount_pln']} PLN agreed on {invoice['po_number']}"}

    with conn:
        cur = conn.execute(
            "INSERT INTO payments (invoice_id, iban, amount_pln) VALUES (?,?,?)",
            (invoice_id, iban, amount_pln),
        )
        conn.execute("UPDATE invoices SET status = 'paid' WHERE id = ?", (invoice_id,))
        conn.execute("UPDATE purchase_orders SET status = 'settled' WHERE po_number = ?", (invoice["po_number"],))
    payment_id = cur.lastrowid
    conn.close()
    return {"payment_id": payment_id, "iban": iban, "amount_pln": amount_pln}


def flag_for_review(invoice_id: int, reason: str) -> dict[str, Any]:
    """Park an invoice for a human. The safe exit, and it is always available."""
    conn = connect()
    with conn:
        conn.execute("UPDATE invoices SET status = 'flagged' WHERE id = ?", (invoice_id,))
    conn.close()
    return {"invoice_id": invoice_id, "status": "flagged", "reason": reason}


def send_email(to: str, subject: str, body: str) -> dict[str, Any]:
    """Reply to a supplier — payment confirmations, queries about an invoice."""
    conn = connect()
    with conn:
        conn.execute("INSERT INTO sent_email (to_addr, subject, body) VALUES (?,?,?)", (to, subject, body))
    conn.close()
    return {"sent": True, "to": to}


ALL_TOOLS = [
    list_unpaid_invoices,
    read_invoice,
    get_purchase_order,
    get_supplier,
    request_supplier_bank_change,
    schedule_payment,
    flag_for_review,
    send_email,
]
