"""The clinic's domain functions: ids in, rows out. No authorization, by design.

This is the service layer of an ordinary booking system, and it is deliberately
the layer that does *not* decide who may do what. `cancel_appointment` takes an
appointment id and cancels that appointment; `get_patient` takes a patient id and
returns that patient. Every function validates what a function validates —
`book_appointment` refuses a double-booking, `find_free_slots` parses its date —
and none of them asks who is calling, because nothing in this file knows.

That is not a hole in this file. It is where the boundary is. Authorization lives
one layer up, in whatever front end supplies the ids: an HTTP handler reads them
from the session, a back-office screen reads them from the logged-in operator.
Both wirings in `wiring.py` add that layer, one by hand and one by policy, and
neither of them changes a line below.

The mistake this demo is about is handing these functions *straight* to a model,
which is the only caller that makes up its own ids out of text it was given.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from clinic.store import connect

OPENING_HOUR, CLOSING_HOUR = 8, 18


def _row_to_dict(row: Any) -> dict[str, Any]:
    # `.keys()` is required here: iterating a sqlite3.Row yields its *values*, so
    # the shorter spelling ruff suggests would build a dict keyed by data.
    return {k: row[k] for k in row.keys()}  # noqa: SIM118


def find_patient_by_phone(phone: str) -> dict[str, Any]:
    """Look a patient up by the phone number they are calling from.

    Called by the switchboard before the model starts, to turn a calling line into
    a caller. It is not on the agent's toolbelt: the identity it produces is the
    one value in the system the model must not be able to influence, so the model
    does not get a tool that recomputes it.
    """
    conn = connect()
    row = conn.execute("SELECT * FROM patients WHERE phone = ?", (phone,)).fetchone()
    conn.close()
    if row is None:
        return {"error": "no patient with that phone number"}
    return _row_to_dict(row)


def get_patient(patient_id: int) -> dict[str, Any]:
    """Full patient record: name, phone, national identity number and the intake note."""
    conn = connect()
    row = conn.execute("SELECT * FROM patients WHERE id = ?", (patient_id,)).fetchone()
    conn.close()
    if row is None:
        return {"error": "no such patient"}
    return _row_to_dict(row)


def list_appointments(patient_id: int) -> list[dict[str, Any]]:
    """Every upcoming appointment for a patient, with therapist and service."""
    conn = connect()
    rows = conn.execute(
        """SELECT a.id, a.starts_at, a.status, t.full_name AS therapist,
                  s.name AS service, s.price_pln
           FROM appointments a
           JOIN therapists t ON t.id = a.therapist_id
           JOIN services   s ON s.id = a.service_id
           WHERE a.patient_id = ? AND a.status = 'booked'
           ORDER BY a.starts_at""",
        (patient_id,),
    ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def list_services() -> list[dict[str, Any]]:
    """The price list."""
    conn = connect()
    rows = conn.execute("SELECT id, name, minutes, price_pln FROM services").fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def find_free_slots(therapist_id: int, date: str) -> list[str]:
    """Open starting times for one therapist on one day (YYYY-MM-DD)."""
    try:
        day = datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        return []
    conn = connect()
    taken = {
        r["starts_at"]
        for r in conn.execute(
            "SELECT starts_at FROM appointments WHERE therapist_id = ? AND status = 'booked'",
            (therapist_id,),
        ).fetchall()
    }
    conn.close()
    slots = []
    for hour in range(OPENING_HOUR, CLOSING_HOUR):
        stamp = (day + timedelta(hours=hour)).strftime("%Y-%m-%dT%H:%M")
        if stamp not in taken:
            slots.append(stamp)
    return slots


def book_appointment(patient_id: int, therapist_id: int, service_id: int, starts_at: str) -> dict[str, Any]:
    """Book a slot. Refuses a double-booking, which is the check that actually matters here."""
    conn = connect()
    clash = conn.execute(
        "SELECT 1 FROM appointments WHERE therapist_id = ? AND starts_at = ? AND status = 'booked'",
        (therapist_id, starts_at),
    ).fetchone()
    if clash:
        conn.close()
        return {"error": "that slot is already taken"}
    with conn:
        cur = conn.execute(
            "INSERT INTO appointments (patient_id, therapist_id, service_id, starts_at, status) "
            "VALUES (?,?,?,?,'booked')",
            (patient_id, therapist_id, service_id, starts_at),
        )
    appointment_id = cur.lastrowid
    conn.close()
    return {"appointment_id": appointment_id, "starts_at": starts_at, "status": "booked"}


def cancel_appointment(appointment_id: int) -> dict[str, Any]:
    """Cancel one appointment."""
    conn = connect()
    with conn:
        cur = conn.execute(
            "UPDATE appointments SET status = 'cancelled' WHERE id = ? AND status = 'booked'",
            (appointment_id,),
        )
    changed = cur.rowcount
    conn.close()
    if not changed:
        return {"error": "no such booked appointment"}
    return {"appointment_id": appointment_id, "status": "cancelled"}


def reschedule_appointment(appointment_id: int, new_starts_at: str) -> dict[str, Any]:
    """Move an appointment to a new time."""
    conn = connect()
    with conn:
        cur = conn.execute(
            "UPDATE appointments SET starts_at = ? WHERE id = ? AND status = 'booked'",
            (new_starts_at, appointment_id),
        )
    changed = cur.rowcount
    conn.close()
    if not changed:
        return {"error": "no such booked appointment"}
    return {"appointment_id": appointment_id, "starts_at": new_starts_at, "status": "booked"}


def send_sms(phone: str, body: str) -> dict[str, Any]:
    """Send an SMS. The clinic uses this for confirmations and reminders. The result's
    `to` is the number actually texted; report that, never the `phone` you passed."""
    # The docstring is the tool description the model reads, so it is kept to the two
    # facts the model must act on. The reason is here instead: under the policy
    # `phone` is overwritten from the verified calling line before this function
    # runs, so `to` is the only record of where the message went, and an assistant
    # that reports its own argument tells the caller something untrue. Every word
    # added here is a word the model weighs before deciding to call at all — a
    # longer version of this docstring stopped `qwen2.5:7b` calling `send_sms`
    # entirely and had it ask the caller to confirm the number instead.
    conn = connect()
    with conn:
        conn.execute("INSERT INTO sent_messages (to_phone, body) VALUES (?,?)", (phone, body))
    conn.close()
    return {"sent": True, "to": phone}


# What the receptionist agent can reach. `find_patient_by_phone` is missing on
# purpose and stays missing in both wirings: a tool that maps any phone number to
# a full patient record has no job in a conversation with one identified caller,
# and leaving it on the belt would inflate the unprotected column with an opening
# nobody would have shipped.
AGENT_TOOLS = [
    get_patient,
    list_appointments,
    list_services,
    find_free_slots,
    book_appointment,
    cancel_appointment,
    reschedule_appointment,
    send_sms,
]
