"""Two wirings of the same agent, both of them competent.

`unprotected()` is the v1 a good team ships in 2026: the clinic's domain functions
with ordinary session scoping in front of them. The app already knows who rang —
it identified them from the calling line — so the tools the model sees do not take
a `patient_id` at all, and the two that are keyed by `appointment_id` look the
row's owner up before touching it. That is thirty lines of the same authorization
every REST backend already has, and it is the baseline the policy has to beat.

`protected()` is the same domain functions with no wrapper at all, gated by
`security.policy.yaml`.

The diff between them is the product, and after the baseline was made honest the
diff is smaller and more specific than the first version of this demo claimed.
Read `README.md` for what survives.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from clinic import tools as clinic_tools
from clinic.store import connect
from langchain_core.tools import StructuredTool

from histos import Gate, Principal, ResourceNotFound, load_policy
from histos.integrations.langchain import protect_tools

POLICY_PATH = Path(__file__).resolve().parent / "security.policy.yaml"


@dataclass(frozen=True)
class Caller:
    """Who is on the line. Established before the model sees a single token."""

    patient_id: int
    name: str
    phone: str


def resolve_caller(phone: str) -> Caller:
    """Turn a calling line into a caller, the way the switchboard does.

    This is the one fact in the system the model cannot influence, so it is
    computed from the phone number and never from anything the model said.
    """
    row = clinic_tools.find_patient_by_phone(phone)
    if "error" in row:
        raise LookupError(f"no patient calling from {phone}")
    return Caller(patient_id=row["id"], name=row["full_name"], phone=row["phone"])


def _as_langchain_tools(functions: list[Any]) -> list[StructuredTool]:
    """LangChain tools straight from the clinic's functions and their type hints."""
    return [
        StructuredTool.from_function(fn, name=fn.__name__, description=(fn.__doc__ or "").strip()) for fn in functions
    ]


def _appointment_owner(appointment_id: int) -> int | None:
    conn = connect()
    row = conn.execute("SELECT patient_id FROM appointments WHERE id = ?", (appointment_id,)).fetchone()
    conn.close()
    return None if row is None else row["patient_id"]


# ── the competent v1: session scoping, no policy engine ──────────────────


def unprotected(caller: Caller) -> list[StructuredTool]:
    """Every tool the agent gets, scoped to the session the app already holds.

    No Histos anywhere in this function. This is the fair fight: an earlier version
    of this demo handed the model raw `patient_id` and `appointment_id` parameters
    and then counted the resulting cross-patient reads and cancellations as wins,
    which was a straw man — the app knew the caller the whole time and was simply
    declining to use it.

    One artifact worth knowing before you read a transcript: the system prompt tells
    the model its own patient_id, so it often emits `get_patient(patient_id=4)` even
    here, where `get_patient` takes no arguments at all. LangChain drops the
    unexpected key and the call runs scoped. The printed tool call therefore shows an
    argument the function never received — it is noise from the model, not a
    parameter this wiring exposes.
    """

    def get_patient() -> dict[str, Any]:
        """Your own patient record: name, phone, national identity number, intake note."""
        return clinic_tools.get_patient(caller.patient_id)

    def list_appointments() -> list[dict[str, Any]]:
        """Your own upcoming appointments, with therapist and service."""
        return clinic_tools.list_appointments(caller.patient_id)

    def book_appointment(therapist_id: int, service_id: int, starts_at: str) -> dict[str, Any]:
        """Book a slot for yourself (starts_at is YYYY-MM-DDTHH:MM)."""
        return clinic_tools.book_appointment(caller.patient_id, therapist_id, service_id, starts_at)

    # Cancelling and rescheduling are keyed by appointment, not by patient, so
    # there is no argument to drop. The owner has to be fetched and compared —
    # which is exactly what `resource.owns` does in the policy, written by hand.
    # The wrong id is reported as "not found", not "not yours", so the agent
    # cannot use the error to enumerate the clinic's bookings.
    def cancel_appointment(appointment_id: int) -> dict[str, Any]:
        """Cancel one of your own appointments."""
        if _appointment_owner(appointment_id) != caller.patient_id:
            return {"error": "no such booked appointment"}
        return clinic_tools.cancel_appointment(appointment_id)

    def reschedule_appointment(appointment_id: int, new_starts_at: str) -> dict[str, Any]:
        """Move one of your own appointments to a new time."""
        if _appointment_owner(appointment_id) != caller.patient_id:
            return {"error": "no such booked appointment"}
        return clinic_tools.reschedule_appointment(appointment_id, new_starts_at)

    # `send_sms` is handed over unscoped, and that is not an oversight. There is no
    # session value to scope a recipient to: the clinic genuinely texts numbers
    # that are not the calling line — a carer, a spouse, a new handset — so no
    # ownership predicate can be written here without deleting a real feature.
    # This is the one tool where the baseline has nothing to say.
    return _as_langchain_tools(
        [
            clinic_tools.list_services,
            clinic_tools.find_free_slots,
            get_patient,
            list_appointments,
            book_appointment,
            cancel_appointment,
            reschedule_appointment,
            clinic_tools.send_sms,
        ]
    )


# ── the same functions, behind a policy ──────────────────────────────────


def resolve_resource(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Fetch the record the call actually touches, so ownership is checked against
    the datastore rather than against what the model claimed.

    This is the half a policy file cannot contain: only the application knows that
    `cancel_appointment(appointment_id=...)` reaches a row whose owner lives in
    `appointments.patient_id`. It is the same query `unprotected()` runs by hand —
    the difference is where the *decision* lives, not how much code it takes.
    """
    conn = connect()
    try:
        if tool_name in ("cancel_appointment", "reschedule_appointment"):
            row = conn.execute("SELECT patient_id FROM appointments WHERE id = ?", (args["appointment_id"],)).fetchone()
            if row is None:
                raise ResourceNotFound(f"no appointment {args['appointment_id']}")
            return {"patient_id": row["patient_id"]}

        if tool_name in ("get_patient", "list_appointments"):
            row = conn.execute("SELECT id FROM patients WHERE id = ?", (args["patient_id"],)).fetchone()
            if row is None:
                raise ResourceNotFound(f"no patient {args['patient_id']}")
            return {"patient_id": row["id"]}
    finally:
        conn.close()
    return {}


def caller_principal(caller: Caller) -> Principal:
    """The one value the model cannot influence: who is actually on the line.

    Built from the verified phone number before the model sees anything. Bound
    per request with `use_principal()`, which is the documented path for a server
    — `fixed_principal=` would pin one identity for the life of the wrapper.

    `can_view` carries a decision worth seeing: a patient may read their own phone
    number back, because it is theirs and "what number do you have on file for me?"
    is a reception task. The national identity number stays redacted — that one is
    not needed to book a massage.

    `can_view` holds sensitivity *classes*, not field names. This said
    `{"phone"}` and therefore matched nothing, so `phone` came back `[REDACTED]`
    alongside `national_id` and the carve-out this demo is built on never existed.
    The engine is right to fail that way — an unknown name redacts rather than
    discloses — and the README's claim that the capability "survives at the data
    layer and dies in the model's summary" was the wrong diagnosis: the model was
    accurately reporting a genuinely redacted field. `pii` is the class `phone`
    carries; `secret`, which `national_id` carries, stays out.
    """
    return Principal(
        role="patient",
        identity=f"patient:{caller.patient_id}",
        attributes={"patient_id": caller.patient_id, "phone": caller.phone},
        can_view=frozenset({"pii"}),
    )


@dataclass(frozen=True)
class Protected:
    """The gated toolbelt, and the gate that produced it.

    The gate is returned rather than discarded because a run that only records
    *whether* harm occurred cannot say whether the policy is the reason. Its audit
    trail names the rule behind every decision, so "no damage" can be told apart from
    "the model never tried" — and a gate that allowed the destructive call while the
    model happened not to make it looks identical to a working one until you read it.
    """

    tools: list[StructuredTool]
    gate: Gate


def protected() -> Protected:
    """The domain functions with no wrapper, gated. The policy decides; identity
    arrives per request from `use_principal()`."""
    gate = Gate(load_policy(POLICY_PATH), resource_resolver=resolve_resource)
    return Protected(protect_tools(_as_langchain_tools(clinic_tools.AGENT_TOOLS), gate=gate), gate)
