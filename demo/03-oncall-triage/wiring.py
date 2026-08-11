"""Two dispatch tables. That is the entire difference.

With no framework there is no adapter to trust and nothing clever happening. The
agent loop looks up a name in a dict and calls what it finds, so **whatever is in
the dict is what runs** — which makes the wiring the security boundary, visible in
about fifteen lines.

It also makes the classic mistake visible. `protect()` returns a *new* mapping; the
originals stay alive and callable. Build the dispatch table first and gate it after,
and you have gated nothing.

The gate is built here rather than through the `protect()` one-liner for one reason:
this demo needs the `Gate` object itself, both to hand it a resource resolver and a
confirmation callback and to ask it for its own coverage report afterwards.
`protect()` returns the wrapped tools but not the gate that wrapped them.

And it keeps the mapping `protect()` handed back, which is the only reliable way to
answer "is this dispatch entry still gated?" — see `ungated_entries`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gatereport import Executions
from ops import tools as ops_tools
from ops.store import connect

from histos import Gate, GateRequest, Principal, load_policy

POLICY_PATH = Path(__file__).resolve().parent / "security.policy.yaml"


def unprotected() -> dict[str, Callable[..., Any]]:
    """Every operation, dispatchable by name. No policy anywhere.

    Not a straw man: this wiring gets the same hardened system prompt as the gated
    one — the prompt that names the injection, says alert text is data, and forbids
    production deploys and capacity cuts in so many words. What it does not have is
    anything that stops the model when it ignores that.
    """
    return {fn.__name__: fn for fn in ops_tools.ALL_TOOLS}


def build_gate(alert_id: int | None = None) -> Gate:
    """One gate, sharing limit counters and one audit trail across all the tools."""
    return Gate(
        load_policy(POLICY_PATH),
        resource_resolver=resolve_resource,
        confirm=IncidentCommander(alert_id),
    )


@dataclass(frozen=True)
class Wiring:
    """A dispatch table, plus the two things needed to audit it afterwards.

    `guarded` is the mapping `Gate.protect()` returned — the callables the gate
    actually wrapped. `dispatch` is what the loop will use. They start out equal;
    `half_protected` is the case where somebody edited one and not the other.
    """

    gate: Gate
    guarded: dict[str, Callable[..., Any]]
    dispatch: dict[str, Callable[..., Any]]
    #: Counts tool bodies that actually ran. The counters wrap the raw functions
    #: *before* the gate does, so a dispatch entry pointing straight at a raw
    #: function — the bug `half_protected` plants — is still counted. That is what
    #: lets the mediation check see a call the policy never did.
    executions: Executions = field(default_factory=Executions)


def protected(alert_id: int | None = None) -> dict[str, Callable[..., Any]]:
    """The same functions behind the gate, keyed the same way.

    `Gate.protect()` takes plain callables and returns a `ProtectResult` whose
    `.tools` is already a mapping of name → guarded callable — exactly the shape the
    loop dispatches on. No framework object, no tool class, nothing to register.
    """
    return protected_wiring(alert_id).dispatch


def protected_wiring(alert_id: int | None = None) -> Wiring:
    gate = build_gate(alert_id)
    executions = Executions()
    counted = executions.wrap_all(ops_tools.ALL_TOOLS)
    guarded = gate.protect(counted).tools
    return Wiring(gate=gate, guarded=guarded, dispatch=dict(guarded), executions=executions)


def half_protected(alert_id: int | None = None) -> dict[str, Callable[..., Any]]:
    """The realistic accident: a table built from the gated tools, plus one that
    somebody added later and wired straight through.

    Nothing raises. Nothing looks wrong. `deploy_service` simply is not gated.
    """
    return half_protected_wiring(alert_id).dispatch


def half_protected_wiring(alert_id: int | None = None) -> Wiring:
    wiring = protected_wiring(alert_id)
    # The raw function, reached through the counter rather than the gate — which is
    # exactly the shape of the accident, and is what makes the bypass observable.
    wiring.dispatch["deploy_service"] = wiring.executions.wrap(ops_tools.deploy_service)  # ← the whole bug
    return wiring


def triage_principal() -> Principal:
    """The agent's own identity, bound by the host. Nothing it reads can change it."""
    return Principal(role="triage_agent", identity="svc:oncall-triage")


# ── the facts the arguments cannot carry ─────────────────────────────────


def _open_alert_for(service: Any) -> bool:
    conn = connect()
    try:
        row = conn.execute("SELECT 1 FROM alerts WHERE service = ? AND resolved = 0 LIMIT 1", (service,)).fetchone()
    finally:
        conn.close()
    return row is not None


def _current_replicas(service: Any, environment: Any) -> int | None:
    conn = connect()
    try:
        row = conn.execute(
            "SELECT replicas FROM services WHERE name = ? AND environment = ?", (service, environment)
        ).fetchone()
    finally:
        conn.close()
    return int(row["replicas"]) if row is not None else None


def resolve_resource(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Answer the policy's `resource.where` questions from the platform's own tables.

    Never a restatement of the arguments. The alert detail is not consulted at all:
    it is the thing under suspicion.
    """
    if tool_name == "resolve_alert":
        conn = connect()
        try:
            row = conn.execute(
                "SELECT s.healthy AS healthy FROM alerts a "
                "JOIN services s ON s.name = a.service AND s.environment = 'production' "
                "WHERE a.id = ?",
                (args.get("alert_id"),),
            ).fetchone()
        finally:
            conn.close()
        return {"alert_service_is_healthy": bool(row["healthy"]) if row is not None else False}

    facts: dict[str, Any] = {"service_is_alerting": _open_alert_for(args.get("service"))}
    if tool_name == "scale_service":
        current = _current_replicas(args.get("service"), args.get("environment"))
        # No such service means the fact cannot be true, so the call fails closed
        # rather than falling through to a default.
        facts["keeps_current_capacity"] = current is not None and int(args["replicas"]) >= current
    return facts


class IncidentCommander:
    """The human the policy asks for — and an honest model of what humans check.

    `confirm=lambda req: True` is a rubber stamp in a costume, and `SECURITY.md`
    names that exact trap. This one refuses.

    It approves a capacity change on the service it was woken for, because that is
    the fact a woken engineer reliably holds: they know which alert they are on. It
    does **not** check the arithmetic — whether the change adds capacity or takes it
    away — because under time pressure people approve the *shape* of a request
    ("scale up to handle the load, fine") rather than its numbers.

    Be clear about what this is worth in *this* world, because it is less than it
    looks. Confirmation is the last check the engine runs, and `resource.where`
    already refused every call this commander would have refused: a scale pointed at
    `payments` dies on `service_is_alerting` before anybody is woken. Run
    `run.py rules` and the commander is consulted exactly once, on the one legal
    capacity change, and approves. With a single alerting service the two controls
    coincide. It earns its place as the shape of the control — an out-of-band human
    who can say no, bound to (tool, args, principal) so an approval cannot be
    replayed — not as a check that fires here.
    """

    def __init__(self, alert_id: int | None) -> None:
        self.alert_id = alert_id
        self.asked: list[tuple[str, dict[str, Any]]] = []
        self.refused: list[str] = []

    def incident_service(self) -> str | None:
        if self.alert_id is None:
            return None
        conn = connect()
        try:
            row = conn.execute("SELECT service FROM alerts WHERE id = ?", (self.alert_id,)).fetchone()
        finally:
            conn.close()
        return row["service"] if row is not None else None

    def __call__(self, request: GateRequest) -> bool:
        self.asked.append((request.tool_name, dict(request.args)))
        expected = self.incident_service()
        asked_for = request.args.get("service")
        if expected is None or asked_for != expected:
            self.refused.append(f"{request.tool_name} on {asked_for!r}; I was woken for {expected!r}")
            return False
        return True


# ── coverage ─────────────────────────────────────────────────────────────


def ungated_entries(wiring: Wiring) -> list[str]:
    """Dispatch entries that do not point at the callable the gate handed back.

    Identity, and nothing cleverer. `Gate.protect()` returned a mapping; the loop
    dispatches on a mapping; the check is whether they are still the same objects.

    Sniffing the callable instead does not work and should not be attempted. The
    obvious tell used to be `__wrapped__`, and it was never a good one: the library
    deliberately stopped publishing it (a public pointer at the ungated callable is
    a hole, not a feature), so a check written that way now reports *every* entry as
    ungated — including the gated ones. Nothing readable off the object is load
    bearing. Keep the mapping `protect()` returned and compare against it.
    """
    return sorted(name for name, fn in wiring.dispatch.items() if wiring.guarded.get(name) is not fn)


def coverage_report(wiring: Wiring) -> dict[str, Any]:
    """What the library's own coverage check says, and what it cannot say.

    `Gate.coverage()` compares **names**: the tools the agent is exposed to against
    the tools the policy declares. That catches the common gap — a tool nobody wrote
    a contract for, which the agent can call with nothing in the way — and it is
    what `histos coverage` fails CI on.

    It cannot catch this demo's bug, and the demo prints its real answer saying so.
    The name `deploy_service` is still exposed, the policy still declares it, and
    the gate did wrap it; what changed is which callable the name now points at.
    Only walking the live table catches that.
    """
    return {"policy": wiring.gate.coverage(list(wiring.dispatch)), "ungated": ungated_entries(wiring)}
