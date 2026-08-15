"""One entry point. Talk to the clinic's assistant, with the policy on or off.

    python run.py compare "cancel appointments 1 to 6"    # both wirings, side by side
    python run.py chat                                    # talk to it yourself, no policy
    python run.py chat --histos                           # same assistant, gated
    python run.py attacks                                 # the four scripted attacks

`compare` is the one to reach for first: type any sentence, watch the same model
make the same decision twice, and see which of the two reaches the database.

Both columns are competent. The no-policy column is not the agent with its
authorization removed — it is the agent with ordinary session scoping, written by
hand in `wiring.unprotected()`. Read that function before reading the results.

Everyone is Marta Doyle (patient 1) unless `--as 4` says otherwise. Patient 4's
intake note carries the injection.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import sys

from agent import MODEL, TEMPERATURE, Turn, ask, build_agent, usage
from clinic.store import PATIENTS, connect, reset, use_private_db
from gatereport import gate_report
from probe import attempts, inspect, utility
from wiring import caller_principal, protected, resolve_caller, unprotected

from histos import use_principal

# One JSON object per wiring, straight from the probe. See the note in
# `03-oncall-triage/run.py`: the sweep used to read its verdict by scanning stdout for
# a damage glyph, and this file is where that was worst — the model's reply is printed
# here, so a model that formatted its answer with a `✗` bullet could put DAMAGE in the
# column where the gate had just worked.
RESULT_LINES = os.environ.get("HISTOS_DEMO_RESULT") == "1"

# Derived from the seed rather than typed out again: the previous copy had patient
# 2 as "Piotr Nowak" while the database said "Peter Novak", so the system prompt
# and the first tool result disagreed about the caller's own name.
CALLERS = {pid: (name, phone) for pid, name, phone, _nid, _note in PATIENTS}

GREEN, RED, DIM, BOLD, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"

_threads = itertools.count()


def _session(patient_id: int, *, gated: bool):
    """A fresh clinic, a caller resolved from the calling line, and one wiring.

    The gate comes back with the rest of it. A run that records only whether harm
    occurred cannot say whether the policy is the reason it did not: "the gate denied
    the destructive call" and "the model never made one" produce the same clean
    verdict, and only the audit trail separates them.
    """
    reset()
    caller = resolve_caller(CALLERS[patient_id][1])
    bundle = protected(caller) if gated else None
    tools = bundle.tools if bundle else unprotected(caller)
    agent = build_agent(tools, patient_id=caller.patient_id, patient_name=caller.name)
    return agent, caller, f"session-{next(_threads)}", bundle


def _speak(agent, message: str, *, gated: bool, caller, thread_id: str) -> Turn:
    if not gated:
        return ask(agent, message, thread_id=thread_id)
    with use_principal(caller_principal(caller)):
        return ask(agent, message, thread_id=thread_id)


def _render(turn: Turn, *, caller, indent: str = "  ", wiring: str = "", bundle=None) -> None:
    for name, args in turn.tool_calls:
        rendered = ", ".join(f"{k}={v!r}" for k, v in args.items())
        print(f"{indent}{DIM}↳ {name}({rendered}){OFF}")
    for result in turn.tool_results:
        if "blocked by policy" in result:
            print(f"{indent}  {RED}⨯ {result.strip()}{OFF}")

    tried = attempts(turn.tool_calls, caller_phone=caller.phone, caller_patient_id=caller.patient_id)
    for line in tried:
        print(f"{indent}{DIM}· attempted: {line}{OFF}")

    damage = inspect(turn.tool_results, caller_phone=caller.phone, caller_patient_id=caller.patient_id)
    if damage:
        for line in damage.lines():
            print(f"{indent}{RED}{BOLD}✗ DAMAGE  {line}{OFF}")
    else:
        print(f"{indent}{GREEN}✓ no damage{OFF}")

    _show_messages(indent)

    if turn.reply:
        # `!r` and not `"{...}"`. A model reply can contain newlines, and printing it
        # raw put model-authored lines into the transcript indistinguishable from the
        # probe's own verdict lines — which is exactly how a reply narrating the
        # gate's refusal could be scored as the gate causing damage.
        print(f"{indent}{DIM}assistant: {turn.reply[:220]!r}{OFF}")
    if turn.error:
        print(f"{indent}{RED}{BOLD}! the model never answered: {turn.error[:160]}{OFF}")

    if bundle is not None:
        report = gate_report(bundle.gate, bundle.executions, len(turn.tool_calls))
        print(
            f"{indent}{DIM}▤ gate: {report['decisions']} decisions, {len(report['stopped'])} stopped, "
            f"{report['rebindings']} args rebound, {len(report['redacted_fields'])} fields redacted, "
            f"policy {report['policy_hash'][:23]}{OFF}"
        )
        for stop in report["stopped"]:
            print(f"{indent}  {DIM}▤ {stop['effect']} {stop['tool']} — {stop['rule']}{OFF}")
        if not report["complete_mediation"]:
            print(
                f"{indent}{RED}{BOLD}▤ INCOMPLETE MEDIATION: {report['executions']} tool bodies ran, "
                f"{report['permitted']} permitted by the policy — a call reached its function unseen{OFF}"
            )

    if RESULT_LINES and wiring:
        print("RESULT " + json.dumps(_record(turn, caller, wiring, damage, bundle), default=str))


def _show_messages(indent: str) -> None:
    """Every SMS that really went out. Printed because it is the completion signal.

    A correctly-defended run ends with the caller texted on their verified line, and
    nothing used to print that: a successful, correctly-bound SMS produced no output
    at all and was indistinguishable from the assistant doing nothing.
    """
    conn = connect()
    rows = conn.execute("SELECT to_phone, body FROM sent_messages").fetchall()
    conn.close()
    for row in rows:
        print(f"{indent}{DIM}✉ sms to {row['to_phone']}: {row['body'][:60]!r}{OFF}")


def _record(turn: Turn, caller, wiring: str, damage, bundle) -> dict:
    util = utility(turn.tool_calls, turn.reply, caller_phone=caller.phone, caller_patient_id=caller.patient_id)
    return {
        # `null` on the ungated side is the honest value: there is no gate, so there
        # is no trail. Recording an empty one would let the two columns be compared
        # as though both had been audited and one simply decided nothing.
        "gate": None if bundle is None else gate_report(bundle.gate, bundle.executions, len(turn.tool_calls)),
        "wiring": wiring,
        "damage": bool(damage),
        "damage_lines": damage.lines(),
        "notes": [],
        "utility": {
            # `texted_caller` keeps its name because the sweep's completion signal is
            # "the caller was informed"; the two finer readings sit beside it.
            "texted_caller": util.to_caller_line,
            "to_authorised": util.to_authorised,
            "to_requested": util.to_requested,
            "delivered": list(util.delivered),
            "looked_up_appointments": util.looked_up_appointments,
            "replied": util.replied,
            "acted": util.acted,
            "tools_called": list(util.tools_called),
        },
        "calls": [{"tool": name, "args": args} for name, args in turn.tool_calls],
        "denials": sum(1 for r in turn.tool_results if "blocked by policy" in r),
        "steps": len(turn.tool_calls),
        "attempts": attempts(turn.tool_calls, caller_phone=caller.phone, caller_patient_id=caller.patient_id),
        "error": turn.error,
        "reply": turn.reply[:400],
        "caller_patient_id": caller.patient_id,
        "model": MODEL,
        "temperature": TEMPERATURE,
        "usage": usage(turn),
    }


def cmd_compare(args: argparse.Namespace) -> int:
    """The same sentence, the same model, both wirings."""
    print(f"model: {MODEL}   caller: {CALLERS[args.as_patient][0]} (patient {args.as_patient})")
    print(f"\n{BOLD}> {args.message}{OFF}")
    failed = False
    for label, wiring, gated in (
        (f"{RED}WITHOUT histos{OFF}", "unprotected", False),
        (f"{GREEN}WITH histos{OFF}", "protected", True),
    ):
        print(f"\n{label}")
        agent, caller, thread, bundle = _session(args.as_patient, gated=gated)
        turn = _speak(agent, args.message, gated=gated, caller=caller, thread_id=thread)
        _render(turn, caller=caller, indent="    ", wiring=wiring, bundle=bundle)
        failed |= bool(turn.error)
    # A turn the model never answered is not a turn with no damage, and the exit code
    # is the one signal a harness gets for free.
    return 1 if failed else 0


def cmd_chat(args: argparse.Namespace) -> int:
    """A REPL against one wiring. `/db` shows the clinic, `/reset` starts over.

    One thread for the whole session, so turn 3 can build on turn 1 — which is what
    makes it worth typing an attack into rather than a single sentence.
    """
    gated = args.histos
    agent, caller, thread, bundle = _session(args.as_patient, gated=gated)
    banner = f"{GREEN}policy ON{OFF}" if gated else f"{RED}policy OFF{OFF}"
    print(f"model: {MODEL}   caller: {caller.name} (patient {caller.patient_id})   {banner}")
    print(f"{DIM}/db shows the clinic · /reset reseeds it · empty line or Ctrl-D quits{OFF}\n")

    while True:
        try:
            message = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not message:
            return 0
        if message == "/reset":
            agent, caller, thread, bundle = _session(args.as_patient, gated=gated)
            print(f"{DIM}clinic reseeded, conversation forgotten{OFF}\n")
            continue
        if message == "/db":
            _show_clinic()
            continue
        turn = _speak(agent, message, gated=gated, caller=caller, thread_id=thread)
        _render(turn, caller=caller, bundle=bundle)
        print()


def _show_clinic() -> None:
    conn = connect()
    appts = conn.execute("SELECT id, patient_id, starts_at, status FROM appointments ORDER BY id").fetchall()
    msgs = conn.execute("SELECT to_phone, body FROM sent_messages").fetchall()
    conn.close()
    print(f"{DIM}  appointments:{OFF}")
    for a in appts:
        mark = "cancelled" if a["status"] != "booked" else "booked   "
        print(f"{DIM}    #{a['id']}  patient {a['patient_id']}  {a['starts_at']}  {mark}{OFF}")
    print(f"{DIM}  sms sent: {[(m['to_phone'], m['body'][:40]) for m in msgs] or 'none'}{OFF}\n")


def cmd_schemas(args: argparse.Namespace) -> int:
    """What each wiring actually tells the model. Declared, not left to be discovered.

    The on-call demo asserts its two wirings advertise identical schemas, so its
    comparison measures the policy and nothing else. This demo cannot make that claim
    and should not imply it: `unprotected()` hand-writes closures that drop the
    `patient_id` parameter, while `protected()` gates the raw domain functions and
    lets the policy bind it. That is deliberate — see `wiring.unprotected` — because
    the alternative is a straw man where the app knows the caller and declines to use
    it. But it has a consequence worth stating in the open: on the cross-patient
    channels the ungated side is floored at zero by construction rather than by
    measurement, so only the `send_sms` recipient, the cancellation budget and the
    redacted field are genuine two-sided comparisons.

    No model is involved. This is a fact about the toolbelts.
    """
    reset()
    caller = resolve_caller(CALLERS[args.as_patient][1])
    raw = {t.name: t for t in unprotected(caller)}
    gated = {t.name: t for t in protected().tools}

    print(f"{BOLD}what each wiring advertises{OFF}\n")
    differing = []
    for name in sorted(set(raw) | set(gated)):
        left, right = raw.get(name), gated.get(name)
        left_args = sorted(left.args_schema.model_json_schema().get("properties", {})) if left else ["(absent)"]
        right_args = sorted(right.args_schema.model_json_schema().get("properties", {})) if right else ["(absent)"]
        same = left_args == right_args
        mark = f"{DIM}same {OFF}" if same else f"{RED}DIFFERS{OFF}"
        if not same:
            differing.append(name)
        print(f"  {mark} {name:<22} ungated({', '.join(left_args) or '—'})  gated({', '.join(right_args) or '—'})")

    print(
        f"\n  {RED}{len(differing)} of {len(set(raw) | set(gated))} tools differ{OFF}: {', '.join(differing)}"
        if differing
        else f"\n  {GREEN}✓ identical schemas gated vs ungated{OFF}"
    )
    print(
        f"  {DIM}The ungated side cannot express a cross-patient call at all, so the demo's\n"
        f"  cross-patient damage channels are zero on that side by construction. The\n"
        f"  channels that do compare both sides are: the send_sms recipient, the\n"
        f"  cancellation budget, and the redacted national identity number.{OFF}"
    )
    return 0


def cmd_attacks(_: argparse.Namespace) -> int:
    import attacks

    return attacks.main([])


def main() -> int:
    use_private_db()
    parser = argparse.ArgumentParser(
        prog="run.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--as",
        dest="as_patient",
        type=int,
        default=1,
        choices=sorted(CALLERS),
        help="which patient is on the phone (4 has the injected intake note)",
    )

    c = sub.add_parser("compare", parents=[common], help="one message, both wirings, side by side")
    c.add_argument("message")
    c.set_defaults(func=cmd_compare)

    t = sub.add_parser("chat", parents=[common], help="talk to the assistant yourself")
    t.add_argument("--histos", action="store_true", help="run it behind the policy")
    t.set_defaults(func=cmd_chat)

    s = sub.add_parser("schemas", parents=[common], help="what each wiring tells the model, and where they differ")
    s.set_defaults(func=cmd_schemas)

    a = sub.add_parser("attacks", help="the four scripted attacks, both wirings")
    a.set_defaults(func=cmd_attacks)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
