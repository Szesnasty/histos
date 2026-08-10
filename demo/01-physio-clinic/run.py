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
import sys

from agent import MODEL, Turn, ask, build_agent
from clinic.store import PATIENTS, connect, reset, use_private_db
from probe import attempts, inspect
from wiring import caller_principal, protected, resolve_caller, unprotected

from histos import use_principal

# Derived from the seed rather than typed out again: the previous copy had patient
# 2 as "Piotr Nowak" while the database said "Peter Novak", so the system prompt
# and the first tool result disagreed about the caller's own name.
CALLERS = {pid: (name, phone) for pid, name, phone, _nid, _note in PATIENTS}

GREEN, RED, DIM, BOLD, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"

_threads = itertools.count()


def _session(patient_id: int, *, gated: bool):
    """A fresh clinic, a caller resolved from the calling line, and one wiring."""
    reset()
    caller = resolve_caller(CALLERS[patient_id][1])
    tools = protected() if gated else unprotected(caller)
    agent = build_agent(tools, patient_id=caller.patient_id, patient_name=caller.name)
    return agent, caller, f"session-{next(_threads)}"


def _speak(agent, message: str, *, gated: bool, caller, thread_id: str) -> Turn:
    if not gated:
        return ask(agent, message, thread_id=thread_id)
    with use_principal(caller_principal(caller)):
        return ask(agent, message, thread_id=thread_id)


def _render(turn: Turn, *, caller, indent: str = "  ") -> None:
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

    if turn.reply:
        print(f'{indent}{DIM}assistant: "{turn.reply[:220]}"{OFF}')


def cmd_compare(args: argparse.Namespace) -> int:
    """The same sentence, the same model, both wirings."""
    print(f"model: {MODEL}   caller: {CALLERS[args.as_patient][0]} (patient {args.as_patient})")
    print(f"\n{BOLD}> {args.message}{OFF}")
    for label, gated in ((f"{RED}WITHOUT histos{OFF}", False), (f"{GREEN}WITH histos{OFF}", True)):
        print(f"\n{label}")
        agent, caller, thread = _session(args.as_patient, gated=gated)
        turn = _speak(agent, args.message, gated=gated, caller=caller, thread_id=thread)
        _render(turn, caller=caller, indent="    ")
    return 0


def cmd_chat(args: argparse.Namespace) -> int:
    """A REPL against one wiring. `/db` shows the clinic, `/reset` starts over.

    One thread for the whole session, so turn 3 can build on turn 1 — which is what
    makes it worth typing an attack into rather than a single sentence.
    """
    gated = args.histos
    agent, caller, thread = _session(args.as_patient, gated=gated)
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
            agent, caller, thread = _session(args.as_patient, gated=gated)
            print(f"{DIM}clinic reseeded, conversation forgotten{OFF}\n")
            continue
        if message == "/db":
            _show_clinic()
            continue
        turn = _speak(agent, message, gated=gated, caller=caller, thread_id=thread)
        _render(turn, caller=caller)
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


def cmd_attacks(_: argparse.Namespace) -> int:
    import attacks

    attacks.main()
    return 0


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

    a = sub.add_parser("attacks", help="the four scripted attacks, both wirings")
    a.set_defaults(func=cmd_attacks)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
