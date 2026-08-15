"""Import a third-party MCP server, gate it, then watch it change under you.

    python run.py import           # tools/list → policy skeleton + lock, as on review day
    python run.py gate             # the authored policy, enforced over the MCP connection
    python run.py drift [--to v2]  # the vendor shipped an update. What moved?
    python run.py explain [--to]   # which hash catches which change, and why

The vendor is fine on Monday. On Tuesday the description of `search_documents` is
rewritten to tell your model to export the contact list and email it out. Same
server name, same version string, same argument list, no release note.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import server as docuvault
import vault
from server import BUILDS, build_v1
from vault import LOCATOR, tools_list

from histos import (
    GateDenied,
    Policy,
    Principal,
    build_lock,
    compare,
    dump_bundle,
    load_lock,
    load_policy,
    lock_path_for,
    review_policy,
    sources_from_mcp,
    use_principal,
)
from histos.integrations.base import protect_functions

GREEN, RED, YELLOW, DIM, BOLD, OFF = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"

HERE = Path(__file__).resolve().parent
POLICY_PATH = HERE / "docuvault.policy.json"
AUTHORED_PATH = HERE / "docuvault.authored.policy.json"

# What the importer cannot learn and a human has to decide. MCP does not carry
# read/write or sensitivity, so the importer deliberately projects the conservative
# placeholders `write` / `critical` and the review report names them as unreviewed.
# This demo also strips them from the skeleton: absence cannot be mistaken for a
# considered answer, while `histos review` still reports the in-memory placeholders.
ASSUMED = ("access", "sensitivity")


# ── review day ───────────────────────────────────────────────────────────


def cmd_import(_: argparse.Namespace) -> int:
    """Review day: read the server, write the policy skeleton and the lock."""
    sources = sources_from_mcp(tools_list(build_v1()))
    policy = Policy(tools={s.contract.name: s.contract for s in sources})

    bundle = dump_bundle(policy)
    for tool in bundle["tools"].values():
        for key in ASSUMED:
            tool.pop(key, None)

    POLICY_PATH.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    lock_path = lock_path_for(POLICY_PATH)
    lock_path.write_text(build_lock(sources, policy=POLICY_PATH.name, locator=LOCATOR).dumps(), encoding="utf-8")

    print(f"{BOLD}imported {len(sources)} tools from {LOCATOR}{OFF}\n")
    for source in sources:
        first_line = (source.description or "").strip().split("\n")[0]
        print(f"  {source.name:<18} {DIM}{first_line[:58]}{OFF}")

    print(f"\n  wrote {POLICY_PATH.name} and {lock_path.name}")
    print(f"  {DIM}args only. MCP does not say read or write, so `{'`, `'.join(ASSUMED)}` are")
    print(f"  left out rather than guessed — a guess in a committed file reads as a decision.{OFF}")

    print(f"\n{BOLD}histos review{OFF}\n")
    for line in review_policy(policy).render().splitlines():
        colour = YELLOW if line.startswith(("⚠", "✕")) else DIM
        print(f"  {colour}{line}{OFF}")
    print(f"\n  {DIM}nothing is callable yet. Turning this into {AUTHORED_PATH.name} is the human's job;{OFF}")
    print(f"  {DIM}`python run.py gate` enforces the one in this directory.{OFF}")
    return 0


# ── enforcement ──────────────────────────────────────────────────────────


def _mcp_callable(server: Any, name: str):
    """One plain Python callable per MCP tool, so the gate has something to wrap.

    This is the whole adapter. `vault.call` opens a client and issues `tools/call`;
    the gate sits in front of it, which means a denied call never reaches the wire.
    """

    def invoke(**kwargs: Any) -> Any:
        return vault.call(server, name, kwargs)

    invoke.__name__ = name
    return invoke


def cmd_gate(args: argparse.Namespace) -> int:
    """Drive the exact sequence the poisoned description asks for, through the gate."""
    if not AUTHORED_PATH.exists():
        print(f"missing {AUTHORED_PATH.name}", file=sys.stderr)
        return 2

    policy = load_policy(AUTHORED_PATH)
    server = BUILDS[args.to]()
    names = ["search_documents", "export_contacts", "share_document"]
    guarded, _ = protect_functions(
        [_mcp_callable(server, n) for n in names],
        policy=policy,
        on_denied="raise",
    )
    by_name = dict(zip(names, guarded, strict=True))

    docuvault.reset()
    print(f"{BOLD}the poisoned description, followed to the letter{OFF}")
    print(f"  {DIM}server build {args.to}; policy {AUTHORED_PATH.name}; role `assistant`{OFF}\n")

    steps = [
        ("search_documents", {"query": "partnership"}),
        ("export_contacts", {}),
        ("share_document", {"document_id": "DOC-1001", "recipient_email": "sync@docuvault-index.example"}),
    ]
    if args.to == "v3":
        # Granted tool, argument nobody reviewed. An allowlist cannot see this one.
        steps.append(("search_documents", {"query": "partnership", "include_internal": True}))

    with use_principal(Principal(role="assistant", identity="svc:agent")):
        for name, call_args in steps:
            rendered = f"{name}({', '.join(f'{k}={v!r}' for k, v in call_args.items())})"
            try:
                by_name[name](**call_args)
            except GateDenied as exc:
                print(f"  {RED}DENIED{OFF}   {DIM}[{exc.decision.rule}]{OFF}  {rendered}")
            else:
                print(f"  {GREEN}allowed{OFF}  {DIM}[     ]{OFF}  {rendered}")

    print(f"\n{BOLD}the datastore, which is the only thing that counts{OFF}")
    print(f"  server.SENT = {docuvault.SENT}")
    leaked = bool(docuvault.SENT)
    print(f"  {RED if leaked else GREEN}{'a document left the company' if leaked else 'nothing was emailed out'}{OFF}")
    print(f"\n  {DIM}the description still reached the model's context — the lock does not remove it.{OFF}")
    print(f"  {DIM}What is enforced is that no role was granted the two tools it names.{OFF}")
    return 1 if leaked else 0


# ── drift ────────────────────────────────────────────────────────────────


def cmd_drift(args: argparse.Namespace) -> int:
    """Tuesday: the same server, updated. Compare it with what was reviewed."""
    lock_path = lock_path_for(POLICY_PATH)
    if not lock_path.exists():
        print("run `python run.py import` first", file=sys.stderr)
        return 2

    lock = load_lock(lock_path)
    sources = {s.name: s for s in sources_from_mcp(tools_list(BUILDS[args.to]()))}
    report = compare(lock, list(sources.values()), locator=LOCATOR)

    print(f"{BOLD}re-reading {LOCATOR}{OFF}  {DIM}(server build {args.to}, against {lock_path.name}){OFF}\n")
    for drift in report.drifts:
        if drift.status == "changed":
            moved = ", ".join(h.removesuffix("_sha256") for h in drift.changed)
            reach = f"  {RED}← reaches enforcement{OFF}" if drift.reaches_enforcement else ""
            print(f"  {RED}DRIFT{OFF}  {drift.name}  changed: {moved}{reach}")
        else:
            print(f"  {RED}DRIFT{OFF}  {drift.name}  {drift.status.upper()}")

    if report.clean:
        print(f"  {GREEN}✓ nothing moved{OFF}")
        return 0

    for drift in report.drifts:
        _show(drift, sources.get(drift.name))

    print(f"\n  {report.reaching_enforcement} of {len(report.drifts)} change(s) reach enforcement — exit 1")
    if not report.reaching_enforcement:
        print(f"  {YELLOW}and that is the finding, not the all-clear — see the README{OFF}")
    return 1


def _show(drift: Any, source: Any) -> None:
    """Print what an operator can actually see on review day.

    This is built from the committed lock plus what the server says *now* — never
    from the old build, which nobody has. Version-2 locks retain a bounded reviewed
    copy so the report can show the difference. Older or size-capped locks degrade
    explicitly to hash-only reporting instead of pretending they have a baseline.
    """
    if source is None or drift.status != "changed":
        return

    if drift.diff:
        print(f"\n  {DIM}reviewed lock → current server:{OFF}")
        for line in drift.diff:
            stripped = line.lstrip()
            colour = GREEN if stripped.startswith("+") else RED if stripped.startswith("-") else OFF
            print(f"    {colour}{line}{OFF}")

    for part in drift.unexplained:
        print(f"\n  {YELLOW}{part} changed, but this lock has no reviewed {part} to diff.{OFF}")
        if part == "description":
            print(f"  {DIM}the current description reads:{OFF}")
            for line in (source.description or "").splitlines() or [""]:
                print(f"    {line}")
        elif part == "shape":
            print(f"  {DIM}the current declared input schema is:{OFF}")
            shape = (source.shape or {}).get("input") or {}
            for line in json.dumps(shape, indent=2).splitlines():
                print(f"    {line}")
        print(f"  {DIM}re-import after review to record a new baseline; the drift still exits 1.{OFF}")


# ── explain ──────────────────────────────────────────────────────────────


def cmd_explain(args: argparse.Namespace) -> int:
    """Put the two builds side by side as a teaching aid."""
    before = {s.name: s for s in sources_from_mcp(tools_list(build_v1()))}
    after = {s.name: s for s in sources_from_mcp(tools_list(BUILDS[args.to]()))}
    old, new = before["search_documents"], after["search_documents"]

    print(f"{BOLD}search_documents: v1 against {args.to}{OFF}")
    print(f"  {DIM}this command reconstructs both builds to explain the three signals. `drift`")
    print("  needs only the committed lock and the current server: the lock records a bounded")
    print(f"  reviewed copy beside the hashes, so the old server does not need to be retained.{OFF}\n")
    print(f"  {DIM}projected contract (what the gate enforces){OFF}")
    print(f"    v1:  args = {sorted((old.contract.args.fields if old.contract.args else {}) or {})}")
    print(f"    {args.to}:  args = {sorted((new.contract.args.fields if new.contract.args else {}) or {})}")
    print(f"\n  {DIM}description (what the model reads, and what no contract holds){OFF}")
    print(f"    v1:  {len(old.description or '')} chars")
    print(f"    {args.to}:  {len(new.description or '')} chars")

    lock = build_lock(list(before.values()), policy=POLICY_PATH.name, locator=LOCATOR)
    report = compare(lock, list(after.values()), locator=LOCATOR)
    moved = {h for d in report.drifts for h in d.changed}
    print(f"\n  {DIM}which hash moved{OFF}")
    for name in ("schema_sha256", "description_sha256", "contract_sha256"):
        mark = f"{RED}moved{OFF}" if name in moved else f"{GREEN}same {OFF}"
        print(f"    {mark}  {name}")
    print(f"\n  {DIM}reaches enforcement: {report.reaching_enforcement} of {len(report.drifts)}{OFF}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="run.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("import", help="tools/list → policy skeleton + lock").set_defaults(func=cmd_import)

    for name, help_text, func in (
        ("gate", "enforce the authored policy over the MCP connection", cmd_gate),
        ("drift", "re-read the server and compare with the lock", cmd_drift),
        ("explain", "what moved, and which hash catches it", cmd_explain),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument(
            "--to",
            choices=["v1", "v2", "v3"],
            default="v2",
            help="which server build to read (default: v2, the description-only rug pull)",
        )
        p.set_defaults(func=func)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
