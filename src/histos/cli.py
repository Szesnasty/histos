"""``histos`` — inspect and debug a policy without running an agent (Phase 0.1).

Subcommands (stdlib argparse, zero deps):

    histos validate  security.policy.yaml          # structural validity → exit 0/1 (CI)
    histos review    security.policy.yaml          # ✓ ready / ⚠ review / ✕ blocked
    histos coverage  security.policy.yaml --tools a,b,c   # exposed-but-undeclared → exit 1
    histos explain   security.policy.yaml <tool> --role support --args '{"amount": 999}'
    histos import    tools.json --kind mcp [--out security.policy.yaml]
    histos import    tools.json --kind mcp --update security.policy.yaml
    histos drift     security.policy.yaml --source tools.json --kind mcp   # → exit 0/1 (CI)
    histos audit verify audit.jsonl [--key <hex>]  # hash-chain integrity → exit 0/1
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

from histos.audit import verify_chain
from histos.bundle import dump_bundle, load_bundle_json, load_bundle_yaml
from histos.contracts import GateRequest, Policy, Principal
from histos.errors import PolicyError
from histos.gate import Gate
from histos.importers import ToolSource, sources_from_mcp, sources_from_openai, sources_from_openapi
from histos.lockfile import build_lock, compare, contract_hash, load_lock, lock_path_for, unverifiable_tools
from histos.review import review_policy

_SOURCE_READERS = {
    "mcp": sources_from_mcp,
    "openai": sources_from_openai,
    "openapi": sources_from_openapi,
}


def _read_sources(path: str, kind: str) -> list[ToolSource]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return _SOURCE_READERS[kind](data)


def _load_policy(path: str) -> Policy:
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith((".yaml", ".yml")):
        return load_bundle_yaml(text)
    return load_bundle_json(text)


def _cmd_validate(args: argparse.Namespace) -> int:
    issues = _load_policy(args.policy).validate()
    if not issues:
        print("OK — policy is structurally valid")
        return 0
    print(f"INVALID — {len(issues)} issue(s):")
    for i in issues:
        print(f"  ✕ {i}")
    return 1


def _cmd_review(args: argparse.Namespace) -> int:
    review = review_policy(_load_policy(args.policy))
    print(review.render())
    return 1 if review.blocked else 0


def _cmd_coverage(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    exposed = {t.strip() for t in args.tools.split(",") if t.strip()}
    declared = set(policy.tools)
    undeclared = sorted(exposed - declared)
    unwrapped = sorted(declared - exposed)
    print(f"{len(exposed & declared)}/{len(exposed)} exposed tools are covered by the policy")
    for t in undeclared:
        print(f"  ✕ {t}: exposed to the agent but NOT in the policy (ungated gap)")
    for t in unwrapped:
        print(f"  · {t}: in the policy but not in the exposed set")
    return 1 if undeclared else 0


def _cmd_explain(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    attrs: dict[str, Any] = {}
    for kv in args.attr or []:
        k, _, v = kv.partition("=")
        attrs[k] = v
    principal = Principal(role=args.role, identity=args.identity, attributes=attrs)
    call_args = json.loads(args.args) if args.args else {}
    gate = Gate(policy)
    decision = gate.engine.pre(GateRequest(args.tool, call_args, principal, phase="pre"))
    print("developer:")
    print(f"  {decision.explain()}")
    if decision.remedy:
        print(f"  remedy: {decision.remedy}")
    print("agent:")
    print(f"  {decision.public_reason}")
    return 0 if decision.allowed else 1


def _write_lock(sources: list[ToolSource], *, policy_path: str, locator: str) -> Path:
    """Record where the imported half came from, beside the policy it belongs to."""
    lock = build_lock(sources, policy=Path(policy_path).name, locator=locator)
    path = lock_path_for(policy_path)
    path.write_text(lock.dumps(), encoding="utf-8")
    return path


def _has_comments(text: str) -> bool:
    return any(line.lstrip().startswith("#") for line in text.splitlines())


def _cmd_import(args: argparse.Namespace) -> int:
    sources = _read_sources(args.source, args.kind)
    locator = args.locator or args.source

    if args.update:
        return _update_policy(args.update, sources, locator=locator, force=args.force)

    policy = Policy(tools={s.contract.name: s.contract for s in sources})
    out = json.dumps(dump_bundle(policy), indent=2, ensure_ascii=False)
    if not args.out:
        print(out)
        return 0

    Path(args.out).write_text(out + "\n", encoding="utf-8")
    lock = _write_lock(sources, policy_path=args.out, locator=locator)
    print(f"wrote {len(sources)} tool contract(s) → {args.out} (REVIEW: add roles/authz before enforcing)")
    print(f"wrote provenance for {len(sources)} tool(s) → {lock} (commit it; `histos drift` reads it)")
    return 0


def _update_policy(policy_path: str, sources: list[ToolSource], *, locator: str, force: bool) -> int:
    """Refresh `args`/`returns` from the source, and touch nothing else.

    Roles, `resource`, `bind`, `confirmation`, `output`, limits and access are the
    security semantics a human wrote; no schema can supply them, so regenerating them
    would destroy the valuable half of the policy.
    """
    policy = _load_policy(policy_path)
    by_name = {s.contract.name: s for s in sources}

    updated: list[str] = []
    tools = dict(policy.tools)
    for name, existing in policy.tools.items():
        source = by_name.get(name)
        if source is None:
            continue
        merged = dataclasses.replace(existing, args=source.contract.args, returns=source.contract.returns)
        if contract_hash(merged) != contract_hash(existing):
            updated.append(name)
        tools[name] = merged

    added = sorted(set(by_name) - set(policy.tools))
    for name in added:
        print(f"NEW  {name} — in the source, not in the policy. Decide deliberately, then declare it.")

    if not updated:
        print("no contract changes to apply" + (f"; {len(added)} new tool(s) above" if added else ""))
        _report_lock_written(_write_lock(sources, policy_path=policy_path, locator=locator))
        return 0

    text = Path(policy_path).read_text(encoding="utf-8")
    if _has_comments(text) and not force:
        print(f"refusing to rewrite {policy_path}: it has comments this writer cannot preserve.", file=sys.stderr)
        print(f"contract changed for: {', '.join(updated)}", file=sys.stderr)
        print("apply those by hand, or re-run with --force to regenerate the file without them.", file=sys.stderr)
        return 1

    merged_policy = dataclasses.replace(policy, tools=tools)
    Path(policy_path).write_text(json.dumps(dump_bundle(merged_policy), indent=2, ensure_ascii=False) + "\n")
    print(f"updated args/returns for {len(updated)} tool(s) → {policy_path}: {', '.join(updated)}")
    print("review the diff — git is what approves this change.")
    _report_lock_written(_write_lock(sources, policy_path=policy_path, locator=locator))
    return 0


def _report_lock_written(path: Path) -> None:
    print(f"refreshed {path}")


def _cmd_drift(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    lock = load_lock(args.lock or lock_path_for(args.policy))
    sources = _read_sources(args.source, args.kind)
    report = compare(lock, sources, locator=args.locator or args.source)

    for drift in report.drifts:
        if drift.status == "added":
            print(f"DRIFT  {drift.name}  ADDED — a tool the policy never declared")
        elif drift.status == "removed":
            print(f"DRIFT  {drift.name}  REMOVED — gone from the source, still in the lock")
        else:
            moved = ", ".join(h.removesuffix("_sha256") for h in drift.changed)
            reach = "  ← reaches enforcement" if drift.reaches_enforcement else ""
            print(f"DRIFT  {drift.name}  changed: {moved}{reach}")

    unverifiable = unverifiable_tools(sorted(policy.tools), lock)
    if unverifiable:
        # A clean report must never read as coverage it does not have: hand-written
        # tools, and any defined in a language this process cannot re-read, are simply
        # not checked here.
        print(f"unverifiable from here ({len(unverifiable)}): {', '.join(unverifiable)}")

    if report.clean:
        print(f"OK — {len(lock.tools)} tool(s) match the lock")
        return 0
    print(f"{len(report.drifts)} tool(s) drifted, {report.reaching_enforcement} reaching enforcement")
    return 1


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    key = bytes.fromhex(args.key) if args.key else None
    ok, detail = verify_chain(args.log, key=key)
    print(detail)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="histos", description="Inspect a histos policy without running an agent.")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="structural validity (CI gate)")
    v.add_argument("policy")
    v.set_defaults(func=_cmd_validate)

    r = sub.add_parser("review", help="import→review tri-state verdict")
    r.add_argument("policy")
    r.set_defaults(func=_cmd_review)

    c = sub.add_parser("coverage", help="exposed-but-undeclared tools (fails CI)")
    c.add_argument("policy")
    c.add_argument("--tools", required=True, help="comma-separated names of tools exposed to the agent")
    c.set_defaults(func=_cmd_coverage)

    e = sub.add_parser("explain", help="evaluate one request against the policy (no tool run)")
    e.add_argument("policy")
    e.add_argument("tool")
    e.add_argument("--role", required=True)
    e.add_argument("--identity", default=None)
    e.add_argument("--args", default=None, help="JSON object of call arguments")
    e.add_argument("--attr", action="append", help="trusted principal attribute k=v (repeatable)")
    e.set_defaults(func=_cmd_explain)

    i = sub.add_parser("import", help="import tool shapes → policy bundle skeleton")
    i.add_argument("source")
    i.add_argument("--kind", choices=sorted(_SOURCE_READERS), default="mcp")
    i.add_argument("--out", default=None)
    i.add_argument("--update", default=None, metavar="POLICY", help="refresh args/returns in an existing policy")
    i.add_argument("--force", action="store_true", help="with --update, rewrite even if comments would be lost")
    i.add_argument("--locator", default=None, help="what to record as the source's address in the lock")
    i.set_defaults(func=_cmd_import)

    d = sub.add_parser("drift", help="tool definitions vs the lock (fails CI)")
    d.add_argument("policy")
    d.add_argument("--source", required=True)
    d.add_argument("--kind", choices=sorted(_SOURCE_READERS), default="mcp")
    d.add_argument("--lock", default=None, help="defaults to <policy>.lock.json beside the policy")
    d.add_argument("--locator", default=None)
    d.set_defaults(func=_cmd_drift)

    a = sub.add_parser("audit", help="audit-trail tools")
    asub = a.add_subparsers(dest="audit_cmd", required=True)
    av = asub.add_parser("verify", help="check hash-chain integrity")
    av.add_argument("log")
    av.add_argument("--key", default=None, help="hex HMAC key (for keyed chains)")
    av.set_defaults(func=_cmd_audit_verify)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: no such file: {exc.filename}", file=sys.stderr)
        return 2
    # JSONDecodeError subclasses ValueError, so it has to be caught first or the
    # generic branch swallows it and the message loses its context.
    except json.JSONDecodeError as exc:
        print(f"error: not valid JSON ({exc})", file=sys.stderr)
        return 2
    except (PolicyError, ValueError) as exc:
        # A malformed input file is a user mistake, not a crash. Printing a
        # traceback at somebody on their first command teaches them the tool is
        # fragile, which is the opposite of what a security tool should be
        # teaching on day one.
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
