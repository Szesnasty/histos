"""``histos`` — inspect and debug a policy without running an agent (Phase 0.1).

Subcommands (stdlib argparse, zero deps):

    histos validate  security.policy.yaml          # structural validity → exit 0/1 (CI)
    histos review    security.policy.yaml          # ✓ ready / ⚠ review / ✕ blocked
    histos coverage  security.policy.yaml --tools a,b,c   # exposed-but-undeclared → exit 1
    histos explain   security.policy.yaml <tool> --role support --args '{"amount": 999}'
    histos import    tools.json --kind mcp [--out security.policy.yaml]
    histos import    tools.json --kind mcp --update security.policy.yaml
    histos drift     security.policy.yaml --source tools.json --kind mcp [--allow-unverifiable]  # → exit 0/1 (CI)
    histos audit verify audit.jsonl [--key-file f]  # hash-chain integrity → exit 0/1
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from pathlib import Path
from typing import Any

from histos._version import __version__
from histos.audit import verify_chain
from histos.bundle import dump_bundle, load_policy
from histos.contracts import GateRequest, Policy, Principal
from histos.display import safe_text
from histos.errors import PolicyError
from histos.gate import Gate
from histos.importers import KINDS, ToolSource, reader_for
from histos.lockfile import build_lock, compare, contract_hash, load_lock, lock_path_for, unverifiable_tools
from histos.review import review_policy


def _read_sources(path: str, kind: str) -> list[ToolSource]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return reader_for(kind)(data)


def _cmd_validate(args: argparse.Namespace) -> int:
    issues = load_policy(args.policy).validate()
    if not issues:
        print("OK — policy is structurally valid")
        return 0
    print(f"INVALID — {len(issues)} issue(s):")
    for i in issues:
        print(f"  ✕ {i}")
    return 1


def _cmd_review(args: argparse.Namespace) -> int:
    review = review_policy(load_policy(args.policy))
    print(review.render())
    # An unreviewed import fails the gate as hard as a tool that cannot be gated at
    # all. `histos review` is the step between `import` and `protect`, and a policy
    # whose tools still carry the importer's assumption has not been through it — so
    # this is the check that stops such a policy reaching `enforce` in CI.
    # `validate`'s own issues arrive here too, so a `review` that exits 0 on a file
    # `validate` rejects is the weaker of two commands claiming to check the same thing
    # — and it is the one the docs put in the middle of import→review→protect. Only the
    # structural half fails the command; the advisory warnings are printed and are for a
    # human to weigh.
    return 1 if review.blocked or review.unreviewed or review.structural_issues else 0


def _cmd_coverage(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    exposed = {t.strip() for t in args.tools.split(",") if t.strip()}
    declared = set(policy.tools)
    undeclared = sorted(exposed - declared)
    unwrapped = sorted(declared - exposed)
    print(f"{len(exposed & declared)}/{len(exposed)} exposed tools are covered by the policy")
    # Every name below is source-authored, and this report is where a human decides
    # whether to grant the tool. See `histos.display`.
    for t in undeclared:
        print(f"  ✕ {safe_text(t)}: exposed to the agent but NOT in the policy (ungated gap)")
    for t in unwrapped:
        print(f"  · {safe_text(t)}: in the policy but not in the exposed set")
    return 1 if undeclared else 0


def _cmd_explain(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
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
    # Say what the skeleton claims about the tools, in the same breath as writing it.
    # The values are the import's worst-case assumption, not a reading of the source,
    # and a committed file that does not say so reads as somebody's decision.
    print(
        "  access/sensitivity are the import's unreviewed assumption, not the source's — "
        "`histos review` exits 1 until they are decided"
    )
    print(f"wrote provenance for {len(sources)} tool(s) → {lock} (commit it; `histos drift` reads it)")
    return 0


def _update_policy(policy_path: str, sources: list[ToolSource], *, locator: str, force: bool) -> int:
    """Refresh `args`/`returns` from the source, and touch nothing else.

    Roles, `resource`, `bind`, `confirmation`, `output`, limits and access are the
    security semantics a human wrote; no schema can supply them, so regenerating them
    would destroy the valuable half of the policy.
    """
    policy = load_policy(policy_path)
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
        print(f"NEW  {safe_text(name)} — in the source, not in the policy. Decide deliberately, then declare it.")

    if not updated:
        print("no contract changes to apply" + (f"; {len(added)} new tool(s) above" if added else ""))
        _report_lock_written(_write_lock(sources, policy_path=policy_path, locator=locator))
        return 0

    text = Path(policy_path).read_text(encoding="utf-8")
    if _has_comments(text) and not force:
        print(f"refusing to rewrite {policy_path}: it has comments this writer cannot preserve.", file=sys.stderr)
        print(f"contract changed for: {', '.join(safe_text(t) for t in updated)}", file=sys.stderr)
        print("apply those by hand, or re-run with --force to regenerate the file without them.", file=sys.stderr)
        return 1

    merged_policy = dataclasses.replace(policy, tools=tools)
    Path(policy_path).write_text(json.dumps(dump_bundle(merged_policy), indent=2, ensure_ascii=False) + "\n")
    print(f"updated args/returns for {len(updated)} tool(s) → {policy_path}: "
          f"{', '.join(safe_text(t) for t in updated)}")
    print("review the diff — git is what approves this change.")
    _report_lock_written(_write_lock(sources, policy_path=policy_path, locator=locator))
    return 0


def _report_lock_written(path: Path) -> None:
    print(f"refreshed {path}")


def _cmd_drift(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    lock = load_lock(args.lock or lock_path_for(args.policy))
    sources = _read_sources(args.source, args.kind)
    report = compare(lock, sources, locator=args.locator or args.source)

    for drift in report.drifts:
        if drift.status == "added":
            print(f"DRIFT  {safe_text(drift.name)}  ADDED — a tool the policy never declared")
        elif drift.status == "removed":
            print(f"DRIFT  {safe_text(drift.name)}  REMOVED — gone from the source, still in the lock")
        else:
            moved = ", ".join(h.removesuffix("_sha256") for h in drift.changed)
            reach = "  ← reaches enforcement" if drift.reaches_enforcement else ""
            print(f"DRIFT  {safe_text(drift.name)}  changed: {moved}{reach}")
            # The difference itself, straight from the committed lock — no second
            # build of the source needed, which is the whole point of recording it.
            for line in drift.diff:
                print(f"         {line}")
            for part in drift.unexplained:
                print(
                    f"         {part}: this lock (version {lock.version}) recorded a hash and not the "
                    f"{part} itself, so there is nothing here to diff against. Re-run `histos import` "
                    "to record one."
                )

    unverifiable = unverifiable_tools(sorted(policy.tools), lock)
    if unverifiable:
        # A clean report must never read as coverage it does not have: hand-written
        # tools, and any defined in a language this process cannot re-read, are simply
        # not checked here.
        print(f"unverifiable from here ({len(unverifiable)}): {', '.join(safe_text(t) for t in unverifiable)}")

    if report.clean:
        # State the fraction, not just the count: CI reads the exit code, but a human
        # reads this line, and "OK — 0 tool(s) match the lock" against a policy of ten
        # is not the reassurance it looks like.
        verified = len(policy.tools) - len(unverifiable)
        print(f"OK — {verified} of {len(policy.tools)} policy tool(s) match the lock", flush=True)
        # Fail-closed on what could not be checked. This used to be opt-in, which made
        # the default a CI gate that passed having verified nothing — the one arrangement
        # worse than no gate, because it is reported as a pass.
        if unverifiable and not args.allow_unverifiable:
            print(
                f"FAIL — {len(unverifiable)} policy tool(s) were not checked at all: "
                f"{', '.join(unverifiable)}. Import them so the lock covers them, or pass "
                "--allow-unverifiable to accept the gap deliberately.",
                file=sys.stderr,
            )
            return 1
        return 0
    print(f"{len(report.drifts)} tool(s) drifted, {report.reaching_enforcement} reaching enforcement")
    return 1


def _read_chain_key(args: argparse.Namespace) -> bytes | None:
    """Resolve the chain key, preferring the spellings that do not leak it.

    ``--key <hex>`` puts the secret in ``argv``, where it is readable by any process
    on the box via ``ps`` and lands in shell history. It stays, because breaking a
    documented flag is its own harm, but it warns and is documented last. The key file
    is read whole and stripped, so a trailing newline from ``echo >`` is not part of
    the secret.
    """
    if getattr(args, "key_file", None):
        return bytes.fromhex(Path(args.key_file).read_text(encoding="utf-8").strip())
    env = os.environ.get("HISTOS_AUDIT_KEY")
    if env:
        return bytes.fromhex(env.strip())
    if args.key:
        print("warning: --key exposes the secret in `ps` and shell history; prefer --key-file or "
              "HISTOS_AUDIT_KEY", file=sys.stderr)
        return bytes.fromhex(args.key)
    return None


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    ok, detail = verify_chain(args.log, key=_read_chain_key(args))
    print(detail)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="histos", description="Inspect a histos policy without running an agent.")
    # The version is stamped into every audit record as `gate_version`, so an operator
    # correlating a trail back to a build needs to be able to ask for it. `histos
    # --version` used to be an argparse usage error, exit 2, because the subcommand was
    # required and nothing answered above it.
    p.add_argument("--version", action="version", version=f"histos {__version__}")
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
    i.add_argument("--kind", choices=sorted(KINDS), default="mcp")
    i.add_argument("--out", default=None)
    i.add_argument("--update", default=None, metavar="POLICY", help="refresh args/returns in an existing policy")
    i.add_argument("--force", action="store_true", help="with --update, rewrite even if comments would be lost")
    i.add_argument("--locator", default=None, help="what to record as the source's address in the lock")
    i.set_defaults(func=_cmd_import)

    d = sub.add_parser("drift", help="tool definitions vs the lock (fails CI)")
    d.add_argument("policy")
    d.add_argument("--source", required=True)
    d.add_argument("--kind", choices=sorted(KINDS), default="mcp")
    d.add_argument("--lock", default=None, help="defaults to <policy>.lock.json beside the policy")
    d.add_argument("--locator", default=None)
    d.add_argument(
        "--allow-unverifiable",
        action="store_true",
        help="exit 0 even when a policy tool has no lock entry (the gap is accepted deliberately)",
    )
    # Kept, and now a no-op, because it names the default. Removing a flag that a
    # pipeline already passes would fail that pipeline on upgrade for asking for the
    # behaviour it is about to get anyway.
    d.add_argument("--fail-on-unverifiable", action="store_true", help=argparse.SUPPRESS)
    d.set_defaults(func=_cmd_drift)

    a = sub.add_parser("audit", help="audit-trail tools")
    asub = a.add_subparsers(dest="audit_cmd", required=True)
    av = asub.add_parser("verify", help="check hash-chain integrity")
    av.add_argument("log")
    av.add_argument("--key-file", default=None, help="file holding the hex HMAC key (preferred)")
    av.add_argument(
        "--key",
        default=None,
        help="hex HMAC key — visible in `ps` and shell history; prefer --key-file or HISTOS_AUDIT_KEY",
    )
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
    except ImportError as exc:
        # The YAML extra is optional and `bundle.py` already composes the sentence that
        # tells you what to install. It used to reach the terminal as a traceback, so
        # the one error a first-time user is most likely to hit looked like a crash in
        # the library rather than a missing install.
        print(f"error: {exc}", file=sys.stderr)
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
