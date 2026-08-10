"""Review a policy before enforcing it — the "import → review" step.

Turns a :class:`~histos.contracts.Policy` into an at-a-glance report:
what was discovered, what is destructive, what no role can reach, and what looks
incomplete or wrong. ``histos review`` prints :meth:`PolicyReview.render`, and a
host can render the same structure itself. Deterministic and read-only.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from histos.contracts import Policy, Sensitivity

# Per-tool verdict for the import→review→protect journey.
READY = "ready"  # ✓ safe to gate as-is
REVIEW = "review"  # ⚠ gated, but a human should confirm a decision
BLOCKED = "blocked"  # ✕ cannot be safely gated as-is (always fail-closed)

# NOTE: the IDOR check that used to live here is gone, and its absence is a
# feature. Policy Format 0.1 removed the self-declared-argument constraint from
# the language, so the mistake cannot be written down and there is nothing left to
# warn about. What replaces it is the check below for a *missing* constraint —
# which is the residual the format cannot close on its own.
_NO_ROW_AUTHZ = (
    "no resource constraint — authorization is tool-level, not row-level, so a caller "
    "granted this tool may act on any resource of this type. Add `resource: {owns: ...}`"
)


def _needs_row_authz(tool) -> bool:  # noqa: ANN001 — ToolContract, kept loose to avoid a cycle
    """A tool where tool-level authorization is not enough, but none was authored.

    Writes have always been flagged. High/critical-sensitivity **reads** are flagged
    too: `read_invoice(id)` marked critical with an RBAC grant and no constraint lets
    a caller read any row, and "this role may call read_invoice" is true for all of
    them. That gap used to be tolerated because the rule would have had to be written
    twice; there is one implementation now.
    """
    if tool.constraints:
        return False
    return tool.access == "write" or tool.sensitivity in (Sensitivity.HIGH, Sensitivity.CRITICAL)


@dataclass
class PolicyReview:
    tools_discovered: int = 0
    roles_discovered: int = 0
    destructive: list[str] = field(default_factory=list)
    unreachable: list[str] = field(default_factory=list)  # no role can call
    missing_arg_schema: list[str] = field(default_factory=list)
    missing_return_schema: list[str] = field(default_factory=list)
    callable_by: dict[str, list[str]] = field(default_factory=dict)  # tool -> roles
    warnings: list[str] = field(default_factory=list)
    # Import→review classification: tool -> (verdict, reasons)
    classification: dict[str, tuple[str, list[str]]] = field(default_factory=dict)

    def _by_verdict(self, verdict: str) -> list[str]:
        return sorted(name for name, (v, _) in self.classification.items() if v == verdict)

    @property
    def ready(self) -> list[str]:
        return self._by_verdict(READY)

    @property
    def needs_review(self) -> list[str]:
        return self._by_verdict(REVIEW)

    @property
    def blocked(self) -> list[str]:
        return self._by_verdict(BLOCKED)

    def ok(self) -> bool:
        return not self.warnings and not self.missing_arg_schema

    def render(self) -> str:
        lines = [
            f"{self.tools_discovered} tools discovered",
            f"  ✓ {len(self.ready)} ready   ⚠ {len(self.needs_review)} need review   "
            f"✕ {len(self.blocked)} cannot be safely gated",
            f"{self.roles_discovered} roles discovered",
        ]
        for name in self.needs_review:
            reasons = "; ".join(self.classification[name][1])
            lines.append(f"⚠ {name}: {reasons}")
        for name in self.blocked:
            reasons = "; ".join(self.classification[name][1])
            lines.append(f"✕ {name}: {reasons}")
        if not self.missing_return_schema:
            lines.append("return schema complete")
        lines.append(f"{len(self.warnings)} policy warning" + ("" if len(self.warnings) == 1 else "s"))
        return "\n".join(lines)


def review_policy(policy: Policy) -> PolicyReview:
    reachable: set[str] = set()
    callable_by: dict[str, list[str]] = {name: [] for name in policy.tools}
    for role in policy.permissions:
        for tool in policy.allowed_tools(role):
            reachable.add(tool)
            callable_by.setdefault(tool, []).append(role)

    warnings = list(policy.validate())
    for name, tool in sorted(policy.tools.items()):
        # Permissive argument schema (e.g. inferred from **kwargs) turns off
        # deny-by-default on the argument surface for this tool.
        if tool.args is not None and tool.args.allow_extra:
            warnings.append(
                f"tool {name!r} has a permissive argument schema (accepts any argument) — "
                "deny-by-default on arguments is off for it"
            )
        # A reachable high-risk tool with no resource constraint is authorized only
        # at the tool level — a caller granted it may act on any row.
        if _needs_row_authz(tool) and name in reachable:
            kind = "write tool" if tool.access == "write" else f"{tool.sensitivity.value}-sensitivity read tool"
            warnings.append(f"{kind} {name!r} has {_NO_ROW_AUTHZ}")

    # Per-tool import→review verdict: ✓ ready / ⚠ review / ✕ cannot be gated.
    classification: dict[str, tuple[str, list[str]]] = {}
    for name, tool in policy.tools.items():
        if tool.args is None:
            classification[name] = (BLOCKED, ["no argument schema — always fail-closed; cannot be safely gated"])
            continue
        reasons: list[str] = []
        if name not in reachable:
            reasons.append("no role can call it (no grant yet)")
        if tool.args.allow_extra:
            reasons.append("permissive argument schema (accepts any argument)")
        if _needs_row_authz(tool):
            reasons.append("no resource constraint (authorization is tool-level, not row-level)")
        classification[name] = (REVIEW, reasons) if reasons else (READY, [])

    return PolicyReview(
        tools_discovered=len(policy.tools),
        roles_discovered=len(policy.permissions),
        destructive=sorted(name for name, t in policy.tools.items() if t.access == "write"),
        unreachable=sorted(name for name in policy.tools if name not in reachable),
        missing_arg_schema=sorted(name for name, t in policy.tools.items() if t.args is None),
        missing_return_schema=sorted(name for name, t in policy.tools.items() if t.returns is None),
        callable_by={k: sorted(v) for k, v in callable_by.items()},
        warnings=warnings,
        classification=classification,
    )
