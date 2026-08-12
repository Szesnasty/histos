"""Review a policy before enforcing it — the "import → review" step.

Turns a :class:`~histos.contracts.Policy` into an at-a-glance report:
what was discovered, what is destructive, what no role can reach, and what looks
incomplete or wrong. ``histos review`` prints :meth:`PolicyReview.render`, and a
host can render the same structure itself. Deterministic and read-only.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from histos.contracts import Policy, Sensitivity, ToolContract
from histos.display import safe_text
from histos.importers.sources import UNREVIEWED_SENSITIVITY

# Per-tool verdict for the import→review→protect journey.
READY = "ready"  # ✓ safe to gate as-is
REVIEW = "review"  # ⚠ gated, but a human should confirm a decision
BLOCKED = "blocked"  # ✕ cannot be safely gated as-is (always fail-closed)

_UNREVIEWED = (
    "sensitivity and access are still the import's unreviewed assumption, and nothing else "
    "has been decided for this tool — no constraint, binding, confirmation or limit. Say what "
    "this tool actually is"
)

# NOTE: the IDOR check that used to live here is gone, and its absence is a
# feature. Policy Format 0.1 removed the self-declared-argument constraint from
# the language, so the mistake cannot be written down and there is nothing left to
# warn about. What replaces it is the check below for a *missing* constraint —
# which is the residual the format cannot close on its own.
_NO_ROW_AUTHZ = (
    "no resource constraint — authorization is tool-level, not row-level, so a caller "
    "granted this tool may act on any resource of this type. Add `resource: {owns: ...}`"
)

_NO_CONTRACT = (
    "handed to protect() but the policy declares no contract for it — every call denies "
    "with `unknown_tool` until a human writes one"
)


def _needs_row_authz(tool: ToolContract) -> bool:
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


def _is_unreviewed_import(tool: ToolContract) -> bool:
    """A tool still shaped exactly as ``histos import`` left it.

    The importers assume the worst they can express (see
    :data:`~histos.importers.sources.UNREVIEWED_SENSITIVITY`), so a tool carrying that
    sensitivity **with no authored mitigation of any kind** is one nobody has made a
    decision about. The conjunction is what makes this a fact rather than a guess: the
    test is not "does this look dangerous" but "is every field a human would touch
    still untouched". A reviewer who genuinely means `critical` writes down what
    protects it in the same edit — that is what reviewing a critical tool consists of
    — and a critical tool with nothing protecting it wants naming either way.

    Deliberately not derived from the tool's name. A heuristic that reads `get_*` as a
    read is right often enough to teach a reviewer to skim, and wrong exactly where
    skimming costs.
    """
    return (
        tool.sensitivity is UNREVIEWED_SENSITIVITY
        and not tool.constraints
        and not tool.bindings
        and not tool.requires_confirmation
        and tool.rate_limit is None
        and tool.budget is None
    )


def _all_any(tool: ToolContract) -> bool:
    """A non-empty argument schema that constrains nothing — every field typed ``any``."""
    return tool.args is not None and bool(tool.args.fields) and all(f.type == "any" for f in tool.args.fields.values())


def _untyped_fields(tool: ToolContract) -> list[str]:
    """Arguments declaring no type, so no value of them is validated.

    Named one by one, because the all-`any` check above only fires when *every* field
    is untyped: a tool with four bounded arguments and one `payload: any` reviewed
    clean, and `payload` is where the interesting value goes. One field is enough to
    turn deny-by-default off for the thing an attacker controls.
    """
    if tool.args is None:
        return []
    return sorted(name for name, f in tool.args.fields.items() if f.type == "any")


@dataclass
class PolicyReview:
    tools_discovered: int = 0
    roles_discovered: int = 0
    destructive: list[str] = field(default_factory=list)
    unreachable: list[str] = field(default_factory=list)  # no role can call
    missing_arg_schema: list[str] = field(default_factory=list)
    missing_return_schema: list[str] = field(default_factory=list)
    unreviewed: list[str] = field(default_factory=list)  # still carrying an import's assumption
    callable_by: dict[str, list[str]] = field(default_factory=dict)  # tool -> roles
    warnings: list[str] = field(default_factory=list)
    #: Tools handed to ``protect()`` that the policy never declares. `render()` names
    #: them, and `ok()` has to as well: a host asserting `review.ok()` in CI was told
    #: everything was fine about a tool set containing one the gate denies outright.
    no_contract: list[str] = field(default_factory=list)
    #: The subset of :attr:`warnings` that came from :meth:`Policy.validate` — a grant
    #: for a tool that does not exist, a role inheriting itself. Structural, not
    #: advisory, and separated so `histos review` can fail CI on exactly what `histos
    #: validate` fails on without also failing on "this write tool could use a resource
    #: constraint", which is good advice and not a broken policy.
    structural_issues: list[str] = field(default_factory=list)
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
        return not (self.warnings or self.missing_arg_schema or self.unreviewed or self.no_contract)

    def render(self) -> str:
        lines = [
            f"{self.tools_discovered} tools discovered",
            f"  ✓ {len(self.ready)} ready   ⚠ {len(self.needs_review)} need review   "
            f"✕ {len(self.blocked)} cannot be safely gated",
            f"{self.roles_discovered} roles discovered",
        ]
        # Tool names come from whoever wrote the MCP server or the OpenAPI document,
        # and this is the report a human reads before granting the tool — so they are
        # rendered as quoted data, never as something a terminal may act on.
        if self.unreviewed:
            lines.append(
                f"{len(self.unreviewed)} tool(s) carry an unreviewed import assumption: "
                + ", ".join(safe_text(n) for n in self.unreviewed)
            )
        for name in self.needs_review:
            reasons = "; ".join(self.classification[name][1])
            lines.append(f"⚠ {safe_text(name)}: {reasons}")
        for name in self.blocked:
            reasons = "; ".join(self.classification[name][1])
            lines.append(f"✕ {safe_text(name)}: {reasons}")
        if not self.missing_return_schema:
            lines.append("return schema complete")
        # Printed, not counted. A bare "3 policy warnings" is the same report whether
        # the three are cosmetic or whether one of them is `role 'admin' grants unknown
        # tool 'delete_user'` — the finding this whole report exists to surface. It also
        # made `review` read as milder than `validate` on the same file, since
        # `policy.validate()`'s own issues arrive here as warnings.
        lines.append(f"{len(self.warnings)} policy warning" + ("" if len(self.warnings) == 1 else "s"))
        lines.extend(f"  ⚠ {safe_text(w)}" for w in self.warnings)
        return "\n".join(lines)


def review_policy(policy: Policy, *, discovered: Iterable[str] = ()) -> PolicyReview:
    """Report on ``policy``; ``discovered`` names tools that exist but the policy does not.

    ``protect()`` passes the tools it was handed which the *authored* policy never
    declares. They are, by definition, absent from ``policy.tools`` — that is the whole
    finding — so every check below would look straight past them, and the review would
    describe a smaller world than the one the agent was actually given. Naming them here
    keeps the two halves of the report honest about the same set of tools.
    """
    reachable: set[str] = set()
    callable_by: dict[str, list[str]] = {name: [] for name in policy.tools}
    for role in policy.permissions:
        for tool_name in policy.allowed_tools(role):
            reachable.add(tool_name)
            callable_by.setdefault(tool_name, []).append(role)

    structural_issues = list(policy.validate())
    warnings = list(structural_issues)
    for name, tool in sorted(policy.tools.items()):
        # Permissive argument schema (e.g. inferred from **kwargs) turns off
        # deny-by-default on the argument surface for this tool.
        if tool.args is not None and tool.args.allow_extra:
            warnings.append(
                f"tool {name!r} has a permissive argument schema (accepts any argument) — "
                "deny-by-default on arguments is off for it"
            )
        # A schema whose every field is `any` accepts every value of every type. It
        # is what signature inference produces when the annotations could not be
        # resolved, and it is indistinguishable from a real schema in every other
        # report — so it gets named here rather than counted as coverage.
        if _all_any(tool):
            warnings.append(
                f"tool {name!r} has an argument schema in which no field declares a type "
                "(every field is `any`) — it names the arguments but validates none of them"
            )
        elif untyped := _untyped_fields(tool):
            warnings.append(
                f"tool {name!r} declares no type for {', '.join(repr(f) for f in untyped)} — "
                "no value of those arguments is validated"
            )
        # A reachable high-risk tool with no resource constraint is authorized only
        # at the tool level — a caller granted it may act on any row.
        if _needs_row_authz(tool) and name in reachable:
            kind = "write tool" if tool.access == "write" else f"{tool.sensitivity.value}-sensitivity read tool"
            warnings.append(f"{kind} {name!r} has {_NO_ROW_AUTHZ}")
        # An imported tool arrives claiming the worst about itself, because the import
        # read a shape and nothing else. That claim is not a review, and a policy full
        # of them must not read as one — so it is a warning, which is what `ok()` and
        # `histos review`'s exit code are built on.
        if _is_unreviewed_import(tool):
            warnings.append(f"tool {name!r}: {_UNREVIEWED}")

    # Per-tool import→review verdict: ✓ ready / ⚠ review / ✕ cannot be gated.
    classification: dict[str, tuple[str, list[str]]] = {}
    for name, tool in policy.tools.items():
        if tool.args is None:
            classification[name] = (BLOCKED, ["no argument schema — always fail-closed; cannot be safely gated"])
            continue
        reasons: list[str] = []
        if _is_unreviewed_import(tool):
            reasons.append(_UNREVIEWED)
        if name not in reachable:
            reasons.append("no role can call it (no grant yet)")
        if tool.args.allow_extra:
            reasons.append("permissive argument schema (accepts any argument)")
        if _all_any(tool):
            reasons.append("no field declares a type (every argument is `any`)")
        elif untyped := _untyped_fields(tool):
            reasons.append(f"no type declared for {', '.join(repr(f) for f in untyped)}")
        if _needs_row_authz(tool):
            reasons.append("no resource constraint (authorization is tool-level, not row-level)")
        classification[name] = (REVIEW, reasons) if reasons else (READY, [])

    # A tool with no contract cannot be READY, and calling it BLOCKED would say the
    # policy decided something it never mentions. It needs a human, which is what
    # REVIEW means.
    undeclared = sorted(set(discovered) - set(policy.tools))
    for name in undeclared:
        classification[name] = (REVIEW, [_NO_CONTRACT])

    return PolicyReview(
        tools_discovered=len(policy.tools) + len(undeclared),
        roles_discovered=len(policy.permissions),
        destructive=sorted(name for name, t in policy.tools.items() if t.access == "write"),
        unreachable=sorted(name for name in policy.tools if name not in reachable),
        missing_arg_schema=sorted(name for name, t in policy.tools.items() if t.args is None),
        missing_return_schema=sorted(name for name, t in policy.tools.items() if t.returns is None),
        unreviewed=sorted(name for name, t in policy.tools.items() if _is_unreviewed_import(t)),
        callable_by={k: sorted(v) for k, v in callable_by.items()},
        warnings=warnings,
        structural_issues=structural_issues,
        no_contract=undeclared,
        classification=classification,
    )
