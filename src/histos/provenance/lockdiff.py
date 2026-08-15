"""What moved between the tool the reviewer signed off and the tool on the wire now.

Split out of `lockfile.py`. The lock records what was reviewed; this says what changed,
and the hard part is not detecting a change but *ranking* it. A vendor rewriting a
description is a prompt-injection surface and reaches no enforcement; a vendor widening
a bound reaches enforcement and changes what the gate allows. Reporting both the same way
makes the second invisible in the noise of the first, and reporting only the second
misses the rug-pull this whole mechanism exists to catch.

So the diff is rendered by *where it lands*, the count of changes reaching enforcement is
what the exit code keys on, and the description change is still printed in full — because
a human reading it is the control for that one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from histos.display import safe_text
from histos.importers.sources import ToolSource
from histos.provenance.lockfile import _MAX_DIFF_LINES, HASHES, Lock, LockEntry, _difflib

# ── diffing the reviewed copy against what the source says now ───────────

_ABSENT: Any = object()


def _flatten(node: Any, prefix: str = "") -> dict[str, Any]:
    """A JSON document as ``path -> leaf``, so two of them subtract.

    An empty object or array is itself a leaf: ``properties: {}`` becoming
    ``properties: {"include_internal": ...}`` is the change a reviewer is looking for,
    and a walk that only yields scalars would report the addition without ever saying
    what it replaced.
    """
    if isinstance(node, dict) and node:
        out: dict[str, Any] = {}
        for key, value in node.items():
            out.update(_flatten(value, f"{prefix}.{key}" if prefix else str(key)))
        return out
    if isinstance(node, list) and node:
        out = {}
        for index, value in enumerate(node):
            out.update(_flatten(value, f"{prefix}[{index}]"))
        return out
    return {prefix: node}


def _render(value: Any) -> str:
    if value is _ABSENT:
        return "<absent>"
    return safe_text(json.dumps(value, ensure_ascii=False, sort_keys=True))


def _same(a: Any, b: Any) -> bool:
    """Equal *and* the same JSON type — ``True`` and ``1`` are not one value here.

    The hashes already separate them (the canonicalizer tags the type before it
    normalises the number), so a diff that collapsed them would show nothing for a
    drift the report has just declared.
    """
    return a == b and isinstance(a, bool) == isinstance(b, bool)


def _cap(lines: list[str]) -> tuple[str, ...]:
    if len(lines) <= _MAX_DIFF_LINES:
        return tuple(lines)
    return (*lines[:_MAX_DIFF_LINES], f"… and {len(lines) - _MAX_DIFF_LINES} more line(s)")


def shape_diff(recorded: dict[str, Any], current: dict[str, Any]) -> tuple[str, ...]:
    """Path-by-path difference between the reviewed shape and the current one."""
    was, now = _flatten(recorded), _flatten(current)
    lines: list[str] = []
    for path in sorted(set(was) | set(now)):
        before, after = was.get(path, _ABSENT), now.get(path, _ABSENT)
        if _same(before, after):
            continue
        # The path goes through `safe_text` as well as the value. It is built from the
        # source document's own JSON keys, so it is as attacker-authored as anything
        # else here — a property renamed to `x\r\x1b[2KOK — no drift` rewrites the
        # line `histos drift` just printed, in the report a human reads to decide
        # whether to accept a tool change.
        shown = safe_text(path)
        if before is _ABSENT:
            lines.append(f"+ {shown}: {_render(after)}")
        elif after is _ABSENT:
            lines.append(f"- {shown}: {_render(before)}")
        else:
            lines.append(f"~ {shown}: {_render(before)} → {_render(after)}")
    return _cap(lines)


def _description_lines(text: str | None) -> list[str]:
    """A description as diffable lines. ``None`` and ``""`` are different facts."""
    if text is None:
        return ["<no description>"]
    return [safe_text(line) for line in text.splitlines()] or [""]


def description_diff(recorded: str | None, current: str | None) -> tuple[str, ...]:
    """Line diff of the description, every line rendered through :func:`safe_text` first.

    Sanitised *before* difflib sees it, so a payload cannot arrive with its escaping
    split across a hunk boundary, and the ``-``/``+`` column a reader relies on stays
    difflib's rather than something the description drew for itself.
    """
    lines = [
        line
        for line in _difflib().unified_diff(_description_lines(recorded), _description_lines(current), n=1, lineterm="")
        if not line.startswith(("---", "+++"))
    ]
    return _cap(lines)


@dataclass(frozen=True)
class ToolDrift:
    """What moved for one tool, and — when the lock recorded enough — what it now says."""

    name: str
    status: str  # "changed" | "added" | "removed"
    changed: tuple[str, ...] = ()  # which of HASHES differ, most significant first
    diff: tuple[str, ...] = ()  # human-readable, already sanitised; empty when unexplained
    unexplained: tuple[str, ...] = ()  # parts ("shape"|"description") the lock cannot show

    @property
    def reaches_enforcement(self) -> bool:
        """True when the change touches what the gate actually evaluates."""
        return self.status != "removed" and "contract_sha256" in self.changed

    @property
    def explained(self) -> bool:
        """True when the report can show the difference, not merely assert one."""
        return not self.unexplained


@dataclass(frozen=True)
class DriftReport:
    """The result of comparing a lock against a freshly read source."""

    drifts: tuple[ToolDrift, ...]
    unverifiable: tuple[str, ...] = ()  # policy tools with no lock entry

    @property
    def clean(self) -> bool:
        return not self.drifts

    @property
    def reaching_enforcement(self) -> int:
        return sum(1 for d in self.drifts if d.reaches_enforcement)


def _explain(
    recorded: LockEntry, source: ToolSource, moved: tuple[str, ...]
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Turn "these hashes moved" into "here is the difference", or say why it cannot.

    The two hashes over the source are reported separately because they answer
    different questions, but they are explained from one recorded copy: ``schema`` and
    ``contract`` both move when the shape does, and printing the same diff twice under
    two headings would read as two findings.
    """
    reviewed = recorded.reviewed
    diff: list[str] = []
    unexplained: list[str] = []

    if {"schema_sha256", "contract_sha256"} & set(moved):
        if reviewed is not None and reviewed.has("shape") and reviewed.shape is not None:
            diff.extend(shape_diff(reviewed.shape, source.shape))
        else:
            unexplained.append("shape")
    if "description_sha256" in moved:
        if reviewed is not None and reviewed.has("description"):
            diff.append("description:")
            diff.extend(f"  {line}" for line in description_diff(reviewed.description, source.description))
        else:
            unexplained.append("description")

    return tuple(diff), tuple(unexplained)


def compare(lock: Lock, sources: list[ToolSource], *, locator: str) -> DriftReport:
    """Compare what the lock recorded against what the source says now.

    A tool that disappeared is drift too: an agent may still hold a reference to it,
    and a silently vanished tool is exactly as interesting as a silently added one.

    Where the lock carries a reviewed copy the drift is *shown*, not just asserted. A
    version-1 lock has none, so those entries come back with ``unexplained`` naming
    what could not be diffed — reporting less is fine, implying more is not.
    """
    by_name = {s.name: s for s in sources}
    fresh = {name: LockEntry.of(source, locator) for name, source in by_name.items()}
    drifts: list[ToolDrift] = []

    for name in sorted(set(lock.tools) | set(fresh)):
        recorded, current = lock.tools.get(name), fresh.get(name)
        if recorded is None:
            drifts.append(ToolDrift(name, "added", HASHES))
        elif current is None:
            drifts.append(ToolDrift(name, "removed"))
        else:
            moved = tuple(h for h in HASHES if getattr(recorded, h) != getattr(current, h))
            if moved:
                diff, unexplained = _explain(recorded, by_name[name], moved)
                drifts.append(ToolDrift(name, "changed", moved, diff, unexplained))

    return DriftReport(drifts=tuple(drifts))


def unverifiable_tools(policy_tools: list[str], lock: Lock) -> tuple[str, ...]:
    """Policy tools the lock says nothing about.

    Hand-written tools, and any imported from a source this process cannot re-read
    (a Zod schema, from a Python CLI). A clean drift report must never be presented
    as coverage it does not have, so these are reported alongside it.
    """
    return tuple(sorted(name for name in policy_tools if name not in lock.tools))
