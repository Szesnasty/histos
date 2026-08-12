"""The tool lock: what each imported tool looked like when a human last read it.

A policy is a self-contained, hashed artifact and must stay one, so it never points
at a contract it does not contain (`docs/tool-contracts.md` records why a live
reference was rejected: the same ``content_hash`` could then decide differently in
two places, and the *tool* would get to declare which of its own arguments are
legal). Provenance is build metadata, and build metadata belongs in a lock file
beside the artifact — the precedent is every package manager in use.

**Three hashes, because there are three different questions.**

``schema_sha256``
    Over the normative per-kind ``shape``. Did the declared shape change at all,
    including in a part the projection discards?
``description_sha256``
    Over the description alone. It never reaches a ``ToolContract``, and it is where
    a tool-poisoning payload hides, so *"the contract is unchanged"* must never be
    reported as *"the tool definition is unchanged"*.
``contract_sha256``
    Over ``ToolContract.shape_fingerprint()`` — arguments and returns only. Did the
    change reach the part that is actually enforced? Security semantics a human
    wrote (roles, ``owns``, ``bind``, confirmation, limits, output rules) are
    excluded on purpose: adding an ownership rule is not tool drift.

All three are defined over :func:`histos.canonical.canonical_json`, so a second
implementation reproduces them byte for byte. That is a conformance obligation, not
an implementation detail — see ``spec/tool-lock-0.1.schema.json``. A drift signal
that differs between runtimes is worse than none, because it teaches people to
ignore it.

**And the reviewed copy, because a hash says THAT and never WHAT.**

Version 2 records, beside the hashes, the ``shape`` and ``description`` the reviewer
actually read (:class:`Reviewed`). Hashes alone left ``histos drift`` able to name
the tool and the moved digest and nothing else, so the only way to show a human the
difference was to re-read the build they had reviewed — which on review day nobody
has, and which is the exact job a lock exists to remove. With the reviewed copy
committed, the explanation is derivable from the artifact in the repository.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from histos.canonical import canonical_json
from histos.contracts import ToolContract
from histos.display import safe_text
from histos.errors import PolicyError
from histos.importers.sources import KINDS, ToolSource

LOCK_VERSION = 2

# Versions this engine reads. A lock written by an older histos must not become
# unreadable the day the format grows: the file is committed, CI runs it, and a
# hard refusal would turn a routine upgrade into a broken pipeline for a file that
# is still perfectly valid. A version-1 entry simply carries no reviewed copy, and
# every report about it says so rather than quietly reporting less.
READABLE_LOCK_VERSIONS = frozenset({1, LOCK_VERSION})

_LOCK_KEYS = frozenset({"lock_version", "policy", "tools"})
_ENTRY_KEYS_V1 = frozenset({"source", "schema_sha256", "description_sha256", "contract_sha256"})
_ENTRY_KEYS = _ENTRY_KEYS_V1 | {"reviewed"}
_SOURCE_KEYS = frozenset({"kind", "locator"})
_REVIEWED_KEYS = frozenset({"shape", "description", "elided"})

# Which hash moved, in the order a reader should care about. `contract` first: it is
# the only one that says enforcement changed.
HASHES = ("contract_sha256", "schema_sha256", "description_sha256")

# The lock is a committed artifact: it is diffed in review, carried in every clone,
# and grows once per imported tool. The reviewed copy is therefore bounded rather
# than unlimited — both halves come from the source, so both are attacker-sized. Past
# these limits the entry keeps its hashes, records nothing, and names the omission in
# `elided`, so a report degrades to "hash only, and here is why" instead of silently
# explaining less than it looks like it does. The limits are far above any real tool
# definition (the largest shape in `demo/` is under 700 bytes).
MAX_RECORDED_SHAPE_BYTES = 16_384
MAX_RECORDED_DESCRIPTION_CHARS = 4_096

# A rendered diff is for a human to read once. Bounds keep a source that ships a
# 10,000-line schema from burying the one line that matters.
_MAX_DIFF_LINES = 40


def _difflib() -> Any:
    """`difflib` on first use, not at import.

    It costs three quarters of a millisecond to import and is reached only by the drift
    report — a CLI path. A library whose selling point is that wrapping a tool costs one
    `pip install` and no infrastructure should not pay for its diff renderer in every
    process that merely gates a call.
    """
    import difflib

    return difflib


def _digest(obj: Any) -> str:
    """Type-tagged, number-normalised digest — the same rule as ``Policy.content_hash``.

    ``numbers_as_text=True`` collapses ``8`` and ``8.0`` (no JSON parser can tell them
    apart, so a second implementation must not be asked to) while the canonicalizer
    still tags the type first, which is what keeps the integer ``1`` and the string
    ``"1"`` apart. Flattening numbers *before* this call destroyed that tag.
    """
    return "sha256:" + hashlib.sha256(canonical_json(obj, numbers_as_text=True).encode("utf-8")).hexdigest()


def schema_hash(shape: dict[str, Any]) -> str:
    """Hash of the normative per-kind shape.

    The raw source document is hashed as it arrived, types included: a source that
    swaps an integer bound or enum member for its string spelling has changed what the
    tool will accept, and the lock exists to say so.
    """
    return _digest(shape)


def description_hash(description: str | None) -> str:
    """Hash of the description. ``None`` hashes as JSON ``null``, so absent and empty differ."""
    return _digest(description)


def contract_hash(contract: ToolContract) -> str:
    """Hash of the imported half of a contract: arguments and returns, nothing else.

    Taken over ``shape_structure``, not the flattened ``shape_fingerprint`` projection
    — one rule, one place, and the same one ``Policy.content_hash`` uses.
    """
    return _digest(contract.shape_structure())


@dataclass(frozen=True)
class Reviewed:
    """What the reviewer actually read, committed beside the hashes that pin it.

    ``elided`` names the parts that were too large to record (see
    :data:`MAX_RECORDED_SHAPE_BYTES`). It is the difference between "the source had no
    description" — ``description`` is ``None`` and ``elided`` is empty — and "there was
    one and this file does not carry it", which a report has to be able to state.
    """

    shape: dict[str, Any] | None = None
    description: str | None = None
    elided: tuple[str, ...] = ()

    @classmethod
    def of(cls, source: ToolSource) -> Reviewed:
        elided: list[str] = []
        shape: dict[str, Any] | None = source.shape
        if len(canonical_json(source.shape).encode("utf-8")) > MAX_RECORDED_SHAPE_BYTES:
            shape = None
            elided.append("shape")
        description = source.description
        if description is not None and len(description) > MAX_RECORDED_DESCRIPTION_CHARS:
            description = None
            elided.append("description")
        return cls(shape=shape, description=description, elided=tuple(elided))

    def has(self, part: str) -> bool:
        """True when this entry can explain a change to ``part`` ("shape"|"description")."""
        return part not in self.elided

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.has("shape"):
            out["shape"] = self.shape
        if self.has("description"):
            out["description"] = self.description
        if self.elided:
            out["elided"] = list(self.elided)
        return out


@dataclass(frozen=True)
class LockEntry:
    """One tool's recorded provenance.

    ``reviewed`` is ``None`` only for an entry read from a version-1 file, which
    recorded hashes and nothing else. Everything that renders a difference has to
    check for that rather than assume a baseline it does not have.
    """

    kind: str
    locator: str
    schema_sha256: str
    description_sha256: str
    contract_sha256: str
    reviewed: Reviewed | None = None

    @classmethod
    def of(cls, source: ToolSource, locator: str) -> LockEntry:
        return cls(
            kind=source.kind,
            locator=locator,
            schema_sha256=schema_hash(source.shape),
            description_sha256=description_hash(source.description),
            contract_sha256=contract_hash(source.contract),
            reviewed=Reviewed.of(source),
        )

    def to_dict(self) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "source": {"kind": self.kind, "locator": self.locator},
            "schema_sha256": self.schema_sha256,
            "description_sha256": self.description_sha256,
            "contract_sha256": self.contract_sha256,
        }
        if self.reviewed is not None:
            entry["reviewed"] = self.reviewed.to_dict()
        return entry


@dataclass(frozen=True)
class Lock:
    """The lock file: a policy path and one entry per tool that came from a source.

    ``version`` is the version this object was *read* at, so re-dumping a version-1
    file does not stamp it as a version-2 one it has no reviewed copy to back up.
    """

    policy: str
    tools: dict[str, LockEntry]
    version: int = LOCK_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "lock_version": self.version,
            "policy": self.policy,
            "tools": {name: entry.to_dict() for name, entry in sorted(self.tools.items())},
        }

    def dumps(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"


def build_lock(sources: list[ToolSource], *, policy: str, locator: str) -> Lock:
    """Record the sources an import just read."""
    return Lock(policy=policy, tools={s.name: LockEntry.of(s, locator) for s in sources})


def _reject_unknown(where: str, data: dict[str, Any], allowed: frozenset[str]) -> None:
    unknown = sorted(k for k in data if k not in allowed)
    if unknown:
        raise PolicyError(
            f"unknown key {unknown[0]!r} in {where} of the tool lock"
            + (f" (also: {', '.join(unknown[1:])})" if len(unknown) > 1 else "")
            + " — refusing to load. Understood here: "
            + ", ".join(sorted(allowed))
            + "."
        )


def parse_lock(data: dict[str, Any]) -> Lock:
    """Load a lock, failing closed on anything this version does not understand."""
    if not isinstance(data, dict):
        raise PolicyError(f"a tool lock must be an object, got {type(data).__name__}")
    _reject_unknown("the top level", data, _LOCK_KEYS)

    version = data.get("lock_version")
    # `True` equals `1` in Python, so a set membership test alone would read
    # `"lock_version": true` as a version-1 file. The version decides which keys are
    # legal, so it has to be a number and nothing that merely compares like one.
    if not isinstance(version, int) or isinstance(version, bool) or version not in READABLE_LOCK_VERSIONS:
        raise PolicyError(
            f"tool lock version {version!r} is not supported by this engine "
            f"(reads: {', '.join(str(v) for v in sorted(READABLE_LOCK_VERSIONS))}). "
            "Re-run the import that produced it rather than editing the file."
        )
    # A version-1 file predates the reviewed copy, so a `reviewed` block in one is not
    # an old file this engine can read — it is a file somebody edited by hand, or a
    # newer one mislabelled. Either way its version does not describe its contents.
    entry_keys = _ENTRY_KEYS_V1 if version == 1 else _ENTRY_KEYS

    tools_node = data.get("tools") or {}
    if not isinstance(tools_node, dict):
        raise PolicyError(f"`tools` in a tool lock must be an object, got {type(tools_node).__name__}")

    entries: dict[str, LockEntry] = {}
    for name, node in tools_node.items():
        if not isinstance(node, dict):
            raise PolicyError(f"tool {name!r} in the lock must be an object, got {type(node).__name__}")
        _reject_unknown(f"tool {name!r}", node, entry_keys)
        source = node.get("source") or {}
        if not isinstance(source, dict):
            raise PolicyError(f"`source` for tool {name!r} must be an object, got {type(source).__name__}")
        _reject_unknown(f"`source` for tool {name!r}", source, _SOURCE_KEYS)
        kind = source.get("kind")
        if kind not in KINDS:
            raise PolicyError(
                f"tool {name!r} in the lock names source kind {kind!r}, which this engine does not read. "
                f"Understood here: {', '.join(sorted(KINDS))}."
            )
        entries[name] = LockEntry(
            kind=str(kind),
            locator=source.get("locator") or "",
            schema_sha256=node.get("schema_sha256") or "",
            description_sha256=node.get("description_sha256") or "",
            contract_sha256=node.get("contract_sha256") or "",
            reviewed=_reviewed_from_node(name, node.get("reviewed")) if "reviewed" in node else None,
        )

    return Lock(policy=data.get("policy") or "", tools=entries, version=int(version))


def _reviewed_from_node(name: str, node: Any) -> Reviewed:
    """Parse the reviewed copy, refusing anything whose shape it cannot vouch for."""
    where = f"`reviewed` for tool {name!r}"
    if not isinstance(node, dict):
        raise PolicyError(f"{where} must be an object, got {type(node).__name__}")
    _reject_unknown(where, node, _REVIEWED_KEYS)

    shape = node.get("shape")
    if shape is not None and not isinstance(shape, dict):
        raise PolicyError(f"`shape` in {where} must be an object, got {type(shape).__name__}")
    description = node.get("description")
    if description is not None and not isinstance(description, str):
        raise PolicyError(f"`description` in {where} must be a string, got {type(description).__name__}")

    elided = node.get("elided") or []
    if not isinstance(elided, list) or any(part not in _REVIEWED_KEYS - {"elided"} for part in elided):
        raise PolicyError(
            f"`elided` in {where} must be a list naming recorded parts "
            f"({', '.join(sorted(_REVIEWED_KEYS - {'elided'}))})"
        )
    # An absent `shape` key with nothing in `elided` would read as "the source had no
    # shape", which no importer can produce. Treat it as elided rather than as a
    # baseline: reporting hash-only is honest, inventing an empty shape is not.
    missing = tuple(part for part in sorted(_REVIEWED_KEYS - {"elided"}) if part not in node and part not in elided)
    return Reviewed(shape=shape, description=description, elided=tuple(sorted({*elided, *missing})))


def load_lock(path: str | Path) -> Lock:
    return parse_lock(json.loads(Path(path).read_text(encoding="utf-8")))


def lock_path_for(policy_path: str | Path) -> Path:
    """`security.policy.yaml` → `security.policy.lock.json`, beside it.

    Only the final extension is replaced, so the policy's own name survives — the two
    files have to be recognisable as a pair in a directory listing.
    """
    p = Path(policy_path)
    return p.with_name(p.stem + ".lock.json")


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
        if before is _ABSENT:
            lines.append(f"+ {path}: {_render(after)}")
        elif after is _ABSENT:
            lines.append(f"- {path}: {_render(before)}")
        else:
            lines.append(f"~ {path}: {_render(before)} → {_render(after)}")
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
