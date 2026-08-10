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
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from histos.canonical import canonical_fingerprint, normalize_numbers
from histos.contracts import ToolContract
from histos.errors import PolicyError
from histos.importers.sources import KINDS, ToolSource

LOCK_VERSION = 1

_LOCK_KEYS = frozenset({"lock_version", "policy", "tools"})
_ENTRY_KEYS = frozenset({"source", "schema_sha256", "description_sha256", "contract_sha256"})
_SOURCE_KEYS = frozenset({"kind", "locator"})

# Which hash moved, in the order a reader should care about. `contract` first: it is
# the only one that says enforcement changed.
HASHES = ("contract_sha256", "schema_sha256", "description_sha256")


def _digest(obj: Any) -> str:
    return "sha256:" + canonical_fingerprint(obj)


def schema_hash(shape: dict[str, Any]) -> str:
    """Hash of the normative per-kind shape.

    Normalises here as well as in the fingerprint, because a raw source document
    carries arbitrary JSON numbers that never pass through ``Policy.fingerprint``.
    """
    return _digest(normalize_numbers(shape))


def description_hash(description: str | None) -> str:
    """Hash of the description. ``None`` hashes as JSON ``null``, so absent and empty differ."""
    return _digest(description)


def contract_hash(contract: ToolContract) -> str:
    """Hash of the imported half of a contract: arguments and returns, nothing else.

    ``shape_fingerprint`` already renders its numbers as decimal text, so this is the
    same normalisation the policy's own ``content_hash`` gets — one rule, one place.
    """
    return _digest(contract.shape_fingerprint())


@dataclass(frozen=True)
class LockEntry:
    """One tool's recorded provenance."""

    kind: str
    locator: str
    schema_sha256: str
    description_sha256: str
    contract_sha256: str

    @classmethod
    def of(cls, source: ToolSource, locator: str) -> LockEntry:
        return cls(
            kind=source.kind,
            locator=locator,
            schema_sha256=schema_hash(source.shape),
            description_sha256=description_hash(source.description),
            contract_sha256=contract_hash(source.contract),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": {"kind": self.kind, "locator": self.locator},
            "schema_sha256": self.schema_sha256,
            "description_sha256": self.description_sha256,
            "contract_sha256": self.contract_sha256,
        }


@dataclass(frozen=True)
class Lock:
    """The lock file: a policy path and one entry per tool that came from a source."""

    policy: str
    tools: dict[str, LockEntry]

    def to_dict(self) -> dict[str, Any]:
        return {
            "lock_version": LOCK_VERSION,
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
    if version != LOCK_VERSION:
        raise PolicyError(
            f"tool lock version {version!r} is not supported by this engine (expected {LOCK_VERSION}). "
            "Re-run the import that produced it rather than editing the file."
        )

    tools_node = data.get("tools") or {}
    if not isinstance(tools_node, dict):
        raise PolicyError(f"`tools` in a tool lock must be an object, got {type(tools_node).__name__}")

    entries: dict[str, LockEntry] = {}
    for name, node in tools_node.items():
        if not isinstance(node, dict):
            raise PolicyError(f"tool {name!r} in the lock must be an object, got {type(node).__name__}")
        _reject_unknown(f"tool {name!r}", node, _ENTRY_KEYS)
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
            kind=kind,
            locator=source.get("locator") or "",
            schema_sha256=node.get("schema_sha256") or "",
            description_sha256=node.get("description_sha256") or "",
            contract_sha256=node.get("contract_sha256") or "",
        )

    return Lock(policy=data.get("policy") or "", tools=entries)


def load_lock(path: str | Path) -> Lock:
    return parse_lock(json.loads(Path(path).read_text(encoding="utf-8")))


def lock_path_for(policy_path: str | Path) -> Path:
    """`security.policy.yaml` → `security.policy.lock.json`, beside it.

    Only the final extension is replaced, so the policy's own name survives — the two
    files have to be recognisable as a pair in a directory listing.
    """
    p = Path(policy_path)
    return p.with_name(p.stem + ".lock.json")


@dataclass(frozen=True)
class ToolDrift:
    """What moved for one tool."""

    name: str
    status: str  # "changed" | "added" | "removed"
    changed: tuple[str, ...] = ()  # which of HASHES differ, most significant first

    @property
    def reaches_enforcement(self) -> bool:
        """True when the change touches what the gate actually evaluates."""
        return self.status != "removed" and "contract_sha256" in self.changed


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


def compare(lock: Lock, sources: list[ToolSource], *, locator: str) -> DriftReport:
    """Compare what the lock recorded against what the source says now.

    A tool that disappeared is drift too: an agent may still hold a reference to it,
    and a silently vanished tool is exactly as interesting as a silently added one.
    """
    fresh = {s.name: LockEntry.of(s, locator) for s in sources}
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
                drifts.append(ToolDrift(name, "changed", moved))

    return DriftReport(drifts=tuple(drifts))


def unverifiable_tools(policy_tools: list[str], lock: Lock) -> tuple[str, ...]:
    """Policy tools the lock says nothing about.

    Hand-written tools, and any imported from a source this process cannot re-read
    (a Zod schema, from a Python CLI). A clean drift report must never be presented
    as coverage it does not have, so these are reported alongside it.
    """
    return tuple(sorted(name for name in policy_tools if name not in lock.tools))
