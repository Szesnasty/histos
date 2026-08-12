"""What a tool definition looked like at the moment it was imported.

:func:`~histos.importers.mcp.contracts_from_mcp` and its siblings answer *"what
does the policy enforce"*. This module answers the other question, the one drift
detection needs: *"what did the source say, and what part of it reached the
policy"*.

Three things are kept per tool, and the split is the whole point (see
`docs/tool-contracts.md`):

``shape``
    The schema-bearing part of the source, normalised per kind. Hashing this
    detects **any** change to the declared shape, including one the projection
    discards.
``description``
    Kept separately because it never reaches a :class:`ToolContract` at all —
    and a description is where a tool-poisoning payload hides, so "the contract
    is unchanged" must not be reported as "the tool definition is unchanged".
``contract``
    The projection. Hashing this answers the question an on-call engineer
    actually has: *did the change reach the part that is enforced?*

The ``shape`` layout per kind is **normative** — a second implementation must
produce the same bytes, or the same tool drifts in one runtime and not another.
It is written down in `spec/tool-lock-0.1.schema.json`.
"""

from __future__ import annotations

import re
import warnings
from collections.abc import Callable, Iterable, Iterator, Sequence, Set
from dataclasses import dataclass
from typing import Any

from histos.contracts import Sensitivity, ToolContract
from histos.errors import PolicyError

SourceReader = Callable[[Any], list["ToolSource"]]

# What an importer is allowed to assume about a tool whose *shape* is all it has read.
#
# It used to assume the best: `access: read`, `sensitivity: low`. A vendor's
# `export_contacts` therefore landed in a generated skeleton labelled a harmless read,
# in a committed file, in the same words a human would have used had they decided it —
# and the library advertised a review step that would flag the assumption, which did
# not exist. A default in a security artifact is not a placeholder; it is a claim.
#
# So the import now assumes the worst it can express. `write` and `critical` are not
# guesses at what the tool does — they are the only reading that is safe to be wrong
# about, and they make every imported tool something `review_policy` reports as an
# outstanding decision. Guessing from the name (`get_*` is a read, `send_*` is a
# write) was rejected for the same reason: a rule that is right most of the time is
# how a reviewer learns to skim, and the one it gets wrong is the one that matters.
UNREVIEWED_ACCESS = "write"
UNREVIEWED_SENSITIVITY = Sensitivity.CRITICAL


class _SourceKinds(Set[str]):
    """The kinds this process can read, and the reader for each.

    A registry rather than a literal set, because the alternative made importing
    from anything the library did not ship — Anthropic tool definitions, a Pydantic
    model, an internal tool registry — impossible rather than merely unimplemented.
    A host could always build a :class:`~histos.contracts.ToolContract`, but not a
    :class:`ToolSource`, so its tools could never enter a lock file and `histos
    drift` reported them forever as "unverifiable from here" with no way to close
    the gap short of forking.

    Registration is an **explicit host call**. There is deliberately no entry-point
    discovery: a lock file records where a tool definition came from, and a plugin
    that installs itself by being on the path would let an unrelated package decide
    what that provenance means.
    """

    def __init__(self) -> None:
        self._readers: dict[str, SourceReader] = {}

    def __contains__(self, kind: object) -> bool:
        return kind in self._readers

    def __iter__(self) -> Iterator[str]:
        return iter(self._readers)

    def __len__(self) -> int:
        return len(self._readers)

    def __repr__(self) -> str:
        return f"KINDS({', '.join(sorted(self._readers))})"

    def register(self, kind: str, reader: SourceReader) -> None:
        if not kind or not kind.replace("_", "").isalnum():
            raise ValueError(f"source kind {kind!r} must be a non-empty alphanumeric identifier")
        existing = self._readers.get(kind)
        if existing is not None and existing is not reader:
            raise ValueError(
                f"source kind {kind!r} is already registered to {existing!r} — a lock entry names its "
                "kind, so silently rebinding one would change what recorded provenance means"
            )
        self._readers[kind] = reader

    def reader(self, kind: str) -> SourceReader:
        try:
            return self._readers[kind]
        except KeyError:
            raise ValueError(f"unknown source kind {kind!r} — expected one of {', '.join(sorted(self))}") from None


# Recognised source kinds. A lock entry naming anything else is refused rather
# than assumed, on the same principle as an unknown policy key. This is a live view:
# `register_source_kind` adds to it, and everything that reads it (the lock loader,
# the CLI's `--kind` choices) sees the addition without a second list to keep in sync.
KINDS = _SourceKinds()


def register_source_kind(kind: str, reader: SourceReader) -> None:
    """Teach this process to read a new kind of tool source.

    ``reader`` takes an already-parsed document and returns a list of
    :class:`ToolSource`. Call it before loading a lock that names ``kind``.
    """
    KINDS.register(kind, reader)


def reader_for(kind: str) -> SourceReader:
    """The registered reader for ``kind``, or ``ValueError`` naming what is registered."""
    return KINDS.reader(kind)


@dataclass(frozen=True)
class ToolSource:
    """One tool as its source declared it, plus the contract that was projected from it."""

    name: str
    kind: str
    description: str | None
    shape: dict[str, Any]
    contract: ToolContract

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown source kind {self.kind!r} — expected one of {', '.join(sorted(KINDS))}")
        _reject_unusable_name(self.name)


# A tool name is a policy key, a dict key in a YAML document, a column in every report
# and something a human types into `histos explain`. The source picks it, and the source
# is the untrusted party here.
_UNUSABLE_IN_A_NAME = re.compile(
    "[\x00-\x1f\x7f-\x9f"  # C0 and C1 controls — \r rewrites a printed line
    "\u061c\u200b-\u200f\u2028-\u202e"  # bidi marks and overrides, line/paragraph separators
    "\u2060-\u2064\u2066-\u206f\ufeff]"  # word joiners, bidi isolates, BOM
)


def _reject_unusable_name(name: str) -> None:
    """Refuse a tool name that cannot survive being written down and read back.

    Sanitising these at every printing path keeps a *report* honest, and that is a
    different job from this one: `histos import --out policy.yaml` writes the raw name
    into a document, and a C1 control there produced a file histos itself then refused
    to load — an import that succeeds and leaves an unusable artifact. Refusing at the
    point the name enters the library is the only place that fixes both, and it is the
    same posture the loader already takes for a policy key it cannot understand.
    """
    if not isinstance(name, str):
        # `{"name": 7}` reached the regex and came back as an uncaught TypeError, which
        # skipped the per-tool skip and took the whole manifest with it — the failure
        # mode that machinery exists to prevent, reached through the type system.
        raise PolicyError(f"a tool name must be a string, got {type(name).__name__}", code="invalid_import")
    if not name:
        raise PolicyError("a tool with an empty name cannot be a policy key", code="invalid_import")
    found = _UNUSABLE_IN_A_NAME.search(name)
    if found:
        raise PolicyError(
            f"tool name {name!r} contains U+{ord(found.group()):04X}, which steers a terminal and cannot be "
            "written into a policy document that reads back. A tool name is a policy key; ask the source "
            "to rename it, or import it under a name of your own.",
            code="invalid_import",
        )


def contracts_of(sources: list[ToolSource]) -> list[ToolContract]:
    """The contracts alone, for callers that do not care where they came from."""
    return [s.contract for s in sources]


# ── one unprojectable tool must not take the manifest with it ────────────


class ToolImportSkipped(UserWarning):
    """A tool definition the projection refused; the rest of the manifest imported."""


@dataclass(frozen=True)
class SkippedTool:
    """One tool that did not import, named, with the refusal that stopped it."""

    name: str
    kind: str
    reason: str


class ImportedSources(list[ToolSource]):
    """The tools that imported, carrying the ones that did not on ``skipped``.

    A plain ``list`` subclass so every existing caller — the CLI, the lock writer,
    ``contracts_of`` — keeps working unchanged, while a caller that wants to report
    the losses has somewhere to read them from.
    """

    def __init__(self, sources: Iterable[ToolSource] = (), skipped: Iterable[SkippedTool] = ()) -> None:
        super().__init__(sources)
        self.skipped: tuple[SkippedTool, ...] = tuple(skipped)


def project_tools[Entry](
    kind: str,
    entries: Sequence[Entry],
    name_of: Callable[[Entry], str],
    read_one: Callable[[Entry], ToolSource],
) -> ImportedSources:
    """Project each tool on its own, so one refusal cannot take the manifest down.

    The projection refuses an assertion keyword it cannot carry, which is right — a
    dropped bound is a policy that reads as constrained and enforces nothing. It used
    to raise out of the whole read, though, so one ``maxItems`` on the ninth tool of a
    manifest meant the other eight healthy tools did not import either, and the message
    named the argument and the keyword but not the tool, so on a real server there was
    nothing to go and fix. A refusal that takes down eight working tools with the ninth
    is not fail-closed; the user's next move is to stop importing.

    So the refusal is now scoped to the tool it came from. Skipping is safe in the
    direction that matters: a tool with no contract has no policy entry, and the engine
    denies an unknown tool by default (``unknown_tool``), so a skipped tool cannot be
    called — it just cannot be granted either, which is the outcome the user needs to
    see. Every skip is warned about *and* recorded on the returned list.

    A source where *nothing* imported still raises: an empty policy written without a
    word about why is the silent failure this whole module exists to avoid.

    Every ``PolicyError`` out of ``read_one`` is caught, not only ``invalid_import``: a
    ``pattern`` the ReDoS screen refuses arrives as ``unsafe_pattern`` and a bad bound as
    ``invalid_field``, and both are statements about the one tool being projected. That
    one is attacker-reachable — the server picks its own patterns — so leaving it fatal
    would let a single hostile tool definition deny the import of every honest tool
    beside it. A malformed *document* is a ``ValueError`` and is raised before this loop.
    """
    kept: list[ToolSource] = []
    skipped: list[SkippedTool] = []
    for entry in entries:
        try:
            kept.append(read_one(entry))
        except PolicyError as exc:
            name = name_of(entry)
            skipped.append(SkippedTool(name=name, kind=kind, reason=f"{kind} tool {name!r} was not imported: {exc}"))

    if entries and not kept:
        raise PolicyError(
            f"no tool in this {kind} source could be imported:\n" + "\n".join(f"  - {s.reason}" for s in skipped),
            code="invalid_import",
        )
    for skip in skipped:
        warnings.warn(skip.reason, ToolImportSkipped, stacklevel=3)
    return ImportedSources(kept, skipped)
