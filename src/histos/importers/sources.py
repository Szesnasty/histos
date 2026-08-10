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

from collections.abc import Callable, Iterator, Set
from dataclasses import dataclass
from typing import Any

from histos.contracts import Sensitivity, ToolContract

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


def contracts_of(sources: list[ToolSource]) -> list[ToolContract]:
    """The contracts alone, for callers that do not care where they came from."""
    return [s.contract for s in sources]
