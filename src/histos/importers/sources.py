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

from dataclasses import dataclass
from typing import Any

from histos.contracts import ToolContract

# Recognised source kinds. A lock entry naming anything else is refused rather
# than assumed, on the same principle as an unknown policy key.
KINDS = frozenset({"mcp", "openai", "openapi"})


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
