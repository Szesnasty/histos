"""Where a tool definition came from, and whether it still says what it said.

A policy imported from an MCP or OpenAPI source is a claim about a server the host does
not control, and the server can change its mind after the review. The lock records what
was reviewed; the diff says what moved and — the part that matters — whether it reaches
enforcement, because a rewritten description and a widened bound are not the same event
and reporting them the same way hides the second one.
"""

from histos.provenance.infer import infer_schema
from histos.provenance.lockdiff import DriftReport, ToolDrift, compare, unverifiable_tools
from histos.provenance.lockfile import (
    Lock,
    LockEntry,
    Reviewed,
    build_lock,
    contract_hash,
    description_hash,
    load_lock,
    lock_path_for,
    parse_lock,
    schema_hash,
)

__all__ = [
    "DriftReport",
    "Lock",
    "LockEntry",
    "Reviewed",
    "ToolDrift",
    "build_lock",
    "compare",
    "contract_hash",
    "description_hash",
    "infer_schema",
    "load_lock",
    "lock_path_for",
    "parse_lock",
    "schema_hash",
    "unverifiable_tools",
]
