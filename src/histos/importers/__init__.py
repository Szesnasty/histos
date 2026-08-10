"""Import tool *descriptions* from standard formats into a ``ToolContract``.

Two-layer design (author direction, 2026-08-08): a tool's **shape** — name,
arguments, types, required, enums, return shape — is standard and importable
(JSON Schema / OpenAPI / MCP / Python signatures). The **authorization policy** —
roles, permissions, resource constraints, limits, confirmation, sensitivity,
canaries — is Histos' own language (see :mod:`histos.bundle`).

JSON Schema is the common denominator: OpenAPI and MCP both carry JSON Schema for
their arguments, so :func:`schema_from_json_schema` is the shared bridge and the
other importers build on it. All importers here are **stdlib-only** and operate on
already-parsed dict/JSON — no network, no schema-fetching.
"""

from __future__ import annotations

from histos.importers.json_schema import field_from_json_schema, schema_from_json_schema
from histos.importers.mcp import contracts_from_mcp, sources_from_mcp
from histos.importers.openai import contracts_from_openai, sources_from_openai
from histos.importers.openapi import contracts_from_openapi, sources_from_openapi
from histos.importers.sources import KINDS, ToolSource, contracts_of, reader_for, register_source_kind

__all__ = [
    "KINDS",
    "ToolSource",
    "contracts_from_mcp",
    "contracts_from_openai",
    "contracts_from_openapi",
    "contracts_of",
    "field_from_json_schema",
    "reader_for",
    "register_source_kind",
    "schema_from_json_schema",
    "sources_from_mcp",
    "sources_from_openai",
    "sources_from_openapi",
]
