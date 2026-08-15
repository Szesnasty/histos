"""histos — the tool call as a security boundary, in both directions.

Deterministic authorization on the way in: RBAC, argument-schema validation,
**resource-level constraints**, trusted argument binding, rate/budget limits and
exact-match canary detection. Deterministic control on the way out: output
projection, sensitive-field and secret redaction, and the same treatment for a
tool that raises — because a return value is a surface an attacker gets to write.

All of it in-process, with no proxy, no models, and no infrastructure. Policy
evaluation itself is microsecond-scale; a call that
declares a `resource_resolver` or a `confirm` callback is as fast as those are,
since looking up a resource's real owner or waiting on a human is IO by nature.

The promise: *the model can be manipulated; the gate makes sure it still can't do
more than you allowed.*

Quick start::

    from histos import protect, use_principal, Principal

    guarded = protect(my_tools, policy="security.policy.yaml")

    with use_principal(Principal(role="support", identity="svc-1", attributes={"tenant_id": "acme"})):
        guarded.tools["make_refund"](order_id="ORD-1", amount=400)

**Identity is bound out-of-band.** ``use_principal`` is a context variable a
*trusted host* sets per request from workload identity or an authenticated
session — never from a tool argument or model output. With none bound, every call
is denied. ``fixed_principal=`` binds one identity for the lifetime of a wrapper
and exists for scripts and workers, not for request handlers.

Or wrap a single tool with a policy authored in code::

    from histos import gate, Policy, ToolContract, Schema, Field

    policy = Policy(
        tools={"delete_user": ToolContract(
            name="delete_user",
            args=Schema({"user_id": Field(type="integer")}),
            access="write",
        )},
        permissions={"admin": frozenset({"delete_user"})},
    )
    safe_delete = gate(delete_user, policy=policy)

    with use_principal(Principal(role="admin", identity="svc-1")):
        safe_delete(user_id=42)        # allowed
    with use_principal(Principal(role="viewer")):
        safe_delete(user_id=42)        # raises GateDenied (rbac)

A coroutine tool is detected automatically and gets an ``async`` wrapper.

See ``docs/design.md`` for the trust model, the core invariant and the
resource-aware authorization model this enforces, and ``SECURITY.md`` for where
the guarantee stops.
"""

from __future__ import annotations

import sys as _sys

from histos._version import __version__
from histos.approvals import ApprovalStore, request_fingerprint
from histos.audit import AuditSink, InMemoryAuditSink, JSONLAuditSink
from histos.auditrecord import AuditRecord, digest_args
from histos.bundle import (
    ENGINE_FEATURES,
    SUPPORTED_SCHEMA_VERSIONS,
    dump_bundle,
    load_bundle,
    load_bundle_json,
    load_bundle_yaml,
    load_policy,
    merge_contracts,
    parse_json_bundle,
    parse_yaml_bundle,
)
from histos.canonical import canonical_fingerprint, canonical_json, canonical_number, normalize_numbers
from histos.content_rules import ContentRules
from histos.contracts import (
    Binding,
    Constraint,
    ConstraintResult,
    Effect,
    GateDecision,
    GateRequest,
    Policy,
    Principal,
    Sensitivity,
    ToolContract,
)
from histos.errors import (
    GateConfirmationRequired,
    GateDenied,
    GateError,
    PolicyError,
    ResourceNotFound,
    ToolErrorRedacted,
)
from histos.gate import (
    Gate,
    ProtectResult,
    gate,
    protect,
)

# From `identity`, not re-exported through `gate`: the two ContextVars behind these are
# process-wide singletons, and importing them from the module that owns them is what
# keeps a second copy from ever being plausible.
from histos.identity import (
    reset_principal,
    set_principal,
    use_principal,
)
from histos.importers import (
    ToolSource,
    contracts_from_mcp,
    contracts_from_openai,
    contracts_from_openapi,
    schema_from_json_schema,
    sources_from_mcp,
    sources_from_openai,
    sources_from_openapi,
)
from histos.infer import infer_contract, infer_schema
from histos.limits import LimitStore
from histos.lockfile import (
    DriftReport,
    Lock,
    LockEntry,
    ToolDrift,
    build_lock,
    compare,
    contract_hash,
    description_hash,
    load_lock,
    lock_path_for,
    parse_lock,
    schema_hash,
    unverifiable_tools,
)
from histos.review import PolicyReview, review_policy
from histos.schema import Field, Schema
from histos.verify import verify_chain

# `from histos.gate import gate` rebinds this package's `gate` attribute from the
# submodule the import machinery had just installed there to the one-liner of the same
# name. So `histos.gate.Gate` raised AttributeError after a plain `import histos`,
# while `from histos.gate import Gate` worked — one name meaning two things depending
# on how you reached it, and the failure lands on a reader following the docs. The
# function keeps the name, since that is the documented API, and the module's public
# surface is re-attached to it so both spellings resolve to the same objects.
# `histos.gate.use_principal` is a documented spelling and stays one, even though the
# three identity names moved to `histos.identity` when `gate.py` was split. The source
# module is named per attribute rather than assumed, so the next move is a one-line edit
# here instead of an AttributeError a reader meets after following the docs.
for _name, _home in (
    ("Gate", "histos.gate"),
    ("ProtectResult", "histos.gate"),
    ("gate", "histos.gate"),
    ("protect", "histos.gate"),
    ("reset_principal", "histos.identity"),
    ("set_principal", "histos.identity"),
    ("use_principal", "histos.identity"),
):
    setattr(gate, _name, getattr(_sys.modules[_home], _name))
del _name, _home

__all__ = [
    "ApprovalStore",
    "AuditRecord",
    "AuditSink",
    "Binding",
    "Constraint",
    "ConstraintResult",
    "ContentRules",
    "DriftReport",
    "ENGINE_FEATURES",
    "Effect",
    "Field",
    "Gate",
    "GateConfirmationRequired",
    "GateDecision",
    "GateDenied",
    "GateError",
    "GateRequest",
    "InMemoryAuditSink",
    "JSONLAuditSink",
    "LimitStore",
    "Lock",
    "LockEntry",
    "Policy",
    "PolicyError",
    "PolicyReview",
    "Principal",
    "ProtectResult",
    "ResourceNotFound",
    "SUPPORTED_SCHEMA_VERSIONS",
    "Schema",
    "Sensitivity",
    "ToolContract",
    "ToolDrift",
    "ToolErrorRedacted",
    "ToolSource",
    "__version__",
    "build_lock",
    "canonical_fingerprint",
    "canonical_json",
    "canonical_number",
    "compare",
    "contract_hash",
    "contracts_from_mcp",
    "contracts_from_openai",
    "contracts_from_openapi",
    "description_hash",
    "digest_args",
    "dump_bundle",
    "gate",
    "infer_contract",
    "infer_schema",
    "load_bundle",
    "load_bundle_json",
    "load_bundle_yaml",
    "load_lock",
    "load_policy",
    "lock_path_for",
    "merge_contracts",
    "normalize_numbers",
    "parse_json_bundle",
    "parse_lock",
    "parse_yaml_bundle",
    "protect",
    "request_fingerprint",
    "reset_principal",
    "review_policy",
    "schema_from_json_schema",
    "schema_hash",
    "set_principal",
    "sources_from_mcp",
    "sources_from_openai",
    "sources_from_openapi",
    "unverifiable_tools",
    "use_principal",
    "verify_chain",
]
