"""A policy written back out, so that reading it again yields the same policy.

Split out of `bundle.py`. Round-tripping is not cosmetic here: `histos import --update`
re-dumps on every run, so a field this loses converges on a policy weaker than the one
the author reviewed, and a field it spells differently makes the command never settle.
"""

from __future__ import annotations

from typing import Any

from histos.errors import PolicyError
from histos.policy.contracts import Constraint, Policy, ToolContract
from histos.policy.schema import Field, Schema

# ── dump (round-trip / export) ───────────────────────────────────────────


def _field_to_compact(field: Field) -> dict[str, Any]:
    out: dict[str, Any] = {"type": field.type}
    if not field.required:
        out["required"] = False
    if field.enum is not None:
        out["enum"] = list(field.enum)
    if field.max_length is not None:
        out["max_length"] = field.max_length
    if field.min_length is not None:
        out["min_length"] = field.min_length
    if field.pattern is not None:
        out["pattern"] = field.pattern
    if field.sensitive is not None:
        out["sensitive"] = field.sensitive
    if field.nullable:
        # Dropped here, so `histos import --out` threw away the nullability the importer
        # had just read off `anyOf: [T, null]` — a round trip that quietly tightened the
        # policy, and then denied the null the source explicitly allows.
        out["nullable"] = True
    if field.unique_items:
        out["unique_items"] = True
    if field.item_enum is not None:
        out["item_enum"] = list(field.item_enum)
    if field.item_type is not None:
        out["item_type"] = field.item_type
    for attr in ("max_items", "min_items"):
        value = getattr(field, attr)
        if value is not None:
            out[attr] = value
    for attr in ("minimum", "maximum", "exclusive_minimum", "exclusive_maximum", "multiple_of"):
        value = getattr(field, attr)
        if value is not None:
            out[attr] = value
    return out


def _schema_to_node(schema: Schema | None) -> dict[str, Any] | None:
    if schema is None:
        return None
    # Refused rather than merely made unlikely. The `$` prefix moved the collision by
    # one character: nothing reserves `$allow_extra` as a property name, a JSON Schema
    # `properties` key may be any string, and the flag is written into the same map as
    # the fields — so a tool with an argument spelled exactly that way silently lost it
    # on the way out and had the argument surface opened on the way back in.
    if "$allow_extra" in schema.fields:
        raise PolicyError(
            "a tool argument named `$allow_extra` cannot be written in this format: the key is "
            "reserved for the schema's own open/closed flag, and emitting both would make the "
            "argument and the flag the same entry"
        )
    node: dict[str, Any] = {name: _field_to_compact(field) for name, field in schema.fields.items()}
    # Emitted only when true, so every closed schema — which is all of them unless a
    # source said otherwise — dumps byte-identically to how it always did.
    if schema.allow_extra:
        node["$allow_extra"] = True
    return node


def _condition_to_dict(c: Constraint) -> dict[str, Any]:
    d: dict[str, Any] = {"field": c.field, "op": c.op}
    if c.principal_attr is not None:
        d["principal_attr"] = c.principal_attr
    else:
        # principal_attr is None ⇒ constructor guarantees a literal value is set
        d["value"] = list(c.value) if isinstance(c.value, tuple) else c.value
    return d


def _resource_to_node(tool: ToolContract) -> dict[str, Any]:
    """Inverse of :func:`_resource_from_dict`: recover `owns` sugar where it applies.

    Only the *first* constraint can become `owns`, because the loader re-emits `owns`
    ahead of every `where` condition. Hoisting an ownership rule out of the middle of
    the list reordered it on the way back in, and ``Policy.fingerprint`` hashes the
    constraint list in order — so a policy that was dumped, reviewed and reloaded (what
    `histos import --update` does) came back with a different ``content_hash`` and
    silently invalidated every approval pinned to the old one. An ownership constraint
    that is not first is written out longhand instead; it round-trips identically.
    """
    node: dict[str, Any] = {}
    constraints = list(tool.constraints)
    first = constraints[0] if constraints else None
    if first is not None and first.op == "eq" and first.principal_attr is not None:
        node["owns"] = (
            first.field
            if first.principal_attr == first.field
            else {"field": first.field, "principal_attr": first.principal_attr}
        )
        constraints.pop(0)
    if constraints:
        node["where"] = [_condition_to_dict(c) for c in constraints]
    return node


def dump_bundle(policy: Policy) -> dict[str, Any]:
    """Serialise a :class:`Policy` back to a bundle dict (inverse of load).

    Only non-default values are emitted, so a dumped bundle round-trips to the same
    ``content_hash`` — defaults are normalized away rather than written out. That
    property is part of Policy Format 0.1, not an implementation detail: two
    documents that mean the same thing must hash the same.
    """
    tools: dict[str, Any] = {}
    for name, tool in policy.tools.items():
        entry: dict[str, Any] = {"access": tool.access, "sensitivity": tool.sensitivity.value}
        args = _schema_to_node(tool.args)
        if args is not None:
            entry["args"] = args
        returns = _schema_to_node(tool.returns)
        if returns is not None:
            entry["returns"] = returns
        if tool.rate_limit is not None:
            entry["rate_limit"] = tool.rate_limit
        if tool.budget is not None:
            entry["budget"] = tool.budget
        # Emitted whenever either half is set. The loader reads `required` and
        # `expires_in` independently, so `confirmation: {expires_in: 300}` with no
        # `required` is a legal bundle — and the dump only wrote the block when
        # `required` was true, so that bundle came back without its window and hashed
        # differently. `dump_bundle`'s own docstring states the round trip.
        if tool.requires_confirmation or tool.confirmation_expires_in is not None:
            entry["confirmation"] = {}
            if tool.requires_confirmation:
                entry["confirmation"]["required"] = True
            if tool.confirmation_expires_in is not None:
                entry["confirmation"]["expires_in"] = tool.confirmation_expires_in
        if tool.requires_escalation:
            entry["escalate"] = {"required": True}
        resource = _resource_to_node(tool)
        if resource:
            entry["resource"] = resource
        if tool.bindings:
            entry["bind"] = {b.field: f"principal.{b.principal_attr}" for b in tool.bindings}
        output: dict[str, Any] = {}
        if tool.project_output:
            output["project"] = True
        if tool.strict_returns:
            output["strict"] = True
        if tool.on_output_violation != "redact_all":
            output["on_violation"] = tool.on_output_violation
        if not tool.scan_output_for_canary:
            output["scan_canary"] = False
        if not tool.redact_secret_output:
            output["redact_secrets"] = False
        if output:
            entry["output"] = output
        if not tool.deny_secret_args:
            entry["deny_secret_args"] = False
        tools[name] = entry

    roles: dict[str, Any] = {}
    for role, allowed in policy.permissions.items():
        spec: dict[str, Any] = {"allow": sorted(allowed)}
        if role in policy.role_inherits:
            spec["inherits"] = policy.role_inherits[role]
        roles[role] = spec

    bundle: dict[str, Any] = {
        "version": policy.policy_version,
        "schema_version": policy.schema_version,
        "tools": tools,
        "roles": roles,
    }
    if policy.policy_id:
        bundle["policy_id"] = policy.policy_id
    if policy.created_at:
        bundle["created_at"] = policy.created_at
    if policy.canaries:
        bundle["canaries"] = sorted(policy.canaries)
    return bundle
