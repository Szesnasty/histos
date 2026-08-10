"""The Histos policy bundle — the *authorization* language (second layer).

Where the importers (:mod:`histos.importers`) describe a tool's **shape**,
the bundle describes **who may do what**: roles, permissions, resource
constraints, limits, confirmation, sensitivity, canaries. JSON Schema can say
"``invoice_id`` is a string"; it cannot say "support may only read their own
customer's invoice" — that is policy, and it lives here.

The bundle is the portable artifact — the contract between whoever authors
policy and every engine that enforces it. It round-trips: :func:`load_bundle` /
:func:`dump_bundle`. YAML is optional (``pip install ...[yaml]``); JSON is stdlib.

Import → review → protect: import contracts from standard schemas, author the
authz here, :func:`merge_contracts` to join them, then hand the :class:`Policy`
to a :class:`~histos.gate.Gate`.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

from histos.contracts import SCHEMA_VERSION, Binding, Constraint, Policy, Sensitivity, ToolContract
from histos.errors import PolicyError
from histos.importers.json_schema import schema_from_json_schema
from histos.schema import Field, Schema

# ── compatibility gate (Policy Format Draft 0.1) ─────────────────────────
#
# A policy is a security artifact, so an engine that does not understand part of
# one must REFUSE it, never load the parts it recognises and silently skip the
# rest. Consider a policy that says::
#
#     tools:
#       - name: fetch
#         url_egress_allowlist: {hosts: ["api.example.com"]}
#
# An engine without that check would happily load it, enforce everything else,
# and let every egress through — while `validate()` reports no issues. Half a
# fleet on an older build would silently stop enforcing a control the policy
# asks for. That is the one place in this library where the default was
# fail-OPEN, and it is closed here.
#
# Two independent gates, because they fail differently:
#
#   * **unknown key** catches a policy written for a newer engine (or a typo);
#   * **requires.features** catches the subtler cross-implementation case where
#     a key is *recognised* but its semantics are not the ones the author meant.
#     A policy declares the capabilities it depends on and the engine must prove
#     it implements them. That is what makes the format portable across the
#     Python engine, a future TypeScript one, and any third-party implementation
#     — an engine *version* stops being a usable contract the moment there is
#     more than one engine.

SUPPORTED_SCHEMA_VERSIONS = frozenset({SCHEMA_VERSION})

# Capability names a policy may list under `requires.features`. This is a
# published part of the format: adding one is a format change, removing one
# breaks policies in the field. Names describe *semantics the engine guarantees*,
# not internal module names.
ENGINE_FEATURES = frozenset(
    {
        "arg_schema",
        "array_items",
        "budget",
        "canary",
        "enum",
        "numeric_range",
        "output_projection",
        "rate_limit",
        "rbac",
        "requires_confirmation",
        "resource_authz",
        "role_inheritance",
        "secret_detectors",
        "sensitive_redaction",
        "strict_returns",
        "string_bounds",
        "trusted_arg_binding",
    }
)

_BUNDLE_KEYS = frozenset(
    {"canaries", "created_at", "policy_id", "requires", "roles", "schema_version", "tools", "version"}
)
_REQUIRES_KEYS = frozenset({"features"})
_TOOL_KEYS = frozenset(
    {
        "access",
        "args",
        "bind",
        "budget",
        "confirmation",
        "deny_secret_args",
        "output",
        "rate_limit",
        "resource",
        "returns",
        "sensitivity",
    }
)
_RESOURCE_KEYS = frozenset({"owns", "where"})
_CONFIRMATION_KEYS = frozenset({"expires_in", "required"})
_OUTPUT_KEYS = frozenset({"on_violation", "project", "redact_secrets", "scan_canary", "strict"})
# `bind` values are frozen to exactly `principal.<identifier>` — a substitution, not
# an expression language. See `_bind_from_dict`.
_PRINCIPAL_REF = re.compile(r"principal\.([A-Za-z_][A-Za-z0-9_]*)")
_FIELD_KEYS = frozenset(
    {
        "enum",
        "exclusive_maximum",
        "exclusive_minimum",
        "item_type",
        "max_length",
        "maximum",
        "min_length",
        "minimum",
        "multiple_of",
        "pattern",
        "required",
        "sensitive",
        "type",
    }
)
_CONDITION_KEYS = frozenset({"field", "op", "principal_attr", "value"})
_ROLE_KEYS = frozenset({"allow", "inherits"})


def _reject_unknown(where: str, data: dict[str, Any], allowed: frozenset[str]) -> None:
    """Fail closed on any key this engine does not understand."""
    unknown = sorted(k for k in data if k not in allowed)
    if not unknown:
        return
    raise PolicyError(
        f"unknown key {unknown[0]!r} in {where}"
        + (f" (also: {', '.join(unknown[1:])})" if len(unknown) > 1 else "")
        + " — refusing to load. A policy this engine only partly understands would enforce only "
        "part of what it says. Either this engine is older than the policy, or the key is a typo. "
        f"Understood here: {', '.join(sorted(allowed))}.",
        code="unknown_key",
    )


def _check_compatibility(data: dict[str, Any]) -> None:
    declared = data.get("schema_version")
    if declared is not None and declared not in SUPPORTED_SCHEMA_VERSIONS:
        raise PolicyError(
            f"policy schema_version {declared!r} is not supported by this engine "
            f"(supports: {', '.join(sorted(SUPPORTED_SCHEMA_VERSIONS))})",
            code="unsupported_version",
        )

    requires = data.get("requires")
    if requires is None:
        return
    if not isinstance(requires, dict):
        raise PolicyError(f"`requires` must be a mapping, got {type(requires).__name__}")
    _reject_unknown("`requires`", requires, _REQUIRES_KEYS)

    features = requires.get("features", [])
    if not isinstance(features, list):
        raise PolicyError(f"`requires.features` must be a list, got {type(features).__name__}")
    missing = sorted(f for f in features if f not in ENGINE_FEATURES)
    if missing:
        raise PolicyError(
            f"policy requires capability {missing[0]!r}"
            + (f" (also: {', '.join(missing[1:])})" if len(missing) > 1 else "")
            + " which this engine does not implement — refusing to load rather than silently not "
            f"enforcing it. This engine implements: {', '.join(sorted(ENGINE_FEATURES))}.",
            code="unsupported_feature",
        )


# ── field / schema (compact form used inside a bundle) ───────────────────


def _field_from_compact(spec: dict[str, Any]) -> Field:
    _reject_unknown("an argument/return field", spec, _FIELD_KEYS)
    return Field(
        type=spec.get("type", "string"),
        required=spec.get("required", True),
        enum=tuple(spec["enum"]) if isinstance(spec.get("enum"), list) else None,
        max_length=spec.get("max_length"),
        min_length=spec.get("min_length"),
        pattern=spec.get("pattern"),
        sensitive=spec.get("sensitive"),
        item_type=spec.get("item_type"),
        minimum=spec.get("minimum"),
        maximum=spec.get("maximum"),
        exclusive_minimum=spec.get("exclusive_minimum"),
        exclusive_maximum=spec.get("exclusive_maximum"),
        multiple_of=spec.get("multiple_of"),
    )


def _schema_from_node(node: dict[str, Any] | None) -> Schema | None:
    if node is None:
        return None
    # allow an inline standard JSON Schema via {"json_schema": {...}}
    if set(node.keys()) == {"json_schema"}:
        return schema_from_json_schema(node["json_schema"])
    return Schema({name: _field_from_compact(spec) for name, spec in node.items()})


def _condition_from_dict(name: str, d: dict[str, Any]) -> Constraint:
    _reject_unknown(f"a `resource.where` condition on tool {name!r}", d, _CONDITION_KEYS)
    kwargs: dict[str, Any] = {"field": d["field"], "op": d["op"]}
    if "principal_attr" in d:
        kwargs["principal_attr"] = d["principal_attr"]
    if "value" in d:
        kwargs["value"] = d["value"]
    return Constraint(**kwargs)


def _resource_from_dict(name: str, d: dict[str, Any]) -> tuple[Constraint, ...]:
    """Parse the `resource:` block into constraints, `owns` first.

    `owns` is sugar for the row-ownership case and is listed first so a denial names
    ownership before a secondary condition — the answer a reader wants first.
    """
    _reject_unknown(f"the `resource` block on tool {name!r}", d, _RESOURCE_KEYS)
    out: list[Constraint] = []
    owns = d.get("owns")
    if isinstance(owns, str):
        out.append(Constraint.owns(owns))
    elif isinstance(owns, dict):
        _reject_unknown(f"`resource.owns` on tool {name!r}", owns, frozenset({"field", "principal_attr"}))
        out.append(Constraint.owns(owns["field"], owns["principal_attr"]))
    elif owns is not None:
        raise PolicyError(f"`resource.owns` on tool {name!r} must be a string or a mapping, got {type(owns).__name__}")
    out.extend(_condition_from_dict(name, c) for c in d.get("where", []))
    return tuple(out)


def _bind_from_dict(name: str, d: dict[str, Any]) -> tuple[Binding, ...]:
    """Parse `bind: {field: principal.attr}`.

    The grammar is frozen hard on purpose: exactly ``principal.<identifier>``. A
    binding is a *substitution*, not a language — the moment templating, fallbacks
    (``a ?? b``) or functions are allowed here, the policy stops being decidable by
    inspection and every engine has to agree on an evaluator.
    """
    out: list[Binding] = []
    for arg, ref in d.items():
        if not isinstance(ref, str) or not _PRINCIPAL_REF.fullmatch(ref):
            raise PolicyError(
                f"binding for {arg!r} on tool {name!r} must be exactly 'principal.<attr>', got {ref!r} — "
                "bindings are substitutions, not expressions (no templating, fallbacks or functions)",
                code="invalid_binding",
            )
        out.append(Binding(arg, ref.split(".", 1)[1]))
    return tuple(out)


def _tool_from_dict(name: str, d: dict[str, Any]) -> ToolContract:
    _reject_unknown(f"tool {name!r}", d, _TOOL_KEYS)
    confirmation = d.get("confirmation") or {}
    if confirmation:
        _reject_unknown(f"`confirmation` on tool {name!r}", confirmation, _CONFIRMATION_KEYS)
    output = d.get("output") or {}
    if output:
        _reject_unknown(f"`output` on tool {name!r}", output, _OUTPUT_KEYS)
    return ToolContract(
        name=name,
        args=_schema_from_node(d.get("args")),
        returns=_schema_from_node(d.get("returns")),
        access=d.get("access", "read"),
        sensitivity=Sensitivity(d.get("sensitivity", "low")),
        rate_limit=d.get("rate_limit"),
        budget=d.get("budget"),
        requires_confirmation=bool(confirmation.get("required", False)),
        confirmation_expires_in=confirmation.get("expires_in"),
        constraints=_resource_from_dict(name, d.get("resource") or {}),
        bindings=_bind_from_dict(name, d.get("bind") or {}),
        scan_output_for_canary=output.get("scan_canary", True),
        deny_secret_args=d.get("deny_secret_args", True),
        redact_secret_output=output.get("redact_secrets", True),
        project_output=output.get("project", False),
        strict_returns=output.get("strict", False),
        on_output_violation=output.get("on_violation", "redact_all"),
    )


# ── canonical parsing ──────────────────────────────────────────
#
# "The same security.policy.yaml behaves identically in Python and TypeScript" is
# only true if *loading* is specified rather than left to whatever a given parser
# happens to do. So parsing is strict and the canonical model — not the parser —
# is normative:
#
#   * duplicate keys are a PolicyError, never "last one wins";
#   * YAML 1.1's `yes`/`no`/`on`/`off` do NOT silently become booleans, so a YAML
#     bundle and the equivalent JSON produce the identical `content_hash`;
#   * YAML is loaded through a vetted parser behind the optional [yaml] extra —
#     we never hand-roll a parser for a security artifact.
#
# Honest scope: this normalizes the divergences that actually bite a policy file
# (duplicate keys, the YAML bool set). It is not a full YAML-1.1-vs-1.2
# reconciliation — exotic scalars (sexagesimals, underscore-separated ints) are
# not remapped. Quote anything you mean as a string.


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise PolicyError(
                f"duplicate key {key!r} in policy — refusing to guess which one wins", code="duplicate_key"
            )
        seen.add(key)
    return dict(pairs)


def parse_json_bundle(text: str) -> dict[str, Any]:
    """Strictly parse a JSON bundle into a dict (duplicate keys are refused)."""
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_json_pairs)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"policy is not valid JSON: {exc}", code="unparseable") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"policy must be an object at the top level, got {type(data).__name__}", code="not_an_object")
    return data


# Only the JSON-compatible spellings are booleans. Everything else YAML 1.1 would
# have resolved (`yes`, `no`, `on`, `off`, `y`, `n`) stays the string it looks like.
_JSON_BOOL = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")

_yaml_loader_cache: Any = None


def _strict_yaml_loader() -> Any:
    """Build (once) a SafeLoader that rejects duplicate keys and JSON-aligns bools."""
    global _yaml_loader_cache
    if _yaml_loader_cache is not None:
        return _yaml_loader_cache

    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - exercised only without pyyaml
        raise ImportError(
            "YAML bundles need PyYAML: pip install histos[yaml] "
            "(or parse the YAML yourself and call load_bundle(dict))."
        ) from exc

    class StrictLoader(yaml.SafeLoader):
        def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
            self.flatten_mapping(node)
            mapping: dict[Any, Any] = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if key in mapping:
                    line = key_node.start_mark.line + 1
                    raise PolicyError(
                        f"duplicate key {key!r} in policy at line {line} — refusing to guess which one wins",
                        code="duplicate_key",
                    )
                mapping[key] = self.construct_object(value_node, deep=deep)
            return mapping

    # Replace YAML 1.1's bool resolver with the JSON-compatible one. Copy the
    # table first so SafeLoader itself (and anyone else's YAML) is untouched.
    bool_tag = "tag:yaml.org,2002:bool"
    StrictLoader.yaml_implicit_resolvers = {
        ch: [(tag, regexp) for tag, regexp in resolvers if tag != bool_tag]
        for ch, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    StrictLoader.add_implicit_resolver(bool_tag, _JSON_BOOL, list("tTfF"))

    _yaml_loader_cache = StrictLoader
    return StrictLoader


def parse_yaml_bundle(text: str) -> dict[str, Any]:
    """Strictly parse a YAML bundle into a dict. Requires the optional ``[yaml]`` extra."""
    import yaml

    loader = _strict_yaml_loader()
    try:
        data = yaml.load(text, Loader=loader)  # noqa: S506 — StrictLoader derives from SafeLoader
    except PolicyError:
        raise
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy is not valid YAML: {exc}", code="unparseable") from exc
    if data is None:
        raise PolicyError("policy file is empty", code="unparseable")
    if not isinstance(data, dict):
        raise PolicyError(f"policy must be a mapping at the top level, got {type(data).__name__}", code="not_an_object")
    return data


def load_policy(source: str | Path | dict[str, Any]) -> Policy:
    """Load a policy from a ``.yaml``/``.yml``/``.json`` path, or from a parsed dict.

    The one entry point a developer should reach for. Parsing is canonical (see
    above), so the same logical policy has the same ``content_hash`` whichever
    format it was written in — which is what makes a policy-bound approval and the
    cross-language conformance suite agree.

    Fail-loud on anything ambiguous: a missing file, an unknown extension, a
    duplicate key, or a top-level value that is not an object.
    """
    if isinstance(source, dict):
        return load_bundle(source)

    path = Path(source)
    if not path.is_file():
        raise PolicyError(f"policy file not found: {path}", code="not_found")
    suffix = path.suffix.lower()
    if suffix not in (".yaml", ".yml", ".json"):
        raise PolicyError(
            f"cannot tell how to parse {path.name!r} — policy files must be .yaml, .yml or .json "
            "(or pass an already-parsed dict)"
        )
    text = path.read_text(encoding="utf-8")
    data = parse_yaml_bundle(text) if suffix in (".yaml", ".yml") else parse_json_bundle(text)
    return load_bundle(data)


# ── load ─────────────────────────────────────────────────────────────────


def load_bundle(data: dict[str, Any]) -> Policy:
    """Build a :class:`Policy` from a parsed bundle dict.

    Fails closed on anything this engine does not fully understand: an unknown
    key, an unsupported ``schema_version``, or a capability listed under
    ``requires.features`` that is not implemented here. Loading a policy
    partially would enforce only part of what it says — see the compatibility
    gate above.
    """
    _reject_unknown("the policy bundle", data, _BUNDLE_KEYS)
    _check_compatibility(data)

    tools_node = data.get("tools") or {}
    if not isinstance(tools_node, dict):
        raise PolicyError(
            "`tools` must be a mapping keyed by tool name, not a list (Policy Format 0.1). "
            "A mapping makes a repeated tool name a duplicate key, which canonical parsing "
            "already refuses — a list made it a silent override.",
            code="tools_not_a_mapping",
        )
    # No duplicate-name check here on purpose: as a mapping, a repeated name is a
    # duplicate key and the strict parsers reject it before this code runs.
    tools = {name: _tool_from_dict(name, spec or {}) for name, spec in tools_node.items()}

    permissions: dict[str, frozenset[str]] = {}
    role_inherits: dict[str, str] = {}
    for role, spec in (data.get("roles") or {}).items():
        spec = spec or {}
        _reject_unknown(f"role {role!r}", spec, _ROLE_KEYS)
        allow = spec.get("allow", [])
        for entry in allow:
            if not isinstance(entry, str):
                raise PolicyError(
                    f"role {role!r} grants {entry!r} — `allow` is a list of tool names "
                    "(Policy Format 0.1 dropped the {tool: name} object form)",
                    code="invalid_grant",
                )
        permissions[role] = frozenset(allow)
        if spec.get("inherits"):
            role_inherits[role] = spec["inherits"]

    return Policy(
        tools=tools,
        permissions=permissions,
        role_inherits=role_inherits,
        canaries=frozenset(data.get("canaries", [])),
        policy_id=data.get("policy_id"),
        policy_version=str(data.get("version", "0")),
        created_at=data.get("created_at"),
        schema_version=data.get("schema_version", SCHEMA_VERSION),
    )


def load_bundle_json(text: str) -> Policy:
    """Parse a JSON bundle *string*. Canonical (see §9): duplicate keys are refused."""
    return load_bundle(parse_json_bundle(text))


def load_bundle_yaml(text: str) -> Policy:
    """Parse a YAML bundle *string*. Requires the optional ``[yaml]`` extra (PyYAML).

    Canonical (see §9): duplicate keys are refused and only ``true``/``false`` are
    booleans, so this agrees with :func:`load_bundle_json` on the same policy.
    """
    return load_bundle(parse_yaml_bundle(text))


# ── merge (import → review → protect) ────────────────────────────────────


def merge_contracts(policy: Policy, contracts: list[ToolContract]) -> Policy:
    """Fill/override tool *shapes* from imported contracts, keep the *authz*.

    The imported contract is authoritative for ``args`` / ``returns`` (it came
    from the app's real schema); the bundle keeps ``access`` / ``sensitivity`` /
    ``rate_limit`` / ``constraints`` / ``requires_confirmation`` (the policy). A
    contract with no matching bundle entry is added as a *discovered* tool — with
    no RBAC grant it stays denied-by-default until a human authorises it.
    """
    tools = dict(policy.tools)
    for contract in contracts:
        existing = tools.get(contract.name)
        if existing is not None:
            tools[contract.name] = replace(
                existing,
                args=contract.args if contract.args is not None else existing.args,
                returns=contract.returns if contract.returns is not None else existing.returns,
            )
        else:
            tools[contract.name] = contract
    return replace(policy, tools=tools)


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
    if field.item_type is not None:
        out["item_type"] = field.item_type
    for attr in ("minimum", "maximum", "exclusive_minimum", "exclusive_maximum", "multiple_of"):
        value = getattr(field, attr)
        if value is not None:
            out[attr] = value
    return out


def _schema_to_node(schema: Schema | None) -> dict[str, Any] | None:
    if schema is None:
        return None
    return {name: _field_to_compact(field) for name, field in schema.fields.items()}


def _condition_to_dict(c: Constraint) -> dict[str, Any]:
    d: dict[str, Any] = {"field": c.field, "op": c.op}
    if c.principal_attr is not None:
        d["principal_attr"] = c.principal_attr
    else:
        # principal_attr is None ⇒ constructor guarantees a literal value is set
        d["value"] = list(c.value) if isinstance(c.value, tuple) else c.value
    return d


def _resource_to_node(tool: ToolContract) -> dict[str, Any]:
    """Inverse of :func:`_resource_from_dict`: recover `owns` sugar where it applies."""
    node: dict[str, Any] = {}
    where: list[dict[str, Any]] = []
    for c in tool.constraints:
        is_owns = c.op == "eq" and c.principal_attr is not None
        if is_owns and "owns" not in node:
            node["owns"] = (
                c.field
                if c.principal_attr == c.field
                else {
                    "field": c.field,
                    "principal_attr": c.principal_attr,
                }
            )
        else:
            where.append(_condition_to_dict(c))
    if where:
        node["where"] = where
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
        if tool.requires_confirmation:
            entry["confirmation"] = {"required": True}
            if tool.confirmation_expires_in is not None:
                entry["confirmation"]["expires_in"] = tool.confirmation_expires_in
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
