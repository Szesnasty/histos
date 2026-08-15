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

from dataclasses import replace
from pathlib import Path
from typing import Any

from histos.bundlekeys import (
    _BUNDLE_KEYS,
    _ROLE_KEYS,
    _as_list,
    _as_mapping,
    _check_compatibility,
    _reject_expansion_bomb,
    _reject_unknown,
)
from histos.bundleparse import parse_json_bundle, parse_yaml_bundle
from histos.bundleread import _tool_from_dict
from histos.contracts import (
    _MIN_CANARY_LENGTH,
    SCHEMA_VERSION,
    Policy,
    ToolContract,
)
from histos.errors import PolicyError

# ── load ─────────────────────────────────────────────────────────────────


def _canaries(node: Any) -> list[str]:
    tokens = _as_list("`canaries`", node)
    for token in tokens:
        if not isinstance(token, str):
            raise PolicyError(
                f"canary {token!r} is a {type(token).__name__}; canaries are string tokens", code="invalid_canary"
            )
        if len(token) < _MIN_CANARY_LENGTH:
            raise PolicyError(
                f"canary {token!r} is shorter than {_MIN_CANARY_LENGTH} characters — a token this short "
                "appears in ordinary text, so it would deny every call and redact every result",
                code="invalid_canary",
            )
    return tokens


def load_bundle(data: dict[str, Any]) -> Policy:
    """Build a :class:`Policy` from a parsed bundle dict.

    Fails closed on anything this engine does not fully understand: an unknown
    key, an unsupported ``schema_version``, or a capability listed under
    ``requires.features`` that is not implemented here. Loading a policy
    partially would enforce only part of what it says — see the compatibility
    gate above.
    """
    data = _as_mapping("a policy bundle", data)
    _reject_expansion_bomb(data)
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
    # `spec is None` is the YAML spelling of a tool with no body (`t:`); anything else
    # non-mapping is a mistake `_tool_from_dict` names.
    tools = {name: _tool_from_dict(name, {} if spec is None else spec) for name, spec in tools_node.items()}

    permissions: dict[str, frozenset[str]] = {}
    role_inherits: dict[str, str] = {}
    for role, raw_spec in _as_mapping("`roles`", data.get("roles") or {}).items():
        spec = _as_mapping(f"role {role!r}", raw_spec or {})
        _reject_unknown(f"role {role!r}", spec, _ROLE_KEYS)
        allow = _as_list(f"`allow` on role {role!r}", spec.get("allow", []))
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
        canaries=frozenset(_canaries(data.get("canaries", []))),
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
