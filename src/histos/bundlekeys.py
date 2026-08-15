"""What a bundle is allowed to say, and what happens when it says something else.

Split out of `bundle.py`. A policy document is the artifact a human reviews and signs
off, so a key this loader does not recognise is a refusal rather than a shrug: the
alternative is a document whose author believes it constrains something it does not.
The allow-lists here are that decision, one per node type, written out rather than
derived — a vocabulary is a compatibility surface and it should be edited on purpose.

The expansion screen is here for the same reason at a different scale: YAML anchors
compose, so a few kilobytes of document can expand into hundreds of megabytes of nodes
before any of the above gets a chance to look at it.
"""

from __future__ import annotations

import re
from typing import Any

from histos.contracts import SCHEMA_VERSION
from histos.errors import PolicyError

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
        "escalation",
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
        "escalate",
        "output",
        "rate_limit",
        "resource",
        "returns",
        "sensitivity",
    }
)
_RESOURCE_KEYS = frozenset({"owns", "where"})
_CONFIRMATION_KEYS = frozenset({"expires_in", "required"})
# An object, not a boolean, for the same reason `confirmation` is one: which tier, and
# what it is being asked, are the fields this block will grow, and widening a boolean
# afterwards breaks every policy in the field.
_ESCALATE_KEYS = frozenset({"required"})
_OUTPUT_KEYS = frozenset({"on_violation", "project", "redact_secrets", "scan_canary", "strict"})
# `bind` values are frozen to exactly `principal.<identifier>` — a substitution, not
# an expression language. See `_bind_from_dict`.
_PRINCIPAL_REF = re.compile(r"principal\.([A-Za-z_][A-Za-z0-9_]*)")
_FIELD_KEYS = frozenset(
    {
        "enum",
        "exclusive_maximum",
        "exclusive_minimum",
        "item_enum",
        "item_type",
        "max_items",
        "max_length",
        "maximum",
        "min_items",
        "min_length",
        "minimum",
        "multiple_of",
        "nullable",
        "pattern",
        "required",
        "sensitive",
        "type",
        "unique_items",
    }
)
_CONDITION_KEYS = frozenset({"field", "op", "principal_attr", "value"})
_ROLE_KEYS = frozenset({"allow", "inherits"})


# A YAML alias is a reference, not a copy: PyYAML resolves every `*a` to the *same*
# object, so seven nested levels of `[*a,*a,...]` parse in milliseconds and cost
# almost nothing to hold. They cost everything to *walk* — and `content_hash`,
# `validate()` and `dump_bundle` all walk. Measured: 276 bytes of policy became 59 MB
# of canonical JSON and 700 MB of RSS, inside `content_hash`, before any decision was
# made. The document is still a DAG at load time, so the expanded size is cheap to
# compute here and ruinous to discover later. The budget is far above any real policy
# (the largest in `policies/` is under 2,000 nodes) and far below anything that hurts.
_MAX_EXPANDED_NODES = 200_000


def _expanded_size(node: Any, memo: dict[int, int]) -> int:
    """How many nodes a consumer that walks this document as a *tree* would visit."""
    if isinstance(node, dict):
        children: Any = [x for item in node.items() for x in item]
    elif isinstance(node, list | tuple):
        children = node
    else:
        return 1
    cached = memo.get(id(node))
    if cached is not None:
        return cached
    total = 1 + sum(_expanded_size(child, memo) for child in children)
    if total > _MAX_EXPANDED_NODES:
        raise PolicyError(
            f"policy expands to more than {_MAX_EXPANDED_NODES:,} nodes — refusing to load. "
            "Aliases that reference other aliases multiply, so a small file can expand to "
            "gigabytes the moment anything walks it (hashing, validation, dumping).",
            code="policy_too_large",
        )
    memo[id(node)] = total
    return total


def _reject_expansion_bomb(data: dict[str, Any]) -> None:
    try:
        _expanded_size(data, {})
    except RecursionError as exc:
        raise PolicyError("policy is nested too deeply to walk — refusing to load", code="policy_too_large") from exc


def _as_mapping(where: str, node: Any) -> dict[str, Any]:
    """Assert a node is a mapping, as a :class:`PolicyError` rather than an AttributeError.

    Every ``load_bundle`` failure has to be a ``PolicyError``: the documented contract
    is that a host wraps ``load_policy`` in ``except PolicyError`` and fails closed, and
    a raw ``AttributeError`` from a mistyped node walks straight past that handler and
    out of the CLI as a traceback.
    """
    if not isinstance(node, dict):
        raise PolicyError(f"{where} must be a mapping, got {type(node).__name__}", code="not_a_mapping")
    return node


def _as_list(where: str, node: Any) -> list[Any]:
    """Assert a node is a list. A ``str`` is iterable, which is the whole problem.

    ``canaries: SECRET-TOKEN`` (one missing bracket) iterates into nine one-character
    canaries that deny every call containing any of those letters, and `validate()`
    reports the policy as fine.
    """
    if not isinstance(node, list):
        raise PolicyError(
            f"{where} must be a list, got {type(node).__name__}"
            + (" — a bare string iterates into one entry per character" if isinstance(node, str) else ""),
            code="not_a_list",
        )
    return node


# The Python constructor and the file format spell three things differently, and the
# file format is the one that is versioned and published. A reader who followed the
# README quickstart in code and then wrote the same policy to disk hit a bare "unknown
# key 'permissions'" — technically correct and useless, because the key they wrote is
# the name the library itself told them to use one page earlier. The loader still
# accepts exactly one spelling; it just stops pretending it has never heard of the
# other. See docs/policy-reference.md for the whole mapping.
_PYTHON_SPELLINGS = {
    "permissions": "roles (as `roles: {<role>: {allow: [...]}}`)",
    "policy_version": "version",
    "role_inherits": "roles.<role>.inherits",
}


def _reject_unknown(where: str, data: dict[str, Any], allowed: frozenset[str]) -> None:
    """Fail closed on any key this engine does not understand."""
    unknown = sorted(k for k in data if k not in allowed)
    if not unknown:
        return
    # Only at the top level: `permissions` nested inside `tools.<name>` is not the
    # constructor's `permissions`, and suggesting `roles` there sends the reader to the
    # wrong place. Elsewhere the generic message, which lists what this scope accepts,
    # is the more useful one.
    if allowed is _BUNDLE_KEYS and unknown[0] in _PYTHON_SPELLINGS:
        raise PolicyError(
            f"{unknown[0]!r} in {where} is the Python constructor's name for this; the file format "
            f"spells it {_PYTHON_SPELLINGS[unknown[0]]}. The two vocabularies are listed in "
            "docs/policy-reference.md.",
            code="unknown_key",
        )
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
