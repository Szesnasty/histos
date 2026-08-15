"""Turning what a caller passed into the ruleset a Gate owns.

Split out of `gate.py`. A Gate must not share its policy with anything: `Policy` is
frozen but the maps inside it were not, so one Gate's `protect()` rewrote the ruleset of
every other Gate holding the same object, and an edit landed under a `policy_hash`
computed before it. Making that ruleset read-only *all the way down* is this module's
only subject, together with the two small coercions that decide a Gate's mode and its
fixed identity.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from histos.bundle import load_policy
from histos.contracts import Policy, Principal, ToolContract
from histos.errors import PolicyError
from histos.frozen import ReadOnlyDict
from histos.schema import Schema

# Anything `load_policy` accepts, plus an already-built Policy and None (which means
# "empty policy" — every call then denies by default).
PolicySource = Policy | str | Path | dict[str, Any] | None

# ── policy / mode coercion ───────────────────────────────────────────────


def _coerce_policy(policy: PolicySource) -> Policy:
    if policy is None:
        return Policy()
    if isinstance(policy, Policy):
        # A Gate owns its ruleset. `Policy` is frozen but its `tools`/`permissions`
        # dicts are not, so aliasing the caller's object meant one Gate's `protect()`
        # rewrote the ruleset of every other Gate holding it, and a grant added to the
        # dict after construction took effect against a `policy_hash` that no longer
        # described the policy that decided.
        # Read-only, not merely copied. Copying stopped one Gate's `protect()` rewriting
        # another's ruleset; it did not stop `gate.policy.permissions[role] |= {...}`,
        # which the Engine sees immediately — it holds the same object — while every
        # subsequent audit record keeps naming the hash computed before the edit. A
        # record that attests a ruleset which did not decide is the one failure the
        # trail cannot survive, so the ruleset a Gate owns cannot be edited in place at
        # all. Swap it with `gate.policy = ...`, which re-hashes.
        #
        # One level was not deep enough. `ToolContract.args` hands out a `Schema`, which
        # is frozen, whose `.fields` is a plain mutable dict — so
        # `gate.policy.tools["wire"].args.fields["amount"] = Field(type="integer")`
        # removed a `maximum` from the live ruleset the engine consults on the next call
        # while `_policy_hash` still named the pre-edit hash. Identical end state to the
        # `|=` edit above, reached through the container the wrapper did not cover.
        return replace(
            policy,
            tools=ReadOnlyDict({name: _read_only_contract(c) for name, c in policy.tools.items()}),
            permissions=ReadOnlyDict(dict(policy.permissions)),
            role_inherits=ReadOnlyDict(dict(policy.role_inherits)),
        )
    return load_policy(policy)


def _read_only_contract(contract: ToolContract) -> ToolContract:
    """The same contract with its argument and return field maps made read-only."""
    args = _read_only_schema(contract.args)
    returns = _read_only_schema(contract.returns)
    if args is contract.args and returns is contract.returns:
        return contract
    return replace(contract, args=args, returns=returns)


def _read_only_schema(schema: Schema | None) -> Schema | None:
    if schema is None or isinstance(schema.fields, ReadOnlyDict):
        return schema
    return replace(schema, fields=ReadOnlyDict(dict(schema.fields)))


def _resolve_mode(mode: str | None, enforcement: str | None) -> str:
    """``mode`` is the public spelling; ``enforcement`` is the original kwarg."""
    if mode is not None and enforcement is not None and mode != enforcement:
        raise PolicyError(f"mode={mode!r} and enforcement={enforcement!r} disagree; pass one of them")
    resolved = mode if mode is not None else (enforcement if enforcement is not None else "enforce")
    if resolved not in ("enforce", "observe"):
        raise PolicyError(f"mode must be 'enforce'|'observe', got {resolved!r}")
    return resolved


def _resolve_fixed_principal(fixed_principal: Principal | None, principal: Principal | None) -> Principal | None:
    """Accept ``fixed_principal=``; refuse the ``principal=`` alias outright.

    ``principal=`` used to be accepted with a ``DeprecationWarning``, and that was the
    wrong instrument twice. The name reads like the per-request identity and does the
    opposite — it binds ONE identity for the lifetime of the wrapper, so on a
    multi-tenant server every caller runs as that identity, which is the single worst
    misconfiguration this library has. And the warning was invisible: Python filters
    ``DeprecationWarning`` outside ``__main__`` by default, and the ``stacklevel`` was
    counted for one entry point while three call this, so it pointed inside the
    library. "Your fail-closed default is off" is not a deprecation notice.

    Nothing is published yet, so there is no compatibility to keep. It raises.
    """
    if principal is None:
        return fixed_principal
    raise PolicyError(
        "`principal=` is gone. It bound ONE identity for the lifetime of the wrapper while reading like "
        "the per-request one, so on a server every caller ran as it. Use use_principal() per request, or "
        "fixed_principal= if you really do mean one identity for a script or worker.",
        code="removed_argument",
    )


# Tool identity, wrapper metadata and lazy-return inspection live beside this module.
