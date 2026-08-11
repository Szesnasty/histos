"""`content_hash` is a contract, not an implementation detail.

Approvals bind to it, policy pinning rests on it, every audit record names it, and the
spec requires a second implementation to reproduce it byte for byte. So it has to be
*injective* (two policies that decide differently must not share a hash) and
*deterministic* (the same policy must hash the same way in every process).

It was neither. `Policy.fingerprint` flattened every number to bare text and
`content_hash` hashed it with `json.dumps(..., default=str)`, so the integer `1` and
the string `"1"` produced one hash while reaching opposite verdicts, and a set-valued
field inherited Python's `PYTHONHASHSEED`-dependent iteration order — which silently
unbinds an approval issued by one worker from every other worker.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from histos.bundle import load_policy
from histos.contracts import Constraint, Policy, ToolContract
from histos.schema import Field, Schema

POLICIES = Path(__file__).resolve().parent.parent / "policies"


def _policy_with(value: object) -> Policy:
    return Policy(
        tools={
            "t": ToolContract(
                name="t",
                args=Schema({"tier": Field(type="string")}),
                access="write",
                constraints=(Constraint("tier", "eq", value=value),),
            )
        },
        permissions={"r": frozenset({"t"})},
    )


# ── injectivity ──────────────────────────────────────────────────────────


def test_an_integer_and_a_string_do_not_share_a_hash():
    """The collision that mattered: these two policies reach opposite verdicts."""
    assert _policy_with(1).content_hash() != _policy_with("1").content_hash()


def test_a_boolean_and_an_integer_do_not_share_a_hash():
    assert _policy_with(True).content_hash() != _policy_with(1).content_hash()


def test_null_and_the_string_none_do_not_share_a_hash():
    assert _policy_with(None).content_hash() != _policy_with("None").content_hash()


def test_a_list_and_a_string_do_not_share_a_hash():
    assert _policy_with(["a"]).content_hash() != _policy_with("a").content_hash()


def test_an_integer_bound_and_its_float_spelling_still_agree():
    """The one collapse that is deliberate: no JSON parser can tell 500 from 500.0."""
    assert _policy_with(500).content_hash() == _policy_with(500.0).content_hash()


# ── determinism ──────────────────────────────────────────────────────────

_HASH_SCRIPT = """
from histos.contracts import Policy, ToolContract
from histos.schema import Schema
p = Policy(
    tools={"t": ToolContract(name="t", args=Schema({}), access="write")},
    permissions={"r": frozenset({"t"})},
    canaries=frozenset({"A", "B", "C", "D", "E", "F", "G"}),
)
print(p.content_hash())
"""


@pytest.mark.parametrize("seed", ["0", "1", "42", "12345"])
def test_the_same_policy_hashes_identically_under_any_hash_seed(seed: str):
    """Set-valued fields used to capture Python's per-process iteration order."""
    baseline = subprocess.run(
        [sys.executable, "-c", _HASH_SCRIPT],
        capture_output=True,
        text=True,
        check=True,
        env={"PYTHONHASHSEED": "0", "PATH": "/usr/bin:/bin"},
    ).stdout.strip()
    other = subprocess.run(
        [sys.executable, "-c", _HASH_SCRIPT],
        capture_output=True,
        text=True,
        check=True,
        env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin"},
    ).stdout.strip()
    assert baseline and baseline == other


def test_hashing_is_stable_across_repeated_calls():
    policy = _policy_with(1)
    assert len({policy.content_hash() for _ in range(50)}) == 1


# ── the property the README makes normative ──────────────────────────────


def _yaml_json_pairs() -> list[tuple[Path, Path]]:
    return [(y, y.with_suffix(".json")) for y in sorted(POLICIES.rglob("*.yaml")) if y.with_suffix(".json").exists()]


def test_there_are_policies_in_both_spellings_to_check():
    assert _yaml_json_pairs(), "the corpus that pins YAML/JSON hash parity is missing"


@pytest.mark.parametrize("yaml_path,json_path", _yaml_json_pairs(), ids=lambda p: p.name)
def test_the_same_policy_hashes_identically_in_yaml_and_json(yaml_path: Path, json_path: Path):
    assert load_policy(yaml_path).content_hash() == load_policy(json_path).content_hash()


# ── a policy that cannot be hashed reproducibly must not load ────────────


def test_a_constraint_literal_that_cannot_be_canonicalized_is_refused():
    """Better to fail at build time than to hash an object through `str()`."""
    from histos.errors import PolicyError

    with pytest.raises(PolicyError):
        _policy_with(object())


# ── the lock must see the change it exists to catch ──────────────────────


def _mcp(tier_type: str, enum: list) -> object:
    from histos.importers.mcp import sources_from_mcp

    (source,) = sources_from_mcp(
        [
            {
                "name": "t",
                "description": "d",
                "inputSchema": {"type": "object", "properties": {"tier": {"type": tier_type, "enum": enum}}},
            }
        ]
    )
    return source


def test_a_retyped_enum_moves_every_lock_hash():
    """The MCP rug-pull the lock is for: same names, inverted enforcement.

    A server that reships `enum: [1, 2]` as `enum: ["1", "2"]` has flipped which calls
    the tool accepts — the honest policy allows `tier=1`, the crafted one denies it.
    Both lock hashes used to be byte-identical, so `histos drift` reported CLEAN and
    exited 0. A drift detector that passes on this is worse than none.
    """
    from histos.lockfile import contract_hash, schema_hash

    honest, crafted = _mcp("integer", [1, 2]), _mcp("string", ["1", "2"])
    assert schema_hash(honest.shape) != schema_hash(crafted.shape)
    assert contract_hash(honest.contract) != contract_hash(crafted.contract)


def test_an_integer_bound_and_its_float_spelling_do_not_move_a_lock_hash():
    """The deliberate collapse survives the fix: no JSON parser separates 8 from 8.0."""
    from histos.lockfile import schema_hash

    assert schema_hash({"maxLength": 8}) == schema_hash({"maxLength": 8.0})
