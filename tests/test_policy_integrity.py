"""Policy versioning + structural integrity."""

from __future__ import annotations

from histos import Constraint, Field, Policy, Schema, ToolContract


def _policy(**over) -> Policy:
    base = dict(
        tools={
            "t": ToolContract(
                name="t",
                args=Schema({"tenant_id": Field(type="string")}),
                constraints=(Constraint("tenant_id", "eq", principal_attr="tenant_id"),),
            )
        },
        permissions={"r": frozenset({"t"})},
    )
    base.update(over)
    return Policy(**base)


def test_content_hash_is_stable_and_structural():
    a = _policy(policy_version="1")
    b = _policy(policy_version="2")  # metadata differs, structure identical
    assert a.content_hash() == b.content_hash()
    assert a.content_hash().startswith("sha256:")


def test_content_hash_changes_when_a_constraint_changes():
    a = _policy()
    b = Policy(
        tools={
            "t": ToolContract(
                name="t",
                args=Schema({"tenant_id": Field(type="string")}),
                constraints=(Constraint("tenant_id", "ne", principal_attr="tenant_id"),),  # eq → ne
            )
        },
        permissions={"r": frozenset({"t"})},
    )
    assert a.content_hash() != b.content_hash()


def test_validate_flags_unknown_grant_and_missing_schema():
    policy = Policy(
        tools={"real": ToolContract(name="real", args=None)},  # no schema
        permissions={"r": frozenset({"real", "ghost"})},  # ghost not defined
    )
    issues = policy.validate()
    assert any("ghost" in i for i in issues)
    assert any("arg schema" in i for i in issues)


def test_strict_gate_raises_on_invalid_policy():
    import pytest

    from histos import Gate, PolicyError

    policy = Policy(
        tools={"real": ToolContract(name="real", args=None)},
        permissions={"r": frozenset({"real"})},
    )
    with pytest.raises(PolicyError):
        Gate(policy, strict=True)
