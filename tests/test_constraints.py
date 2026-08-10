"""Row-level authorization against the RESOLVED resource (Policy Format 0.1).

Draft 0.1 removed the ability to constrain a call argument, so every constraint here
compares an attribute of the resource actually being acted on. The tests that used to
exercise the argument form are gone with it — see
``test_the_idor_footgun_is_unexpressible`` for what replaced them.
"""

from __future__ import annotations

import pytest

from histos import (
    Constraint,
    Field,
    Gate,
    GateDenied,
    Policy,
    PolicyError,
    Principal,
    Schema,
    ToolContract,
    use_principal,
)

# The trusted resource store the resolver reads. The whole point is that ownership
# comes from HERE and never from what the caller said.
_DOCS = {1: {"tenant_id": "acme", "status": "open"}, 2: {"tenant_id": "rival", "status": "open"}}


def _resolver(tool, args):
    return _DOCS.get(args["doc_id"], {})


def read_doc(doc_id):
    return {"body": "hello"}


def _policy(*constraints: Constraint) -> Policy:
    return Policy(
        tools={
            "read_doc": ToolContract(
                name="read_doc",
                args=Schema({"doc_id": Field(type="integer")}),
                constraints=constraints,
            )
        },
        permissions={"member": frozenset({"read_doc"})},
    )


def test_row_ownership_allows_your_own_and_refuses_another_tenants():
    safe = Gate(_policy(Constraint.owns("tenant_id")), resource_resolver=_resolver).wrap(read_doc)
    with use_principal(Principal(role="member", attributes={"tenant_id": "acme"})):
        assert safe(doc_id=1) == {"body": "hello"}
        with pytest.raises(GateDenied) as exc:
            safe(doc_id=2)  # belongs to the rival tenant
    assert exc.value.decision.rule == "resource_constraint"
    assert exc.value.decision.field == "tenant_id"


def test_the_idor_footgun_is_unexpressible():
    """The point of Draft 0.1: you cannot write the confused-deputy check any more.

    The old form compared a caller-supplied `tenant_id` ARGUMENT to the principal's.
    It passed while the tool keyed on `doc_id`, so `doc_id=<someone else's>,
    tenant_id=<mine>` was a cross-tenant read that every check approved. There is no
    `source=` parameter to reach for now — a constraint is resource-bound or it does
    not exist.
    """
    with pytest.raises(TypeError):
        Constraint("tenant_id", "eq", principal_attr="tenant_id", source="call")  # type: ignore[call-arg]

    # And the surviving constructor reads the resolved resource, never the arguments:
    owns = Constraint.owns("tenant_id")
    principal = Principal(role="member", attributes={"tenant_id": "acme"})
    assert owns.evaluate({"tenant_id": "acme"}, principal).ok
    assert not owns.evaluate({"tenant_id": "rival"}, principal).ok


def test_a_condition_on_resource_state():
    """`resource.where` — the general form, over resolved attributes."""
    policy = _policy(Constraint.owns("tenant_id"), Constraint("status", "ne", value="archived"))
    archived = {1: {"tenant_id": "acme", "status": "archived"}}
    safe = Gate(policy, resource_resolver=lambda t, a: archived.get(a["doc_id"], {})).wrap(read_doc)
    with use_principal(Principal(role="member", attributes={"tenant_id": "acme"})):
        with pytest.raises(GateDenied) as exc:
            safe(doc_id=1)
    assert exc.value.decision.rule == "resource_constraint"
    assert exc.value.decision.field == "status"


def test_missing_principal_attribute_fails_closed():
    safe = Gate(_policy(Constraint.owns("tenant_id")), resource_resolver=_resolver).wrap(read_doc)
    with use_principal(Principal(role="member")):  # no tenant_id attribute
        with pytest.raises(GateDenied) as exc:
            safe(doc_id=1)
    assert exc.value.decision.rule == "resource_constraint"
    assert "not set" in exc.value.decision.reason


def test_missing_resource_attribute_fails_closed():
    """A resolver that does not return the attribute cannot prove ownership."""
    safe = Gate(_policy(Constraint.owns("tenant_id")), resource_resolver=lambda t, a: {"unrelated": 1}).wrap(read_doc)
    with use_principal(Principal(role="member", attributes={"tenant_id": "acme"})):
        with pytest.raises(GateDenied) as exc:
            safe(doc_id=1)
    assert exc.value.decision.rule == "resource_constraint"
    assert "no attribute" in exc.value.decision.reason


def test_any_constraint_without_a_resolver_fails_closed():
    """Every constraint is resource-bound now, so any of them needs a resolver."""
    safe = Gate(_policy(Constraint.owns("tenant_id"))).wrap(read_doc)  # no resolver configured
    with use_principal(Principal(role="member", attributes={"tenant_id": "acme"})):
        with pytest.raises(GateDenied) as exc:
            safe(doc_id=1)
    assert exc.value.decision.rule == "no_resource_resolver"


@pytest.mark.parametrize(
    "op,value,state,ok",
    [
        ("le", 1000, 500, True),
        ("le", 1000, 1500, False),
        ("in", ("eu", "us"), "eu", True),
        ("in", ("eu", "us"), "apac", False),
        ("ne", "root", "user", True),
        ("ne", "root", "root", False),
    ],
)
def test_literal_condition_ops(op, value, state, ok):
    safe = Gate(_policy(Constraint("attr", op, value=value)), resource_resolver=lambda t, a: {"attr": state}).wrap(
        read_doc
    )
    with use_principal(Principal(role="member")):
        if ok:
            assert safe(doc_id=1) == {"body": "hello"}
        else:
            with pytest.raises(GateDenied):
                safe(doc_id=1)


def test_constraint_needs_exactly_one_comparand():
    with pytest.raises(PolicyError, match="exactly one"):
        Constraint("tenant_id", "eq")
    with pytest.raises(PolicyError, match="exactly one"):
        Constraint("tenant_id", "eq", value="x", principal_attr="tenant_id")
