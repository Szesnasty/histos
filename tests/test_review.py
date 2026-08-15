"""review_policy — the Import→review screen."""

from __future__ import annotations

from histos import load_bundle, review_policy
from histos.policy.contracts import Constraint, Policy, Sensitivity, ToolContract
from histos.policy.schema import Field, Schema


def test_review_reports_discovery_destructive_and_gaps():
    policy = load_bundle(
        {
            "version": "1",
            "tools": {
                "get_invoice": {
                    "access": "read",
                    "args": {"id": {"type": "string"}},
                    "returns": {"total": {"type": "number"}},
                },
                "delete_invoice": {"access": "write", "args": {"id": {"type": "string"}}},  # no returns
                "orphan": {"access": "read", "args": {"id": {"type": "string"}}},  # no role can call
            },
            "roles": {"billing": {"allow": ["get_invoice", "delete_invoice"]}},
        }
    )
    review = review_policy(policy)
    assert review.tools_discovered == 3
    assert review.roles_discovered == 1
    assert review.destructive == ["delete_invoice"]
    assert review.unreachable == ["orphan"]
    assert review.missing_return_schema == ["delete_invoice", "orphan"]
    assert review.callable_by["delete_invoice"] == ["billing"]

    # import→review tri-state: get_invoice ready; delete_invoice (write, no constraint)
    # and orphan (no grant) need review.
    assert review.ready == ["get_invoice"]
    assert set(review.needs_review) == {"delete_invoice", "orphan"}
    assert review.blocked == []

    text = review.render()
    assert "3 tools discovered" in text
    assert "1 ready" in text
    assert "⚠ delete_invoice" in text
    assert "⚠ orphan" in text


def test_review_flags_policy_warnings():
    policy = load_bundle(
        {
            "version": "1",
            "tools": {"real": {"access": "read", "args": {"id": {"type": "string"}}}},
            "roles": {"r": {"allow": ["real", "ghost"]}},  # ghost undefined
        }
    )
    review = review_policy(policy)
    assert any("ghost" in w for w in review.warnings)
    assert not review.ok()


def test_review_clean_policy_has_no_warnings():
    policy = load_bundle(
        {
            "version": "1",
            "tools": {
                "real": {
                    "access": "read",
                    "args": {"id": {"type": "string"}},
                    "returns": {"ok": {"type": "boolean"}},
                }
            },
            "roles": {"r": {"allow": ["real"]}},
        }
    )
    review = review_policy(policy)
    assert review.ok()
    assert "return schema complete" in review.render()


def _tool_with_constraint(*constraints, access="write", sensitivity=Sensitivity.LOW):
    return Policy(
        tools={
            "delete_invoice": ToolContract(
                name="delete_invoice",
                args=Schema({"invoice_id": Field(type="string")}),
                returns=Schema({"ok": Field(type="boolean")}),
                access=access,
                sensitivity=sensitivity,
                constraints=constraints,
            ),
        },
        permissions={"billing": frozenset({"delete_invoice"})},
    )


def test_review_flags_a_high_risk_tool_with_no_row_authz():
    """The residual the format cannot close: a constraint that was never written.

    Draft 0.1 made the IDOR *constraint* unexpressible, so review no longer warns
    about a wrong constraint — it warns about a missing one. `delete_invoice` with an
    RBAC grant and nothing else is authorized at the tool level, so a caller may act
    on any row.
    """
    policy = _tool_with_constraint()  # write tool, no resource constraint at all
    review = review_policy(policy)
    assert "delete_invoice" in review.needs_review
    assert any("no resource constraint" in r for r in review.classification["delete_invoice"][1])
    assert any("no resource constraint" in w for w in review.warnings)


def test_review_does_not_flag_a_tool_with_row_authz():
    policy = _tool_with_constraint(Constraint.owns("tenant_id"))
    review = review_policy(policy)
    assert review.classification["delete_invoice"][1] == []
    assert review.warnings == []


def test_review_flags_a_critical_read_with_no_row_authz():
    """Not only writes. A critical-sensitivity read with an RBAC grant and no
    constraint lets a caller read any row, and "this role may call it" is true for
    every one of them. This gap was tolerated while the rule had to be maintained in
    two implementations; there is one now."""
    policy = _tool_with_constraint(access="read", sensitivity=Sensitivity.CRITICAL)
    review = review_policy(policy)
    assert "delete_invoice" in review.needs_review
    assert any("no resource constraint" in r for r in review.classification["delete_invoice"][1])


def test_review_leaves_a_low_sensitivity_read_alone():
    """The narrow version of the rule — flagging every read would be noise."""
    policy = _tool_with_constraint(access="read", sensitivity=Sensitivity.LOW)
    assert review_policy(policy).warnings == []
