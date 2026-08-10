"""Pre-merge hardening: trusted confirmation, malformed-output policy, review tri-state."""

from __future__ import annotations

import pytest

from histos import (
    ApprovalStore,
    Field,
    Gate,
    GateConfirmationRequired,
    GateDenied,
    Policy,
    Principal,
    Schema,
    ToolContract,
    load_bundle,
    request_fingerprint,
    review_policy,
    use_principal,
)

# ── Trusted, out-of-band confirmation ────────────────────────────────────


def _confirm_policy() -> Policy:
    return Policy(
        tools={
            "wire_money": ToolContract(
                name="wire_money", args=Schema({"to": Field(type="string")}), requires_confirmation=True
            )
        },
        permissions={"clerk": frozenset({"wire_money"})},
    )


def test_confirmation_requires_out_of_band_grant():
    store = ApprovalStore()
    calls = []

    def wire_money(to):
        calls.append(to)
        return {"ok": True}

    safe = Gate(_confirm_policy(), confirm=store.as_confirm()).wrap(wire_money)
    principal = Principal(role="clerk", identity="c1")

    # Without an approval, the agent cannot proceed and cannot self-approve.
    with use_principal(principal):
        with pytest.raises(GateConfirmationRequired):
            safe(to="acct-1")
    assert calls == []

    # A trusted host grants the exact action out-of-band, then the call proceeds.
    fp = request_fingerprint("wire_money", {"to": "acct-1"}, principal)
    store.grant(fp)
    with use_principal(principal):
        assert safe(to="acct-1") == {"ok": True}
    assert calls == ["acct-1"]


def test_approval_is_single_use_and_action_bound():
    store = ApprovalStore()

    def wire_money(to):
        return {"ok": True}

    safe = Gate(_confirm_policy(), confirm=store.as_confirm()).wrap(wire_money)
    principal = Principal(role="clerk", identity="c1")

    store.grant(request_fingerprint("wire_money", {"to": "acct-1"}, principal))
    with use_principal(principal):
        safe(to="acct-1")  # consumes the approval
        # single-use: a second identical call needs a fresh approval
        with pytest.raises(GateConfirmationRequired):
            safe(to="acct-1")
        # action-bound: the approval for acct-1 does not approve acct-2
        store.grant(request_fingerprint("wire_money", {"to": "acct-1"}, principal))
        with pytest.raises(GateConfirmationRequired):
            safe(to="acct-2")


# ── Malformed-output policy (strict_returns) ─────────────────────────────


def _strict_policy(on_violation: str = "redact_all") -> Policy:
    return Policy(
        tools={
            "get_acct": ToolContract(
                name="get_acct",
                args=Schema({}),
                returns=Schema({"balance": Field(type="number")}),
                strict_returns=True,
                on_output_violation=on_violation,
            )
        },
        permissions={"r": frozenset({"get_acct"})},
    )


def test_conforming_output_passes():
    def get_acct():
        return {"balance": 10.0}

    safe = Gate(_strict_policy()).wrap(get_acct)
    with use_principal(Principal(role="r")):
        assert safe() == {"balance": 10.0}


def test_undeclared_field_is_redacted_all_by_default():
    """A secret in an UNDECLARED field can't be name-redacted → conservative redact-all."""

    def get_acct():
        return {"balance": 10.0, "root_password": "hunter2"}  # undeclared field

    safe = Gate(_strict_policy()).wrap(get_acct)
    with use_principal(Principal(role="r")):
        out = safe()
    assert "hunter2" not in str(out)
    assert out == "[REDACTED: tool output did not match its declared return schema]"


def test_schema_violation_can_deny():
    def get_acct():
        return {"balance": "not-a-number"}  # type violation

    safe = Gate(_strict_policy(on_violation="deny")).wrap(get_acct)
    with use_principal(Principal(role="r")):
        with pytest.raises(GateDenied) as exc:
            safe()
    assert exc.value.decision.rule == "output_schema"


def test_non_strict_default_lets_undeclared_fields_through():
    """Default (strict_returns=False) keeps prior behavior — documents the trade-off."""
    policy = Policy(
        tools={
            "get_acct": ToolContract(
                name="get_acct", args=Schema({}), returns=Schema({"balance": Field(type="number")})
            )
        },
        permissions={"r": frozenset({"get_acct"})},
    )

    def get_acct():
        return {"balance": 10.0, "extra": "kept"}

    safe = Gate(policy).wrap(get_acct)
    with use_principal(Principal(role="r")):
        assert safe()["extra"] == "kept"


# ── Review tri-state: blocked ────────────────────────────────────────────


def test_tool_without_arg_schema_is_blocked():
    policy = load_bundle(
        {
            "version": "1",
            "tools": {"mystery": {"access": "read"}},  # no args → cannot be safely gated
            "roles": {"r": {"allow": ["mystery"]}},
        }
    )
    review = review_policy(policy)
    assert review.blocked == ["mystery"]
    assert "✕ mystery" in review.render()
