"""Phase 0.1 — the composite that makes histos 'not just RBAC'."""

from __future__ import annotations

import math

import pytest

from histos import (
    Binding,
    Constraint,
    Field,
    Gate,
    GateDenied,
    JSONLAuditSink,
    Policy,
    Principal,
    ResourceNotFound,
    Schema,
    ToolContract,
    canonical_json,
    request_fingerprint,
    use_principal,
    verify_chain,
)
from histos.decide import detectors
from histos.integrations.base import denial_message, guard_callable, protect_functions

PAN = "4111111111111111"  # Luhn-valid test card
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # structural (prefix), not checksum-verified


# ── numeric_range ─────────────────────────────────────────────────────────


def _num_gate(**field_kwargs):
    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({"n": Field(type="number", **field_kwargs)}))},
        permissions={"r": frozenset({"t"})},
    )
    return Gate(policy).wrap(lambda **k: k, name="t")


def test_numeric_bounds_enforced():
    safe = _num_gate(maximum=500)
    with use_principal(Principal(role="r")):
        assert safe(n=500) == {"n": 500}
        with pytest.raises(GateDenied) as exc:
            safe(n=501)
    assert exc.value.decision.rule == "arg_schema"


def test_non_finite_number_is_denied():
    safe = _num_gate(maximum=500)
    with use_principal(Principal(role="r")):
        for bad in (math.nan, math.inf, -math.inf):
            with pytest.raises(GateDenied) as exc:
                safe(n=bad)
            assert "non-finite" in exc.value.decision.reason


def test_multiple_of_and_exclusive():
    safe = _num_gate(multiple_of=5, exclusive_minimum=0)
    with use_principal(Principal(role="r")):
        assert safe(n=10) == {"n": 10}
        with pytest.raises(GateDenied):
            safe(n=7)  # not a multiple of 5
        with pytest.raises(GateDenied):
            safe(n=0)  # not > exclusive_minimum


# ── canonical serializer ──────────────────────────────────────────────────


def test_canonical_distinguishes_types_and_is_order_stable():
    assert canonical_json(1) != canonical_json("1")
    assert canonical_json(True) != canonical_json(1)
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})
    assert canonical_json([1, 2]) != canonical_json([2, 1])
    with pytest.raises(ValueError):
        canonical_json(math.nan)
    with pytest.raises(ValueError):
        canonical_json(lambda: 1)


def test_fingerprint_uses_canonical_no_type_collision():
    p = Principal(role="r")
    assert request_fingerprint("t", {"x": 1}, p) != request_fingerprint("t", {"x": "1"}, p)


# ── trusted_arg_binding ────────────────────────────────────────────────────


def _binding_gate(seen):
    policy = Policy(
        tools={
            "read_order": ToolContract(
                name="read_order",
                args=Schema({"order_id": Field(type="string"), "tenant_id": Field(type="string")}),
                bindings=(Binding("tenant_id", "tenant"),),
            )
        },
        permissions={"support": frozenset({"read_order"})},
    )

    def read_order(order_id, tenant_id):
        seen["tenant_id"] = tenant_id
        return {"ok": True}

    return Gate(policy).wrap(read_order)


def test_trusted_arg_binding_overrides_attacker_value():
    seen: dict = {}
    safe = _binding_gate(seen)
    with use_principal(Principal(role="support", identity="u1", attributes={"tenant": "acme"})):
        safe(order_id="O1", tenant_id="attacker")
    assert seen["tenant_id"] == "acme"  # the model's value was replaced, not validated


def test_trusted_arg_binding_fails_closed_without_attribute():
    seen: dict = {}
    safe = _binding_gate(seen)
    with use_principal(Principal(role="support", attributes={})), pytest.raises(GateDenied) as exc:
        safe(order_id="O1", tenant_id="x")
    assert exc.value.decision.rule == "arg_binding_unresolved"


# ── resource resolver taxonomy + IDOR block ────────────────────────────────


def _resource_gate(resolver):
    policy = Policy(
        tools={
            "read": ToolContract(
                name="read", args=Schema({"id": Field(type="string")}), constraints=(Constraint.owns("tenant_id"),)
            )
        },
        permissions={"support": frozenset({"read"})},
    )
    return Gate(policy, resource_resolver=resolver).wrap(lambda id: {"ok": True}, name="read")


def test_resource_not_found_is_a_clean_deny():
    def resolver(tool, args):
        raise ResourceNotFound("row deleted")

    safe = _resource_gate(resolver)
    with use_principal(Principal(role="support", attributes={"tenant_id": "acme"})), pytest.raises(GateDenied) as exc:
        safe(id="x")
    assert exc.value.decision.rule == "resource_not_found"


def test_resolver_exception_is_distinct_from_internal_error():
    def resolver(tool, args):
        raise ValueError("db down")

    safe = _resource_gate(resolver)
    with use_principal(Principal(role="support", attributes={"tenant_id": "acme"})), pytest.raises(GateDenied) as exc:
        safe(id="x")
    assert exc.value.decision.rule == "resolver_error"


def test_owns_form_authorizes_on_the_resource():
    safe = _resource_gate(lambda t, a: {"tenant_id": "acme"})
    with use_principal(Principal(role="support", attributes={"tenant_id": "acme"})):
        assert safe(id="x") == {"ok": True}
    with use_principal(Principal(role="support", attributes={"tenant_id": "evil"})), pytest.raises(GateDenied) as exc:
        safe(id="x")
    assert exc.value.decision.rule == "resource_constraint"


def test_the_idor_construct_no_longer_exists_to_refuse():
    """Policy Format 0.1 deleted the check this test used to need.

    `Gate(strict=True)` used to refuse a write tool authorized on a caller-declared
    argument. That constraint form is gone from the language, so the load-time
    refusal has nothing left to refuse — the format prevents the mistake instead of
    detecting it. What remains is the resource-bound form, which loads fine.
    """
    policy = Policy(
        tools={
            "del": ToolContract(
                name="del",
                args=Schema({"id": Field(type="string")}),
                access="write",
                constraints=(Constraint.owns("tenant_id"),),
            )
        },
        permissions={"admin": frozenset({"del"})},
    )
    assert Gate(policy, strict=True).policy.validate() == []


# ── structured detectors (PRE deny / POST redact, by confidence) ────────────


def test_checksum_secret_detectors():
    assert detectors.luhn_ok(PAN)
    assert detectors.iban_ok("GB82WEST12345698765432")
    kinds = {d.kind: d.confidence for d in detectors.scan_string(f"card {PAN} key {AWS_KEY}")}
    assert kinds["pan"] == detectors.CHECKSUM
    assert kinds["aws_key"] == detectors.STRUCTURAL


def _secret_gate(returns=None, **contract_kwargs):
    policy = Policy(
        tools={
            "t": ToolContract(name="t", args=Schema({"body": Field(type="string")}), returns=returns, **contract_kwargs)
        },
        permissions={"r": frozenset({"t"})},
    )
    return policy


def test_checksum_secret_in_arg_is_denied():
    safe = Gate(_secret_gate()).wrap(lambda body: {"ok": True}, name="t")
    with use_principal(Principal(role="r")), pytest.raises(GateDenied) as exc:
        safe(body=f"here is my card {PAN}")
    assert exc.value.decision.rule == "secret_detected"


def test_structural_secret_in_arg_is_not_denied_but_redacted_in_output():
    # structural (AWS prefix) does NOT hard-deny an arg…
    safe = Gate(_secret_gate()).wrap(lambda body: {"echo": body}, name="t")
    with use_principal(Principal(role="r")):
        out = safe(body=f"token {AWS_KEY}")
    # …but the same secret is redacted if it comes back in the output.
    assert AWS_KEY not in str(out)
    assert "[REDACTED-SECRET]" in str(out)


def test_secret_in_output_is_redacted():
    safe = Gate(_secret_gate()).wrap(lambda body: {"card": PAN, "status": "ok"}, name="t")
    with use_principal(Principal(role="r")):
        out = safe(body="hi")
    assert out["card"] == "[REDACTED-SECRET]"
    assert out["status"] == "ok"


# ── output_field_projection ────────────────────────────────────────────────


def test_output_projection_drops_undeclared_fields():
    policy = _secret_gate(returns=Schema({"status": Field(type="string")}), project_output=True)
    safe = Gate(policy).wrap(lambda body: {"status": "ok", "internal_token": "sekret"}, name="t")
    with use_principal(Principal(role="r")):
        out = safe(body="hi")
    assert out == {"status": "ok"}


# ── two-audience decisions ─────────────────────────────────────────────────


def test_two_audience_public_reason_and_remedy():
    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({"x": Field(type="integer")}))},
        permissions={"admin": frozenset({"t"})},
    )
    safe = Gate(policy).wrap(lambda x: x, name="t")
    with use_principal(Principal(role="viewer")), pytest.raises(GateDenied) as exc:
        safe(x=1)
    assert exc.value.public_reason == "ACTION_NOT_AUTHORIZED"  # what the model sees
    assert "grant" in exc.value.decision.remedy  # what the developer sees
    assert "viewer" in exc.value.decision.explain()  # rich detail stays developer-side


# ── coverage ───────────────────────────────────────────────────────────────


def test_coverage_flags_exposed_but_undeclared():
    policy = Policy(
        tools={"a": ToolContract(name="a", args=Schema({"x": Field(type="integer")}))},
        permissions={"r": frozenset({"a"})},
    )
    g = Gate(policy)
    g.wrap(lambda x: x, name="a")
    cov = g.coverage(["a", "b"])
    assert cov["undeclared"] == ["b"]
    assert cov["covered"] == ["a"]


# ── audit verifier ─────────────────────────────────────────────────────────


def test_verify_chain_ok_then_detects_tamper(tmp_path):
    log = tmp_path / "audit.jsonl"
    sink = JSONLAuditSink(log, hash_chain=True)
    sink.record({"decision_id": 1, "effect": "allow", "rule": "allow"})
    sink.record({"decision_id": 2, "effect": "deny", "rule": "rbac"})
    ok, detail = verify_chain(log)
    assert ok and "2 records" in detail

    lines = log.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"allow"', '"deny"')  # tamper record #1
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok2, detail2 = verify_chain(log)
    assert not ok2 and "line 1" in detail2


# ── adapter core (framework-free) ──────────────────────────────────────────


def test_guard_callable_returns_non_coaching_message_on_deny():
    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({"x": Field(type="integer")}))},
        permissions={"admin": frozenset({"t"})},
    )
    guarded = guard_callable(lambda x: x, name="t", gate=Gate(policy))
    with use_principal(Principal(role="viewer")):
        msg = guarded(x=2)  # a denied call becomes the agent-facing message, not a crash
    assert isinstance(msg, str) and "ACTION_NOT_AUTHORIZED" in msg
    assert denial_message  # exported helper exists


def test_protect_functions_wraps_and_gates():
    def add(a, b):
        return a + b

    policy = Policy(
        tools={"add": ToolContract(name="add", args=Schema({"a": Field(type="integer"), "b": Field(type="integer")}))},
        permissions={"r": frozenset({"add"})},
    )
    guarded, gate = protect_functions([add], policy=policy)
    with use_principal(Principal(role="r")):
        assert guarded[0](a=2, b=3) == 5
    with use_principal(Principal(role="viewer")):
        assert "ACTION_NOT_AUTHORIZED" in guarded[0](a=2, b=3)
