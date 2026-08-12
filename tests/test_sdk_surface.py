"""The v0.1 public surface: canonical loading (§9), protect() (§3), identity (§4), modes (§7)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from histos import (
    Field,
    Gate,
    GateDenied,
    InMemoryAuditSink,
    Policy,
    PolicyError,
    Principal,
    Schema,
    ToolContract,
    dump_bundle,
    load_bundle,
    load_bundle_json,
    load_bundle_yaml,
    load_policy,
    parse_yaml_bundle,
    protect,
    review_policy,
    use_principal,
)

EXAMPLE_POLICY = Path(__file__).resolve().parent.parent / "examples" / "security.policy.yaml"


# ── §9 canonical loading ─────────────────────────────────────────────────


def test_load_policy_accepts_a_yaml_path_a_json_path_and_a_dict(tmp_path):
    from_yaml = load_policy(EXAMPLE_POLICY)
    assert set(from_yaml.tools) == {"search_docs", "get_order", "make_refund"}

    json_path = tmp_path / "policy.json"
    json_path.write_text(json.dumps(dump_bundle(from_yaml)), encoding="utf-8")
    from_json = load_policy(json_path)

    from_dict = load_policy(dump_bundle(from_yaml))

    # The canonical model, not the parser, is the source of truth — so the same
    # logical policy hashes identically whichever format it arrived in.
    assert from_yaml.content_hash() == from_json.content_hash() == from_dict.content_hash()


def test_duplicate_keys_are_refused_in_both_formats():
    with pytest.raises(PolicyError, match="duplicate key"):
        load_bundle_yaml("version: '1'\nversion: '2'\n")
    with pytest.raises(PolicyError, match="duplicate key"):
        load_bundle_json('{"version": "1", "version": "2"}')


def test_duplicate_tool_name_is_refused_by_the_parser():
    """With `tools` a mapping, a repeated name IS a duplicate key — no bespoke check.

    That is the argument for the mapping shape: the engine used to carry a
    hand-written duplicate-name guard purely because `tools` was a list.
    """
    with pytest.raises(PolicyError, match="duplicate key"):
        load_bundle_yaml("schema_version: histos.policy/0.1\ntools:\n  t: {}\n  t: {}\n")


def test_a_list_of_tools_is_refused_with_an_explanation():
    with pytest.raises(PolicyError, match="must be a mapping"):
        load_bundle({"version": "1", "tools": [{"name": "t"}]})


def test_yaml_1_1_booleans_do_not_silently_appear():
    """`yes`/`no`/`on`/`off` stay strings, so YAML and JSON agree (§9)."""
    parsed = parse_yaml_bundle("version: '1'\nprobe: {a: yes, b: off, c: true, d: false}\n")
    assert parsed["probe"] == {"a": "yes", "b": "off", "c": True, "d": False}


def test_load_policy_fails_loud_on_unusable_input(tmp_path):
    with pytest.raises(PolicyError, match="not found"):
        load_policy(tmp_path / "nope.yaml")
    odd = tmp_path / "policy.txt"
    odd.write_text("version: '1'", encoding="utf-8")
    with pytest.raises(PolicyError, match="must be .yaml"):
        load_policy(odd)
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(PolicyError, match="empty"):
        load_policy(empty)


def test_shipped_example_policy_is_valid_and_reviews_clean():
    """The artifact the README and CLI point at must not rot."""
    policy = load_policy(EXAMPLE_POLICY)
    assert policy.validate() == []
    review = review_policy(policy)
    assert review.blocked == []
    assert review.needs_review == []
    assert review.warnings == []


def test_output_policy_survives_the_bundle_round_trip():
    """A setting that loads but does not dump silently disappears on export."""
    policy = Policy(
        tools={
            "t": ToolContract(
                name="t",
                args=Schema({}),
                returns=Schema({"ok": Field(type="boolean")}),
                strict_returns=True,
                on_output_violation="deny",
                scan_output_for_canary=False,
            )
        }
    )
    again = load_bundle(dump_bundle(policy))
    tool = again.tools["t"]
    assert (tool.strict_returns, tool.on_output_violation, tool.scan_output_for_canary) == (True, "deny", False)
    assert again.content_hash() == policy.content_hash()


# ── §3 protect() ─────────────────────────────────────────────────────────


def search_docs(query: str, top_k: int = 5):
    return [{"title": "t", "snippet": "s"}]


def undeclared_tool(x: int):
    return x


def test_top_level_protect_returns_tools_coverage_and_review():
    result = protect([search_docs, undeclared_tool], policy=EXAMPLE_POLICY)

    assert set(result.tools) == {"search_docs", "undeclared_tool"}
    status = {r["tool"]: r["status"] for r in result.coverage}
    assert status == {"search_docs": "ready", "undeclared_tool": "needs-policy"}
    assert result.review is not None
    # The discovered tool now shows up in the review as unreachable, not as ready.
    assert "undeclared_tool" in result.review.needs_review
    assert "needs a decision: undeclared_tool" in result.summary()


def test_protect_result_iterates_over_the_wrapped_tools():
    result = protect([search_docs], policy=EXAMPLE_POLICY)
    assert list(result) == [result.tools["search_docs"]]


def test_protect_report_is_still_available_as_an_alias():
    result = protect([search_docs], policy=EXAMPLE_POLICY)
    assert result.report is result.coverage


def test_protect_wraps_an_undeclared_tool_but_denies_it():
    result = protect([undeclared_tool], policy=EXAMPLE_POLICY)
    with use_principal(Principal(role="support")), pytest.raises(GateDenied) as exc:
        result.tools["undeclared_tool"](x=1)
    assert exc.value.decision.rule == "rbac"


def test_protected_tool_enforces_the_policy_from_the_file():
    result = protect([search_docs], policy=EXAMPLE_POLICY)
    safe = result.tools["search_docs"]
    with use_principal(Principal(role="viewer")):
        assert safe(query="hello") == [{"title": "t", "snippet": "s"}]
        with pytest.raises(GateDenied) as exc:
            safe(query="hello", top_k=999)  # maximum is 20
    assert exc.value.decision.rule == "arg_schema"


# ── §4 identity ──────────────────────────────────────────────────────────


def _echo_policy() -> Policy:
    return Policy(
        tools={"echo": ToolContract(name="echo", args=Schema({"x": Field(type="integer")}))},
        permissions={"r": frozenset({"echo"})},
    )


def echo(x: int) -> int:
    return x


def test_fixed_principal_binds_one_identity_for_the_wrapper():
    safe = Gate(_echo_policy()).wrap(echo, fixed_principal=Principal(role="r", identity="worker"))
    assert safe(x=1) == 1  # no use_principal() needed


def test_the_principal_alias_is_refused_rather_than_deprecated():
    """It reads like the per-request identity and binds one for the wrapper's life.

    A DeprecationWarning was the wrong channel — filtered by default outside
    `__main__`, so the misconfiguration it warned about was silent in every real host.
    """
    with pytest.raises(PolicyError, match="use_principal"):
        Gate(_echo_policy()).wrap(echo, principal=Principal(role="r"))


def test_passing_both_principal_forms_is_still_an_error():
    with pytest.raises(PolicyError):
        Gate(_echo_policy()).wrap(echo, fixed_principal=Principal(role="r"), principal=Principal(role="r"))


def test_use_principal_still_wins_when_nothing_is_fixed():
    safe = Gate(_echo_policy()).wrap(echo)
    with use_principal(Principal(role="nobody")), pytest.raises(GateDenied):
        safe(x=1)


# ── §7 modes ─────────────────────────────────────────────────────────────


def test_mode_and_enforcement_are_the_same_switch():
    assert Gate(_echo_policy(), mode="observe").enforcement == "observe"
    assert Gate(_echo_policy(), enforcement="observe").mode == "observe"
    assert Gate(_echo_policy()).mode == "enforce"


def test_conflicting_mode_and_enforcement_is_an_error():
    with pytest.raises(PolicyError, match="disagree"):
        Gate(_echo_policy(), mode="observe", enforcement="enforce")


def test_unknown_mode_is_an_error():
    with pytest.raises(PolicyError, match="must be 'enforce'"):
        Gate(_echo_policy(), mode="audit-only")


def test_observe_records_denied_but_executed():
    """The record that must never be mistaken for a block."""
    sink = InMemoryAuditSink()
    safe = Gate(_echo_policy(), audit=sink, mode="observe").wrap(echo)
    with use_principal(Principal(role="nobody")):
        assert safe(x=1) == 1

    pre = [e for e in sink.entries if e["phase"] == "pre"][0]
    assert pre["effect"] == "deny"
    assert pre["enforced"] is False
    assert pre["executed"] is True


def test_enforce_records_denied_and_not_executed():
    sink = InMemoryAuditSink()
    safe = Gate(_echo_policy(), audit=sink).wrap(echo)
    with use_principal(Principal(role="nobody")), pytest.raises(GateDenied):
        safe(x=1)

    pre = [e for e in sink.entries if e["phase"] == "pre"][0]
    assert (pre["effect"], pre["enforced"], pre["executed"]) == ("deny", True, False)


def test_allowed_call_records_executed():
    sink = InMemoryAuditSink()
    safe = Gate(_echo_policy(), audit=sink).wrap(echo)
    with use_principal(Principal(role="r")):
        safe(x=1)
    assert all(e["executed"] is True for e in sink.entries)


# ── Policy Format Draft 0.1: the compatibility gate ──────────────────────


def test_unknown_tool_key_is_refused_not_ignored():
    """The one place the library used to fail OPEN.

    A policy asking for a check this engine lacks must be refused outright — loading
    it partially would enforce only part of what it says, silently, with a clean
    `validate()`. Half a fleet on an older build is the realistic version of this.
    """
    future = {
        "version": "1",
        "tools": {
            "fetch": {
                "access": "write",
                "args": {"url": {"type": "string"}},
                "url_egress_allowlist": {"hosts": ["api.example.com"]},
            }
        },
        "roles": {"agent": {"allow": ["fetch"]}},
    }
    with pytest.raises(PolicyError, match="url_egress_allowlist"):
        load_bundle(future)


def test_unknown_keys_are_refused_at_every_level():
    base = {"version": "1", "tools": {}, "roles": {}}
    with pytest.raises(PolicyError, match="policy bundle"):
        load_bundle({**base, "totally_new_section": {}})
    with pytest.raises(PolicyError, match="maxium"):  # a typo, caught the same way
        load_bundle({**base, "tools": {"t": {"args": {"x": {"type": "integer", "maxium": 5}}}}})
    with pytest.raises(PolicyError, match="where"):
        load_bundle({**base, "tools": {"t": {"resource": {"where": [{"field": "a", "op": "eq", "ttl": 60}]}}}})
    with pytest.raises(PolicyError, match="resource"):
        load_bundle({**base, "tools": {"t": {"resource": {"owns": "a", "unless": "b"}}}})
    with pytest.raises(PolicyError, match="output"):
        load_bundle({**base, "tools": {"t": {"output": {"project": True, "shout": False}}}})
    with pytest.raises(PolicyError, match="confirmation"):
        load_bundle({**base, "tools": {"t": {"confirmation": {"required": True, "approvers": 2}}}})
    with pytest.raises(PolicyError, match="role"):
        load_bundle({**base, "roles": {"r": {"allow": [], "deny": ["x"]}}})


def test_bindings_are_substitutions_not_expressions():
    """The grammar is frozen at `principal.<attr>` so a policy stays decidable by eye."""
    base = {"version": "1", "tools": {}, "roles": {}}
    ok = load_bundle({**base, "tools": {"t": {"args": {}, "bind": {"tenant_id": "principal.tenant_id"}}}})
    assert ok.tools["t"].bindings[0].principal_attr == "tenant_id"

    for bad in ("principal.tenant ?? args.tenant", "{{ principal.tenant }}", "args.tenant_id", "principal"):
        with pytest.raises(PolicyError, match="principal"):
            load_bundle({**base, "tools": {"t": {"args": {}, "bind": {"tenant_id": bad}}}})


def test_policy_may_declare_the_capabilities_it_needs():
    """`requires.features` is the portable contract — an engine *version* stops
    being usable the moment there is more than one implementation."""
    ok = load_bundle(
        {
            "version": "1",
            "requires": {"features": ["rbac", "resource_authz", "numeric_range"]},
            "tools": {"t": {"args": {"x": {"type": "integer", "maximum": 5}}}},
            "roles": {"r": {"allow": ["t"]}},
        }
    )
    assert "t" in ok.tools

    with pytest.raises(PolicyError, match="does not implement"):
        load_bundle({"version": "1", "requires": {"features": ["taint_labels"]}, "tools": {}, "roles": {}})


def test_unsupported_schema_version_is_refused():
    with pytest.raises(PolicyError, match="schema_version"):
        load_bundle({"version": "1", "schema_version": "histos.policy/99", "tools": {}, "roles": {}})


def test_every_declarable_feature_is_a_real_capability():
    """Guard against the feature registry drifting into marketing."""
    from histos import ENGINE_FEATURES

    assert "rbac" in ENGINE_FEATURES
    # Phase 0.2 checks are not built yet, so a policy must not be able to claim them.
    for unbuilt in ("url_egress_allowlist", "path_containment", "call_sequence_constraint", "cost_budget"):
        assert unbuilt not in ENGINE_FEATURES


def test_requires_does_not_change_the_policy_hash():
    """A compatibility assertion is not policy content — adding it must not
    invalidate pending approvals bound to the policy hash."""
    without = load_bundle({"version": "1", "tools": {"t": {"args": {}}}, "roles": {}})
    with_req = load_bundle(
        {"version": "1", "requires": {"features": ["rbac"]}, "tools": {"t": {"args": {}}}, "roles": {}}
    )
    assert without.content_hash() == with_req.content_hash()
