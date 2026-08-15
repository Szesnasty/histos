"""Regressions from the final pre-release adversarial audit."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from histos import (
    ApprovalStore,
    Constraint,
    Field,
    Gate,
    GateConfirmationRequired,
    InMemoryAuditSink,
    Policy,
    PolicyError,
    Principal,
    Schema,
    ToolContract,
    load_bundle,
    parse_lock,
    sources_from_openapi,
)
from histos.trail.verify import verify_chain


def _bundle(tool: dict | None = None) -> dict:
    return {
        "version": "histos.policy/0.1",
        "tools": {"t": {"args": {}, **(tool or {})}},
        "roles": {"operator": {"allow": ["t"]}},
    }


@pytest.mark.parametrize("value", [None, [], "", False, 0])
@pytest.mark.parametrize("key", ["confirmation", "escalate", "output", "resource", "bind"])
def test_present_malformed_security_blocks_are_never_treated_as_absent(key, value):
    with pytest.raises(PolicyError):
        load_bundle(_bundle({key: value}))


@pytest.mark.parametrize("key", ["confirmation", "escalate"])
def test_switch_blocks_must_explicitly_declare_required(key):
    with pytest.raises(PolicyError, match="required"):
        load_bundle(_bundle({key: {}}))


@pytest.mark.parametrize("key", ["confirmation", "escalate"])
@pytest.mark.parametrize("value", [None, 0, 1, "false", [], {}])
def test_required_switch_is_an_exact_boolean(key, value):
    with pytest.raises(PolicyError, match="true or false"):
        load_bundle(_bundle({key: {"required": value}}))


@pytest.mark.parametrize("flag", ["scan_canary", "redact_secrets", "project", "strict"])
@pytest.mark.parametrize("value", [None, 0, 1, "false"])
def test_output_switches_are_exact_booleans(flag, value):
    with pytest.raises(PolicyError, match="true or false"):
        load_bundle(_bundle({"output": {flag: value}}))


@pytest.mark.parametrize("value", [None, 0, 1, "false"])
def test_argument_secret_switch_is_an_exact_boolean(value):
    with pytest.raises(PolicyError, match="true or false"):
        load_bundle(_bundle({"deny_secret_args": value}))


@pytest.mark.parametrize("key", ["tools", "roles"])
@pytest.mark.parametrize("value", [None, [], "", False, 0])
def test_present_malformed_top_level_maps_are_rejected(key, value):
    bundle = _bundle()
    bundle[key] = value
    with pytest.raises(PolicyError):
        load_bundle(bundle)


@pytest.mark.parametrize("value", [None, [], "", False, 0])
def test_present_malformed_role_body_is_rejected(value):
    bundle = _bundle()
    bundle["roles"] = {"operator": value}
    with pytest.raises(PolicyError):
        load_bundle(bundle)


@pytest.mark.parametrize("value", [None, [], "", False, 0])
def test_present_malformed_tool_body_is_rejected(value):
    bundle = _bundle()
    bundle["tools"] = {"t": value}
    with pytest.raises(PolicyError):
        load_bundle(bundle)


@pytest.mark.parametrize(
    ("section", "name"),
    [("tools", ""), ("tools", 1), ("tools", "has space"), ("roles", ""), ("roles", 1)],
)
def test_tool_and_role_names_are_non_empty_strings(section, name):
    bundle = _bundle()
    bundle[section] = {name: {}}
    with pytest.raises(PolicyError, match="name"):
        load_bundle(bundle)


@pytest.mark.parametrize("value", [None, "", False, 0, [], {}])
def test_role_inheritance_is_a_non_empty_role_name(value):
    bundle = _bundle()
    bundle["roles"] = {"operator": {"allow": ["t"], "inherits": value}}
    with pytest.raises(PolicyError, match="inherits"):
        load_bundle(bundle)


def test_non_string_unknown_bundle_key_is_a_policy_error_not_a_sort_crash():
    bundle = _bundle()
    bundle[1] = "unknown"
    with pytest.raises(PolicyError, match="unknown key"):
        load_bundle(bundle)


@pytest.mark.parametrize("key", ["schema_version", "requires"])
def test_present_null_compatibility_metadata_is_rejected(key):
    bundle = _bundle()
    bundle[key] = None
    with pytest.raises(PolicyError):
        load_bundle(bundle)


@pytest.mark.parametrize("value", [None, 0, False, [], {}])
@pytest.mark.parametrize("key", ["version", "policy_id", "created_at"])
def test_present_policy_metadata_is_an_exact_string(key, value):
    bundle = _bundle()
    bundle[key] = value
    with pytest.raises(PolicyError, match="string"):
        load_bundle(bundle)


@pytest.mark.parametrize("features", [[None], [0], [False], [[]], [{}], ["rbac", "rbac"]])
def test_required_feature_names_are_unique_strings(features):
    with pytest.raises(PolicyError):
        load_bundle({**_bundle(), "requires": {"features": features}})


@pytest.mark.parametrize("flag", ["required", "nullable", "unique_items"])
@pytest.mark.parametrize("value", [None, 0, 1, "false"])
def test_field_switches_are_exact_booleans(flag, value):
    with pytest.raises(PolicyError, match="true or false"):
        Field(**{flag: value})


def test_array_item_type_and_schema_switch_are_validated_in_python_api():
    with pytest.raises(PolicyError, match="item_type"):
        Field(type="array", item_type="not-a-type")
    with pytest.raises(PolicyError, match="allow_extra"):
        Schema({}, allow_extra=None)


@pytest.mark.parametrize(
    "flag",
    [
        "requires_confirmation",
        "requires_escalation",
        "scan_output_for_canary",
        "deny_secret_args",
        "redact_secret_output",
        "project_output",
        "strict_returns",
    ],
)
@pytest.mark.parametrize("value", [None, 0, 1, "false"])
def test_contract_switches_are_exact_booleans(flag, value):
    with pytest.raises(PolicyError, match="true or false"):
        ToolContract(name="t", args=Schema({}), **{flag: value})


def _confirmation_policy(window: int | None) -> Policy:
    return Policy(
        tools={
            "t": ToolContract(
                name="t",
                args=Schema({}),
                requires_confirmation=True,
                confirmation_expires_in=window,
            )
        },
        permissions={"operator": frozenset({"t"})},
    )


@pytest.mark.parametrize(
    ("store_window", "request_window", "after", "accepted"),
    [(None, 1, 2.0, False), (1, None, 100.0, True), (3600, 1, 2.0, False), (1, 3600, 2.0, True)],
)
def test_approval_uses_the_paused_requests_window_across_hot_reload(store_window, request_window, after, accepted):
    now = [0.0]
    store = ApprovalStore(_confirmation_policy(store_window), clock=lambda: now[0])
    gate = Gate(_confirmation_policy(store_window), confirm=store.as_confirm())
    safe = gate.wrap(lambda: "ran", name="t", fixed_principal=Principal(role="operator", identity="human"))

    gate.policy = _confirmation_policy(request_window)
    with pytest.raises(GateConfirmationRequired) as pending:
        safe()
    assert pending.value.request is not None
    assert pending.value.request.confirmation_expires_in == request_window

    store.grant(pending.value.request)
    now[0] = after
    if accepted:
        assert safe() == "ran"
    else:
        with pytest.raises(GateConfirmationRequired):
            safe()


def _simple_policy(name: str = "t") -> Policy:
    return Policy(
        tools={name: ToolContract(name=name, args=Schema({}))},
        permissions={"operator": frozenset({name})},
    )


def test_coverage_rejects_a_wrapper_from_a_different_gate():
    def t():
        return "ok"

    permissive = Gate(_simple_policy())
    strict = Gate(_simple_policy())
    wrapped_elsewhere = permissive.wrap(t, fixed_principal=Principal(role="operator"))
    assert strict.ungated_tools([wrapped_elsewhere]) == ["t"]


def test_explicit_wrap_name_is_the_exposed_name_and_must_match_framework_name():
    def delete():
        return "ok"

    gate = Gate(_simple_policy("read"))
    wrapped = gate.wrap(delete, name="read", fixed_principal=Principal(role="operator"))
    assert wrapped.__name__ == "read"
    assert gate.ungated_tools([wrapped]) == []

    published_under_wrong_name = SimpleNamespace(name="delete", func=wrapped, coroutine=None)
    assert gate.ungated_tools([published_under_wrong_name]) == ["delete"]


def test_sync_confirmation_cancellation_is_recorded_and_propagated():
    sink = InMemoryAuditSink()

    def cancel(_request):
        raise asyncio.CancelledError

    gate = Gate(_confirmation_policy(None), audit=sink, confirm=cancel)
    safe = gate.wrap(lambda: "must not run", name="t", fixed_principal=Principal(role="operator"))

    with pytest.raises(asyncio.CancelledError):
        safe()
    assert sink.entries[-1]["rule"] == "confirm_cancelled"
    assert sink.entries[-1]["executed"] is False


def test_sync_resource_resolver_cancellation_is_recorded_and_propagated():
    sink = InMemoryAuditSink()
    policy = Policy(
        tools={
            "t": ToolContract(
                name="t",
                args=Schema({}),
                constraints=(Constraint("tenant", "eq", value="acme"),),
            )
        },
        permissions={"operator": frozenset({"t"})},
    )

    def cancel(_tool, _args):
        raise asyncio.CancelledError

    gate = Gate(policy, audit=sink, resource_resolver=cancel)
    safe = gate.wrap(lambda: "must not run", name="t", fixed_principal=Principal(role="operator"))
    with pytest.raises(asyncio.CancelledError):
        safe()
    assert sink.entries[-1]["rule"] == "pre_cancelled"
    assert sink.entries[-1]["executed"] is False


def test_async_escalation_cancellation_is_recorded_and_propagated():
    sink = InMemoryAuditSink()
    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({}), requires_escalation=True)},
        permissions={"operator": frozenset({"t"})},
    )

    async def cancel(_request):
        raise asyncio.CancelledError

    async def tool():
        return "must not run"

    gate = Gate(policy, audit=sink, escalate=cancel)
    safe = gate.wrap(tool, name="t", fixed_principal=Principal(role="operator"))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(safe())
    assert sink.entries[-1]["rule"] == "pre_cancelled"
    assert sink.entries[-1]["executed"] is False


@pytest.mark.parametrize("value", [None, 0, 1, "false", [], {}])
def test_openapi_parameter_required_is_an_exact_boolean(value):
    spec = {
        "paths": {
            "/search": {
                "get": {
                    "operationId": "search",
                    "parameters": [{"name": "q", "in": "query", "required": value, "schema": {"type": "string"}}],
                }
            }
        }
    }
    with pytest.raises(PolicyError, match="boolean"):
        sources_from_openapi(spec)


@pytest.mark.parametrize("value", [None, [], "", False, 0])
def test_openapi_present_malformed_request_content_is_rejected(value):
    spec = {"paths": {"/write": {"post": {"operationId": "write", "requestBody": {"content": value}}}}}
    with pytest.raises(PolicyError, match="content"):
        sources_from_openapi(spec)


def _valid_v2_lock() -> dict:
    digest = "sha256:" + "0" * 64
    return {
        "lock_version": 2,
        "policy": "security.policy.json",
        "tools": {
            "t": {
                "source": {"kind": "mcp", "locator": "mcp://tools"},
                "schema_sha256": digest,
                "description_sha256": digest,
                "contract_sha256": digest,
                "reviewed": {"shape": {}, "description": None},
            }
        },
    }


@pytest.mark.parametrize("value", [None, [], "", False, 0])
def test_lock_tools_map_is_required_and_must_be_an_object(value):
    lock = _valid_v2_lock()
    lock["tools"] = value
    with pytest.raises(PolicyError):
        parse_lock(lock)


@pytest.mark.parametrize("field", ["source", "schema_sha256", "description_sha256", "contract_sha256", "reviewed"])
def test_version_two_lock_entry_requires_every_evidence_field(field):
    lock = _valid_v2_lock()
    del lock["tools"]["t"][field]
    with pytest.raises(PolicyError, match="required"):
        parse_lock(lock)


@pytest.mark.parametrize("value", [None, "", "sha256:xyz", "sha256:" + "A" * 64])
def test_lock_digest_has_the_normative_shape(value):
    lock = _valid_v2_lock()
    lock["tools"]["t"]["schema_sha256"] = value
    with pytest.raises(PolicyError, match="sha256"):
        parse_lock(lock)


@pytest.mark.parametrize("value", [None, "shape", {}, [None], ["unknown"]])
def test_lock_reviewed_elision_is_a_typed_list(value):
    lock = _valid_v2_lock()
    lock["tools"]["t"]["reviewed"]["elided"] = value
    with pytest.raises(PolicyError, match="elided"):
        parse_lock(lock)


@pytest.mark.parametrize("document", [b'"hash"\n', b"[]\n", b"null\n"])
def test_audit_verifier_rejects_non_object_json_without_crashing(tmp_path, document):
    log = tmp_path / "audit.jsonl"
    log.write_bytes(document)
    ok, detail = verify_chain(log)
    assert not ok
    assert "expected an object" in detail


def test_audit_verifier_handles_invalid_utf8_and_non_file(tmp_path):
    invalid = tmp_path / "invalid.jsonl"
    invalid.write_bytes(b"\xff\n")
    ok, detail = verify_chain(invalid)
    assert not ok
    assert "unreadable" in detail

    ok, detail = verify_chain(tmp_path)
    assert not ok
    assert "unreadable" in detail
