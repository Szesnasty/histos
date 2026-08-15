"""Regressions from the final pre-release adversarial audit."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from histos import (
    ApprovalStore,
    Binding,
    Constraint,
    ContentRules,
    Effect,
    Field,
    Gate,
    GateConfirmationRequired,
    GateRequest,
    InMemoryAuditSink,
    JSONLAuditSink,
    LimitStore,
    Policy,
    PolicyError,
    Principal,
    Schema,
    ToolContract,
    ToolSource,
    build_lock,
    dump_bundle,
    load_bundle,
    merge_contracts,
    parse_lock,
    review_policy,
    schema_hash,
    sources_from_mcp,
    sources_from_openai,
    sources_from_openapi,
)
from histos.provenance.lockfile import Reviewed
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


@pytest.mark.parametrize("verdict", ["denied", {"approved": False}, 1, [0], None])
def test_escalation_only_exact_true_can_release_a_call(verdict):
    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({}), requires_escalation=True)},
        permissions={"operator": {"t"}},
    )
    decision = Gate(policy, escalate=lambda _request: verdict).engine.pre(
        GateRequest("t", {}, Principal(role="operator"))
    )
    assert decision.effect is Effect.DENY
    assert decision.rule == "escalation_error"
    assert decision.escalate is True


def test_false_is_a_real_semantic_refusal_and_true_is_the_only_release():
    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({}), requires_escalation=True)},
        permissions={"operator": {"t"}},
    )
    request = GateRequest("t", {}, Principal(role="operator"))
    assert Gate(policy, escalate=lambda _request: False).engine.pre(request).rule == "escalation_denied"
    assert Gate(policy, escalate=lambda _request: True).engine.pre(request).rule == "escalated"


@pytest.mark.parametrize("value", [[], {}])
def test_unhashable_field_types_are_policy_errors(value):
    with pytest.raises(PolicyError, match="field type"):
        Field(type=value)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"enum": "ab"}, "list or tuple"),
        ({"enum": {"a", "b"}}, "list or tuple"),
        ({"item_enum": "ab", "type": "array"}, "list or tuple"),
        ({"enum": ()}, "at least one"),
        ({"enum": (object(),)}, "cannot be hashed reproducibly"),
        ({"enum": (b"bytes",)}, "JSON values"),
        ({"enum": ({1: "value"},)}, "keys must be strings"),
    ],
)
def test_python_enum_literals_are_portable_and_deterministic(kwargs, match):
    with pytest.raises(PolicyError, match=match):
        Field(**kwargs)


def test_a_cyclic_enum_literal_is_rejected_before_policy_hashing():
    cycle = []
    cycle.append(cycle)
    with pytest.raises(PolicyError, match="reference cycle"):
        Field(enum=(cycle,))


def test_list_and_tuple_enum_literals_cannot_enforce_differently_behind_one_hash():
    as_list = Field(type="array", enum=([1],))
    as_tuple = Field(type="array", enum=((1,),))
    assert as_list.enum == as_tuple.enum == ([1],)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {1: "value"}, b"bytes"])
def test_constraint_literals_that_cannot_survive_the_policy_format_are_rejected(value):
    with pytest.raises(PolicyError):
        Constraint("status", "eq", value=value)


def test_a_cyclic_constraint_literal_is_a_policy_error_not_recursion_error():
    cycle = []
    cycle.append(cycle)
    with pytest.raises(PolicyError, match="reference cycle"):
        Constraint("status", "eq", value=cycle)


def test_list_and_tuple_constraint_literals_enforce_identically_behind_one_hash():
    def policy(value):
        return Policy(
            tools={
                "t": ToolContract(
                    "t",
                    Schema({}),
                    constraints=(Constraint("tags", "eq", value=value),),
                )
            },
            permissions={"r": {"t"}},
        )

    left, right = policy(["safe"]), policy(("safe",))
    assert left.content_hash() == right.content_hash()
    principal = Principal(role="r")
    assert left.tools["t"].constraints[0].evaluate({"tags": ["safe"]}, principal).ok
    assert right.tools["t"].constraints[0].evaluate({"tags": ["safe"]}, principal).ok


def test_set_constraint_literal_has_a_stable_portable_round_trip():
    policy = Policy(
        tools={
            "t": ToolContract(
                "t",
                Schema({}),
                constraints=(Constraint("status", "in", value={"new", "open"}),),
            )
        },
        permissions={"r": {"t"}},
    )
    assert load_bundle(dump_bundle(policy)).content_hash() == policy.content_hash()


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (lambda: Schema([]), "mapping"),
        (lambda: Schema({1: Field()}), "field name"),
        (lambda: Schema({"x": {"type": "string"}}), "must be a Field"),
        (lambda: Constraint(1, "eq", value="x"), "constraint field"),
        (lambda: Constraint("x", [], value="x"), "constraint op"),
        (lambda: Binding(1, "tenant"), "binding field"),
        (lambda: Binding("tenant", []), "principal_attr"),
        (lambda: ToolContract("", Schema({})), "contract name"),
        (lambda: ToolContract("t", {}), "args must be a Schema"),
        (lambda: ToolContract("t", Schema({}), constraints=(object(),)), "Constraint"),
        (lambda: Policy(tools=[]), "tools must be a mapping"),
        (
            lambda: Policy(tools={"t": ToolContract("other", Schema({}))}),
            "disagrees with its contract name",
        ),
        (lambda: Policy(permissions={1: {"t"}}), "role name"),
        (lambda: Policy(permissions={"r": {1}}), "non-empty tool names"),
        (lambda: Policy(schema_version="histos.policy/99"), "not supported"),
        (lambda: Principal(role=1), "principal role"),
        (lambda: Principal(role="r", identity=1), "principal identity"),
        (lambda: Principal(role="r", attributes=[]), "attributes must be a mapping"),
        (lambda: Principal(role="r", attributes={1: "x"}), "attribute name"),
        (lambda: Principal(role="r", can_view=None), "can_view"),
        (lambda: Principal(role="r", can_view=[1]), "can_view"),
    ],
)
def test_python_policy_graph_rejects_malformed_nodes_at_construction(factory, match):
    with pytest.raises(PolicyError, match=match):
        factory()


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"strict": "false"}, "strict"),
        ({"confirm_suspends": [RuntimeError]}, "confirm_suspends"),
        ({"confirm_suspends": ("RuntimeError",)}, "confirm_suspends"),
        ({"audit_key": "secret"}, "audit_key"),
        ({"audit_key": b""}, "audit_key"),
        ({"confirm": True}, "confirm must be callable"),
        ({"resource_resolver": {}}, "resource_resolver must be callable"),
        ({"escalate": "tier"}, "escalate must be callable"),
    ],
)
def test_gate_configuration_switches_and_callbacks_fail_loud_at_wiring_time(kwargs, match):
    with pytest.raises(PolicyError, match=match):
        Gate(_simple_policy(), **kwargs)


def test_wrap_and_protect_configuration_values_are_exact():
    def t():
        return "ok"

    gate = Gate(_simple_policy())
    with pytest.raises(PolicyError, match="wrap name"):
        gate.wrap(t, name="")
    with pytest.raises(PolicyError, match="is_async"):
        gate.wrap(t, is_async="false")
    with pytest.raises(PolicyError, match="fixed_principal"):
        gate.wrap(t, fixed_principal={})
    with pytest.raises(PolicyError, match="infer_missing"):
        gate.protect([t], infer_missing="false")


@pytest.mark.parametrize("kind", [[], {}])
def test_unhashable_lock_source_kind_is_a_policy_error(kind):
    lock = _valid_v2_lock()
    lock["tools"]["t"]["source"]["kind"] = kind
    with pytest.raises(PolicyError, match="source.kind"):
        parse_lock(lock)


def test_tool_source_and_lock_review_evidence_are_snapshots():
    shape = {"input": {"type": "object", "properties": {"q": {"type": "string"}}}}
    source = ToolSource(
        name="t",
        kind="mcp",
        description=None,
        shape=shape,
        contract=ToolContract(name="t", args=Schema({})),
    )
    lock = build_lock([source], policy="security.policy.json", locator="mcp://tools")

    shape["input"]["properties"]["q"]["type"] = "integer"
    assert source.shape["input"]["properties"]["q"]["type"] == "string"
    assert lock.tools["t"].reviewed.shape["input"]["properties"]["q"]["type"] == "string"
    with pytest.raises(TypeError, match="read-only"):
        lock.tools.clear()
    with pytest.raises(TypeError, match="read-only"):
        lock.tools["t"].reviewed.shape["input"]["properties"]["q"]["type"] = "number"


def test_reviewed_shape_does_not_alias_the_parsed_lock_document():
    shape = {"method": "get", "path": "/before"}
    reviewed = Reviewed(shape=shape)
    shape["path"] = "/after"
    assert reviewed.shape == {"method": "get", "path": "/before"}


@pytest.mark.parametrize("schema", [None, "string", [], False, 1])
def test_openapi_present_malformed_parameter_schema_is_rejected(schema):
    spec = {
        "paths": {
            "/search": {
                "get": {
                    "operationId": "search",
                    "parameters": [{"name": "q", "in": "query", "schema": schema}],
                }
            }
        }
    }
    with pytest.raises(PolicyError, match="schema of parameter"):
        sources_from_openapi(spec)


@pytest.mark.parametrize("content", [None, "json", [], False, 1, {}])
def test_openapi_present_malformed_parameter_content_is_rejected(content):
    spec = {
        "paths": {
            "/search": {
                "get": {
                    "operationId": "search",
                    "parameters": [{"name": "q", "in": "query", "content": content}],
                }
            }
        }
    }
    with pytest.raises(PolicyError, match="content of parameter"):
        sources_from_openapi(spec)


@pytest.mark.parametrize("name", [None, 1, [], {}])
def test_openapi_parameter_name_is_a_non_empty_string(name):
    spec = {
        "paths": {
            "/search": {
                "get": {
                    "operationId": "search",
                    "parameters": [{"name": name, "in": "query", "schema": {"type": "string"}}],
                }
            }
        }
    }
    with pytest.raises(PolicyError, match="name"):
        sources_from_openapi(spec)


@pytest.mark.parametrize("location", [None, 1, [], {}, "body"])
def test_openapi_parameter_location_is_a_known_string(location):
    spec = {
        "paths": {
            "/search": {
                "get": {
                    "operationId": "search",
                    "parameters": [{"name": "q", "in": location, "schema": {"type": "string"}}],
                }
            }
        }
    }
    with pytest.raises(PolicyError, match="`in` value"):
        sources_from_openapi(spec)


def test_openapi_document_and_path_shapes_fail_with_controlled_diagnostics():
    with pytest.raises(PolicyError, match="OpenAPI document"):
        sources_from_openapi([])
    with pytest.raises(PolicyError, match="path string"):
        sources_from_openapi({"paths": {1: {"get": {}}}})
    with pytest.raises(PolicyError, match="path parameters are always required"):
        sources_from_openapi(
            {
                "paths": {
                    "/items/{item_id}": {
                        "get": {
                            "parameters": [
                                {"name": "item_id", "in": "path", "required": False, "schema": {"type": "string"}}
                            ]
                        }
                    }
                }
            }
        )


def test_openapi_request_body_required_is_an_exact_boolean():
    spec = {
        "paths": {
            "/write": {
                "post": {
                    "requestBody": {
                        "required": "false",
                        "content": {"application/json": {"schema": {"type": "object"}}},
                    }
                }
            }
        }
    }
    with pytest.raises(PolicyError, match="required on requestBody"):
        sources_from_openapi(spec)


@pytest.mark.parametrize("window", [0, -1, True, float("nan"), float("inf"), "60"])
def test_rate_window_cannot_silently_disable_a_declared_limit(window):
    with pytest.raises(PolicyError, match="positive finite"):
        LimitStore(window_seconds=window)


def test_injected_clock_must_keep_returning_finite_numbers():
    now = [1.0]
    limits = LimitStore(time_fn=lambda: now[0])
    limits.consume("alice", "t", rate_limit=1, budget=None)
    now[0] = float("nan")
    with pytest.raises(PolicyError, match="finite number"):
        limits.check("alice", "t", rate_limit=1, budget=None)


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "100"])
def test_in_memory_audit_capacity_cannot_discard_every_record_by_configuration(value):
    with pytest.raises(ValueError, match="positive integer or None"):
        InMemoryAuditSink(maxlen=value)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"hash_chain": "true"},
        {"key": b""},
        {"key": "secret"},
        {"hash_chain": False, "key": b"secret"},
        {"mode": True},
        {"mode": -1},
        {"mode": 0o10000},
        {"strict": "false"},
    ],
)
def test_jsonl_audit_security_configuration_is_unambiguous(tmp_path, kwargs):
    with pytest.raises(ValueError):
        JSONLAuditSink(tmp_path / "audit.jsonl", **kwargs)


@pytest.mark.parametrize("flag", ["check_injection", "check_exfiltration"])
@pytest.mark.parametrize("value", [None, 0, 1, "false"])
def test_content_rule_switches_are_exact_booleans(flag, value):
    with pytest.raises(PolicyError, match=flag):
        ContentRules(**{flag: value})


def test_import_refuses_duplicate_tool_names_instead_of_using_list_order():
    spec = {
        "paths": {
            "/first": {"get": {"operationId": "same"}},
            "/second": {"post": {"operationId": "same"}},
        }
    }
    with pytest.raises(PolicyError, match="more than once"):
        sources_from_openapi(spec)


def test_duplicate_identity_is_refused_even_when_one_definition_is_unprojectable():
    source = [
        {"name": "same", "inputSchema": {"type": "object"}},
        {"name": "same", "inputSchema": {"type": "object", "properties": {"x": {"maxItems": 2}}}},
    ]
    with pytest.raises(PolicyError, match="ambiguous even when one definition cannot be projected"):
        sources_from_mcp(source)


def test_merge_refuses_duplicate_contract_names_instead_of_last_one_winning():
    policy = Policy(permissions={"r": set()})
    first = ToolContract("same", Schema({"a": Field()}))
    second = ToolContract("same", Schema({"b": Field()}))
    with pytest.raises(PolicyError, match="order-dependent merge"):
        merge_contracts(policy, [first, second])


def test_lock_builder_refuses_duplicate_sources_instead_of_erasing_evidence():
    source = ToolSource(
        name="same",
        kind="mcp",
        description=None,
        shape={"input": {"type": "object"}},
        contract=ToolContract("same", Schema({})),
    )
    with pytest.raises(PolicyError, match="duplicate tool name"):
        build_lock([source, source], policy="security.policy.json", locator="mcp://tools")


@pytest.mark.parametrize("field", ["inputSchema", "outputSchema"])
@pytest.mark.parametrize("value", [None, False, [], "schema"])
def test_mcp_present_malformed_schemas_are_not_recorded_as_absent(field, value):
    with pytest.raises(PolicyError, match="no tool"):
        sources_from_mcp([{"name": "t", field: value}])


@pytest.mark.parametrize("value", [False, [], {}])
def test_importers_do_not_erase_present_malformed_descriptions(value):
    with pytest.raises(PolicyError, match="no tool"):
        sources_from_mcp([{"name": "t", "description": value}])
    with pytest.raises(PolicyError, match="no tool"):
        sources_from_openai([{"name": "t", "description": value}])
    with pytest.raises(PolicyError, match="no tool"):
        sources_from_openapi({"paths": {"/x": {"get": {"operationId": "t", "description": value}}}})


@pytest.mark.parametrize("value", [None, False, [], "schema"])
def test_openai_present_malformed_parameters_are_not_recorded_as_absent(value):
    with pytest.raises(PolicyError, match="no tool"):
        sources_from_openai([{"name": "t", "parameters": value}])


@pytest.mark.parametrize("value", [None, False, [], "function"])
def test_openai_present_malformed_function_wrapper_is_refused(value):
    with pytest.raises(PolicyError, match="no tool"):
        sources_from_openai([{"type": "function", "function": value}])


@pytest.mark.parametrize("value", [None, "", False, 0, [], {}])
def test_openapi_present_invalid_operation_id_is_not_silently_replaced(value):
    with pytest.raises(PolicyError, match="no tool"):
        sources_from_openapi({"paths": {"/x": {"get": {"operationId": value}}}})


def test_openai_non_projected_source_fields_move_the_shape_hash():
    base = {
        "type": "function",
        "function": {"name": "t", "parameters": {"type": "object"}, "strict": True},
    }
    changed = {
        "type": "function",
        "function": {"name": "t", "parameters": {"type": "object"}, "strict": False},
    }
    assert schema_hash(sources_from_openai([base])[0].shape) != schema_hash(sources_from_openai([changed])[0].shape)


def test_approval_clock_cannot_disable_expiry_by_becoming_invalid_or_moving_backwards():
    clock = [10.0]
    store = ApprovalStore(None, clock=lambda: clock[0])
    store.grant("fingerprint")
    clock[0] = float("nan")
    with pytest.raises(PolicyError, match="finite number"):
        store.grant("another")

    clock[0] = 9.0
    with pytest.raises(PolicyError, match="moved backwards"):
        store.grant("another")


def test_review_includes_a_role_declared_only_as_an_inheritance_child():
    policy = Policy(
        tools={"t": ToolContract("t", Schema({}), returns=Schema({}))},
        permissions={"parent": {"t"}},
        role_inherits={"child": "parent"},
    )
    review = review_policy(policy)
    assert review.roles_discovered == 2
    assert review.callable_by["t"] == ["child", "parent"]
    assert review.unreachable == []


def test_openapi_explicit_empty_servers_does_not_fall_back_to_a_parent_endpoint():
    inherited = {
        "servers": [{"url": "https://parent.example"}],
        "paths": {"/x": {"get": {"operationId": "t"}}},
    }
    explicit = {
        "servers": [{"url": "https://parent.example"}],
        "paths": {"/x": {"get": {"operationId": "t", "servers": []}}},
    }
    assert sources_from_openapi(inherited)[0].shape["servers"] == [{"url": "https://parent.example"}]
    assert sources_from_openapi(explicit)[0].shape["servers"] == []


@pytest.mark.parametrize("servers", [None, False, {}, "https://example", [None], [{"url": ""}]])
def test_openapi_present_malformed_server_configuration_is_refused(servers):
    with pytest.raises(PolicyError, match="no tool"):
        sources_from_openapi({"paths": {"/x": {"get": {"operationId": "t", "servers": servers}}}})
