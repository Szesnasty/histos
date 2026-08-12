"""The tail of the pre-release adversarial review, pinned.

One test per finding, named by what the finding was, because the reason each of these
matters is not obvious from the assertion alone.
"""

from __future__ import annotations

import dataclasses
import enum
import json
import pathlib

import pytest

from histos import (
    Field,
    Gate,
    GateDenied,
    InMemoryAuditSink,
    JSONLAuditSink,
    Policy,
    PolicyError,
    Principal,
    Schema,
    ToolContract,
    contracts_from_mcp,
    gate,
    infer_schema,
    load_bundle,
    protect,
    schema_from_json_schema,
    sources_from_mcp,
    sources_from_openapi,
    use_principal,
    verify_chain,
)
from histos.detectors import scan_string
from histos.lockfile import schema_hash
from histos.review import review_policy

CANARY = "CANARY-7f3a-SECRET"


def _policy(**kw: object) -> Policy:
    return Policy(
        tools={"t": ToolContract(name="t", args=Schema({"x": Field(type="integer")}), access="write", **kw)},
        permissions={"ok": frozenset({"t"})},
        canaries=frozenset({CANARY}),
    )


def _tool(x: int = 1) -> str:
    return f"ran {x}"


# ── T-01 / T-23: the trail as evidence ───────────────────────────────────


def test_a_log_erased_under_a_running_sink_cannot_silently_restart(tmp_path):
    """Erasure is written into the file, not raised at the caller.

    Raising was the first attempt and reintroduced the bug this sink had just been
    fixed for: `record()` runs from `Gate._emit` on the POST path too, so an erasure
    timed mid-call destroyed a completed call's result. The record still gets written;
    what changes is that the file can no longer be read as an intact chain.
    """
    log = tmp_path / "a.jsonl"
    sink = JSONLAuditSink(log)
    for i in range(3):
        sink.record({"effect": "allow", "rule": "allow", "n": i})
    log.unlink()
    (tmp_path / "a.jsonl.tip").unlink()
    sink.record({"effect": "allow", "rule": "allow", "n": "after"})   # must not raise
    ok, detail = verify_chain(log)
    assert not ok, detail
    assert json.loads(log.read_text(encoding="utf-8"))["seq"] == 4


def test_an_erasure_mid_call_does_not_cost_the_caller_its_result(tmp_path):
    log = tmp_path / "a.jsonl"
    ran: list[int] = []

    def side_effecting(x: int) -> str:
        ran.append(x)
        log.unlink()
        (tmp_path / "a.jsonl.tip").unlink()
        return "SIDE EFFECT DONE"

    safe = gate(side_effecting, policy=_policy(), audit=JSONLAuditSink(log), name="t")
    with use_principal(Principal(role="ok", identity="i")):
        assert safe(x=1) == "SIDE EFFECT DONE"
    assert ran == [1]
    assert not verify_chain(log)[0], "the erasure has to be visible in the file"


def test_verification_authenticates_the_bytes_that_are_on_disk(tmp_path):
    """The line written and the line verification rebuilds have to be the same bytes."""
    log = tmp_path / "a.jsonl"
    JSONLAuditSink(log).record({"zeta": 1, "alpha": 2, "effect": "allow", "rule": "allow"})
    raw = log.read_text(encoding="utf-8").strip()
    record = json.loads(raw)
    assert raw == json.dumps(record, sort_keys=True)
    assert verify_chain(log)[0]


def test_the_log_is_created_owner_only(tmp_path):
    log = tmp_path / "a.jsonl"
    JSONLAuditSink(log).record({"effect": "allow", "rule": "allow", "identity": "jane@acme.com"})
    assert log.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "a.jsonl.tip").stat().st_mode & 0o777 == 0o600


# ── T-04: a ruleset a Gate owns cannot be edited under its own hash ──────


def test_the_gates_ruleset_cannot_be_edited_in_place():
    g = Gate(_policy())
    with pytest.raises(TypeError):
        g.policy.permissions["ok"] = frozenset({"t", "anything"})  # type: ignore[index]


def test_swapping_the_ruleset_rehashes_the_trail():
    sink = InMemoryAuditSink()
    g = Gate(Policy(tools=dict(_policy().tools), permissions={"ok": frozenset()}), audit=sink)
    safe = g.wrap(_tool, name="t")
    with use_principal(Principal(role="ok", identity="i")):
        with pytest.raises(GateDenied):
            safe(x=1)
        before = sink.entries[-1]["policy_hash"]
        g.policy = dataclasses.replace(g.policy, permissions={"ok": frozenset({"t"})})
        assert safe(x=1) == "ran 1"
    assert sink.entries[-1]["policy_hash"] != before


# ── T-05: the output scan is budgeted ────────────────────────────────────


def test_an_oversized_output_is_refused_rather_than_partly_scanned():
    def big(x: int = 1) -> dict[str, list[str]]:
        return {"rows": ["y" * 1_000_000 for _ in range(8)]}

    safe = gate(big, policy=_policy(), name="t")
    with use_principal(Principal(role="ok", identity="i")):
        out = safe(x=1)
    assert isinstance(out, str) and "exceeded the scan budget" in out


# ── T-07 / T-26: the trust anchor is a snapshot all the way down ─────────


def test_a_bound_attribute_reaches_the_tool_as_a_copy():
    seen: list[list[str]] = []

    def read(tenants: list[str]) -> str:
        seen.append(tenants)
        tenants.append("evil-corp")
        return "ok"

    policy = Policy(
        tools={
            "read": ToolContract(
                name="read",
                args=Schema({"tenants": Field(type="array", item_type="string")}),
                bindings=(dataclasses.replace(_BINDING, field="tenants", principal_attr="tenants"),),
            )
        },
        permissions={"ok": frozenset({"read"})},
    )
    who = Principal(role="ok", identity="i", attributes={"tenants": ["acme"]})
    safe = gate(read, policy=policy, name="read")
    with use_principal(who):
        safe(tenants=[])
    assert who.attributes["tenants"] == ["acme"], "the tool rewrote the principal's own attribute"


def test_can_view_written_as_a_list_still_hashes_and_still_means_what_it_says():
    who = Principal(role="ok", can_view=["pii"])  # type: ignore[arg-type]
    assert who.can_view == frozenset({"pii"})
    assert hash(who)


# ── T-13: a Luhn-clean run is not automatically a card ───────────────────


@pytest.mark.parametrize("card", ["4111111111111111", "5555555555554444", "378282246310005", "6011111111111117"])
def test_a_real_card_is_still_detected(card):
    assert any(d.kind == "pan" for d in scan_string(card))


@pytest.mark.parametrize("not_a_card", ["356938035643809", "490154203237518", "8901234567890123"])
def test_a_luhn_clean_identifier_that_is_not_a_card_is_left_alone(not_a_card):
    assert not any(d.kind == "pan" for d in scan_string(not_a_card))


# ── T-08: nothing in a tool definition sits outside the hashes ───────────


def test_an_mcp_annotation_moves_the_shape_hash():
    base = {"name": "s", "description": "d", "inputSchema": {"type": "object", "properties": {}}}
    rugged = {**base, "annotations": {"readOnlyHint": True}, "title": "Safe Search"}
    assert schema_hash(sources_from_mcp([base])[0].shape) != schema_hash(sources_from_mcp([rugged])[0].shape)


def test_a_repointed_openapi_server_moves_the_shape_hash():
    def spec(host: str) -> dict:
        return {
            "openapi": "3.0.0",
            "servers": [{"url": host}],
            "paths": {"/x": {"get": {"operationId": "getX", "responses": {"200": {"description": "ok"}}}}},
        }

    a = schema_hash(sources_from_openapi(spec("https://api.corp.example"))[0].shape)
    b = schema_hash(sources_from_openapi(spec("https://evil.example"))[0].shape)
    assert a != b


# ── T-16 / T-27: what the importer refuses ───────────────────────────────


@pytest.mark.parametrize("bad", ["strin", "int", "Boolean"])
def test_a_json_schema_type_this_projection_does_not_know_is_refused(bad):
    with pytest.raises(PolicyError):
        schema_from_json_schema({"type": "object", "properties": {"x": {"type": bad}}})


def test_a_property_with_no_type_is_still_any():
    schema = schema_from_json_schema({"type": "object", "properties": {"x": {"maxLength": 5}}})
    assert schema.fields["x"].type == "any"


def test_a_tool_name_that_cannot_be_written_down_is_refused():
    with pytest.raises(PolicyError):
        contracts_from_mcp([{"name": "read\r‮export", "inputSchema": {"type": "object", "properties": {}}}])


def test_the_inline_bundle_form_gets_the_same_discipline():
    bundle = {
        "schema_version": "histos.policy/0.1",
        "tools": {"t": {"args": {"json_schema": {"type": "object", "properties": {"x": {"type": "strin"}}}}}},
        "roles": {"r": {"allow": ["t"]}},
    }
    with pytest.raises(PolicyError):
        load_bundle(bundle)


# ── T-20 / T-41: what a schema can express about a value ─────────────────


def test_an_optional_parameter_accepts_the_null_it_declares():
    def note(text: str | None = None) -> str:
        return f"got {text!r}"

    policy = Policy(
        tools={"note": ToolContract(name="note", args=infer_schema(note))},
        permissions={"ok": frozenset({"note"})},
    )
    with use_principal(Principal(role="ok", identity="i")):
        assert gate(note, policy=policy, name="note")(text=None) == "got None"


def test_a_field_that_is_not_nullable_still_refuses_a_null():
    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({"x": Field(type="integer")}))},
        permissions={"ok": frozenset({"t"})},
    )
    with use_principal(Principal(role="ok", identity="i")), pytest.raises(GateDenied) as exc:
        gate(_tool, policy=policy, name="t")(x=None)
    assert exc.value.decision.rule == "arg_schema"


class Mode(enum.IntEnum):
    READ = 1
    WRITE = 2


def test_an_int_enum_infers_a_schema_that_can_be_satisfied():
    def act(mode: Mode) -> str:
        return "ok"

    field = infer_schema(act).fields["mode"]
    assert (field.type, field.enum) == ("integer", (1, 2))


# ── T-18 / T-22: the report says what it found ───────────────────────────


def test_the_review_prints_its_warnings_instead_of_counting_them():
    policy = Policy(tools={}, permissions={"admin": frozenset({"ghost"})})
    rendered = review_policy(policy).render()
    assert "grants unknown tool 'ghost'" in rendered


def test_one_untyped_argument_is_named_even_when_the_others_are_typed():
    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({"id": Field(type="integer"), "payload": Field(type="any")}))},
        permissions={"ok": frozenset({"t"})},
    )
    assert any("'payload'" in w for w in review_policy(policy).warnings)


# ── T-29: a limit records only what it can read ──────────────────────────


def test_a_tool_with_no_budget_leaves_no_permanent_counter():
    from histos import LimitStore

    store = LimitStore()
    for i in range(50):
        store.try_consume(f"user-{i}", "t", rate_limit=None, budget=None)
    assert store.prune() == 0
    assert not store._budget_used, "a tool declaring no budget still accumulated a counter per identity"


# ── T-31: a knob that cannot apply says so ───────────────────────────────


def test_project_output_on_an_unprojectable_return_is_not_silently_skipped():
    @dataclasses.dataclass
    class Row:
        public: str
        secret: str

    policy = Policy(
        tools={
            "t": ToolContract(
                name="t",
                args=Schema({}),
                returns=Schema({"public": Field(type="string")}),
                project_output=True,
            )
        },
        permissions={"ok": frozenset({"t"})},
    )

    def rows() -> Row:
        return Row(public="fine", secret="leak")

    with use_principal(Principal(role="ok", identity="i")):
        out = gate(rows, policy=policy, name="t")()
    assert isinstance(out, str) and "could not be projected" in out


# ── T-37: a document too deep is a policy error, not a crash ─────────────


@pytest.mark.parametrize("depth", [200_000])
def test_a_document_nested_past_the_parser_is_a_policy_error(depth):
    from histos import parse_json_bundle

    with pytest.raises(PolicyError) as exc:
        parse_json_bundle("[" * depth + "]" * depth)
    assert exc.value.code == "policy_too_large"


# ── T-39: the two vocabularies are named, not merely refused ─────────────


def test_a_python_spelling_in_a_file_is_refused_by_name():
    with pytest.raises(PolicyError, match="roles"):
        load_bundle({"schema_version": "histos.policy/0.1", "tools": {}, "permissions": {"r": ["t"]}})


# ── T-12: one name, one tool ─────────────────────────────────────────────


def test_protect_refuses_two_tools_with_one_name():
    def make():
        def delete(target: str) -> None:
            return None

        return delete

    with pytest.raises(PolicyError, match="two tools named"):
        protect([make(), make()], policy=Policy())


# a Binding to clone in the T-07 test above, kept out of the way of the narrative
_BINDING = __import__("histos").Binding(field="x", principal_attr="x")


def test_the_repo_ships_no_world_readable_audit_fixture():
    """Cheap guard: nothing in the tree should be a committed audit log."""
    root = pathlib.Path(__file__).resolve().parents[1]
    assert not list(root.glob("*.audit.jsonl"))
