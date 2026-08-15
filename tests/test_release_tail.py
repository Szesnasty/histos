"""The tail of the pre-release adversarial review, pinned.

One test per finding, named by what the finding was, because the reason each of these
matters is not obvious from the assertion alone.
"""

from __future__ import annotations

import collections
import dataclasses
import datetime
import decimal
import enum
import hashlib
import hmac
import json
import os
import pathlib
import typing
import uuid

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
    ToolErrorRedacted,
    contracts_from_mcp,
    contracts_from_openapi,
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
from histos.contracts import Effect, GateRequest
from histos.detectors import scan_string
from histos.lockfile import schema_hash
from histos.logpath import tip_path_for
from histos.review import review_policy

CANARY = "CANARY-7f3a-SECRET"


def _policy(**kw: object) -> Policy:
    return Policy(
        tools={"t": ToolContract(name="t", args=Schema({"x": Field(type="integer")}), access="write", **kw)},
        permissions={"ok": frozenset({"t"})},
        canaries=frozenset({CANARY}),
    )


def _no_args_policy() -> Policy:
    return Policy(
        tools={"t": ToolContract(name="t", args=Schema({}), access="read")},
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
    sink.record({"effect": "allow", "rule": "allow", "n": "after"})  # must not raise
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


# Windows has no POSIX mode bits to set: `os.chmod` there moves the read-only flag and
# nothing else, so a file asked for as 0o600 reports 0o666. SECURITY.md says the
# owner-only default is a POSIX guarantee, and this is the test that says so too.
@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits; Windows has no equivalent")
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
    """The old assertion held whenever the tool did not get the principal's own list —
    including when the binding never ran at all, so it passed with the `bind` removed.
    It has to check that the binding *did* happen and that the anchor survived it."""
    seen: list[list[str]] = []

    def read(tenants: list[str]) -> str:
        seen.append(list(tenants))  # snapshot before mutating the very object under test
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
    assert seen == [["acme"]], "the binding did not overwrite the argument"
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


def test_project_output_on_a_dataclass_return_drops_the_undeclared_field():
    """A dataclass publishes its field names, so the projector reads them.

    This used to be answered twice, both wrong. First the dataclass was walked past
    untouched and `secret` egressed with `redactions: []` — indistinguishable from
    nothing-to-drop. Then it was refused whole, which stopped the leak and took every
    correctly declared return down with it. Reading the names is what the knob promises
    and the only answer that neither leaks nor refuses.
    """

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

    sink = InMemoryAuditSink()
    with use_principal(Principal(role="ok", identity="i")):
        out = gate(rows, policy=policy, audit=sink, name="t")()
    assert out == {"public": "fine"}, "the declared field did not survive projection"
    assert "leak" not in repr(out)
    assert "drop:secret" in sink.entries[-1]["redactions"]


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


# ── the review of the hardening diff: engine.py ──────────────────────────


def test_the_scan_budget_gates_every_pass_not_only_the_canary_one():
    """It sat inside the canary branch, so the secret detectors — the slowest pass by an
    order of magnitude — read a 63 MB return in full whenever canaries were off."""
    import time

    def big() -> dict:
        return {"rows": ["y" * 1_000_000 for _ in range(8)]}

    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({}), redact_secret_output=True)},
        permissions={"ok": frozenset({"t"})},
    )
    with use_principal(Principal(role="ok", identity="i")):
        started = time.perf_counter()
        out = gate(big, policy=policy, name="t")()
    assert isinstance(out, str) and "scan budget" in out
    assert time.perf_counter() - started < 0.5


# `allow` used to be in this table and returned the payload untouched. It is not a
# choice the policy gets to make any more: `on_output_violation` is malformed-output
# policy, hosts set `allow` because a vendor's response *shape* drifts, and reusing it
# for the size question meant those hosts had silently also switched off canary and
# secret redaction for every oversized return — measured egressing a planted canary and
# an AWS key under an ALLOW record. Over budget is now deny or redact-all; a host that
# legitimately returns more raises the budget, which is the test below.
@pytest.mark.parametrize(
    ("action", "expect"),
    [("deny", "denied"), ("allow", "redacted"), ("redact_all", "redacted")],
)
def test_the_over_budget_action_is_the_policy_s_to_choose(action, expect):
    def big() -> dict:
        return {"rows": ["y" * 1_000_000 for _ in range(8)]}

    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({}), on_output_violation=action)},
        permissions={"ok": frozenset({"t"})},
    )
    with use_principal(Principal(role="ok", identity="i")):
        try:
            out = Gate(policy).wrap(big, name="t")()
        except GateDenied:
            assert expect == "denied"
            return
    assert expect == ("returned" if isinstance(out, dict) else "redacted")


def test_over_budget_never_switches_off_the_output_controls():
    """The regression in its own right, not as a row in a table: a canary planted in an
    oversized return must not reach the caller whatever `on_output_violation` says."""
    canary = "CANARY-7f3a-SECRET"

    def big() -> dict:
        return {"rows": ["y" * 1_000_000 for _ in range(8)], "leak": canary}

    for action in ("allow", "redact_all"):
        policy = Policy(
            tools={"t": ToolContract(name="t", args=Schema({}), on_output_violation=action)},
            permissions={"ok": frozenset({"t"})},
            canaries=frozenset({canary}),
        )
        with use_principal(Principal(role="ok", identity="i")):
            out = Gate(policy).wrap(big, name="t")()
        assert canary not in repr(out), f"the canary egressed under on_output_violation={action!r}"


def test_a_host_can_raise_the_output_budget():
    def big() -> dict:
        return {"rows": ["y" * 1_000_000 for _ in range(8)]}

    policy = Policy(tools={"t": ToolContract(name="t", args=Schema({}))}, permissions={"ok": frozenset({"t"})})
    with use_principal(Principal(role="ok", identity="i")):
        assert isinstance(Gate(policy, output_budget=16_000_000).wrap(big, name="t")(), dict)


def test_an_error_raised_from_None_is_left_alone():
    """`raise X from None` is how a driver error is deliberately hidden; CPython prints
    none of it, so there is nothing there for the caller to read and nothing to redact.
    Walking into it swapped the caller's exception type over a leak that never happened."""

    def boom() -> str:
        try:
            raise ValueError(f"driver said {CANARY}")
        except ValueError:
            raise RuntimeError("repository error") from None

    with use_principal(Principal(role="ok", identity="i")), pytest.raises(RuntimeError) as exc:
        gate(boom, policy=_no_args_policy(), name="t")()
    assert type(exc.value) is RuntimeError
    assert CANARY not in str(exc.value)


def test_a_chain_longer_than_the_bound_is_dropped_rather_than_reported_clean():
    def boom() -> str:
        error: BaseException = RuntimeError(f"innermost {CANARY}")
        for i in range(25):
            wrapper = RuntimeError(f"layer {i}")
            wrapper.__cause__ = error
            error = wrapper
        raise error

    with use_principal(Principal(role="ok", identity="i")), pytest.raises(ToolErrorRedacted) as exc:
        gate(boom, policy=_no_args_policy(), name="t")()
    assert CANARY not in str(exc.value)


def test_a_namedtuple_return_is_projected_field_by_field():
    """It is a tuple, so it passed the guard, and the projector then rebuilt it and
    dropped nothing — the exact outcome the guard was written to prevent. A NamedTuple
    publishes `_fields`, so the names are readable and the undeclared one goes."""
    from typing import NamedTuple

    class Row(NamedTuple):
        public: str
        secret: str

    policy = Policy(
        tools={
            "t": ToolContract(
                name="t", args=Schema({}), returns=Schema({"public": Field(type="string")}), project_output=True
            )
        },
        permissions={"ok": frozenset({"t"})},
    )
    with use_principal(Principal(role="ok", identity="i")):
        out = gate(lambda: Row("fine", "leak"), policy=policy, name="t")()  # noqa: E731
    assert out == {"public": "fine"} and "leak" not in repr(out)


def test_a_value_the_projector_could_not_enter_is_named_in_the_record():
    """ "Nothing undeclared to drop" and "something nobody could look inside" used to
    produce the same audit line.

    The example has to be a value whose state is genuinely unreachable — slots only, no
    instance `__dict__`, not a dataclass, not a NamedTuple. A dataclass used to stand
    here and no longer belongs: the projector reads those now.
    """

    class Opaque:
        __slots__ = ("secret",)

        def __init__(self, secret: str) -> None:
            self.secret = secret

    sink = InMemoryAuditSink()
    policy = Policy(
        tools={
            "t": ToolContract(
                name="t", args=Schema({}), returns=Schema({"public": Field(type="string")}), project_output=True
            )
        },
        permissions={"ok": frozenset({"t"})},
    )
    with use_principal(Principal(role="ok", identity="i")):
        gate(lambda: {"public": Opaque("leak")}, policy=policy, audit=sink, name="t")()  # noqa: E731
    assert "output:uninspectable:Opaque" in sink.entries[-1]["redactions"]


def test_an_ordinary_scalar_value_does_not_take_the_whole_output_down():
    """The P0 the previous answer to the line above opened.

    Routing every uninspectable value through `on_output_violation` (default:
    redact_all) was written for the record that hides a field. It was applied to
    everything outside `str/bytes/int/float/bool/None`, so a declared field holding a
    `datetime` — no undeclared field within a mile of it — replaced the entire tool
    output with a redaction string. Naming it in the trail is the whole of the honest
    answer for a *value*; refusing records is `strict_returns`' job.
    """
    policy = Policy(
        tools={
            "t": ToolContract(
                name="t", args=Schema({}), returns=Schema({"when": Field(type="string")}), project_output=True
            )
        },
        permissions={"ok": frozenset({"t"})},
    )
    for value in (
        datetime.datetime(2026, 1, 1, 12, 0),
        datetime.date(2026, 1, 1),
        decimal.Decimal("12.30"),
        uuid.UUID("12345678-1234-5678-1234-567812345678"),
        pathlib.PurePosixPath("/tmp/x"),
    ):
        with use_principal(Principal(role="ok", identity="i")):
            out = gate(lambda _v=value: {"when": _v}, policy=policy, name="t")()
        assert out == {"when": value}, f"a declared field holding a {type(value).__name__} was redacted away"


# ── the review of the hardening diff: audit.py ───────────────────────────


def test_a_rewrite_that_parses_the_same_but_reads_differently_is_caught(tmp_path):
    """A digest over the parsed record says nothing about the bytes a reader sees. A
    repeated key is the sharp case: `json.loads` keeps the last, a human greps the
    first, so the record verified as `allow` while the file said `deny`."""
    log = tmp_path / "a.jsonl"
    JSONLAuditSink(log).record({"effect": "deny", "rule": "rbac", "n": 1})
    raw = log.read_text(encoding="utf-8").strip()
    log.write_text('{"effect": "deny", ' + raw[1:] + "\n", encoding="utf-8")
    ok, detail = verify_chain(log)
    assert not ok and "repeats the key" in detail


def _write_legacy_tip(log, key: bytes, count: int, tip: str) -> None:
    """The sidecar the writer of that era produced, so verification reaches the line
    check instead of stopping at a missing tip."""
    from histos.audit import _tip_body
    from histos.logpath import tip_path_for

    body = _tip_body(count, tip)
    mac = hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest()
    tip_path_for(log).write_text(json.dumps({"records": count, "hash": tip, "mac": mac}), encoding="utf-8")


def test_an_untouched_pre_release_log_is_not_accused_of_being_rewritten(tmp_path):
    """The byte check used to demand today's exact spelling, exempting a legacy line on
    the theory that its canonical form is a different spelling by construction. That
    holds only for a record with a non-ASCII field. For an ordinary ASCII record the two
    bodies are identical, so the exemption never fired and `histos audit verify` told
    the operator their untouched log had been rewritten — a false accusation about
    evidence, which is worse than the rewrite it was looking for."""
    log = tmp_path / "legacy.jsonl"
    key = b"k" * 32
    prev = ""
    lines = []
    for n in (1, 2):
        # How the pre-0.1.0 writer spelled it: insertion order, ensure_ascii=False.
        rec = {"ts": f"2026-01-0{n}", "effect": "allow", "rule": "allow", "n": n, "seq": n, "prev": prev}
        body = json.dumps(rec, sort_keys=True, ensure_ascii=False)
        rec["hash"] = prev = hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest()
        lines.append(json.dumps(rec, ensure_ascii=False))
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _write_legacy_tip(log, key, len(lines), prev)

    ok, detail = verify_chain(log, key=key)
    assert ok, detail


def test_a_legacy_line_cannot_be_rewritten_either(tmp_path):
    """The exemption was also a hole: a line the check skipped could be given a repeated
    key and still authenticate. Running the check on every line closes it."""
    log = tmp_path / "legacy.jsonl"
    key = b"k" * 32
    rec = {"ts": "2026-01-01", "effect": "deny", "rule": "rbac", "seq": 1, "prev": ""}
    body = json.dumps(rec, sort_keys=True, ensure_ascii=False)
    rec["hash"] = hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest()
    raw = json.dumps(rec, ensure_ascii=False)
    log.write_text('{"effect": "allow", ' + raw[1:] + "\n", encoding="utf-8")
    _write_legacy_tip(log, key, 1, rec["hash"])

    ok, detail = verify_chain(log, key=key)
    assert not ok and "repeats the key" in detail


def test_a_second_sink_on_the_same_path_shares_the_erasure_memory(tmp_path):
    """The memory is the whole erasure defence, and it was per instance — so a second
    sink on the same file wrote a fresh chain over a truncated one."""
    log = tmp_path / "a.jsonl"
    first = JSONLAuditSink(log)
    for i in range(3):
        first.record({"effect": "allow", "rule": "allow", "n": i})
    log.unlink()
    (tmp_path / "a.jsonl.tip").unlink()
    JSONLAuditSink(log).record({"effect": "allow", "rule": "allow", "n": "after"})
    assert not verify_chain(log)[0]


def test_the_redactions_list_is_bounded_like_every_other_free_text_field():
    """`drop:<key>` carries a raw return-value key, so a projected dict with ten
    thousand undeclared keys wrote ten thousand of them into an append-only file."""
    from histos import AuditRecord

    record = AuditRecord(
        ts=0.0,
        decision_id=1,
        phase="post",
        tool="t",
        role="r",
        identity="i",
        effect="redact",
        rule="post_redaction",
        reason="x",
        args_digest="d",
        redactions=[f"drop:key-{i}" for i in range(5000)],
    )
    assert len(record.redactions) < 100
    assert record.redactions[-1] == "...[truncated]"


# ── the review of the hardening diff: importers, format, reports ─────────


def test_a_round_trip_keeps_the_nullability_the_importer_read():
    """`histos import --out` threw it away, so the round trip quietly tightened the
    policy and then denied the null the source explicitly allows."""
    from histos import dump_bundle, load_bundle

    schema = schema_from_json_schema(
        {"type": "object", "properties": {"note": {"anyOf": [{"type": "string"}, {"type": "null"}]}}}
    )
    policy = Policy(tools={"t": ToolContract(name="t", args=schema)})
    again = load_bundle(dump_bundle(policy))
    assert again.tools["t"].args.fields["note"].nullable is True
    assert again.content_hash() == policy.content_hash()


def test_an_array_length_bound_survives_a_round_trip():
    from histos import dump_bundle, load_bundle

    policy = Policy(tools={"t": ToolContract(name="t", args=Schema({"xs": Field(type="array", max_items=3)}))})
    again = load_bundle(dump_bundle(policy))
    assert again.tools["t"].args.fields["xs"].max_items == 3


def test_a_non_string_tool_name_is_refused_rather_than_crashing_the_manifest():
    with pytest.raises(PolicyError):
        contracts_from_mcp([{"name": 7, "inputSchema": {"type": "object", "properties": {}}}])


def test_the_scalar_null_type_imports_like_the_list_form():
    bare = schema_from_json_schema({"type": "object", "properties": {"x": {"type": "null"}}}).fields["x"]
    listed = schema_from_json_schema({"type": "object", "properties": {"x": {"type": ["null"]}}}).fields["x"]
    assert (bare.type, bare.nullable) == (listed.type, listed.nullable)


class Perm(enum.Flag):
    READ = enum.auto()
    WRITE = enum.auto()


def test_a_flag_enum_does_not_deny_every_composed_value():
    """A Flag's satisfiable set is the closure under `|`; listing the members denies
    every combination, which is the whole point of a Flag."""

    def act(perm: Perm) -> str:
        return "ok"

    field = infer_schema(act).fields["perm"]
    assert field.enum is None
    assert field.type == "integer"


def test_a_chained_openapi_ref_is_followed():
    spec = {
        "openapi": "3.0.0",
        "components": {
            "parameters": {
                "A": {"$ref": "#/components/parameters/B"},
                "B": {"name": "mode", "in": "query", "schema": {"type": "string", "maxLength": 4}},
            }
        },
        "paths": {"/x": {"get": {"operationId": "getX", "parameters": [{"$ref": "#/components/parameters/A"}]}}},
    }
    field = contracts_from_openapi(spec)[0].args.fields["mode"]
    assert (field.type, field.max_length) == ("string", 4)


def test_a_review_with_an_undeclared_tool_is_not_ok():
    """`render()` named it and `ok()` did not, so a host asserting `review.ok()` in CI
    was told everything was fine about a tool the gate denies outright."""
    review = review_policy(Policy(tools={}, permissions={}), discovered=["orphan"])
    assert "orphan" in review.no_contract
    assert not review.ok()


def test_the_vocabulary_hint_only_fires_where_it_is_right():
    """`permissions` nested inside a tool is not the constructor's `permissions`, and
    pointing the reader at `roles` there sends them somewhere unrelated."""
    from histos import load_bundle

    with pytest.raises(PolicyError) as exc:
        load_bundle(
            {
                "schema_version": "histos.policy/0.1",
                "tools": {"t": {"args": {}, "permissions": {"r": []}}},
                "roles": {"r": {"allow": ["t"]}},
            }
        )
    assert "Understood here" in str(exc.value)


# ── round three: the 779 lines the round-two fixes added ─────────────────


def test_a_canary_inside_an_exception_group_does_not_egress():
    """The chain walk followed `__cause__`/`__context__` and nothing else, so an
    `ExceptionGroup` — how `asyncio.TaskGroup` and every fan-out tool report partial
    failure — was scanned as its one summary line. Both payloads reached the caller
    intact, while the identical canary on a `raise ... from` chain was caught."""

    def shards() -> str:
        raise ExceptionGroup(
            "2 of 3 shards failed",
            [ValueError(f"shard-1: {CANARY}"), RuntimeError("shard-2 creds AKIAIOSFODNN7EXAMPLE")],
        )

    safe = gate(shards, policy=_no_args_policy(), name="t")
    with use_principal(Principal(role="ok", identity="i")), pytest.raises(ToolErrorRedacted) as exc:
        safe()
    assert CANARY not in str(exc.value)
    assert "AKIAIOSFODNN7EXAMPLE" not in str(exc.value)


def test_a_nested_exception_group_is_walked_too():
    def nested() -> str:
        raise ExceptionGroup("outer", [ExceptionGroup("inner", [ValueError(CANARY)])])

    safe = gate(nested, policy=_no_args_policy(), name="t")
    with use_principal(Principal(role="ok", identity="i")), pytest.raises(ToolErrorRedacted) as exc:
        safe()
    assert CANARY not in str(exc.value)


def test_notes_that_are_not_a_sequence_are_still_scanned():
    """CPython prints a non-Sequence `__notes__` as its repr, so skipping it entirely
    left whatever it holds readable by the caller and invisible to the scan."""

    def noted() -> str:
        exc = ValueError("boom")
        exc.__notes__ = {CANARY}  # a set: iterable, not a Sequence
        raise exc

    safe = gate(noted, policy=_no_args_policy(), name="t")
    with use_principal(Principal(role="ok", identity="i")), pytest.raises(ToolErrorRedacted) as err:
        safe()
    assert CANARY not in str(err.value)


def _projecting_policy() -> Policy:
    return Policy(
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


def test_a_namedtuple_one_level_down_is_not_projected_as_clean():
    """The top-level guard refused a NamedTuple return. One level down — a list of
    record rows, the most ordinary return there is — `isinstance(o, tuple)` won before
    the leaf check, so it was rebuilt with every undeclared field intact and the audit
    record read `redactions: []`: byte-identical to nothing-to-drop."""

    class Row(typing.NamedTuple):
        public: str
        secret: str

    for shape in ({"public": Row("fine", "leak")}, [Row("fine", "leak")]):

        def tool(_shape=shape) -> object:
            return _shape

        sink = InMemoryAuditSink()
        safe = Gate(_projecting_policy(), audit=sink).wrap(tool, name="t")
        with use_principal(Principal(role="ok", identity="i")):
            out = safe()
        assert "leak" not in repr(out), f"the undeclared field egressed from {type(shape).__name__}"
        assert "drop:secret" in sink.entries[-1]["redactions"], f"the drop went unrecorded for {type(shape).__name__}"


def test_projection_still_enters_the_container_subclasses_a_real_tool_returns():
    """`type(value) in (...)` was the overcorrection: `Counter`, `OrderedDict`,
    `defaultdict` and list subclasses carry their data under keys or positionally, hide
    nothing behind a name, and the projector rebuilds them correctly."""

    class Rows(list):
        pass

    for value in (
        collections.Counter({"public": 1, "secret": 2}),
        collections.OrderedDict(public="fine", secret="leak"),
        collections.defaultdict(str, public="fine", secret="leak"),
        Rows([{"public": "fine", "secret": "leak"}]),
    ):

        def tool(_v=value) -> object:
            return _v

        safe = Gate(_projecting_policy()).wrap(tool, name="t")
        with use_principal(Principal(role="ok", identity="i")):
            out = safe()
        assert "leak" not in repr(out) and "secret" not in repr(out), f"{type(value).__name__} was not projected"
        assert "REDACTED" not in repr(out), f"{type(value).__name__} was refused, but the projector handles it"


def test_the_budget_is_asked_only_where_a_pass_will_read_the_value():
    """Moving the size question out of the canary branch also moved it out of every
    condition, so it ran for a contract under which nothing walks the output at all.
    The passes it bounds are the secret detectors, the canary scan when tokens are
    actually planted, and anything keyed on a declared return shape."""
    rows = "\n".join(f"{i},value-{i},xxxxxxxxxx" for i in range(200_000))

    def csv_tool() -> str:
        return rows

    def run(policy: Policy) -> object:
        with use_principal(Principal(role="ok", identity="i")):
            return gate(csv_tool, policy=policy, name="t")()

    def _p(canaries: frozenset[str] = frozenset(), **kw: object) -> Policy:
        return Policy(
            tools={"t": ToolContract(name="t", args=Schema({}), **kw)},
            permissions={"ok": frozenset({"t"})},
            canaries=canaries,
        )

    # Nothing reads it — it comes back as it was.
    assert run(_p(redact_secret_output=False, scan_output_for_canary=False)) is rows
    # The canary pass with no tokens planted reads nothing either.
    assert run(_p(redact_secret_output=False)) is rows
    # But the secret detectors do read it, and bounding that pass is the whole point.
    assert "scan budget" in run(_p())
    # As does the canary scan once a token exists to look for.
    assert "scan budget" in run(_p(canaries=frozenset({"CANARY-TOKEN"}), redact_secret_output=False))


def test_the_raise_path_is_budgeted_like_the_return_path():
    """`_exception_text` materialised the whole chain and handed it to the NFKC pass and
    every detector. Tool error text is as attacker-controlled as tool output, so the
    raise path is the same DoS the return budget exists to close."""
    from histos.excchain import _exception_text

    text, incomplete = _exception_text(ValueError("x" * 5_000_000), 4_194_304)
    assert incomplete
    assert not text, "the over-budget piece must not be joined into the text at all"

    # Under budget, nothing changes.
    text, incomplete = _exception_text(ValueError("small"), 4_194_304)
    assert not incomplete and "small" in text


def test_redaction_growing_the_output_past_the_budget_is_not_scanned_as_a_prefix():
    """Verbatim canary redaction grows text — an 8-character token becomes the
    17-character `[REDACTED-CANARY]` — so an output that fitted on the way in can
    exceed the budget after redaction. The second blob discarded its truncation flag,
    leaving the split-token check reading a prefix and reporting clean about the rest."""
    from histos.engine import Engine
    from histos.limits import LimitStore

    token = "CANARY-A"
    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({}))},
        permissions={"ok": frozenset({"t"})},
        canaries=frozenset({token}),
    )
    # A budget that the value fits under and the redacted value does not.
    engine = Engine(policy, LimitStore(), output_budget=300)
    rows = [token] * 20  # 160 chars in, 340 out
    decision, out = engine.post(GateRequest("t", {}, Principal(role="ok", identity="i")), rows)
    assert decision.effect is Effect.REDACT
    assert "output:redacted_all" in decision.redactions
    assert token not in repr(out)


def test_a_partial_write_does_not_cost_the_whole_log(tmp_path, monkeypatch):
    """`write` + `flush` is not failure-atomic. When the volume filled mid-line the
    accepted bytes stayed in an append-only file with no newline, and every later append
    landed on that same physical line — so one transient quota event cost not one record
    but the log, permanently: `verify_chain` said "not valid JSON" there and never
    recovered.

    Injected at `os.write`, which is the layer the append actually uses. It used to go
    through the buffered handle, and that was the second half of the same bug: the
    buffer kept whatever the raw layer had not accepted, the rollback truncated the file,
    and then `close()` flushed the leftover straight back onto it — the torn line
    restored by the cleanup that exists to prevent it. Both halves are pinned here: the
    file is intact immediately after the failure, and still intact after the handle has
    been closed."""
    key = b"k" * 32
    log = tmp_path / "a.jsonl"
    sink = JSONLAuditSink(log, key=key)
    for n in range(3):
        sink.record({"effect": "allow", "rule": "allow", "n": n})
    assert verify_chain(log, key=key)[0]
    intact = log.read_bytes()

    real_write = os.write
    torn = {"done": False}

    def short_write(fd, data):
        """Accept a prefix and report a full volume, the way ENOSPC arrives."""
        if not torn["done"] and len(data) > 40:
            torn["done"] = True
            real_write(fd, data[: len(data) // 2])
            raise OSError(28, "No space left on device")
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", short_write)
    with pytest.warns(RuntimeWarning, match="could not be written"):
        sink.record({"effect": "deny", "rule": "rbac", "identity": "mallory"})
    monkeypatch.undo()

    assert log.read_bytes() == intact, "the failed write left bytes behind"
    assert sink.failed == 1
    ok, detail = verify_chain(log, key=key)
    assert ok, detail

    # ...and the log keeps working once the volume has room again.
    sink.record({"effect": "allow", "rule": "allow", "n": "after"})
    ok, detail = verify_chain(log, key=key)
    assert ok, detail


def test_a_short_write_with_no_exception_is_also_rolled_back(tmp_path):
    """`os.write` may return fewer bytes than it was given without raising at all. That
    is the same torn line arriving quietly."""
    key = b"k" * 32
    log = tmp_path / "a.jsonl"
    sink = JSONLAuditSink(log, key=key)
    sink.record({"effect": "allow", "rule": "allow"})
    intact = log.read_bytes()

    real_write = os.write
    short = {"done": False}

    def half(fd, data):
        if not short["done"] and len(data) > 40:
            short["done"] = True
            return real_write(fd, data[: len(data) // 2])
        return real_write(fd, data)

    os.write = half  # type: ignore[assignment]
    try:
        with pytest.warns(RuntimeWarning, match="could not be written"):
            sink.record({"effect": "deny", "rule": "rbac"})
    finally:
        os.write = real_write  # type: ignore[assignment]

    assert log.read_bytes() == intact
    assert verify_chain(log, key=key)[0]


def test_rotation_has_a_remedy_that_actually_works(tmp_path):
    """SECURITY.md offered "rotate the `.tip` sidecar with the log" as a remedy and it
    did nothing: the high-water memory is keyed by path and outlives both files, so a
    correctly rotated log stayed broken forever. Deciding on the inode instead would
    have fixed it by handing the erasure back — `rm` leaves a fresh inode exactly as
    `mv` does. An explicit call is the one signal an attacker rewriting files cannot
    produce."""
    log = tmp_path / "a.jsonl"
    key = b"k" * 32
    sink = JSONLAuditSink(log, key=key)
    for n in range(3):
        sink.record({"effect": "allow", "rule": "allow", "n": n})

    os.rename(log, tmp_path / "a.jsonl.1")
    os.rename(sink.tip_path, tmp_path / "a.jsonl.1.tip")
    sink.rotated()
    sink.record({"effect": "allow", "rule": "allow", "n": "fresh"})

    ok, detail = verify_chain(log, key=key)
    assert ok, detail


def test_erasure_without_that_declaration_is_still_caught(tmp_path):
    """The other half of the same property: `rotated()` must be the *only* way to clear
    the memory, or it is not a defence."""
    log = tmp_path / "a.jsonl"
    key = b"k" * 32
    sink = JSONLAuditSink(log, key=key)
    for n in range(3):
        sink.record({"effect": "allow", "rule": "allow", "n": n})
    log.unlink()
    sink.tip_path.unlink()
    sink.record({"effect": "allow", "rule": "allow", "n": "after erasure"})

    ok, _ = verify_chain(log, key=key)
    assert not ok, "an erased log restarted a clean chain"


def test_a_twelve_digit_maestro_is_detected():
    """The PAN table was widened for Maestro with `range(12, 20)` and the two length
    gates in front of it were not, so the shortest Maestro that exists could never reach
    the table."""
    assert any(d.kind == "pan" for d in scan_string("501800000009")), "12-digit Maestro egressed unredacted"


def test_a_policy_can_be_pickled_asdicted_and_deepcopied_off_a_live_gate():
    """`MappingProxyType` gave the read-only guarantee and cost three stdlib operations
    a host doing multiprocessing reaches for: `asdict` falls back to `deepcopy` for
    anything that is not an exact dict, and a proxy cannot be deep-copied."""
    import copy
    import pickle

    g = Gate(_policy())
    assert dataclasses.asdict(g.policy)
    assert copy.deepcopy(g.policy).content_hash() == g.policy.content_hash()
    assert pickle.loads(pickle.dumps(g.policy)).content_hash() == g.policy.content_hash()

    who = Principal(role="r", identity="i", attributes={"tenant": "acme"})
    assert pickle.loads(pickle.dumps(who)) == who
    assert copy.deepcopy(who) == who

    # ...and the guarantee it was chosen for still holds.
    with pytest.raises(TypeError):
        g.policy.permissions["ok"] = frozenset()
    with pytest.raises(TypeError):
        who.attributes["tenant"] = "evil"


def test_a_suppressed_context_holding_a_canary_is_detached_from_the_object():
    """`raise X from None` hides the branch from what CPython *prints*, and leaves it on
    `X.__context__` where an error reporter reads it. The scan skipping it was right;
    leaving the object attached was the half that was not done. The caller's exception
    type and message are untouched — swapping them would punish a leak that never
    reached the text."""

    def boom() -> str:
        try:
            raise ValueError(f"driver said {CANARY}")
        except ValueError:
            raise RuntimeError("repository error") from None

    sink = InMemoryAuditSink()
    with use_principal(Principal(role="ok", identity="i")), pytest.raises(RuntimeError) as exc:
        Gate(_no_args_policy(), audit=sink).wrap(boom, name="t")()
    assert type(exc.value) is RuntimeError
    assert str(exc.value) == "repository error"
    assert exc.value.__context__ is None, "the hidden branch is still reachable"
    assert "exception:suppressed_context_detached" in sink.entries[-1]["redactions"]


@pytest.mark.parametrize("bad", [0, -1, True, 3.5])
def test_a_nonsense_output_budget_is_refused(bad):
    """`0` turns every textual return into a redact-all, which reads as a tool fault and
    is a typo in the host's configuration."""
    with pytest.raises(PolicyError, match="output_budget"):
        Gate(_policy(), output_budget=bad)


def test_a_payload_with_no_text_still_meets_the_budget():
    """The budget measured textual leaves only, so a return of millions of integers cost
    zero budget and was reported under it — while the secret pass then walked and
    rebuilt every one of them."""

    def many() -> list[int]:
        return list(range(6_000_000))

    with use_principal(Principal(role="ok", identity="i")):
        out = gate(many, policy=_no_args_policy(), name="t")()
    assert isinstance(out, str) and "scan budget" in out


def test_a_deep_chain_is_not_dropped_when_nothing_was_going_to_read_it():
    """The `incomplete` check ran before any contract field was consulted, so a contract
    with the canary scan and the secret detectors both off still had a sixteen-link
    exception replaced by a redaction string."""
    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({}), scan_output_for_canary=False, redact_secret_output=False)},
        permissions={"ok": frozenset({"t"})},
    )

    def deep() -> str:
        exc: BaseException = ValueError("root")
        for n in range(30):
            try:
                raise RuntimeError(f"layer {n}") from exc
            except RuntimeError as raised:
                exc = raised
        raise exc

    with use_principal(Principal(role="ok", identity="i")), pytest.raises(RuntimeError) as caught:
        gate(deep, policy=policy, name="t")()
    assert "layer 29" in str(caught.value)


def test_a_confirmation_window_without_required_survives_the_round_trip():
    """`_tool_from_dict` reads the two halves independently, so this is a legal bundle —
    and `dump_bundle` only wrote the block when `required` was true, so it came back
    without its window and hashed differently."""
    from histos import dump_bundle

    bundle = {
        "version": "histos.policy/0.1",
        "tools": {"t": {"args": {}, "confirmation": {"expires_in": 300}}},
        "roles": {"ok": {"allow": ["t"]}},
    }
    policy = load_bundle(bundle)
    assert policy.tools["t"].confirmation_expires_in == 300
    back = load_bundle(dump_bundle(policy))
    assert back.tools["t"].confirmation_expires_in == 300
    assert back.content_hash() == policy.content_hash()


def test_a_source_authored_property_name_cannot_rewrite_the_drift_report():
    """`_render` sanitised every diff *value* and the path was interpolated raw — and
    the path is built from the source document's own JSON keys."""
    from histos.lockfile import shape_diff

    lines = shape_diff({"properties": {}}, {"properties": {"x\r\x1b[2KOK — no drift": {"type": "string"}}})
    assert lines and all("\r" not in line and "\x1b" not in line for line in lines), lines


# ── round three: what the completeness critic found ──────────────────────


def test_re_spelling_the_path_does_not_defeat_the_erasure_memory(tmp_path):
    """`str(path.resolve())` does not canonicalise case, and macOS APFS and every
    Windows volume are case-insensitive — so `Trail.jsonl` and `trail.jsonl` are one
    file with two keys, and the memory that *is* the erasure defence costs one capital
    letter to walk around."""
    upper = tmp_path / "Trail.jsonl"
    lower = tmp_path / "trail.jsonl"
    key = b"k" * 32
    sink = JSONLAuditSink(upper, key=key)
    for n in range(3):
        sink.record({"effect": "allow", "rule": "allow", "n": n})
    assert verify_chain(upper, key=key)[0]

    upper.write_text("", encoding="utf-8")
    tip_path_for(upper).unlink()
    if not os.path.exists(lower) or not os.path.samefile(upper, lower):
        pytest.skip("this filesystem is case-sensitive, so the two names are two files")

    JSONLAuditSink(lower, key=key).record({"effect": "allow", "rule": "allow", "n": "after"})
    ok, _ = verify_chain(upper, key=key)
    assert not ok, "an erased log restarted a clean chain under a different spelling"


def test_a_conformant_log_this_library_did_not_write_still_verifies(tmp_path):
    """The byte check demanded one of four `json.dumps` spellings, which invented an
    unwritten normative byte format — `spec/` describes none — and reported every other
    conformant serialisation as tampering. The real question is narrower: do the bytes
    and the parsed record disagree, which in JSON means a repeated key."""
    key = b"k" * 32
    spellings = {
        "hash first": lambda r: json.dumps({"hash": r.pop("hash"), **r}),
        "compact": lambda r: json.dumps(r, separators=(",", ":")),
        "sorted": lambda r: json.dumps(r, sort_keys=True),
    }
    for label, dump in spellings.items():
        log = tmp_path / f"{label.replace(' ', '_')}.jsonl"
        rec = {"ts": "2026-01-01", "effect": "allow", "rule": "allow", "seq": 1, "prev": ""}
        body = json.dumps(rec, sort_keys=True, ensure_ascii=True)
        rec["hash"] = digest = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
        log.write_text(dump(dict(rec)) + "\n", encoding="utf-8")
        _write_legacy_tip(log, key, 1, digest)
        ok, detail = verify_chain(log, key=key)
        assert ok, f"{label}: {detail}"


def test_a_host_can_ask_the_sink_to_raise_instead_of_losing_a_record(tmp_path):
    """`record()` is total by default because it runs after the tool has already had its
    side effect. A host whose evidence requirement outranks its availability can say so."""
    log = tmp_path / "a.jsonl"
    sink = JSONLAuditSink(log, strict=True)
    sink.record({"effect": "allow", "rule": "allow"})

    # The failure is injected rather than staged out of the filesystem. Making a
    # directory unwritable is a POSIX idea — Windows ignores the mode bits and the write
    # simply succeeded, so the test asserted nothing there. What it is actually about is
    # that `strict` re-raises whatever `_record` hit, and that is platform-free.
    def boom(_entry: object) -> None:
        raise OSError(28, "No space left on device")

    sink._record = boom  # type: ignore[method-assign]
    with pytest.warns(RuntimeWarning, match="could not be written"), pytest.raises(OSError):
        sink.record({"effect": "allow", "rule": "allow"})
    assert sink.failed == 1

    # ...and the default is still total: the same failure costs a record, never a call.
    lenient = JSONLAuditSink(tmp_path / "b.jsonl")
    lenient._record = boom  # type: ignore[method-assign]
    with pytest.warns(RuntimeWarning):
        lenient.record({"effect": "allow", "rule": "allow"})
    assert lenient.failed == 1


def test_the_output_budget_is_reachable_from_the_one_liners():
    """SECURITY.md's remedy for a legitimately large return is to raise the budget, and
    it was reachable only from the class API the README does not teach."""

    def big() -> str:
        return "x" * 5000

    policy = Policy(tools={"t": ToolContract(name="t", args=Schema({}))}, permissions={"ok": frozenset({"t"})})
    with use_principal(Principal(role="ok", identity="i")):
        assert "REDACTED" in gate(big, policy=policy, name="t", output_budget=100)()
        assert gate(big, policy=policy, name="t", output_budget=1_000_000)() == "x" * 5000


def test_the_normative_artifacts_know_about_the_pattern_screen():
    """The release's largest new refusal class was invisible to the spec and the
    conformance corpus, and `spec/` still described `pattern` as "NOT ReDoS-safe"."""
    root = pathlib.Path(__file__).resolve().parent.parent
    codes = json.loads((root / "spec" / "decision-codes.json").read_text(encoding="utf-8"))
    assert "unsafe_pattern" in codes["policy_codes"]

    schema = json.loads((root / "spec" / "policy-0.1.schema.json").read_text(encoding="utf-8"))
    described = schema["$defs"]["field"]["properties"]["pattern"]["description"]
    assert "NOT ReDoS-safe" not in described
    assert "backtracking" in described

    cases = list((root / "conformance" / "invalid-policy").glob("pattern-*.json"))
    assert len(cases) >= 5, "the biggest new refusal class has no conformance cases"


def test_or_equals_cannot_edit_a_live_ruleset():
    """`d |= {...}` calls `__ior__`, which for a dict mutates IN PLACE and then returns
    self for the assignment. On a frozen dataclass field that assignment fails — and the
    mutation has already landed. So this raised, looked refused, and left the grant live
    under the `policy_hash` computed before it: a role with no grant executing a write
    tool, with the trail naming the same ruleset for the denial and the allow.

    The override was removed to silence a mypy variance complaint about a method whose
    only job is to raise. Every mutator is checked here so the next one cannot go the
    same way."""
    sink = InMemoryAuditSink()
    g = Gate(_policy(), audit=sink)
    safe = g.wrap(_tool, name="t")
    before = dict(g.policy.permissions)

    for mutate in (
        lambda: g.policy.permissions.__ior__({"evil": frozenset({"t"})}),
        lambda: g.policy.permissions.update({"evil": frozenset({"t"})}),
        lambda: g.policy.permissions.__setitem__("evil", frozenset({"t"})),
        lambda: g.policy.permissions.setdefault("evil", frozenset({"t"})),
        lambda: g.policy.permissions.pop("ok"),
        lambda: g.policy.permissions.popitem(),
        lambda: g.policy.permissions.clear(),
        lambda: g.policy.permissions.__delitem__("ok"),
    ):
        with pytest.raises(TypeError):
            mutate()

    assert dict(g.policy.permissions) == before
    with use_principal(Principal(role="evil", identity="mallory")), pytest.raises(GateDenied) as exc:
        safe(x=1)
    assert exc.value.decision.rule == "rbac"


def test_a_printable_character_respelt_as_an_escape_is_caught(tmp_path):
    """The duplicate-key check rested on "there is exactly one way for the bytes and the
    parsed record to disagree in JSON". There is a second: a `\\uXXXX` escape of a
    printable ASCII character. `{"effect": "\\u0064eny"}` parses to exactly `deny`, so
    the chain authenticates it and every hash matches, while a human reading the file —
    or grepping it for `deny` — finds neither. `json.dumps` never emits that escape."""
    key = b"k" * 32
    log = tmp_path / "a.jsonl"
    JSONLAuditSink(log, key=key).record({"effect": "deny", "rule": "rbac", "identity": "mallory"})
    raw = log.read_text(encoding="utf-8")
    log.write_text(raw.replace('"deny"', '"\\u0064eny"'), encoding="utf-8")

    ok, detail = verify_chain(log, key=key)
    assert not ok and "no JSON writer produces that escape" in detail


def test_an_honest_log_with_non_ascii_still_verifies(tmp_path):
    """The escape check must not fire on the escapes the writer itself emits: with
    `ensure_ascii` every codepoint above 0x7E is written as `\\uXXXX`, and that is the
    normal contents of a log recording a name."""
    key = b"k" * 32
    log = tmp_path / "a.jsonl"
    sink = JSONLAuditSink(log, key=key)
    sink.record({"effect": "allow", "rule": "allow", "identity": "Łukasz"})
    sink.record({"effect": "deny", "rule": "rbac", "note": "zażółć gęślą jaźń"})
    assert "\\u017c" in log.read_text(encoding="utf-8")
    ok, detail = verify_chain(log, key=key)
    assert ok, detail


def test_the_tip_sidecar_is_read_as_carefully_as_the_log(tmp_path):
    """The sidecar is the one file whose whole job is to say how long the log is, and it
    was exempt from the check every line of the log gets. Keeping the genuine triple
    last and prepending a fabricated `records` makes `json.loads` take the real one — so
    the MAC still authenticates — while a reader sees the forgery."""
    key = b"k" * 32
    log = tmp_path / "a.jsonl"
    sink = JSONLAuditSink(log, key=key)
    for n in range(3):
        sink.record({"effect": "allow", "rule": "allow", "n": n})
    tip = tip_path_for(log)
    tip.write_text('{"records": 99, ' + tip.read_text(encoding="utf-8")[1:], encoding="utf-8")

    ok, detail = verify_chain(log, key=key)
    assert not ok and "says two different things" in detail


def test_rotated_takes_the_lock_the_map_is_otherwise_only_touched_under(tmp_path):
    """Every read and write of `_PATH_HIGH_WATER` inside `_record` happens under the
    path lock; `rotated()` popped it with none. A `record()` past its read of the mark
    and not yet at its write-back re-inserts the pre-rotation `(seq, hash)` after the
    pop, and the next record on the rotated log is numbered from the old chain."""
    import inspect

    assert "_path_lock" in inspect.getsource(JSONLAuditSink.rotated)

    # ...and it still does what it is for.
    key = b"k" * 32
    log = tmp_path / "a.jsonl"
    sink = JSONLAuditSink(log, key=key)
    for n in range(3):
        sink.record({"effect": "allow", "rule": "allow", "n": n})
    os.rename(log, tmp_path / "a.jsonl.1")
    os.rename(sink.tip_path, tmp_path / "a.jsonl.1.tip")
    sink.rotated()
    sink.record({"effect": "allow", "rule": "allow", "n": "fresh"})
    ok, detail = verify_chain(log, key=key)
    assert ok, detail
