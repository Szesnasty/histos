"""Audit-trail and framework-adapter fixes.

Every test here fails against the behaviour it replaces. Grouped by the claim it
defends: what the durable record may contain, that the record exists at all, that a
hash-chained log survives concurrency and detects truncation, what an approval is
bound to, and that the adapters gate what they say they gate.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import threading

import pytest
from conftest import STABLE_KEY, FakeClock

from histos import (
    ApprovalStore,
    Constraint,
    Field,
    Gate,
    GateConfirmationRequired,
    GateDenied,
    InMemoryAuditSink,
    JSONLAuditSink,
    Policy,
    Principal,
    Schema,
    ToolContract,
    digest_args,
    request_fingerprint,
    use_principal,
    verify_chain,
)
from histos.audit import AuditRecord, tip_path_for
from histos.errors import PolicyError
from histos.integrations import langchain as lc_adapter
from histos.integrations.base import guard_callable

PII = "INV-jane.doe@example.com"


def _simple_policy(**contract_kwargs) -> Policy:
    return Policy(
        tools={
            "read_invoice": ToolContract(
                name="read_invoice",
                args=Schema({"invoice_id": Field(type="string")}),
                **contract_kwargs,
            )
        },
        permissions={"clerk": frozenset({"read_invoice"})},
    )


def _clerk() -> Principal:
    return Principal(role="clerk", identity="u1", attributes={"tenant_id": "acme"})


# ── the durable record never quotes observed data ─────────────────────────


def test_resolver_exception_text_is_dropped_from_the_audit_record():
    """A host resolver's exception is foreign text, and it carries the argument."""

    def resolver(tool, args):
        raise KeyError(args["invoice_id"])

    sink = InMemoryAuditSink()
    policy = _simple_policy(constraints=(Constraint.owns("tenant_id"),))
    safe = Gate(policy, audit=sink, resource_resolver=resolver).wrap(lambda **k: "data", name="read_invoice")

    with use_principal(_clerk()), pytest.raises(GateDenied) as exc:
        safe(invoice_id=PII)

    # the developer channel keeps everything — that is what makes a denial debuggable
    assert PII in exc.value.decision.reason
    assert exc.value.decision.rule == "resolver_error"
    assert PII not in json.dumps(list(sink.entries))


def test_arg_schema_denial_names_the_rule_without_quoting_the_value():
    """The audit record's headline claim covers `reason`, not only `args_digest`."""
    policy = Policy(
        tools={"lookup": ToolContract(name="lookup", args=Schema({"tier": Field(type="string", enum=("gold",))}))},
        permissions={"clerk": frozenset({"lookup"})},
    )
    sink = InMemoryAuditSink()
    safe = Gate(policy, audit=sink).wrap(lambda **k: "ok", name="lookup")

    with use_principal(_clerk()), pytest.raises(GateDenied):
        safe(tier="platinum-jane.doe@example.com")

    entry = sink.entries[-1]
    assert entry["rule"] == "arg_schema"
    assert entry["field_name"] == "tier"
    assert "jane.doe@example.com" not in json.dumps(list(sink.entries))


def test_an_unrecognised_rule_redacts_rather_than_trusting_it():
    record = AuditRecord(
        ts=0.0,
        decision_id=1,
        phase="pre",
        tool="t",
        role="r",
        identity="u1",
        effect="deny",
        rule="a_rule_added_later",
        reason=f"something about {PII}",
        args_digest="hmac-sha256:00",
        received=PII,
    )
    assert PII not in json.dumps(record.to_dict())


# ── audit must never make a decision disappear ────────────────────────────


class _SurrogateRepr:
    """An argument object whose repr has no UTF-8 encoding."""

    def __repr__(self) -> str:
        return "\ud800"


def test_an_undigestible_argument_still_produces_a_record():
    assert digest_args({"q": _SurrogateRepr()}, STABLE_KEY).startswith("hmac-sha256:")

    policy = Policy(
        tools={"search": ToolContract(name="search", args=Schema({"q": Field(type="any")}))},
        permissions={"clerk": frozenset({"search"})},
    )
    sink = InMemoryAuditSink()
    safe = Gate(policy, audit=sink).wrap(lambda **k: "res", name="search")
    with use_principal(_clerk()):
        assert safe(q=_SurrogateRepr()) == "res"
    assert [e["phase"] for e in sink.entries] == ["pre", "post"]


def test_jsonl_sink_writes_a_record_whose_argument_key_is_a_lone_surrogate(tmp_path):
    log = tmp_path / "a.jsonl"
    sink = JSONLAuditSink(log, hash_chain=True, key=STABLE_KEY)
    sink.record({"decision_id": 1, "effect": "deny", "arg_keys": ["\ud800"]})
    assert verify_chain(log, key=STABLE_KEY)[0] is True


# ── the default sink is bounded ───────────────────────────────────────────


def test_in_memory_sink_is_bounded_and_says_what_it_dropped():
    sink = InMemoryAuditSink(maxlen=100)
    for i in range(150):
        sink.record({"i": i, "effect": "allow"})
    assert len(sink.entries) == 100
    assert sink.dropped == 50
    assert sink.entries[0]["i"] == 50  # the oldest went, not the newest

    unbounded = InMemoryAuditSink(maxlen=None)
    for i in range(150):
        unbounded.record({"i": i, "effect": "allow"})
    assert len(unbounded.entries) == 150 and unbounded.dropped == 0


def test_the_default_gate_sink_is_bounded():
    assert Gate(_simple_policy()).audit.entries.maxlen is not None


# ── a hash-chained log under concurrency ──────────────────────────────────


def _chained_gate(path, **sink_kwargs):
    policy = Policy(
        tools={"ping": ToolContract(name="ping", args=Schema({"n": Field(type="integer")}))},
        permissions={"clerk": frozenset({"ping"})},
    )
    sink = JSONLAuditSink(path, hash_chain=True, **sink_kwargs)
    return sink, Gate(policy, audit=sink).wrap(lambda **k: "pong", name="ping")


def test_chain_survives_calls_from_many_threads(tmp_path):
    log = tmp_path / "a.jsonl"
    sink, safe = _chained_gate(log)
    principal = _clerk()

    def worker() -> None:
        with use_principal(principal):
            for i in range(25):
                safe(n=i)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ok, detail = verify_chain(log)
    assert ok, detail
    assert "400 records" in detail  # a pre and a post record for each of 8 x 25 calls


def test_two_sinks_on_one_path_chain_instead_of_forking(tmp_path):
    """Two Gates, two workers or two processes sharing one audit file."""
    log = tmp_path / "a.jsonl"
    first = JSONLAuditSink(log, hash_chain=True)
    second = JSONLAuditSink(log, hash_chain=True)
    first.record({"decision_id": 1, "effect": "allow"})
    second.record({"decision_id": 2, "effect": "deny"})
    first.record({"decision_id": 3, "effect": "allow"})
    ok, detail = verify_chain(log)
    assert ok, detail
    assert "3 records" in detail


# ── truncation ────────────────────────────────────────────────────────────


def _write_records(path, n, **sink_kwargs):
    sink = JSONLAuditSink(path, hash_chain=True, **sink_kwargs)
    for i in range(n):
        sink.record({"decision_id": i + 1, "effect": "deny" if i >= n - 2 else "allow"})
    return sink


@pytest.mark.parametrize("key", [None, STABLE_KEY])
def test_deleting_records_off_the_end_is_detected(tmp_path, key):
    log = tmp_path / "a.jsonl"
    _write_records(log, 5, key=key)
    assert verify_chain(log, key=key)[0] is True

    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:3]) + "\n")  # the two denials were the last lines

    ok, detail = verify_chain(log, key=key)
    assert ok is False
    assert "2 removed" in detail


def test_a_log_with_no_tip_file_does_not_pass(tmp_path):
    log = tmp_path / "a.jsonl"
    _write_records(log, 3)
    tip_path_for(log).unlink()
    ok, detail = verify_chain(log)
    assert ok is False
    assert "truncation cannot be ruled out" in detail


def test_a_forged_tip_does_not_authenticate(tmp_path):
    log = tmp_path / "a.jsonl"
    _write_records(log, 5, key=STABLE_KEY)
    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:3]) + "\n")
    # The attacker cannot MAC a count they never saw, so they copy record 3's own hash.
    tip = tip_path_for(log)
    tip.write_text(json.dumps({"records": 3, "hash": json.loads(lines[2])["hash"], "mac": "00" * 32}) + "\n")

    ok, detail = verify_chain(log, key=STABLE_KEY)
    assert ok is False
    assert "does not authenticate" in detail


def test_removing_the_head_is_detected_by_the_record_number(tmp_path):
    """`seq` is inside the hashed body, so record N cannot be presented as record 1."""
    log = tmp_path / "a.jsonl"
    _write_records(log, 4, key=STABLE_KEY)

    # Attacker without the key drops record 1 and re-chains the rest with plain sha256,
    # and fixes the sidecar too — only the record numbering is left to catch it.
    records = [json.loads(x) for x in log.read_text().splitlines()][1:]
    prev = ""
    for rec in records:
        rec.pop("hash", None)
        rec["prev"] = prev
        body = json.dumps(rec, sort_keys=True, ensure_ascii=False)
        rec["hash"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
        prev = rec["hash"]
    log.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    tip_path_for(log).write_text(json.dumps({"records": len(records), "hash": prev, "mac": "00" * 32}) + "\n")

    ok, detail = verify_chain(log, key=STABLE_KEY)
    assert ok is False
    assert "numbered 2" in detail


# ── approvals bind the whole principal ────────────────────────────────────


def test_an_approval_does_not_cross_a_trusted_attribute_boundary():
    acme = Principal(role="agent", identity="u1", attributes={"tenant_id": "acme"})
    evil = Principal(role="agent", identity="u1", attributes={"tenant_id": "evil-corp"})
    assert request_fingerprint("wire", {"amt": 1}, acme) != request_fingerprint("wire", {"amt": 1}, evil)


def test_an_approval_does_not_cross_a_can_view_boundary():
    plain = Principal(role="agent", identity="u1")
    privileged = Principal(role="agent", identity="u1", can_view=frozenset({"ssn"}))
    assert request_fingerprint("wire", {"amt": 1}, plain) != request_fingerprint("wire", {"amt": 1}, privileged)


def test_the_same_principal_still_fingerprints_the_same():
    one = Principal(role="agent", identity="u1", attributes={"tenant_id": "acme"})
    two = Principal(role="agent", identity="u1", attributes={"tenant_id": "acme"})
    assert request_fingerprint("wire", {"amt": 1}, one) == request_fingerprint("wire", {"amt": 1}, two)


# ── the declared approval window is enforced ──────────────────────────────


def _deploy_policy(expires_in):
    return Policy(
        tools={
            "deploy": ToolContract(
                name="deploy",
                args=Schema({"service": Field(type="string")}),
                requires_confirmation=True,
                confirmation_expires_in=expires_in,
            )
        },
        permissions={"sre": frozenset({"deploy"})},
    )


def _confirmed_deploy(policy, clock):
    store = ApprovalStore(policy, clock=clock)
    ran = []
    safe = Gate(policy, confirm=store.as_confirm()).wrap(lambda **k: ran.append(k) or "deployed", name="deploy")
    return store, safe, ran


def test_an_approval_stops_working_once_its_declared_window_has_passed():
    clock = FakeClock()
    policy = _deploy_policy(900)
    store, safe, ran = _confirmed_deploy(policy, clock)
    sre = Principal(role="sre", identity="u1")

    store.grant(request_fingerprint("deploy", {"service": "payments"}, sre))
    clock.tick(901)
    with use_principal(sre), pytest.raises(GateConfirmationRequired):
        safe(service="payments")
    assert ran == []


def test_an_approval_inside_its_window_is_still_consumed_once():
    clock = FakeClock()
    policy = _deploy_policy(900)
    store, safe, ran = _confirmed_deploy(policy, clock)
    sre = Principal(role="sre", identity="u1")

    store.grant(request_fingerprint("deploy", {"service": "payments"}, sre))
    clock.tick(899)
    with use_principal(sre):
        assert safe(service="payments") == "deployed"
    with use_principal(sre), pytest.raises(GateConfirmationRequired):
        safe(service="payments")  # single-use, unchanged
    assert ran == [{"service": "payments"}]


def test_an_expired_approval_is_spent_not_merely_paused():
    clock = FakeClock()
    policy = _deploy_policy(900)
    store, safe, _ = _confirmed_deploy(policy, clock)
    sre = Principal(role="sre", identity="u1")

    store.grant(request_fingerprint("deploy", {"service": "payments"}, sre))
    clock.tick(901)
    with use_principal(sre), pytest.raises(GateConfirmationRequired):
        safe(service="payments")
    clock.tick(-901)  # even if the clock were wound back, the grant is gone
    with use_principal(sre), pytest.raises(GateConfirmationRequired):
        safe(service="payments")


# ── guard_callable ────────────────────────────────────────────────────────


def test_guard_callable_gates_an_async_tool():
    ran = []

    async def send_email(*, to: str) -> str:
        ran.append(to)
        return "sent"

    sink = InMemoryAuditSink()
    gate = Gate(Policy(tools={}, permissions={}), audit=sink)
    safe = guard_callable(send_email, name="send_email", gate=gate)
    assert inspect.iscoroutinefunction(safe)

    with use_principal(_clerk()):
        result = asyncio.run(safe(to="a@b.c"))

    assert result == "[ACTION_NOT_AUTHORIZED] this tool call was blocked by policy."
    assert ran == []
    assert [e["rule"] for e in sink.entries] == ["unknown_tool"]


def test_guard_callable_async_honours_on_denied_raise():
    async def send_email(*, to: str) -> str:  # pragma: no cover - never reached
        return "sent"

    gate = Gate(Policy(tools={}, permissions={}))
    safe = guard_callable(send_email, name="send_email", gate=gate, on_denied="raise")
    with use_principal(_clerk()), pytest.raises(GateDenied):
        asyncio.run(safe(to="a@b.c"))


@pytest.mark.parametrize("bad", ["Raise", "rasie", "throw", True, None])
def test_guard_callable_refuses_an_unknown_on_denied(bad):
    with pytest.raises(PolicyError, match="on_denied"):
        guard_callable(lambda **k: None, name="t", gate=Gate(_simple_policy()), on_denied=bad)


# ── LangChain adapter ─────────────────────────────────────────────────────


class _FakeStructuredTool:
    """Enough of `StructuredTool` to pin the adapter's contract without the framework."""

    def __init__(self, **fields):
        self.__dict__.update(fields)

    def model_copy(self, *, update):
        clone = _FakeStructuredTool(**self.__dict__)
        clone.__dict__.update(update)
        return clone


@pytest.fixture
def fake_langchain(monkeypatch):
    monkeypatch.setattr(lc_adapter, "_HAVE_LANGCHAIN", True)
    monkeypatch.setattr(lc_adapter, "StructuredTool", _FakeStructuredTool)


def _allow_all_gate(sink=None):
    policy = Policy(
        tools={"notify": ToolContract(name="notify", args=Schema({"to": Field(type="string")}))},
        permissions={"clerk": frozenset({"notify"})},
    )
    return Gate(policy, audit=sink or InMemoryAuditSink())


def test_protect_tool_gates_an_async_only_tool(fake_langchain):
    ran = []

    async def notify(*, to: str) -> str:
        ran.append(to)
        return "sent"

    raw = _FakeStructuredTool(name="notify", description="d", args_schema=None, func=None, coroutine=notify)
    protected = lc_adapter.protect_tool(raw, gate=_allow_all_gate())

    assert protected.func is None  # never LangChain's own `_run` dispatcher
    assert protected.coroutine is not notify
    with use_principal(_clerk()):
        assert asyncio.run(protected.coroutine(to="a@b.c")) == "sent"
    assert ran == ["a@b.c"]

    with use_principal(Principal(role="nobody")):
        assert asyncio.run(protected.coroutine(to="a@b.c")).startswith("[ACTION_NOT_AUTHORIZED]")
    assert ran == ["a@b.c"]


def test_protect_tool_keeps_the_fields_from_function_never_knew_about(fake_langchain):
    raw = _FakeStructuredTool(
        name="notify",
        description="d",
        args_schema=None,
        func=lambda **k: "sent",
        coroutine=None,
        return_direct=True,
        metadata={"team": "payments"},
        tags=["prod"],
    )
    protected = lc_adapter.protect_tool(raw, gate=_allow_all_gate())
    assert protected.return_direct is True
    assert protected.metadata == {"team": "payments"}
    assert protected.tags == ["prod"]


def test_protect_tool_gates_both_halves_of_a_dual_mode_tool(fake_langchain):
    ran = []

    def notify(*, to: str) -> str:
        ran.append(("sync", to))
        return "sent"

    async def anotify(*, to: str) -> str:
        ran.append(("async", to))
        return "sent"

    raw = _FakeStructuredTool(name="notify", description="", args_schema=None, func=notify, coroutine=anotify)
    sink = InMemoryAuditSink()
    protected = lc_adapter.protect_tool(raw, gate=_allow_all_gate(sink))

    with use_principal(Principal(role="nobody")):
        assert protected.func(to="a").startswith("[ACTION_NOT_AUTHORIZED]")
        assert asyncio.run(protected.coroutine(to="b")).startswith("[ACTION_NOT_AUTHORIZED]")
    assert ran == []
    assert [e["rule"] for e in sink.entries] == ["rbac", "rbac"]


def test_protect_tool_refuses_a_tool_it_would_have_to_rebuild(fake_langchain):
    class CustomTool:
        name = "notify"

        def _run(self, **kwargs):  # pragma: no cover - never reached
            return "sent"

    with pytest.raises(TypeError, match="guard_callable"):
        lc_adapter.protect_tool(CustomTool(), gate=_allow_all_gate())


def test_protect_tool_refuses_an_unknown_on_denied(fake_langchain):
    raw = _FakeStructuredTool(name="notify", description="", args_schema=None, func=lambda **k: "x", coroutine=None)
    with pytest.raises(PolicyError, match="on_denied"):
        lc_adapter.protect_tool(raw, gate=_allow_all_gate(), on_denied="Raise")


def test_protect_tools_shares_one_gate(fake_langchain):
    sink = InMemoryAuditSink()
    tools = [
        _FakeStructuredTool(name="notify", description="", args_schema=None, func=lambda **k: "x", coroutine=None)
    ]
    protected = lc_adapter.protect_tools(tools, gate=_allow_all_gate(sink))
    with use_principal(_clerk()):
        assert protected[0].func(to="a@b.c") == "x"
    assert [e["phase"] for e in sink.entries] == ["pre", "post"]


# ── package surface ───────────────────────────────────────────────────────


def test_the_gate_submodule_is_reachable_through_the_shadowing_one_liner():
    import histos

    assert histos.gate.Gate is Gate
    assert callable(histos.gate)
