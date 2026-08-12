"""The P1 findings from the pre-release adversarial review, pinned.

Each test here fails on the code as it stood before its fix. They are grouped by the
finding they close rather than by module, because the interesting property of several
of them is that one defect showed up in three places at once.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from histos import (
    ApprovalStore,
    Binding,
    Field,
    Gate,
    GateConfirmationRequired,
    GateDenied,
    InMemoryAuditSink,
    Policy,
    PolicyError,
    Principal,
    Schema,
    ToolContract,
    ToolErrorRedacted,
    gate,
    schema_from_json_schema,
    use_principal,
)
from histos.integrations.base import guard_callable

CANARY = "CANARY-7f3a-SECRET"


def _policy(**contract: object) -> Policy:
    return Policy(
        tools={"t": ToolContract(name="t", args=Schema({"x": Field(type="integer")}), access="write", **contract)},
        permissions={"ok": frozenset({"t"})},
        canaries=frozenset({CANARY}),
    )


def _tool(x: int) -> str:
    return f"ran {x}"


# ── P1-7: switching the mode has to switch the mode ──────────────────────


def test_setting_enforcement_after_construction_actually_enforces():
    g = Gate(_policy(), mode="observe")
    safe = g.wrap(_tool, name="t")
    with use_principal(Principal(role="nobody", identity="i")):
        assert safe(x=1) == "ran 1"  # observing: denied, but executed
        g.enforcement = "enforce"
        with pytest.raises(GateDenied):
            safe(x=1)


def test_setting_mode_is_the_same_switch():
    g = Gate(_policy(), mode="enforce")
    safe = g.wrap(_tool, name="t")
    g.mode = "observe"
    with use_principal(Principal(role="nobody", identity="i")):
        assert safe(x=1) == "ran 1"
    assert g.enforcement == "observe"


def test_a_misspelled_mode_raises_instead_of_quietly_not_enforcing():
    g = Gate(_policy())
    with pytest.raises(PolicyError):
        g.mode = "enfroce"
    assert g.enforcement == "enforce"


# ── P1-8: a positional call is named, not refused ────────────────────────


def test_a_positional_call_reaches_the_tool_with_its_arguments_named():
    sink = InMemoryAuditSink()
    safe = gate(_tool, policy=_policy(), audit=sink, name="t")
    with use_principal(Principal(role="ok", identity="i")):
        assert safe(1) == "ran 1"
    assert [e["arg_keys"] for e in sink.entries] == [["x"], ["x"]]


def test_a_positional_call_is_still_schema_checked():
    safe = gate(_tool, policy=_policy(), name="t")
    with use_principal(Principal(role="ok", identity="i")), pytest.raises(GateDenied) as exc:
        safe("not-an-int")
    assert exc.value.decision.rule == "arg_schema"


def test_a_bind_overwrites_an_argument_that_arrived_positionally():
    """The rewrite is the control; it cannot depend on how the caller spelled the call."""

    def send(to: str, body: str) -> str:
        return to

    policy = Policy(
        tools={
            "send": ToolContract(
                name="send",
                args=Schema({"to": Field(type="string"), "body": Field(type="string")}),
                access="write",
                bindings=(Binding(field="to", principal_attr="phone"),),
            )
        },
        permissions={"ok": frozenset({"send"})},
    )
    safe = gate(send, policy=policy, name="send")
    with use_principal(Principal(role="ok", identity="i", attributes={"phone": "+48111"})):
        assert safe("+48999888777", "hi") == "+48111"


def test_observe_mode_does_not_block_a_positional_call():
    """Observe is documented as blocking nothing, and is where a team finds out."""
    safe = gate(_tool, policy=_policy(), mode="observe", name="t")
    with use_principal(Principal(role="ok", identity="i")):
        assert safe(1) == "ran 1"


def test_the_adapter_still_returns_its_non_coaching_message_for_a_positional_call():
    g = Gate(_policy())
    safe = guard_callable(_tool, name="t", gate=g)
    with use_principal(Principal(role="ok", identity="i")):
        assert safe(1) == "ran 1"
    with use_principal(Principal(role="nobody", identity="i")):
        assert safe(1) == "[ACTION_NOT_AUTHORIZED] this tool call was blocked by policy."


def test_a_call_the_gate_cannot_name_is_denied_and_leaves_a_record():
    def splat(*args: object) -> str:
        return "ran"

    sink = InMemoryAuditSink()
    safe = gate(splat, policy=_policy(), audit=sink, name="t")
    with use_principal(Principal(role="ok", identity="i")), pytest.raises(GateDenied) as exc:
        safe(1)
    assert exc.value.decision.rule == "unnameable_args"
    assert [e["rule"] for e in sink.entries] == ["unnameable_args"]


def test_the_async_path_names_positional_arguments_too():
    async def atool(x: int) -> str:
        return f"ran {x}"

    safe = gate(atool, policy=_policy(), name="t")
    with use_principal(Principal(role="ok", identity="i")):
        assert asyncio.run(safe(1)) == "ran 1"


# ── P1-9: wrapping a wrapper ─────────────────────────────────────────────


def test_wrapping_an_already_gated_callable_is_refused():
    g = Gate(_policy(budget=2))
    once = g.wrap(_tool, name="t")
    with pytest.raises(PolicyError) as exc:
        g.wrap(once, name="t")
    assert "already gated" in str(exc.value)


def test_a_second_gate_also_refuses_a_wrapper_it_did_not_make():
    """Identity cannot answer this — the stamp can, and a doubled limit does not care
    which Gate produced the inner wrapper."""
    once = Gate(_policy()).wrap(_tool, name="t")
    with pytest.raises(PolicyError):
        Gate(_policy()).wrap(once, name="t")


# ── P1-10: an approval for a tool that also has a bind ───────────────────


def test_the_confirmation_pause_carries_the_arguments_the_approval_will_cover():
    def send(to: str, body: str) -> str:
        return to

    policy = Policy(
        tools={
            "send": ToolContract(
                name="send",
                args=Schema({"to": Field(type="string"), "body": Field(type="string")}),
                access="write",
                bindings=(Binding(field="to", principal_attr="phone"),),
                requires_confirmation=True,
            )
        },
        permissions={"ok": frozenset({"send"})},
    )
    store = ApprovalStore(policy)
    safe = gate(send, policy=policy, confirm=store.as_confirm(), name="send")
    who = Principal(role="ok", identity="i", attributes={"phone": "+48111"})

    with use_principal(who):
        with pytest.raises(GateConfirmationRequired) as exc:
            safe(to="+48999888777", body="hi")
        # the host's own arguments are not the ones an approval covers
        assert exc.value.request is not None
        assert exc.value.request.args["to"] == "+48111"
        store.grant(exc.value.fingerprint)
        assert safe(to="+48999888777", body="hi") == "+48111"


def test_the_pause_hands_back_a_detached_copy_of_the_arguments():
    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({"x": Field(type="integer")}), requires_confirmation=True)},
        permissions={"ok": frozenset({"t"})},
    )
    safe = gate(_tool, policy=policy, name="t")
    with use_principal(Principal(role="ok", identity="i")):
        with pytest.raises(GateConfirmationRequired) as exc:
            safe(x=1)
        exc.value.request.args["x"] = 999
        with pytest.raises(GateConfirmationRequired) as second:
            safe(x=1)
        assert second.value.request.args["x"] == 1


# ── P1-11: only True approves ────────────────────────────────────────────


@pytest.mark.parametrize("truthy", ["denied", {"approved": False}, 1, [0]])
def test_a_truthy_non_bool_from_confirm_does_not_approve(truthy):
    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({"x": Field(type="integer")}), requires_confirmation=True)},
        permissions={"ok": frozenset({"t"})},
    )
    safe = gate(_tool, policy=policy, confirm=lambda req: truthy, name="t")
    with use_principal(Principal(role="ok", identity="i")), pytest.raises(GateDenied) as exc:
        safe(x=1)
    assert exc.value.decision.rule == "confirm_error"


def test_true_still_approves_and_false_still_pauses():
    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({"x": Field(type="integer")}), requires_confirmation=True)},
        permissions={"ok": frozenset({"t"})},
    )
    with use_principal(Principal(role="ok", identity="i")):
        assert gate(_tool, policy=policy, confirm=lambda req: True, name="t")(x=1) == "ran 1"
        with pytest.raises(GateConfirmationRequired):
            gate(_tool, policy=policy, confirm=lambda req: False, name="t")(x=1)


# ── P1-12: the sink must not take down the call it records ───────────────


def test_two_sinks_on_one_path_share_a_lock_and_the_chain_survives(tmp_path):
    import threading

    from histos import JSONLAuditSink, verify_chain

    log = tmp_path / "a.jsonl"
    sinks = [JSONLAuditSink(log), JSONLAuditSink(log)]

    def write(sink, n):
        for i in range(20):
            sink.record({"effect": "allow", "rule": "allow", "n": f"{n}-{i}"})

    threads = [threading.Thread(target=write, args=(s, n)) for n, s in enumerate(sinks)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok, detail = verify_chain(log)
    assert ok, detail
    assert "40 records" in detail


def test_the_tip_scratch_file_is_not_a_shared_name(tmp_path):
    """A fixed `<log>.tip.new` was only safe because flock happened to serialise it."""
    from histos import JSONLAuditSink

    log = tmp_path / "a.jsonl"
    JSONLAuditSink(log).record({"effect": "allow", "rule": "allow"})
    assert not list(tmp_path.glob("*.new")), "a scratch file was left behind"


# ── P1-13: the exception chain is part of what the caller can read ───────


@pytest.mark.parametrize("wire", ["cause", "context", "note"])
def test_a_canary_hidden_in_a_chained_exception_is_redacted(wire):
    def boom(x: int) -> str:
        if wire == "note":
            err = RuntimeError("repository error")
            err.add_note(f"while reading {CANARY}")
            raise err
        try:
            raise ValueError(f"driver said {CANARY}")
        except ValueError as inner:
            if wire == "cause":
                raise RuntimeError("repository error") from inner
            raise RuntimeError("repository error")  # noqa: B904 — __context__ is the point

    safe = gate(boom, policy=_policy(), name="t")
    with use_principal(Principal(role="ok", identity="i")), pytest.raises(ToolErrorRedacted) as exc:
        safe(x=1)
    assert CANARY not in str(exc.value)
    assert exc.value.decision.rule == "exception_redaction"


def test_an_ordinary_raising_tool_is_still_re_raised_untouched():
    def boom(x: int) -> str:
        raise ValueError("nothing sensitive here")

    safe = gate(boom, policy=_policy(), name="t")
    with use_principal(Principal(role="ok", identity="i")), pytest.raises(ValueError) as exc:
        safe(x=1)
    assert str(exc.value) == "nothing sensitive here"


def test_a_self_referential_exception_chain_terminates():
    def boom(x: int) -> str:
        first = RuntimeError("a")
        second = RuntimeError("b")
        first.__cause__ = second
        second.__cause__ = first
        raise first

    safe = gate(boom, policy=_policy(), name="t")
    with use_principal(Principal(role="ok", identity="i")), pytest.raises(RuntimeError):
        safe(x=1)


# ── P1-14: a report a human reads cannot be steered by what it reports ───


def test_a_hostile_tool_name_is_escaped_in_the_review():
    from histos.review import review_policy

    hostile = "read_docs\r‮export_contacts​"
    review = review_policy(
        Policy(tools={hostile: ToolContract(name=hostile, args=Schema({}), access="write")}, permissions={})
    )
    rendered = review.render()
    assert not any(ch in rendered for ch in "\r‮​")
    assert "\\u000d" in rendered and "\\u202e" in rendered


# ── P1-15: the one marker whose absence is invisible ─────────────────────


@pytest.mark.parametrize(
    "prop",
    [
        {"type": "string", "x-sensitive": "PII"},
        {"type": "string", "x-sensitive": "confidential"},
        {"type": "string", "x-sensitiv": "pii"},
        {"type": "string", "x_sensitive": "pii"},
    ],
)
def test_a_near_miss_sensitivity_marker_is_refused(prop):
    with pytest.raises(PolicyError) as exc:
        schema_from_json_schema({"type": "object", "properties": {"ssn": prop}})
    assert exc.value.code == "invalid_import"


def test_the_correct_marker_still_imports_and_another_vendors_key_is_still_ignored():
    schema = schema_from_json_schema(
        {
            "type": "object",
            "properties": {
                "ssn": {"type": "string", "x-sensitive": "pii"},
                "note": {"type": "string", "x-acme-hint": "anything"},
            },
        }
    )
    assert schema.fields["ssn"].sensitive == "pii"
    assert schema.fields["note"].sensitive is None


def test_the_audit_line_stays_machine_readable_under_a_hostile_argument_name(tmp_path):
    """P0-4's property, re-asserted end to end because P1 work touched the same file."""
    from histos import JSONLAuditSink

    def anything(**kwargs: object) -> str:
        return "ok"

    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({}, allow_extra=True), access="read")},
        permissions={"ok": frozenset({"t"})},
    )
    log = tmp_path / "a.jsonl"
    safe = gate(anything, policy=policy, audit=JSONLAuditSink(log), name="t")
    with use_principal(Principal(role="ok", identity="i")):
        safe(**{"key\ud800bad": "v"})
    with log.open(encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle]
    assert len(records) == 2


# ── the review of the hardening diff: what the first cut of P1-8 and T-40 broke ──


def test_a_partial_names_its_arguments_from_the_object_that_will_be_called():
    """`_unwrap_target` hands back the underlying function with the pre-bound parameters
    still in it, so every positional argument was named one slot to the left."""
    import functools

    def send(channel: str, to: str, body: str) -> str:
        return f"{channel}->{to}:{body}"

    policy = Policy(
        tools={"send": ToolContract(name="send", args=Schema({}, allow_extra=True))},
        permissions={"ok": frozenset({"send"})},
    )
    safe = gate(functools.partial(send, "sms"), policy=policy, name="send")
    with use_principal(Principal(role="ok", identity="i")):
        assert safe("+48111", "hi") == "sms->+48111:hi"


def test_a_positional_only_parameter_is_handed_back_positionally():
    """The gate reasons in names; `def f(a, /)` does not accept them."""

    def posonly(a: str, /, b: str) -> str:
        return f"{a}|{b}"

    policy = Policy(
        tools={"posonly": ToolContract(name="posonly", args=Schema({}, allow_extra=True))},
        permissions={"ok": frozenset({"posonly"})},
    )
    safe = gate(posonly, policy=policy, name="posonly")
    with use_principal(Principal(role="ok", identity="i")):
        assert safe("x", "y") == "x|y"


def test_observe_reaches_the_same_decision_as_enforce_on_a_bound_argument():
    """Deferring the bind made observe evaluate the model's unbound arguments, so a dry
    run predicted a denial enforce would never make — and the reverse."""

    def send(to: str) -> str:
        return to

    policy = Policy(
        tools={
            "send": ToolContract(
                name="send",
                args=Schema({"to": Field(type="string", enum=("+48111",))}),
                access="write",
                bindings=(Binding(field="to", principal_attr="phone"),),
            )
        },
        permissions={"ok": frozenset({"send"})},
    )
    who = Principal(role="ok", identity="i", attributes={"phone": "+48111"})
    seen = {}
    for mode in ("enforce", "observe"):
        sink = InMemoryAuditSink()
        with use_principal(who):
            returned = gate(send, policy=policy, mode=mode, audit=sink, name="send")(to="+48999888777")
        seen[mode] = (sink.entries[0]["effect"], tuple(sink.entries[0]["rebound_args"]), returned)
    assert seen["enforce"][:2] == seen["observe"][:2], "observe must predict the decision enforce makes"
    assert seen["enforce"][2] == "+48111" and seen["observe"][2] == "+48999888777", "observe must not rewrite"


def test_the_contextmanager_idiom_for_a_request_scope_is_allowed():
    import contextlib

    @contextlib.contextmanager
    def request_scope(principal):
        with use_principal(principal):
            yield

    with request_scope(Principal(role="ok", identity="i")):
        pass
    from histos.gate import _current_principal

    assert _current_principal.get() is None


def test_a_generator_nobody_drives_with_enter_exit_discipline_is_still_refused():
    def stream():
        with use_principal(Principal(role="ok", identity="i")):
            yield 1

    with pytest.raises(PolicyError, match="generator"):
        list(stream())


def test_the_contextmanager_workaround_does_not_smuggle_the_leak_back_in():
    """The refusal recommends `@contextlib.contextmanager`, and that used to be enough
    to satisfy a check that looked exactly one frame up. It is not enough: if the thing
    *consuming* the context manager is itself a generator, the `with` block still spans
    that generator's yields, the binding still lands in the consumer's context, and two
    interleaved streams still run as each other — with nothing raised anywhere.

    Measured before the walk went in: two producers, and the second row of alice's
    stream executed as bob."""
    import contextlib

    @contextlib.contextmanager
    def request_scope(principal):
        with use_principal(principal):
            yield

    def stream(principal):
        with request_scope(principal):
            yield 1
            yield 2

    with pytest.raises(PolicyError, match="consuming it"):
        list(stream(Principal(role="ok", identity="alice")))


def test_the_async_twin_of_the_same_hole_is_refused():
    import asyncio
    import contextlib

    @contextlib.asynccontextmanager
    async def request_scope(principal):
        with use_principal(principal):
            yield

    async def stream(principal):
        async with request_scope(principal):
            yield 1

    async def drain():
        return [row async for row in stream(Principal(role="ok", identity="alice"))]

    with pytest.raises(PolicyError, match="consuming it"):
        asyncio.run(drain())


def test_an_async_contextmanager_awaited_by_an_ordinary_coroutine_still_works():
    """The walk must stop at the first non-generator frame. A coroutine is not one."""
    import asyncio
    import contextlib

    from histos.gate import _current_principal

    @contextlib.asynccontextmanager
    async def request_scope(principal):
        with use_principal(principal):
            yield

    async def handler():
        async with request_scope(Principal(role="ok", identity="i")):
            return _current_principal.get()

    assert asyncio.run(handler()).identity == "i"


def test_a_pytest_style_yield_fixture_is_not_refused(as_a_clerk):
    """`_refuse_a_leaking_frame`'s own docstring names a generator-style test fixture as
    one of the two shapes the ban was too broad for — and only `contextlib` was ever
    exempted, so this raised at fixture setup and errored out every test using it.
    pytest brackets a yield fixture in the same Context, which is the safe case."""
    from histos.gate import _current_principal

    assert _current_principal.get().identity == "clerk-1"


@pytest.fixture
def as_a_clerk():
    with use_principal(Principal(role="ok", identity="clerk-1")):
        yield


def test_reusing_one_use_principal_instance_still_unbinds():
    from histos.gate import _current_principal

    scope = use_principal(Principal(role="ok", identity="i"))
    with scope:
        with scope:
            pass
    assert _current_principal.get() is None


def test_a_refused_value_the_gate_does_not_own_is_not_closed():
    """`close()` on a page wrapper or a cursor tears down live caller state over a value
    the gate merely declined to inspect."""

    class Page:
        closed = False

        def __iter__(self):
            yield {"a": 1}

        def close(self):
            Page.closed = True

    def tool() -> Page:
        return Page()

    policy = Policy(tools={"t": ToolContract(name="t", args=Schema({}))}, permissions={"ok": frozenset({"t"})})
    with use_principal(Principal(role="ok", identity="i")), pytest.raises(GateDenied):
        gate(tool, policy=policy, name="t")()
    assert Page.closed is False


def test_a_gate_owned_policy_can_still_be_pickled_and_copied():
    import copy
    import pickle

    policy = Policy(tools={"t": ToolContract(name="t", args=Schema({}))}, permissions={"ok": frozenset({"t"})})
    owned = Gate(policy).policy
    assert pickle.loads(pickle.dumps(owned)).content_hash() == owned.content_hash()
    assert copy.deepcopy(owned).content_hash() == owned.content_hash()
    with pytest.raises(TypeError):
        owned.tools["x"] = None  # type: ignore[index]


def test_one_use_principal_instance_shared_across_tasks_does_not_leak_an_identity():
    """The token stack lived on the instance, and a `Token` may only be reset in the
    Context that created it. Two tasks sharing one `scope = use_principal(p)` pushed
    onto the same LIFO list and, on any interleaving that was not perfectly nested, each
    popped the other's token. Both scopes raised and *neither* binding was reset — so on
    a pooled worker the identity stayed live, and every later task landing there with no
    principal bound at all executed gated write tools as the leaked one."""
    import asyncio

    from histos.gate import _current_principal

    admin = Principal(role="ok", identity="admin")
    scope = use_principal(admin)
    ran: list[str] = []

    def tool(x: str) -> str:
        ran.append(x)
        return x

    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({"x": Field(type="string")}), access="write")},
        permissions={"ok": frozenset({"t"})},
    )
    safe = gate(tool, policy=policy, name="t")

    async def scoped(tag: str, hold: float) -> str:
        try:
            with scope:
                await asyncio.sleep(hold)
                safe(x=tag)
            return "ok"
        except PolicyError:
            return "PolicyError"

    async def unauthenticated(tag: str) -> str:
        try:
            safe(x=tag)
            return "ALLOWED"
        except GateDenied as exc:
            return exc.decision.rule

    async def main() -> tuple[list[str], list[str]]:
        # Deliberately not nested: A opens first and closes last.
        scoped_results = await asyncio.gather(scoped("u1", 0.02), scoped("u2", 0.001))
        later = await asyncio.gather(*(unauthenticated(f"victim{n}") for n in range(4)))
        return list(scoped_results), list(later)

    scoped_results, later = asyncio.run(main())
    assert scoped_results == ["ok", "ok"], "a shared instance broke its own scopes"
    assert later == ["no_principal"] * 4, f"an identity leaked onto later tasks: {later}"
    assert ran == ["u2", "u1"], f"the wrong tool bodies ran: {ran}"
    assert _current_principal.get() is None


# ── round three: the gate.py P2s ─────────────────────────────────────────


def test_a_half_gated_tool_is_not_wrapped_again():
    """`_gate_stamp` returns None both for "nothing is gated" and for "the handles
    disagree", and `wrap()` read the second as permission — so a tool whose sync half
    was already wrapped got it wrapped twice and consumed every limit twice."""

    class DualMode:
        def __init__(self, func, coroutine):
            self.func = func
            self.coroutine = coroutine

    async def anotify(x: int) -> str:
        return "a"

    g = Gate(_policy())
    tool = DualMode(g.wrap(_tool, name="t"), anotify)
    with pytest.raises(PolicyError, match="already gated"):
        g.wrap(tool, name="t")


def test_wrap_refuses_the_lambda_protect_told_you_to_bring_here():
    with pytest.raises(PolicyError, match="lambda"):
        Gate(_policy()).wrap(lambda x: x, name=None)  # noqa: E731
    # ...and accepts it the moment it is given a name, which is what the message says.
    assert Gate(_policy()).wrap(lambda x: x, name="t")  # noqa: E731


def test_two_tools_of_the_same_name_across_two_protect_calls_are_refused():
    """The duplicate-name refusal looked in a dict local to one `protect()` call, so
    building the tool set in two groups — the "two modules each defining `def
    delete(...)`" case its own comment names — walked straight past it."""

    def delete(x: int) -> str:
        return "db"

    def delete_api(x: int) -> str:
        return "api"

    delete_api.__name__ = "delete"
    g = Gate(_policy())
    g.protect([delete])
    with pytest.raises(PolicyError, match="two different callables"):
        g.protect([delete_api])


def test_a_tool_wrap_refused_is_not_reported_as_wrapped():
    """`_wrapped_tools.add` ran before `_detect_async` could refuse, so after the
    refusal the Gate held no wrapper and `coverage()` still called the tool covered."""

    import functools

    async def atool(x: int) -> str:
        return "a"

    @functools.wraps(atool)
    def sync_wrapper(x: int) -> str:  # a sync callable wrapping an async one
        return "a"

    g = Gate(_policy())
    with pytest.raises(PolicyError, match="cannot tell whether"):
        g.wrap(sync_wrapper, name="t")
    assert "t" in g.coverage(["t"])["unwrapped"]
    assert g.declared_but_unwrapped() == {"t"}


def test_setting_the_mode_to_none_is_refused():
    """Every typo was refused and the one value a config loader produces for a missing
    key silently switched a calibrating gate into enforcement."""
    g = Gate(_policy(), mode="observe")
    with pytest.raises(PolicyError, match="None"):
        g.mode = None
    assert g.enforcement == "observe"


def test_a_kwargs_entry_shadowing_a_positional_only_slot_is_refused_not_merged():
    """PEP 570 makes the name free to reuse, so `f(1, record_id=2)` is two distinct
    values. Flattening one dict over the other kept the keyword and threw the trusted
    positional away, where the raw call raised a loud TypeError."""

    def update(record_id: int, /, **fields: object) -> str:
        return f"{record_id}:{fields}"

    sink = InMemoryAuditSink()
    policy = Policy(
        tools={"u": ToolContract(name="u", args=Schema({}, allow_extra=True))},
        permissions={"ok": frozenset({"u"})},
    )
    safe = gate(update, policy=policy, audit=sink, name="u")
    with use_principal(Principal(role="ok", identity="i")), pytest.raises(GateDenied) as exc:
        safe(1, record_id=2)
    assert exc.value.decision.rule == "unnameable_args"
    assert "record_id" in exc.value.decision.reason


def test_a_hole_in_the_positional_only_run_is_filled_from_the_default():
    """Stopping at the first missing positional-only parameter handed the later ones to
    the tool as keywords, which a positional-only parameter cannot accept — the exact
    defect this re-split was written to fix."""

    def f(a: int = 1, b: int = 2, /) -> str:
        return f"{a},{b}"

    policy = Policy(
        tools={"f": ToolContract(name="f", args=Schema({"b": Field(type="integer", required=False)}))},
        permissions={"ok": frozenset({"f"})},
    )
    safe = gate(f, policy=policy, name="f")
    with use_principal(Principal(role="ok", identity="i")):
        assert safe(b=9) == "1,9"


def test_observe_supplies_a_bound_argument_the_caller_never_sent():
    """Observe must not rewrite what the caller sent — and must still supply what the
    caller omitted, or it raises a TypeError on a call enforce serves. A dry run that
    breaks the app teaches the team to skip the dry run."""

    def read(tenants: list[str]) -> str:
        return f"read {tenants}"

    policy = Policy(
        tools={
            "read": ToolContract(
                name="read",
                args=Schema({"tenants": Field(type="array", item_type="string")}),
                bindings=(Binding(field="tenants", principal_attr="tenants"),),
            )
        },
        permissions={"ok": frozenset({"read"})},
    )
    who = Principal(role="ok", identity="i", attributes={"tenants": ["acme"]})
    for mode in ("enforce", "observe"):
        with use_principal(who):
            assert gate(read, policy=policy, mode=mode, name="read")() == "read ['acme']"


def test_observe_still_does_not_rewrite_what_the_caller_did_send():
    def send(to: str) -> str:
        return to

    policy = Policy(
        tools={
            "send": ToolContract(
                name="send",
                args=Schema({"to": Field(type="string")}),
                bindings=(Binding(field="to", principal_attr="phone"),),
            )
        },
        permissions={"ok": frozenset({"send"})},
    )
    who = Principal(role="ok", identity="i", attributes={"phone": "+48111"})
    seen = {}
    for mode in ("enforce", "observe"):
        with use_principal(who):
            seen[mode] = gate(send, policy=policy, mode=mode, name="send")(to="+48999888777")
    assert seen == {"enforce": "+48111", "observe": "+48999888777"}


def test_an_enum_member_with_its_own_iter_is_not_waived():
    """The blanket exemption said "everything an enum member can hold was written at
    class-definition time". True of the enum machinery's own iteration; not true of a
    member class that writes `__iter__` itself and yields whatever it likes."""
    import enum as _enum

    from histos.gate import _lazy_leaf_kind

    class Sneaky(_enum.Enum):
        A = 1

        def __iter__(self):
            yield "unscanned tool output"

    class Ordinary(_enum.Enum):
        A = 1

    class Flags(_enum.Flag):
        ONE = 1
        TWO = 2

    assert _lazy_leaf_kind(Ordinary.A) is None
    assert _lazy_leaf_kind(Flags.ONE | Flags.TWO) is None
    assert _lazy_leaf_kind(Sneaky.A) is not None
