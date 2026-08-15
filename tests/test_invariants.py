"""Properties, not examples — and the known-broken ones, written down as tests.

Two things live here.

**Invariants.** Statements of the form "for any X, ...", which is what the rest of this
suite does not have. Every P0 the fifth adversarial pass found had the same shape: a fix
verified against the property it was fixing, and never against the property beside it.
An example suite cannot catch that, because the example next door was never written. A
property can: `Principal(attributes=p.attributes)` must work for *any* `p` is one line,
and it fails the moment a snapshot starts handing back a mapping that refuses writes.

**Known-broken invariants, marked `xfail(strict=True)`.** These are the findings that
survived refutation and are not fixed yet. Keeping them here rather than in a review
document outside the repository has three effects: the defect is executable rather than
described, CI stays green while it is open, and the moment a fix lands the strict xfail
turns into a failure that says "remove this marker" — so a fix cannot quietly not-fix
it, and the marker cannot outlive the bug.

When you close one: delete the marker, keep the test.
"""

from __future__ import annotations

import dataclasses
import typing

import pytest

from histos import (
    Field,
    Gate,
    InMemoryAuditSink,
    JSONLAuditSink,
    Policy,
    Principal,
    Schema,
    ToolContract,
    use_principal,
    verify_chain,
)

CANARY = "CANARY-7f3a-SECRET"


def _policy(**contract_kwargs) -> Policy:
    return Policy(
        tools={"t": ToolContract(name="t", args=Schema({}), **contract_kwargs)},
        permissions={"r": frozenset({"t"})},
        canaries=frozenset({CANARY}),
    )


def _run(policy: Policy, tool, audit=None):
    sink = audit if audit is not None else InMemoryAuditSink()
    safe = Gate(policy, audit=sink).wrap(tool, name="t")
    with use_principal(Principal(role="r", identity="i")):
        try:
            return safe(), None, sink
        except Exception as exc:  # noqa: BLE001 — the decision is often an exception
            return None, exc, sink


# ── invariants that hold ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "attributes",
    [
        {},
        {"owner": "alice"},
        {"tenants": ["acme", "globex"]},
        {"meta": {"tier": "gold", "regions": ["eu", "us"]}},
        {"n": 1, "f": 1.5, "b": True, "nil": None},
        {"nested": [{"a": [1, 2]}, {"b": {"c": 3}}]},
    ],
)
def test_a_principal_can_always_be_rebuilt_from_another_principals_attributes(attributes):
    """The invariant `_freeze` broke, and the shape of every P0 in the fifth pass.

    Deriving a principal from one you already hold — narrowing a role, adding a claim
    after a lookup, copying one across a request boundary — is ordinary. It reads the
    attributes back out and hands them to the constructor, so the snapshot's output has
    to be valid input to the snapshot. Nothing in an example suite asks that.
    """
    first = Principal(role="r", identity="i", attributes=attributes)
    second = Principal(role="r", identity="i", attributes=dict(first.attributes))
    third = Principal(role="r", identity="i", attributes=second.attributes)
    assert dict(third.attributes) == dict(first.attributes)


@pytest.mark.parametrize(
    "attributes",
    [{"tenants": ["acme"]}, {"meta": {"k": "v"}}, {"deep": [{"x": [1]}]}],
)
def test_a_bound_anchor_is_never_writable_at_any_depth(attributes):
    """The other half of the same pair: it has to refuse writes *and* survive a rebuild."""
    who = Principal(role="r", identity="i", attributes=attributes)

    def writes(value):
        if isinstance(value, dict):
            with pytest.raises(TypeError):
                value["injected"] = True
            for inner in value.values():
                writes(inner)
        elif isinstance(value, list):
            with pytest.raises(TypeError):
                value.append("injected")
            for inner in value:
                writes(inner)

    writes(who.attributes)


@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_a_denied_call_never_executes_whatever_the_sink_does(tmp_path, mode):
    """Enforcement must not depend on the trail, in either direction."""
    (tmp_path / "log.jsonl").mkdir()  # every write to this sink fails
    calls: list[int] = []

    def tool() -> str:
        calls.append(1)
        return "ran"

    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({}), access="write")},
        permissions={"allowed": frozenset({"t"})},
    )
    safe = Gate(policy, audit=JSONLAuditSink(tmp_path / "log.jsonl"), mode=mode).wrap(tool, name="t")
    with use_principal(Principal(role="denied", identity="x")):
        if mode == "enforce":
            with pytest.raises(Exception):  # noqa: B017 — the type is the gate's to choose
                safe()
        else:
            safe()  # observe records the denial and runs the call anyway, by design
    assert calls == ([] if mode == "enforce" else [1]), "observe executes by design; enforce must not"


def test_a_log_this_library_writes_always_verifies(tmp_path):
    """For any value it can serialise — not for the three we happened to try."""
    backslash = chr(92)
    values = [
        "plain",
        backslash + "u0041",
        "C:" + backslash + "Users" + backslash + "bob",
        "regex " + backslash + "d+{2,}",
        "emoji \U0001f512 and é",
        '{"nested": "json"}',
        "line\nbreak\ttab",
    ]
    for index, value in enumerate(values):
        log = tmp_path / f"{index}.jsonl"
        sink = JSONLAuditSink(log)
        sink.record({"effect": "allow", "rule": "allow", "note": value})
        sink.record({"effect": "deny", "rule": "rbac", "note": value})
        ok, detail = verify_chain(log)
        assert ok, f"{value!r} was reported as forged: {detail}"


# ── known broken: the fifth pass, not yet fixed ──────────────────────────
#
# Each one is a property that should hold and does not. `strict=True` on the marker
# means closing the bug makes the test fail until the marker is removed, so a fix
# cannot land without the record of it being cleaned up.


def test_deriving_a_principal_from_a_frozen_one_does_not_raise():
    """Closed. `_freeze` had no branch for a structure that was already frozen, so it
    took the dict-subclass branch and wrote into a `ReadOnlyDict` — the class whose
    whole purpose is refusing writes, written to by the function that produced it."""
    who = Principal(role="r", identity="i", attributes={"meta": {"tier": "gold"}})
    Principal(role="r", identity="i", attributes=who.attributes)


def test_a_canary_inside_a_record_return_never_egresses():
    """`project_output` enters records now; the passes after it still expect a mapping."""

    @dataclasses.dataclass
    class Row:
        ok: str

    out, _, sink = _run(
        _policy(returns=Schema({"ok": Field(type="string")}), project_output=True),
        lambda: Row(ok=CANARY),
    )
    assert CANARY not in repr(out), f"the canary egressed: {out!r} redactions={sink.entries[-1]['redactions']}"


def test_an_undeclared_field_in_a_records_instance_dict_is_dropped():
    """Claimed as a P0 by the fifth pass and it does not reproduce: `_record_fields`
    reads the instance `__dict__`, which is where an attribute set after construction
    lands, so it is dropped like any other undeclared name. Kept as a passing invariant
    rather than deleted — it is the property the claim was reaching for."""

    @dataclasses.dataclass
    class Row:
        ok: str

    row = Row(ok="fine")
    row.secret = "leak"  # type: ignore[attr-defined]  — ordinary, and what __dict__ holds
    out, _, _ = _run(_policy(returns=Schema({"ok": Field(type="string")}), project_output=True), lambda: row)
    assert "leak" not in repr(out)


def test_a_value_subclass_is_returned_as_a_value():
    class Money(str):
        def __init__(self, *_a) -> None:
            self.currency = "EUR"

    out, _, _ = _run(
        _policy(returns=Schema({"ok": Field(type="string")}), project_output=True),
        lambda: {"ok": Money("12.30")},
    )
    assert out == {"ok": "12.30"}, f"a str subclass came back as {out!r}"


def test_recreating_the_log_directory_does_not_forget_the_erasure(tmp_path):
    import shutil

    directory = tmp_path / "logs"
    directory.mkdir()
    log = directory / "a.jsonl"
    JSONLAuditSink(log).record({"effect": "allow", "rule": "allow", "n": 1})
    shutil.rmtree(directory)
    directory.mkdir()
    JSONLAuditSink(log).record({"effect": "allow", "rule": "allow", "n": 2})
    ok, _ = verify_chain(log)
    assert not ok, "the log was erased and the replacement verifies clean"


def test_a_canary_two_suppressions_deep_never_egresses():
    def nested() -> None:
        try:
            try:
                try:
                    raise ValueError(f"driver: {CANARY}")
                except ValueError:
                    raise RuntimeError("layer one") from None
            except RuntimeError:
                raise LookupError("layer two") from None
        except LookupError as outer:
            raise KeyError("service") from outer

    _, exc, sink = _run(_policy(), nested)
    chain: list[str] = []
    current: BaseException | None = exc
    while current is not None and len(chain) < 12:
        chain.append(str(current))
        current = current.__cause__ or current.__context__
    assert CANARY not in " ".join(chain), f"reachable through the chain; redactions={sink.entries[-1]['redactions']}"


def test_a_strict_sink_does_not_put_the_original_exception_back_on_screen(tmp_path):
    import traceback

    class FailsOnlyOnPost:
        """The shape the claim needs: the PRE record lands, the POST record raises. A
        sink that is dead from the start raises at PRE, before the tool has run, so no
        unredacted exception exists to be chained to."""

        strict = True

        def __init__(self) -> None:
            self.seen = 0

        def record(self, entry: dict) -> None:
            self.seen += 1
            if self.seen > 1:
                raise ConnectionError("collector unreachable")

    def boom() -> None:
        raise RuntimeError(f"not found: {CANARY}")

    _, exc, _ = _run(_policy(), boom, audit=FailsOnlyOnPost())
    printed = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)) if exc else ""
    assert CANARY not in printed


def test_an_element_bound_on_an_untyped_field_is_still_refused_or_enforced():
    """`any` was exempted wholesale so a bound could not be shown dead. Array keywords on
    an untyped field are dead all the same — nothing consults them."""
    from histos.errors import PolicyError
    from histos.policy.schema import validate

    field = None
    try:
        field = Field(type="any", max_items=2)
    except PolicyError:
        return  # refusing is a fine answer
    assert validate(Schema({"xs": field}), {"xs": [1, 2, 3]}), "max_items=2 admitted three elements"


def test_a_nullable_element_union_keeps_the_bounds_beside_it():
    from histos import schema_from_json_schema
    from histos.policy.schema import validate

    field = schema_from_json_schema(
        {
            "type": "object",
            "properties": {
                "xs": {
                    "type": "array",
                    "maxItems": 2,
                    "items": {"anyOf": [{"type": "string", "maxLength": 3}, {"type": "null"}]},
                }
            },
        }
    ).fields["xs"]
    assert field.max_items == 2, "the array bound went with the element union"
    assert validate(Schema({"xs": field}), {"xs": ["toolong"]}), "the element bound is not enforced"


def test_a_return_with_shared_references_does_not_hang():
    """Claimed as exponential at 22 shared references; it returns in well under a
    second. The walk does re-visit shared references, so the depth at which it bites is
    higher than claimed — this pins the depth that was actually asserted, and the
    unbounded-walk question stays open above it."""

    @dataclasses.dataclass
    class Node:
        left: typing.Any = None
        right: typing.Any = None

    node: typing.Any = "leaf"
    for _ in range(22):
        node = Node(left=node, right=node)

    import threading

    done: list[bool] = []

    def run() -> None:
        _run(_policy(returns=Schema({"ok": Field(type="string")}), project_output=True), lambda: {"ok": node})
        done.append(True)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=5)
    assert done, "the post-gate did not return within five seconds"
