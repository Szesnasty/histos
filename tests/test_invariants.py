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

import contextlib
import dataclasses
import typing
import warnings

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
from histos.errors import PolicyError
from histos.mediate.identity import _current_principal
from histos.policy.authz import Constraint

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


# ── the fifth pass, P2 and P3 ────────────────────────────────────────────


def test_the_third_mutable_container_is_read_only_too():
    """`_freeze` swapped dict and list and left `set` writable, while `in`, `<=` and `&`
    are exactly what a Constraint compares — so a set-valued claim could be edited into a
    different authorization answer after it was bound."""
    who = Principal(role="r", identity="i", attributes={"scopes": {"read"}})
    with pytest.raises(TypeError):
        who.attributes["scopes"].add("admin")
    assert who.attributes["scopes"] == {"read"}, "a ReadOnlySet still compares as a set"


def test_a_sink_whose_counter_raises_cannot_kill_a_call(tmp_path):
    """Both `failed` reads sat outside the try that exists so a sink never decides a
    call, and `getattr(obj, name, default)` only swallows AttributeError."""

    class Gauge:
        @property
        def failed(self) -> int:
            raise ConnectionError("the collector is down")

        def record(self, entry: dict) -> None:
            return None  # total: this sink cannot fail

    safe = Gate(_one_write_tool_for_invariants(), audit=Gauge()).wrap(lambda: "receipt", name="charge")  # noqa: E731
    with use_principal(Principal(role="teller", identity="t")):
        assert safe() == "receipt"


def test_strict_has_to_be_written_rather_than_merely_answered():
    """A generic attribute answerer returns something truthy for every name, so
    "evidence outranks availability" was an opt-in nobody had to write."""

    class Proxy:
        def __getattr__(self, name: str):  # every attribute answers
            return object()

        def record(self, entry: dict) -> None:
            raise ConnectionError("collector unreachable")

    gate_ = Gate(_one_write_tool_for_invariants(), audit=Proxy())
    safe = gate_.wrap(lambda: "receipt", name="charge")  # noqa: E731
    with use_principal(Principal(role="teller", identity="t")), warnings.catch_warnings():
        warnings.simplefilter("ignore")
        assert safe() == "receipt", "a proxy sink silently became fatal"


def test_the_default_sinks_losses_reach_the_counter_a_host_alarms_on():
    """`audit_failures` is documented as counting them whatever the sink was, and read an
    attribute only the file sink had."""
    sink = InMemoryAuditSink(2)
    gate_ = Gate(_one_write_tool_for_invariants(), audit=sink)
    safe = gate_.wrap(lambda: "receipt", name="charge")  # noqa: E731
    with use_principal(Principal(role="teller", identity="t")):
        for _ in range(4):
            safe()
    assert sink.dropped and gate_.audit_failures >= sink.dropped


def test_an_uncomparable_bound_argument_does_not_crash_a_wrap():
    """A partial bound to a numpy array or a DataFrame compares to a non-bool, and
    `bool()` on that raises — out of `Gate.wrap`, where a decision was owed."""
    import functools

    class Arrayish:
        def __eq__(self, other):  # noqa: ANN001 — the point is that it is not a bool
            return Arrayish()

        def __bool__(self):
            raise ValueError("truth value of an array is ambiguous")

        __hash__ = None  # type: ignore[assignment]

    def send(payload, channel=None):
        return channel

    gate_ = Gate(_one_write_tool_for_invariants("send"))
    gate_.wrap(functools.partial(send, Arrayish()), name="send")
    with pytest.raises(PolicyError):
        gate_.wrap(functools.partial(send, Arrayish()), name="send")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"type": "array", "item_type": "integer", "max_length": 8},
        {"type": "array", "item_type": "string", "minimum": 1},
        {"type": "integer", "minimum": 10, "exclusive_maximum": 10},
        {"type": "number", "exclusive_minimum": 10.0, "maximum": 5.0},
    ],
)
def test_a_bound_that_no_element_or_value_can_reach_is_refused(kwargs):
    """An array was granted the string and numeric keywords unconditionally, and the
    unsatisfiable check never compared an inclusive bound against the strict twin on the
    other side."""
    from histos.policy.schema import Field as _Field

    with pytest.raises(PolicyError):
        _Field(**kwargs)


def test_an_array_of_nulls_admits_only_null():
    """Converting the sentinel to `None` said nothing at all: `_check_scalar` then took
    `item_type=None` as "no element type declared" and admitted every type."""
    from histos import schema_from_json_schema
    from histos.policy.schema import Schema as _Schema
    from histos.policy.validation import validate

    field = schema_from_json_schema(
        {"type": "object", "properties": {"xs": {"type": "array", "items": {"type": "null"}}}}
    ).fields["xs"]
    schema = _Schema({"xs": field})
    assert validate(schema, {"xs": ["anything"]}), "an array of nulls accepted a string"
    assert validate(schema, {"xs": [None]}) == []


def test_a_composed_form_body_is_still_refused_rather_than_dropped():
    """`allOf: [{$ref: ...}]` is the ordinary way a spec extends a shared model, and
    looking only at the top level read it as declaring nothing."""
    from histos import sources_from_openapi

    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/x": {
                "post": {
                    "operationId": "t",
                    "requestBody": {
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {"allOf": [{"$ref": "#/components/schemas/Form"}]}
                            }
                        }
                    },
                }
            }
        },
        "components": {"schemas": {"Form": {"type": "object", "properties": {"amount": {"type": "integer"}}}}},
    }
    with pytest.raises(PolicyError):
        sources_from_openapi(spec)


def _one_write_tool_for_invariants(name: str = "charge") -> Policy:
    return Policy(
        tools={name: ToolContract(name=name, args=Schema({}), access="write")},
        permissions={"teller": frozenset({name})},
    )


# ── the sixth pass: what the repackaging made legible ────────────────────


def _leaf(base, value, token):
    """A builtin leaf carrying one author-defined attribute — `class Money(str)`."""
    obj = type(f"Sub{base.__name__.title()}", (base,), {})(value)
    obj.hidden = token
    return obj


def _slotted_leaf(token):
    """The same thing written the idiomatic way, and subclassed once more.

    `class Money(str): __slots__ = ("hidden",)` keeps its attribute off `__dict__`, and
    a class that inherits it declares `__slots__ = ()` of its own — so reading the
    instance's own class alone finds nothing at all.
    """
    base = type("Slotted", (str,), {"__slots__": ("hidden",)})
    obj = type("Derived", (base,), {"__slots__": ()})("12.30")
    obj.hidden = token
    return obj


@pytest.mark.parametrize("base,value", [(str, "12.30"), (int, 7), (bytes, b"x"), (float, 1.5)])
def test_a_canary_in_an_attribute_of_a_leaf_subclass_does_not_reach_the_caller(base, value):
    """For any value the scanners read end to end, what hangs *off* it is still output.

    `_record_fields` refuses a leaf on purpose — projection must not shred
    `Money("12.30")` into `{"currency": "EUR"}`. The scanners inherited that refusal and
    have the opposite need: `class Money(str)` with a token on it left through the
    default configuration with `effect=allow` and `redactions: []`, so the trail called
    the output clean. The sixth distinct shape a canary has escaped in.
    """
    out, exc, sink = _run(_policy(), lambda: {"v": _leaf(base, value, CANARY)})
    reached = getattr(out.get("v"), "hidden", None) if isinstance(out, dict) else None
    assert reached != CANARY, "a canary on a leaf's attribute reached the caller"
    assert sink.entries[-1]["redactions"], "and the trail recorded nothing about it"


def test_a_canary_in_an_inherited_slot_of_a_leaf_does_not_reach_the_caller():
    """However the class chose to store it. Reachability is the question, not layout."""
    out, exc, sink = _run(_policy(), lambda: {"v": _slotted_leaf(CANARY)})
    reached = getattr(out.get("v"), "hidden", None) if isinstance(out, dict) else None
    assert reached != CANARY, "a canary in an inherited slot reached the caller"
    assert sink.entries[-1]["redactions"], "and the trail recorded nothing about it"


def test_the_lock_key_and_the_erasure_key_answer_opposite_questions(tmp_path, monkeypatch):
    """Two maps, two requirements, and no single key can satisfy both.

    The lock must collapse every spelling of one file onto one entry: `realpath` sees
    through symlinks and nothing else, so a macOS firmlink and a Linux bind mount each
    hand one log a second spelling, and two sinks over them took two locks and
    interleaved appends into one hash chain.

    The erasure memory must do the reverse and survive `rm -rf logs && mkdir logs` — a
    recreated directory is a new inode, and anchoring the high-water mark to one orphans
    it exactly when a deployment wipes a volume, after which the replaced log verifies
    clean. Sharing one key between them traded one of these for the other, twice.
    """
    import os

    from histos.trail.logpath import _lock_key, _path_key

    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real)  # stands in for the mount: same dev/ino, two spellings
    monkeypatch.setattr(os.path, "realpath", lambda p, **_: os.fspath(p))
    assert _lock_key(real / "log.jsonl") == _lock_key(alias / "log.jsonl")

    monkeypatch.undo()
    home = tmp_path / "logs"
    home.mkdir()
    before = _path_key(home / "log.jsonl")
    home.rmdir()
    home.mkdir()  # a new inode, and the same place
    assert _path_key(home / "log.jsonl") == before


def test_a_bound_the_source_wrote_is_never_a_reason_to_refuse_the_whole_tool():
    """For any legal JSON Schema, the projection imports it or names what it cannot do.

    `{"minimum": 1, "maximum": 100}` with no `type` is legal, ordinary, and what a great
    many MCP servers emit. A guard against dead bounds turned it into a `PolicyError`
    that takes the whole tool with it — the control refusing honest work, which is a
    failure in the same way a leak is.
    """
    from histos import schema_from_json_schema

    schema = schema_from_json_schema(
        {
            "type": "object",
            "properties": {"limit": {"minimum": 1, "maximum": 100}, "tags": {"maxItems": 3}},
            "required": ["limit"],
        }
    )
    assert set(schema.fields) == {"limit", "tags"}


@pytest.mark.parametrize("value", [0, 101, 5.5])
def test_an_untyped_bound_that_imports_is_a_bound_that_fires(value):
    """And the other half: importing it must not be the silent no-op the guard refused.

    Refusing the tool and admitting an unenforced bound are the same failure wearing
    different clothes. If `type` is absent the bound has to be dispatched on the value,
    exactly as the string bounds beside it already are.
    """
    from histos import schema_from_json_schema
    from histos.policy.validation import validate

    schema = schema_from_json_schema(
        {"type": "object", "properties": {"limit": {"minimum": 1, "maximum": 100, "multipleOf": 1}}}
    )
    assert validate(schema, {"limit": value}), f"{value!r} passed a bound the source declared"
    assert validate(schema, {"limit": 50}) == []
    assert validate(schema, {"limit": "not a number"}) == [], "an untyped field still admits other types"


def test_a_form_body_is_refused_however_deep_its_allOf_goes():
    """For any depth, a body naming fields the projection would lose is refused.

    The walk gives up past four levels and returned "declares nothing", which is the
    silent drop it was written to prevent — reachable by a hostile spec at the cost of
    six lines of YAML.
    """
    from histos.importers.openapi import _declares_fields

    depth = 8
    schemas = {
        f"L{i}": (
            {"allOf": [{"$ref": f"#/components/schemas/L{i + 1}"}]}
            if i + 1 < depth
            else {"properties": {"iban": {"type": "string"}}}
        )
        for i in range(depth)
    }
    spec = {"components": {"schemas": schemas}}
    content = {"application/x-www-form-urlencoded": {"schema": {"$ref": "#/components/schemas/L0"}}}

    assert _declares_fields(spec, content, "pay"), "a declared form body was dropped in silence"


def test_no_identity_is_bound_once_every_scope_has_been_left():
    """For any order of exits, leaving every scope leaves nothing bound.

    `with` is LIFO and cannot produce this, but a middleware that enters on request-start
    and exits on response-end can: two overlapping requests in one context, the first to
    finish exiting the outer scope. `__exit__` reset *its own* token without checking
    whether it was the innermost, so `ContextVar.reset` restored the value from before
    that token — and the inner scope's later reset then restored the outer's principal.
    Both scopes closed, and the code after them ran as the first caller.
    """
    outer = use_principal(Principal(role="a", identity="outer"))
    inner = use_principal(Principal(role="b", identity="inner"))
    outer.__enter__()
    inner.__enter__()

    with contextlib.suppress(PolicyError):  # refusing is a fine answer; leaking is not
        outer.__exit__(None, None, None)
    with contextlib.suppress(PolicyError):
        inner.__exit__(None, None, None)

    left = _current_principal.get()
    assert left is None, f"{left.identity!r} is still bound after both its scopes were left"


@pytest.mark.parametrize("value", [10**15 + 1, 10**18 + 1, 2**60 + 1, 10**20 + 7, 9, 10])
def test_two_policies_with_one_content_hash_reach_the_same_verdict(value):
    """The pinning guarantee, stated as the property it actually is.

    `content_hash` is what an approval binds to, what the lockfile pins and what drift
    detection compares — so two rulesets sharing a hash must be one ruleset. Numbers are
    rendered through `canonical_number` before hashing, deliberately: `JSON.parse`
    collapses `3` and `3.0`, so a hash a second implementation has to reproduce cannot
    depend on a distinction that implementation's parser cannot see.

    That collapse is only honest if the two spellings *enforce* identically, and
    `multiple_of` had two code paths — exact modulo when both sides were `int`, a float
    division plus `isclose(rel_tol=1e-9)` otherwise. At 1e18 that tolerance is a window
    about a billion wide, so `multiple_of=3.0` accepted what `multiple_of=3` rejected,
    under one hash.
    """
    from histos.policy.validation import validate

    as_int = Schema({"n": Field(type="integer", multiple_of=3)})
    as_float = Schema({"n": Field(type="integer", multiple_of=3.0)})

    def content_hash(schema):
        return Policy(
            tools={"t": ToolContract(name="t", args=schema)}, permissions={"r": frozenset({"t"})}
        ).content_hash()

    assert content_hash(as_int) == content_hash(as_float), "the premise: these two hash the same"
    assert bool(validate(as_int, {"n": value})) == bool(validate(as_float, {"n": value})), (
        f"{value} is admitted by one spelling of the same hashed policy and refused by the other"
    )


@pytest.mark.parametrize("bad", [None, "high", "HIGH", 3])
def test_a_contract_is_refused_where_it_is_built_not_where_it_is_hashed(bad):
    """The rule `authz.py` states and `ToolContract` applies to two of its three fields.

    `access` and `on_output_violation` are checked in `__post_init__` and name what was
    wrong. `sensitivity` was not, so a wrong one built fine and surfaced later as
    `AttributeError: 'str' object has no attribute 'value'` from inside `content_hash()`
    — at Gate construction, naming neither the tool nor the field. A policy that cannot
    be hashed is refused where it is written.
    """
    with pytest.raises(PolicyError, match="sensitivity"):
        ToolContract(name="t", args=Schema({}), sensitivity=bad)


def test_no_single_invisible_character_hides_a_canary():
    """For *any* Unicode format character, not the five that were listed.

    A canary escaped once through a zero-width space, and the fix was a set holding that
    character and four of its neighbours. All five are Unicode category `Cf`, and so are
    the hundred and sixty-five the set did not name: U+00AD SOFT HYPHEN, the bidi
    overrides U+202A–U+202E, and the tag block U+E0020–U+E007F, which mirrors ASCII
    invisibly and is the standard way an instruction is smuggled past a human reading the
    text. Every one of them renders as nothing and defeats verbatim matching.

    An enumeration was the wrong shape for a rule, which is why this asks the rule.
    """
    import unicodedata

    from histos.decide.canary import find, find_normalized

    token = "CANARY-7f3a-DO-NOT-LEAK"
    tokens = frozenset({token})
    missed = [
        f"U+{cp:04X} {unicodedata.name(chr(cp), '?')}"
        for cp in range(0x110000)
        if unicodedata.category(chr(cp)) == "Cf"
        and not (
            find(token[:6] + chr(cp) + token[6:], tokens) or find_normalized(token[:6] + chr(cp) + token[6:], tokens)
        )
    ]
    assert not missed, f"{len(missed)} invisible characters hide a canary, e.g. {missed[:4]}"


def test_the_invisible_character_table_still_covers_what_python_knows():
    """The enumeration cannot rot in silence.

    The table is written out rather than computed, because scanning 0x110000 codepoints
    at import costs about a third of a second and this library's import time is itself a
    test. That trade is only safe while something checks it, so this is that something:
    if a future Unicode release adds a format character, this fails and names it.
    """
    import unicodedata

    from histos.decide.canary import _STRIP_TABLE

    unknown = [
        f"U+{cp:04X} {unicodedata.name(chr(cp), '?')}"
        for cp in range(0x110000)
        if unicodedata.category(chr(cp)) == "Cf" and cp not in _STRIP_TABLE
    ]
    assert not unknown, f"Unicode {unicodedata.unidata_version} knows format characters the table does not: {unknown}"


@pytest.mark.parametrize(
    "secret",
    [
        "4111 1111 1111 1111",  # PAN, Luhn-clean, issuer prefix
        "DE89370400440532013000",  # IBAN, mod-97
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",  # JWT that decodes
    ],
)
def test_an_invisible_character_does_not_smuggle_a_secret_past_the_gate(secret):
    """The twin of the canary gap, in the control that hard-denies.

    `deny_secret_args` is on by default and refuses a checksum-confidence secret in an
    argument. The canary scan beside it normalises before matching; the detectors match
    the text as it came, so one `Cf` character — a soft hyphen, a bidi mark, a tag
    character — split every pattern and all 170 of them walked a PAN into the tool.

    Both halves are asked here: the denial has to hold, and it has to be the same denial,
    because a control that reads as on and is not is worse than one that is off.
    """
    from histos.decide import detectors

    reached: list[str] = []
    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({"note": Field(type="string")}), deny_secret_args=True)},
        permissions={"r": frozenset({"t"})},
    )
    safe = Gate(policy, audit=InMemoryAuditSink()).wrap(lambda note: reached.append(note), name="t")

    def call(argument):
        with use_principal(Principal(role="r", identity="i")), contextlib.suppress(Exception):
            safe(note=argument)

    call(secret)
    assert not reached, "the premise: a plain checksum secret is denied"

    smuggled = secret[:6] + "­" + secret[6:]  # SOFT HYPHEN, invisible in every renderer
    call(smuggled)
    assert not reached, f"a soft hyphen walked a {detectors.scan_string(secret)[0].kind} into the tool"

    # And on the way out, where the same detectors redact rather than deny.
    redacted, kinds = detectors.redact_string(f"here it is: {smuggled}")
    assert kinds, "the outbound half found nothing"
    assert secret[:6] not in redacted and secret[-6:] not in redacted, f"only partly redacted: {redacted!r}"


@pytest.mark.parametrize("padding", [1_000, 100_000])
def test_a_secret_carrying_an_invisible_character_is_never_partly_redacted(padding):
    """Both sides of the index-map bound, because half a redaction is the worse outcome.

    Locating a hit found in stripped text needs a per-character map back to the original,
    which is the Python loop `str.translate` is here to avoid — so it is bounded, exactly
    as the canary index map is. Under the bound the span has to cover the interleaved
    format characters or their fragments stay behind; over it the answer is the whole
    text, which drops the value instead of redacting part of it.
    """
    from histos.decide import detectors

    pan = "4111 1111 1111 1111"
    smuggled = pan[:6] + "­" + pan[6:]
    text = "note " * (padding // 5) + smuggled + " end"

    redacted, kinds = detectors.redact_string(text)
    assert "pan" in kinds, "the card number was not found at all"
    assert pan[:6] not in redacted, f"the leading digits survived: {redacted[:80]!r}"
    assert pan[-6:] not in redacted, "the trailing digits survived"


# ── standing checks: the shapes that keep coming back, asked as rules ─────
#
# Round six found ten defects and eight of them were two patterns wearing different
# clothes. Sampling the same distribution a seventh time is worth less than making the
# two patterns unable to recur, so each one is asked here as a property over the whole
# surface by reflection — a new field or a new walker is covered the day it is written,
# without anyone remembering to add a case.


def _cyclic_list():
    x = ["a"]
    x.append(x)
    return x


def _cyclic_dict():
    d = {"a": "b"}
    d["self"] = d
    return d


def _deep(levels=20_000):
    """Deep enough to exhaust the stack on *any* runner, which 4000 was not.

    A 4000-deep argument fits the 8 MB thread stack a Linux or macOS runner gives you and
    does not fit Windows' 1 MB — so the first version of this check was green locally and
    green on ten of eleven CI jobs while the defect it was written for was still open on
    the eleventh. A bound that only one platform enforces is not a bound this suite can
    rely on, so the data goes past all of them.
    """
    top = current = {}
    for _ in range(levels):
        nxt: dict = {"pad": "x"}
        current["k"] = nxt
        current = nxt
    return top


@pytest.mark.parametrize("shape", ["cyclic_list", "cyclic_dict", "deep"])
@pytest.mark.parametrize("side", ["argument", "return"])
def test_every_call_gets_a_decision_and_a_record_however_the_data_is_shaped(shape, side):
    """A gate that raises where a verdict was owed has failed, whichever way it fails.

    Six of this library's walkers recurse over data the caller or the tool chooses. The
    outbound ones are bounded — `_over_output_budget` wraps both of its passes and
    answers "too deep to walk is too deep to scan". The inbound digest was not: a
    self-referential argument reached `canonical_json` and the caller got a
    `RecursionError` with **nothing written to the trail at all** — no execution, which
    is the right direction, but no decision and no record either, which is not a denial,
    it is an absence.
    """
    make = {"cyclic_list": _cyclic_list, "cyclic_dict": _cyclic_dict, "deep": _deep}[shape]
    ran: list[int] = []
    policy = Policy(
        tools={
            "t": ToolContract(
                name="t",
                args=Schema({"a": Field(type="any", required=False)}),
                returns=Schema({"k": Field(type="any", required=False)}),
            )
        },
        permissions={"r": frozenset({"t"})},
        canaries=frozenset({CANARY}),
    )
    sink = InMemoryAuditSink()
    tool = (lambda a=None: ran.append(1) or make()) if side == "return" else (lambda a=None: ran.append(1) or "ok")
    safe = Gate(policy, audit=sink).wrap(tool, name="t")

    with use_principal(Principal(role="r", identity="i")):
        try:
            safe(a=make()) if side == "argument" else safe()
        except RecursionError:
            pytest.fail(f"a {shape} {side} raised RecursionError where a decision was owed")
        except Exception:  # noqa: BLE001 — a denial is a fine answer; an unhandled walk is not
            pass

    assert sink.entries, f"a {shape} {side} produced no audit record at all"


# One legal, *different* value per field. A field absent from both this map and the
# metadata list below fails the test that follows, which is the point: the day someone
# adds a knob the gate reads, this says so rather than letting it sit outside the hash.
_A_DIFFERENT_VALUE: dict[str, typing.Any] = {
    # Field
    "type": "integer", "required": False, "enum": (1, 2), "max_length": 7, "min_length": 2,
    "pattern": "^x$", "sensitive": "pii", "nullable": True, "item_type": "string",
    "max_items": 4, "min_items": 1, "item_enum": ("a",), "unique_items": True,
    "minimum": 5, "maximum": 9, "exclusive_minimum": 4, "exclusive_maximum": 10, "multiple_of": 2,
    # ToolContract
    "access": "write", "rate_limit": 3, "budget": 100, "requires_confirmation": True,
    "confirmation_expires_in": 60, "requires_escalation": True, "scan_output_for_canary": False,
    "deny_secret_args": False, "redact_secret_output": False, "project_output": True,
    "strict_returns": True, "on_output_violation": "deny",
    "args": Schema({"different": Field(type="integer")}),
    "returns": Schema({"different": Field(type="integer")}),
}  # fmt: skip

# The only exemption, and it is structural rather than a judgement: a contract's `name`
# is the key it is filed under, so changing it is adding a different tool and removing
# this one, which the hash sees anyway. Everything else has to be in there — including
# `sensitivity`, `constraints` and `bindings`, which an earlier draft of this test waved
# through as "metadata" and which the gate very much enforces.
_NOT_A_RULE = frozenset({"name"})


@pytest.mark.parametrize("holder", ["Field", "ToolContract"])
def test_everything_the_gate_enforces_is_inside_the_content_hash(holder):
    """An approval binds to this hash, the lockfile pins it, drift detection compares it.

    So a knob the engine reads and the hash does not cover is two rulesets wearing one
    identity, and every one of those three reports green across the difference. Asked by
    reflection over the dataclass rather than from a list somebody maintains, because a
    list is what fails silently when a field is added.
    """
    from histos.policy.authz import Binding, Constraint
    from histos.policy.contracts import Sensitivity

    _A_DIFFERENT_VALUE["sensitivity"] = Sensitivity.HIGH
    _A_DIFFERENT_VALUE["constraints"] = (Constraint("f", "eq", value=1),)
    _A_DIFFERENT_VALUE["bindings"] = (Binding("f", "tenant"),)

    def content_hash(field=None, **contract):
        contract.setdefault("args", Schema({"a": field if field is not None else Field(type="any")}))
        return Policy(
            tools={"t": ToolContract(name="t", **contract)}, permissions={"r": frozenset({"t"})}
        ).content_hash()

    baseline = content_hash()
    target = Field if holder == "Field" else ToolContract
    unpinned, uncovered = [], []
    for spec in dataclasses.fields(target):
        if spec.name in _NOT_A_RULE:
            continue
        if spec.name not in _A_DIFFERENT_VALUE:
            uncovered.append(spec.name)
            continue
        value = _A_DIFFERENT_VALUE[spec.name]
        moved = (
            content_hash(field=dataclasses.replace(Field(type="any"), **{spec.name: value}))
            if holder == "Field"
            else content_hash(**{spec.name: value})
        )
        if moved == baseline:
            unpinned.append(spec.name)

    assert not uncovered, f"{holder} has fields this test says nothing about: {uncovered}"
    assert not unpinned, f"{holder} fields the gate enforces and the content hash ignores: {unpinned}"


@pytest.mark.parametrize("holder", ["Field", "ToolContract"])
def test_every_enforced_field_survives_the_document(holder):
    """A policy written to a file and read back has to be the same policy.

    The sibling check asks whether a field is inside `content_hash`. This asks the other
    half, which is not implied by it: a field can be hashed in memory and still be
    dropped by the writer or the reader, and then the committed document enforces
    something the author never wrote — with the lockfile and drift detection both
    comparing the version that lost it.

    Same reflection, same reason: a list of fields to check is the thing that goes stale.
    """
    import json

    from histos import dump_bundle, load_bundle
    from histos.policy.authz import Binding, Constraint
    from histos.policy.contracts import Sensitivity

    _A_DIFFERENT_VALUE["sensitivity"] = Sensitivity.HIGH
    _A_DIFFERENT_VALUE["constraints"] = (Constraint("f", "eq", value=1),)
    _A_DIFFERENT_VALUE["bindings"] = (Binding("f", "tenant"),)

    plain = Field(type="any")
    base = ToolContract(name="t", args=Schema({"a": plain}), returns=Schema({"r": Field(type="any")}))

    def written_and_read_back(tool):
        before = Policy(tools={"t": tool}, permissions={"r": frozenset({"t"})}, canaries=frozenset({CANARY}))
        after = load_bundle(json.loads(json.dumps(dump_bundle(before))))
        return before.content_hash(), after.content_hash()

    lost, uncovered = [], []
    for spec in dataclasses.fields(Field if holder == "Field" else ToolContract):
        if spec.name in _NOT_A_RULE or spec.name in ("args", "returns"):
            continue  # `args`/`returns` are covered field by field via the Field pass
        if spec.name not in _A_DIFFERENT_VALUE:
            uncovered.append(spec.name)
            continue
        value = _A_DIFFERENT_VALUE[spec.name]
        tool = (
            dataclasses.replace(base, args=Schema({"a": dataclasses.replace(plain, **{spec.name: value})}))
            if holder == "Field"
            else dataclasses.replace(base, **{spec.name: value})
        )
        try:
            before_hash, after_hash = written_and_read_back(tool)
        except Exception as exc:  # noqa: BLE001 — a writer that cannot write it is the same defect
            lost.append(f"{spec.name} ({type(exc).__name__}: {exc})")
            continue
        if before_hash != after_hash:
            lost.append(f"{spec.name} (came back as a different ruleset)")

    assert not uncovered, f"{holder} has fields this test says nothing about: {uncovered}"
    assert not lost, f"{holder} fields that do not survive being written to a document: {lost}"


# The shapes the output scanners can and cannot see into, pinned. SECURITY.md states this
# matrix in two places and drifted from it in both, across two rounds, in the *safe*
# direction — it claimed a dataclass field was unreachable for two passes after the scan
# started reading one. An understatement in a security document still misleads: it has an
# operator distrust a control that works, or buy a mitigation they already own. So the
# matrix lives here, where it fails when it stops being true.
_REACHED_BY_THE_SCANNERS = {
    "dataclass field": True,
    "NamedTuple field": True,
    "instance __dict__": True,  # Pydantic v1 and v2, and every ordinary class
    "attribute on a str subclass": True,
    "__slots__ only": False,  # cannot be told from a stdlib value type's internals
    "@property": False,  # arbitrary user code; running it inside a check is the thing not to do
}


@pytest.mark.parametrize("shape", sorted(_REACHED_BY_THE_SCANNERS))
def test_the_documented_reach_of_the_output_scan_is_the_real_one(shape):
    """If this fails, the fix includes SECURITY.md — in whichever direction it moved.

    "Detection reaches exactly as far as redaction does" is a claim a reader acts on, and
    the two passages stating it are listed in the docstring of this module's sibling
    check. Widening the reach without widening the document is the failure this catches;
    so is narrowing it.
    """
    import collections

    @dataclasses.dataclass
    class Row:
        hidden: str

    class InDict:
        def __init__(self, value):
            self.hidden = value

    class Money(str):
        def __new__(cls, amount, hidden):
            obj = super().__new__(cls, amount)
            obj.hidden = hidden
            return obj

    class Slotted:
        __slots__ = ("hidden",)

        def __init__(self, value):
            self.hidden = value

    class Computed:
        @property
        def hidden(self):
            return CANARY

    make = {
        "dataclass field": lambda: Row(CANARY),
        "NamedTuple field": lambda: collections.namedtuple("Nt", "hidden")(CANARY),
        "instance __dict__": lambda: InDict(CANARY),
        "attribute on a str subclass": lambda: Money("12.30", CANARY),
        "__slots__ only": lambda: Slotted(CANARY),
        "@property": Computed,
    }[shape]

    out, _exc, sink = _run(_policy(), make)
    escaped = getattr(out, "hidden", None) == CANARY
    reached = not escaped
    assert reached == _REACHED_BY_THE_SCANNERS[shape], (
        f"the scan {'now reaches' if reached else 'no longer reaches'} {shape!r}; "
        f"update this table, the two passages in SECURITY.md that state it, and D7 in "
        f"docs/tech-debt.md — trail said redactions={sink.entries[-1]['redactions']}"
    )


# Both documents state the reach, and naming only one of them is how they came apart:
# SECURITY.md was corrected and `docs/tech-debt.md` D7 went on describing the old, wider
# residual for another pass. A reviewer found it, not this suite.
_RESIDUAL_STATED_IN = ("SECURITY.md", "docs/tech-debt.md")


@pytest.mark.parametrize("document", _RESIDUAL_STATED_IN)
def test_both_documents_name_the_same_residual(document):
    """Neither may claim the scan misses a shape the table above says it reaches."""
    import pathlib as _pathlib

    text = (_pathlib.Path(__file__).resolve().parents[1] / document).read_text(encoding="utf-8")
    reached_now = [s for s, ok in _REACHED_BY_THE_SCANNERS.items() if ok]
    for shape, phrase in (("dataclass field", "dataclass"), ("instance __dict__", "Pydantic")):
        assert shape in reached_now  # guard: this test is about shapes that ARE reached
        claim = f"{phrase} attribute or any other opaque object"
        assert claim not in text, f"{document} still says {phrase} attributes are unreachable"
    assert "__slots__" in text, f"{document} does not state the residual that is still real"


@pytest.mark.parametrize(
    "bad",
    [
        {"rate_limit": -1},
        {"rate_limit": 0},
        {"rate_limit": 1.5},
        {"rate_limit": "ten"},
        {"rate_limit": True},
        {"budget": -5},
        {"budget": "many"},
        {"confirmation_expires_in": -1},
        {"confirmation_expires_in": 0},
    ],
)
def test_a_limit_that_cannot_be_enforced_is_refused_where_it_is_written(bad):
    """The same rule as `sensitivity`, one field further along.

    `access`, `on_output_violation`, `sensitivity` and every bound on a `Field` are
    checked in `__post_init__`. The three integers on a contract were not, so
    `budget: "many"` built fine and then answered `internal_error` to every call for the
    life of the process, and `rate_limit: -1` denied every call with the reason
    "rate_limit" — which reads as "you are calling too often" to an operator who has
    called zero times. Fail-closed, and a typo that can only be diagnosed at runtime.

    Zero is refused rather than read as "never": a tool nobody may call is spelled by not
    granting it, and an expiry of zero seconds makes every approval stale before it is
    used. Nothing in the tests, demos or docs spells it the other way.
    """
    with pytest.raises(PolicyError, match=next(iter(bad))):
        ToolContract(name="t", args=Schema({}), **bad)


@pytest.mark.parametrize("good", [{}, {"rate_limit": 1}, {"budget": 1000}, {"confirmation_expires_in": 60}])
def test_an_ordinary_limit_is_still_accepted(good):
    """The other half, because refusing honest work is the failure in the other direction."""
    ToolContract(name="t", args=Schema({}), **good)


def test_an_approval_does_not_survive_the_ruleset_it_was_granted_under():
    """The control three documents claim and nothing implemented.

    `README.md`, and two docstrings I wrote in this file earlier today on the strength
    of a comment in `authz.py`, say an approval binds to the policy hash. It does not:
    the fingerprint covers the tool, the arguments and the whole principal, and nothing
    about the rules in force. So an approval granted at 10:00 under a strict ruleset is
    still spendable at 10:06 after a deploy loosened it, and the audit line then reads
    "approved by the finance officer" about a decision made under rules that officer
    never saw.

    This is not a remote bypass — spending it needs the ability to change the Gate's
    policy, and anyone with that can simply drop `requires_confirmation`. It is the
    evidence story failing quietly, which is the thing the confirmation mechanism is
    for, and it was claimed as working.
    """
    from histos.mediate.approvals import ApprovalStore, request_fingerprint

    def ruleset(**extra):
        return Policy(
            tools={
                "pay": ToolContract(
                    name="pay",
                    args=Schema({"amount": Field(type="integer")}),
                    requires_confirmation=True,
                    **extra,
                )
            },
            permissions={"r": frozenset({"pay"})},
        )

    strict, loose = ruleset(), ruleset(scan_output_for_canary=False)
    assert strict.content_hash() != loose.content_hash(), "the premise: two different rulesets"

    alice = Principal(role="r", identity="alice")
    paid: list[int] = []
    store = ApprovalStore(strict)
    gate = Gate(strict, audit=InMemoryAuditSink(), confirm=store.as_confirm())
    safe = gate.wrap(lambda amount: paid.append(amount) or "ok", name="pay")

    store.grant(request_fingerprint("pay", {"amount": 100}, alice))
    gate.policy = loose  # a deploy, between the approval and the call

    with use_principal(alice), contextlib.suppress(Exception):
        safe(amount=100)
    assert not paid, "an approval issued against one ruleset was spent under another"


class _Uncopyable:
    """A DB handle, an ORM row, a lock — anything `deepcopy` refuses."""

    def __deepcopy__(self, memo):
        raise TypeError("this object cannot be copied")


@pytest.mark.parametrize("seam", ["confirm", "escalate", "resolver"])
def test_a_host_callback_can_never_edit_what_the_tool_runs(seam):
    """The property `_callback_args` exists for, asked at all three of its seams.

    It handed the callback a `deepcopy`, and `dict(args)` when that failed — a shallow
    copy, in which every nested value is still the caller's. So a callback writing
    `req.args["payload"]["amount"] = 999` reached the live dict, and the tool ran with
    999 while the audit digest, taken before the callback, recorded 1. Execution and
    trail disagreeing is the failure the function was written to prevent, reachable
    through its own degradation arm.

    A call whose arguments cannot be detached is refused now, at every seam, naming the
    argument. The pause for confirmation is refused too: the fingerprint an approval is
    granted against comes from the request that travels with the pause, so args that
    cannot be detached cannot be safely approved either.
    """
    ran: list[int] = []

    def tool(payload):
        ran.append(payload["amount"])
        return "ok"

    def meddle(req):
        req.args["payload"]["amount"] = 999
        return True

    contract = ToolContract(
        name="pay",
        args=Schema({"payload": Field(type="object")}),
        requires_confirmation=(seam == "confirm"),
        requires_escalation=(seam == "escalate"),
        constraints=(Constraint("owner", "eq", value="alice"),) if seam == "resolver" else (),
    )
    policy = Policy(tools={"pay": contract}, permissions={"r": frozenset({"pay"})})
    wiring = {
        "confirm": {"confirm": meddle},
        "escalate": {"escalate": meddle},
        "resolver": {"resource_resolver": lambda req: meddle(req) and {"owner": "alice"}},
    }[seam]

    sink = InMemoryAuditSink()
    safe = Gate(policy, audit=sink, **wiring).wrap(tool, name="pay")
    with use_principal(Principal(role="r", identity="alice")), contextlib.suppress(Exception):
        safe(payload={"amount": 1, "handle": _Uncopyable()})

    assert 999 not in ran, f"the {seam} callback edited what the tool ran, after every check had passed"
    assert sink.entries, "and it did so with nothing in the trail"
    assert sink.entries[-1]["effect"] == "deny", f"expected a recorded denial, got {sink.entries[-1]['effect']}"


def test_an_ordinary_call_through_a_callback_still_runs():
    """The other direction: only an *undetachable* argument may be refused."""
    ran: list[int] = []
    policy = Policy(
        tools={
            "pay": ToolContract(name="pay", args=Schema({"payload": Field(type="object")}), requires_confirmation=True)
        },
        permissions={"r": frozenset({"pay"})},
    )
    safe = Gate(policy, audit=InMemoryAuditSink(), confirm=lambda req: True).wrap(
        lambda payload: ran.append(payload["amount"]) or "ok", name="pay"
    )
    with use_principal(Principal(role="r", identity="alice")):
        safe(payload={"amount": 1, "note": "ordinary nested data"})
    assert ran == [1]


def test_no_collection_handed_to_the_policy_stays_reachable_by_its_caller():
    """A frozen dataclass freezes the *binding*, not what the binding points at.

    `Field.enum` is annotated `tuple` and the constructor takes a list without copying
    it, so the caller keeps a handle on the allowed values of a live Gate: append to it
    and an argument the gate refused a moment ago is admitted. `ToolContract.constraints`
    is the same shape and worse — `rules.clear()` removes row-level authorization from a
    running gate. In both cases the recorded `policy_hash` stays at the value from
    construction while `content_hash()` has moved, so the trail names a ruleset that is
    no longer the one deciding, which is the one thing it may never do.

    Seven collections reach the policy from the Python API and every one of them was
    live. Asked here as one property rather than seven examples, because the eighth is
    the one nobody writes an example for.
    """
    from histos.policy.authz import Binding, Constraint

    mutations: list[tuple[str, object, object]] = []

    enum_values = ["ok"]
    field = Field(type="string", enum=enum_values)
    enum_values.append("evil")
    mutations.append(("Field.enum", field.enum, "evil"))

    item_values = ["ok"]
    items = Field(type="array", item_type="string", item_enum=item_values)
    item_values.append("evil")
    mutations.append(("Field.item_enum", items.item_enum, "evil"))

    literal = ["ok"]
    constraint = Constraint("f", "in", value=literal)
    literal.append("evil")
    mutations.append(("Constraint.value", constraint.value, "evil"))

    rules = [Constraint("owner", "eq", value="alice")]
    binds = [Binding("tenant", "tenant")]
    contract = ToolContract(name="t", args=Schema({}), constraints=rules, bindings=binds)
    rules.clear()
    binds.clear()
    mutations.append(("ToolContract.constraints", contract.constraints, "<emptied>"))
    mutations.append(("ToolContract.bindings", contract.bindings, "<emptied>"))

    declared = {"a": Field()}
    schema = Schema(declared)
    declared["injected"] = Field()
    mutations.append(("Schema.fields", schema.fields, "injected"))

    grants = {"r": frozenset({"t"})}
    tools = {"t": ToolContract(name="t", args=Schema({}))}
    policy = Policy(tools=tools, permissions=grants)
    grants["admin"] = frozenset({"t"})
    tools["backdoor"] = ToolContract(name="backdoor", args=Schema({}))
    mutations.append(("Policy.permissions", policy.permissions, "admin"))
    mutations.append(("Policy.tools", policy.tools, "backdoor"))

    reached = []
    for name, held, marker in mutations:
        if marker == "<emptied>":
            if not held:
                reached.append(f"{name} was emptied from outside")
        elif marker in held:
            reached.append(f"{name} grew {marker!r} from outside")
    assert not reached, "the caller still owns part of a built policy: " + "; ".join(reached)


def test_a_record_names_the_ruleset_that_decided_it_across_a_hot_swap():
    """The trail's central promise, under the one event that can break it.

    `gate.policy = ...` updates three things in sequence — the Gate's reference, the
    Engine's, and the recorder's hash — and a call in flight reads them at different
    moments. Parked in the resolver, mid-PRE, while another thread swaps the ruleset: the
    call was refused by a `resource_constraint` that exists **only in the old policy**,
    and the record carried the **new** policy's hash. A ruleset with no such constraint,
    named as the author of a constraint denial.

    Nothing is wrong with swapping a policy mid-flight — a deploy does it. What has to
    hold is that one call sees one ruleset from end to end, and that the record says
    which one.
    """
    import threading

    from histos.policy.authz import Constraint

    def ruleset(constrained):
        return Policy(
            tools={
                "t": ToolContract(
                    name="t",
                    args=Schema({"id": Field(type="string")}),
                    constraints=(Constraint("owner", "eq", value="alice"),) if constrained else (),
                )
            },
            permissions={"r": frozenset({"t"})},
        )

    strict, loose = ruleset(True), ruleset(False)
    entered, release = threading.Event(), threading.Event()

    def resolver(tool_name, args):
        entered.set()
        release.wait(5)
        return {"owner": "bob"}  # refused by `strict`, unconstrained under `loose`

    sink = InMemoryAuditSink()
    gate = Gate(strict, audit=sink, resource_resolver=resolver)
    safe = gate.wrap(lambda id: "RESULT", name="t")

    def caller():
        with use_principal(Principal(role="r", identity="i")), contextlib.suppress(Exception):
            safe(id="x")

    worker = threading.Thread(target=caller)
    worker.start()
    assert entered.wait(5), "the resolver never ran"
    gate.policy = loose
    release.set()
    worker.join(5)

    record = sink.entries[-1]
    assert record["rule"] == "resource_constraint", f"expected the old policy to decide, got {record['rule']}"
    assert record["policy_hash"] == strict.content_hash(), (
        "the record names the ruleset that was swapped in, not the one that decided: "
        f"recorded {record['policy_hash'][:20]}, decided under {strict.content_hash()[:20]}"
    )
