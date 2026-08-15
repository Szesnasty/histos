"""Release-review fixes on the gate: lazy results are refused, inference never grants.

Two holes, both of which made a report say `allow` about something nothing had looked
at. P0-1: a tool that *returns* a generator (or a map, or — via ``is_async=False`` — a
coroutine) walked past the whole post chain, because the wrap-time refusal asks the
function whether it yields, and this one does not. P0-2: ``protect()`` synthesised a
contract for a tool a role already granted, turning the documented ``unknown_tool``
denial into an allow, and then recomputed ``review`` off the policy it had just edited
so the warning about that exact tool disappeared.
"""

from __future__ import annotations

import asyncio

import pytest

from histos import (
    Field,
    Gate,
    GateDenied,
    Policy,
    Principal,
    Schema,
    ToolContract,
    use_principal,
)
from histos.inspection import _uninspectable_kind

CLERK = Principal(identity="u1", role="clerk")


def _policy() -> Policy:
    return Policy(
        tools={"lookup": ToolContract(name="lookup", args=Schema({"q": Field(type="string")}))},
        permissions={"clerk": frozenset({"lookup"})},
    )


def _gate(**kwargs: object) -> Gate:
    return Gate(_policy(), **kwargs)  # type: ignore[arg-type]


# ── P0-1: a result the post chain cannot read is refused, not waved through ──


def test_a_tool_returning_a_genexp_is_denied_not_scanned() -> None:
    def lookup(q: str):
        return (row for row in [{"note": q}])

    guarded = _gate().wrap(lookup)
    with use_principal(CLERK), pytest.raises(GateDenied) as exc:
        guarded(q="hello")
    assert exc.value.decision.rule == "uninspectable_output"
    assert "generator" in exc.value.decision.reason


@pytest.mark.parametrize(
    "make",
    [
        lambda q: map(str, [q]),
        lambda q: filter(None, [q]),
        lambda q: iter([q]),
    ],
    ids=["map", "filter", "list_iterator"],
)
def test_any_lazy_iterator_result_is_denied(make) -> None:
    def lookup(q: str):
        return make(q)

    guarded = _gate().wrap(lookup)
    with use_principal(CLERK), pytest.raises(GateDenied) as exc:
        guarded(q="hello")
    assert exc.value.decision.rule == "uninspectable_output"
    assert "iterator" in exc.value.decision.reason


def test_the_is_async_false_escape_hatch_no_longer_returns_an_unscanned_coroutine() -> None:
    """`is_async=False` on an async tool put a coroutine through the sync post chain."""
    held: dict[str, object] = {}

    async def _work(q: str) -> dict[str, str]:
        return {"note": q}

    def lookup(q: str):
        coro = _work(q)
        held["coro"] = coro
        return coro

    guarded = _gate().wrap(lookup, is_async=False)
    with use_principal(CLERK), pytest.raises(GateDenied) as exc:
        guarded(q="hello")
    assert exc.value.decision.rule == "uninspectable_output"
    assert "coroutine" in exc.value.decision.reason
    # closed on the way out: an un-awaited coroutine left to the collector reports a
    # RuntimeWarning against the gate rather than the tool.
    assert held["coro"].cr_frame is None  # type: ignore[attr-defined]


def test_a_returned_async_generator_is_denied() -> None:
    async def _stream(q: str):
        yield q

    def lookup(q: str):
        return _stream(q)

    guarded = _gate().wrap(lookup)
    with use_principal(CLERK), pytest.raises(GateDenied) as exc:
        guarded(q="hello")
    assert exc.value.decision.rule == "uninspectable_output"
    assert "async generator" in exc.value.decision.reason


def test_an_async_tool_returning_a_genexp_is_denied_on_the_async_path() -> None:
    async def lookup(q: str):
        return (row for row in [{"note": q}])

    guarded = _gate().wrap(lookup)

    async def run() -> None:
        with use_principal(CLERK), pytest.raises(GateDenied) as exc:
            await guarded(q="hello")
        assert exc.value.decision.rule == "uninspectable_output"

    asyncio.run(run())


@pytest.mark.parametrize(
    "value",
    [{"note": "x"}, ["x"], ("x",), {"x"}, "x", b"x", 7, None],
    ids=["dict", "list", "tuple", "set", "str", "bytes", "int", "none"],
)
def test_a_result_the_post_chain_can_read_is_untouched(value) -> None:
    """The refusal must not fire for anything the post chain genuinely inspects."""

    def lookup(q: str):
        return value

    guarded = _gate().wrap(lookup)
    with use_principal(CLERK):
        assert guarded(q="hello") == value


def test_an_opaque_object_that_merely_stores_an_iterator_still_allows() -> None:
    class Rows:
        def __init__(self) -> None:
            self.__next__ = iter([1]).__next__  # an instance attribute, not the protocol

    row = Rows()

    def lookup(q: str):
        return row

    guarded = _gate().wrap(lookup)
    with use_principal(CLERK):
        assert guarded(q="hello") is row


def test_the_refusal_is_audited_as_a_post_deny_that_executed() -> None:
    def lookup(q: str):
        return (r for r in [q])

    g = _gate()
    guarded = g.wrap(lookup)
    with use_principal(CLERK), pytest.raises(GateDenied):
        guarded(q="hello")
    post = [e for e in g.audit.entries if e["phase"] == "post"]
    assert len(post) == 1
    assert post[0]["effect"] == "deny"
    assert post[0]["rule"] == "uninspectable_output"
    # the tool ran; the denial only stops the unscanned payload, it cannot undo the call
    assert post[0]["executed"] is True


def test_observe_mode_records_the_refusal_and_changes_nothing() -> None:
    def lookup(q: str):
        return (r for r in [q])

    g = _gate(mode="observe")
    guarded = g.wrap(lookup)
    with use_principal(CLERK):
        out = guarded(q="hello")
    assert list(out) == ["hello"]  # not closed, not swapped — observe blocks nothing
    post = [e for e in g.audit.entries if e["phase"] == "post"]
    assert [e["effect"] for e in post] == ["deny"]
    assert post[0]["enforced"] is False


def test_an_exception_carrying_a_lazy_payload_is_refused_too() -> None:
    from histos.errors import ToolErrorRedacted

    def lookup(q: str):
        rows = (r for r in [q])
        raise RuntimeError(rows)

    guarded = _gate().wrap(lookup)
    with use_principal(CLERK), pytest.raises(ToolErrorRedacted) as exc:
        guarded(q="hello")
    assert exc.value.decision.rule == "uninspectable_output"
    assert "generator" in exc.value.decision.reason


def test_an_ordinary_raising_tool_is_unchanged() -> None:
    def lookup(q: str):
        raise ValueError("plain failure")

    guarded = _gate().wrap(lookup)
    with use_principal(CLERK), pytest.raises(ValueError, match="plain failure"):
        guarded(q="hello")


def test_the_uninspectable_guard_is_wired_into_both_finishers() -> None:
    """It was written, never called, and nothing noticed for a whole release cycle."""
    assert "_uninspectable_kind" in Gate._finish.__code__.co_names
    assert "_uninspectable_kind" in Gate._finish_exception.__code__.co_names


def test_uninspectable_kind_names_each_shape() -> None:
    async def _coro() -> int:
        return 1

    async def _agen():
        yield 1

    coro = _coro()
    coro.close()
    agen = _agen()
    assert _uninspectable_kind(coro) == "coroutine"
    assert _uninspectable_kind(agen) == "async generator"
    assert _uninspectable_kind(r for r in []) == "generator"
    assert _uninspectable_kind(iter([])) == "iterator"
    assert _uninspectable_kind({"a": 1}) is None
    assert _uninspectable_kind("a") is None


# ── P0-1, round two: the guard follows the post chain, not just the top value ──
#
# Round one asked only the top-level object, and only whether its *type* had
# `__next__`. `{"rows": (r for r in hits)}` — the most ordinary MCP return shape there
# is — walked straight through with a post record of (allow, []), and so did a view, a
# memoryview and the ordinary `class Rows: def __iter__` result wrapper.

CANARY = "CANARY-7f3d9a2b1c8e4d5f"
SECRET = "AKIAIOSFODNN7EXAMPLE"
PAYLOAD = f"internal note {CANARY} aws_secret_access_key={SECRET}"


class LazyRows:
    """The ordinary lazy result-set wrapper: iterable, but not an iterator."""

    def __init__(self, rows: list[str]) -> None:
        self._rows = rows

    def __iter__(self):
        yield from self._rows


def _canary_gate(**kwargs: object) -> Gate:
    pol = Policy(
        tools={"lookup": ToolContract(name="lookup", args=Schema({"q": Field(type="string")}))},
        permissions={"clerk": frozenset({"lookup"})},
        canaries=frozenset({CANARY}),
    )
    return Gate(pol, **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "make",
    [
        lambda: {"rows": (r for r in [PAYLOAD])},
        lambda: [(r for r in [PAYLOAD])],
        lambda: {"rows": map(str, [PAYLOAD])},
        lambda: {"page": {"rows": [{"note": (r for r in [PAYLOAD])}]}},
        lambda: ({"rows": iter([PAYLOAD])},),
        lambda: {(r for r in [PAYLOAD]): "keyed by a generator"},
        lambda: {"a": PAYLOAD}.values(),
        lambda: {PAYLOAD: 1}.keys(),
        lambda: LazyRows([PAYLOAD]),
        lambda: {"rows": LazyRows([PAYLOAD])},
        lambda: memoryview(PAYLOAD.encode()),
    ],
    ids=[
        "generator in a dict value",
        "generator in a list",
        "map in a dict value",
        "generator three containers down",
        "iterator in a dict in a tuple",
        "generator as a dict KEY",
        "dict_values view",
        "dict_keys view",
        "iterable-only wrapper",
        "iterable-only wrapper in a dict",
        "memoryview",
    ],
)
def test_a_lazy_payload_anywhere_the_post_chain_walks_is_refused(make) -> None:
    """Every one of these delivered the canary and the key verbatim, logged as allow."""
    g = _canary_gate()
    guarded = g.wrap(lambda q: make(), name="lookup")
    with use_principal(CLERK), pytest.raises(GateDenied) as exc:
        guarded(q="hi")
    assert exc.value.decision.rule == "uninspectable_output"
    post = [e for e in g.audit.entries if e["phase"] == "post"]
    assert [e["effect"] for e in post] == ["deny"]
    # the payload never reached the caller, and the record no longer says otherwise
    assert CANARY not in str(exc.value)


@pytest.mark.parametrize(
    "value",
    [
        {"rows": [{"note": "hello"}, {"note": "world"}], "total": 2},
        {"page": {"items": ({"k": {"v": ["deep", b"but", ("materialised",)]}},)}},
        [{"a": frozenset({"x"})}, {"b": {"y"}}],
        {"n": None, "ok": True, "score": 1.5},
    ],
    ids=["rows", "nested", "sets", "scalars"],
)
def test_an_ordinary_nested_result_is_still_untouched(value) -> None:
    """The recursion must not start refusing the results the gate exists to inspect."""
    guarded = _gate().wrap(lambda q: value, name="lookup")
    with use_principal(CLERK):
        assert guarded(q="hello") == value


def test_an_opaque_object_holding_an_iterator_in_an_attribute_is_still_allowed() -> None:
    """The documented residual: the post chain cannot read it, and neither can a host.

    The distinction the guard draws is whether the value *itself* is the lazy payload.
    An object that merely stores a cursor is inert to anything that walks the result,
    so refusing it would break honest tools to catch nothing.
    """

    class Handle:
        def __init__(self) -> None:
            self.rows = iter([PAYLOAD])

    handle = Handle()
    guarded = _canary_gate().wrap(lambda q: {"handle": handle, "note": "ok"}, name="lookup")
    with use_principal(CLERK):
        assert guarded(q="hi")["handle"] is handle


def test_a_structure_nested_past_the_bound_is_refused_not_waved_through() -> None:
    deep: object = "leaf"
    for _ in range(200):
        deep = [deep]

    guarded = _gate().wrap(lambda q: deep, name="lookup")
    with use_principal(CLERK), pytest.raises(GateDenied) as exc:
        guarded(q="hello")
    assert exc.value.decision.rule == "uninspectable_output"
    assert "deeper" in exc.value.decision.reason


def test_a_container_that_refuses_to_be_walked_is_refused_too() -> None:
    """An unfinished read is not a clean bill of health, and it must still be a decision."""

    class LazyMapping(dict):
        def values(self):
            raise RuntimeError("materialise me first")

    g = _gate()
    guarded = g.wrap(lambda q: LazyMapping(rows="?"), name="lookup")
    with use_principal(CLERK), pytest.raises(GateDenied) as exc:
        guarded(q="hello")
    assert exc.value.decision.rule == "uninspectable_output"
    assert [e["effect"] for e in g.audit.entries if e["phase"] == "post"] == ["deny"]


def test_a_self_referential_result_answers_instead_of_hanging() -> None:
    loop: dict[str, object] = {"note": "hi"}
    loop["self"] = loop
    assert _uninspectable_kind(loop) is None  # terminates; the cycle is not a second answer

    loop["rows"] = (r for r in [PAYLOAD])
    assert _uninspectable_kind(loop) == "structure containing a generator"


def test_an_exception_carrying_a_lazy_payload_one_level_down_is_refused_too() -> None:
    from histos.errors import ToolErrorRedacted

    def lookup(q: str):
        raise RuntimeError([(r for r in [PAYLOAD])])

    guarded = _canary_gate().wrap(lookup, name="lookup")
    with use_principal(CLERK), pytest.raises(ToolErrorRedacted) as exc:
        guarded(q="hello")
    assert exc.value.decision.rule == "uninspectable_output"
    assert "generator" in exc.value.decision.reason
    assert CANARY not in str(exc.value)


def test_a_nested_genexp_is_closed_but_the_tools_own_cursor_is_not() -> None:
    """Closing reclaims what the refused result owns; it must not close the tool's state."""

    class Cursor:
        def __init__(self) -> None:
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            raise StopIteration

        def close(self) -> None:
            self.closed = True

    rows = (r for r in [PAYLOAD])
    cursor = Cursor()
    guarded = _gate().wrap(lambda q: {"rows": rows, "cursor": cursor}, name="lookup")
    with use_principal(CLERK), pytest.raises(GateDenied):
        guarded(q="hello")
    assert rows.gi_frame is None  # nothing else could have been holding it
    assert cursor.closed is False  # the tool's next call still works


@pytest.mark.parametrize(
    "wrap",
    [
        lambda leaf: {"note": leaf},
        lambda leaf: {leaf: "keyed"},
        lambda leaf: [leaf],
        lambda leaf: (leaf,),
        lambda leaf: {leaf},
        lambda leaf: frozenset({leaf}),
    ],
    ids=["dict value", "dict key", "list", "tuple", "set", "frozenset"],
)
def test_the_guard_and_the_post_chain_agree_on_what_a_container_is(wrap) -> None:
    """The guard recurses into these six because the post chain does. If the chain ever
    stops walking one of them, this fails here rather than as a silent hole: the guard
    would keep vouching for a container nothing scans."""
    guarded = _canary_gate().wrap(lambda q: wrap(PAYLOAD), name="lookup")
    with use_principal(CLERK):
        out = guarded(q="hi")
    assert CANARY not in repr(out)


def test_the_refusal_has_its_own_published_code_with_a_remedy() -> None:
    """It used to borrow `output_schema`, which means the opposite: output that WAS read."""
    import json
    from pathlib import Path

    from histos.auditrecord import _REASON_IS_POLICY_TEXT
    from histos.contracts import _REMEDY

    spec = json.loads((Path(__file__).resolve().parent.parent / "spec" / "decision-codes.json").read_text())
    published = {code["code"]: code for code in spec["codes"]}
    assert published["uninspectable_output"]["effect"] == "deny"
    assert published["uninspectable_output"]["phase"] == "post"
    assert "materialised" in _REMEDY["uninspectable_output"]
    # the reason is composed from the tool name and the kind, so the record keeps it
    assert "uninspectable_output" in _REASON_IS_POLICY_TEXT


def test_the_audit_record_keeps_the_refusals_reason() -> None:
    g = _gate()
    guarded = g.wrap(lambda q: {"rows": (r for r in [q])}, name="lookup")
    with use_principal(CLERK), pytest.raises(GateDenied):
        guarded(q="hello")
    post = next(e for e in g.audit.entries if e["phase"] == "post")
    assert "generator" in post["reason"]
    assert "redacted" not in post["reason"]


# ── P0-2: an inferred contract is never the grant's missing declaration ──


def wire_transfer(amount: int, to: str) -> str:
    return f"sent {amount} to {to}"


def _stale_policy() -> Policy:
    """The `tools:` entry was deleted or renamed; the `roles:` grant stayed behind."""
    return Policy(tools={}, permissions={"support": frozenset({"wire_transfer"})})


def test_a_granted_but_undeclared_tool_still_denies_after_protect() -> None:
    g = Gate(_stale_policy())
    result = g.protect([wire_transfer])
    with use_principal(Principal(identity="u1", role="support")), pytest.raises(GateDenied) as exc:
        result.tools["wire_transfer"](amount=1, to="x")
    assert exc.value.decision.rule == "unknown_tool"
    assert "wire_transfer" not in g.policy.tools  # inference did not write the declaration


def test_the_report_still_names_the_granted_undeclared_tool() -> None:
    g = Gate(_stale_policy())
    result = g.protect([wire_transfer])
    row = next(r for r in result.coverage if r["tool"] == "wire_transfer")
    assert row["status"] == "needs-policy"
    assert row["had_contract"] is False
    assert "wire_transfer" in result.summary()


def test_protect_does_not_erase_the_grants_unknown_tool_warning() -> None:
    """`review` used to be computed after inference, so it answered for its own edit."""
    g = Gate(_stale_policy())
    result = g.protect([wire_transfer])
    assert result.review is not None
    assert any("grants unknown tool 'wire_transfer'" in w for w in result.review.warnings)


def test_inference_still_fills_a_declared_tools_missing_arg_schema() -> None:
    """The `tool_d` case is the one inference exists for and must keep working."""

    def refund(amount: int) -> int:
        return amount

    pol = Policy(
        tools={"refund": ToolContract(name="refund", args=None)},
        permissions={"clerk": frozenset({"refund"})},
    )
    g = Gate(pol)
    result = g.protect([refund])
    safe = result.tools["refund"]
    with use_principal(CLERK):
        assert safe(amount=5) == 5
        with pytest.raises(GateDenied) as exc:
            safe(amount="not-an-int")
    assert exc.value.decision.rule == "arg_schema"
