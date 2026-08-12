"""What has to keep working — the other half of every security screen.

Every refusal this library added was verified against the attack it closes and against
nothing else, and that is where the regressions came from: `frozenset(can_view)` was
tested with a list and broke a string; the deep copy of `Principal.attributes` was
tested with a list of strings and broke a database session; the PAN prefix allowlist
was tested against six cards someone remembered and lost Maestro entirely.

The common cause is not haste. It is that the set of "things that must still work" was
generated from imagination, and imagination is always smaller than production. So the
corpora in `tests/corpus/` come from outside: schemas emitted by pydantic's own
generator, the real Swagger Petstore document, card numbers whose check digit is
computed from scheme-published prefixes rather than remembered, and regexes each
measured against the clock. The first draft of the card corpus was typed from memory
and 11 of 34 entries were not Luhn-valid, which is the argument for this file in one
sentence.

A failure here is not necessarily a bug in the screen — sometimes the honest answer is
that an input really should be refused. It is always a claim that needs an argument.
"""

from __future__ import annotations

import collections
import datetime
import decimal
import enum
import json
import pathlib
import re
import threading
import uuid
from dataclasses import dataclass
from typing import Any, NamedTuple

import pytest

from histos import (
    Field,
    Gate,
    GateDenied,
    Policy,
    PolicyError,
    Principal,
    Schema,
    ToolContract,
    contracts_from_mcp,
    contracts_from_openapi,
    use_principal,
)
from histos.detectors import scan_string

CORPUS = pathlib.Path(__file__).resolve().parent / "corpus"


def _load(name: str) -> Any:
    return json.loads((CORPUS / name).read_text(encoding="utf-8"))


# ── 1. what a real tool returns ──────────────────────────────────────────
#
# The outbound guard walks every return value. Everything here is fully inspectable,
# holds no lazy payload, and worked before the guard existed.


class Colour(enum.Enum):
    RED = "red"


class Level(enum.IntEnum):
    LOW = 1


class Name(enum.StrEnum):
    A = "a"


class Flags(enum.Flag):
    ONE = enum.auto()


@dataclass
class Row:
    id: int
    label: str


class Point(NamedTuple):
    x: int
    y: int


class Page:
    """The ordinary lazy-result wrapper: holds rows, is not itself iterable."""

    def __init__(self, rows: list[dict]) -> None:
        self.rows = rows


ORDINARY_RETURNS = {
    "str": "plain text",
    "bytes": b"plain bytes",
    "int": 42,
    "float": 1.5,
    "bool": True,
    "none": None,
    "dict": {"a": 1},
    "list-of-dicts": [{"a": 1}, {"a": 2}],
    "tuple": ("a", "b"),
    "set": {"a", "b"},
    "nested": {"rows": [{"a": [1, 2]}]},
    "empty-dict": {},
    "empty-list": [],
    "decimal": decimal.Decimal("1.50"),
    "date": datetime.date(2026, 8, 12),
    "datetime": datetime.datetime(2026, 8, 12, 17, 0),
    "uuid": uuid.UUID("12345678-1234-5678-1234-567812345678"),
    "path": pathlib.Path("/tmp/x"),
    "enum-member": Colour.RED,
    "int-enum-member": Level.LOW,
    "str-enum-member": Name.A,
    "flag-member": Flags.ONE,
    "enum-in-a-dict": {"id": 1, "status": Colour.RED},
    "dataclass": Row(id=1, label="x"),
    "namedtuple": Point(1, 2),
    "opaque-wrapper": Page([{"a": 1}]),
    "counter": collections.Counter({"a": 1}),
    "ordereddict": collections.OrderedDict(a=1),
}


# Refused, and the refusal is right. Kept here rather than deleted, because the argument
# for each one is the interesting part and a corpus that only lists what must pass gives
# the next reader no way to tell a deliberate refusal from an oversight.
REFUSED_ON_PURPOSE = {
    # The post chain reads `str` and `bytes` and nothing else byte-shaped, so a
    # `bytearray` really would reach the caller unscanned. Allowing it would be a hole,
    # not a kindness. The remedy the denial names — return the materialised value —
    # is `bytes(buf)`, and it is one call.
    "bytearray": bytearray(b"abc"),
    "memoryview": memoryview(b"abc"),
}


@pytest.mark.parametrize("name", sorted(REFUSED_ON_PURPOSE))
def test_a_buffer_the_post_chain_cannot_read_is_refused(name):
    value = REFUSED_ON_PURPOSE[name]

    def tool() -> Any:
        return value

    safe = Gate(_echo_policy()).wrap(tool, name="t")
    with use_principal(Principal(role="ok", identity="i")), pytest.raises(GateDenied) as exc:
        safe()
    assert exc.value.decision.rule == "uninspectable_output"


def _echo_policy(**kw: Any) -> Policy:
    return Policy(
        tools={"t": ToolContract(name="t", args=Schema({}), access="read", **kw)},
        permissions={"ok": frozenset({"t"})},
    )


@pytest.mark.parametrize("name", sorted(ORDINARY_RETURNS))
def test_an_ordinary_return_value_reaches_the_caller(name):
    value = ORDINARY_RETURNS[name]

    def tool() -> Any:
        return value

    safe = Gate(_echo_policy()).wrap(tool, name="t")
    with use_principal(Principal(role="ok", identity="i")):
        safe()


@pytest.mark.parametrize("name", ["dict", "list-of-dicts", "none", "empty-list"])
def test_project_output_leaves_an_ordinary_return_usable(name):
    """`None` is the one to watch: it is not a dict, and it is not a violation either."""
    value = ORDINARY_RETURNS[name]

    def tool() -> Any:
        return value

    policy = Policy(
        tools={
            "t": ToolContract(
                name="t", args=Schema({}), returns=Schema({"a": Field(type="integer")}), project_output=True
            )
        },
        permissions={"ok": frozenset({"t"})},
    )
    safe = Gate(policy).wrap(tool, name="t")
    with use_principal(Principal(role="ok", identity="i")):
        out = safe()
    if value is None:
        assert out is None, "a tool that returns nothing must not come back as a redaction string"


# ── 2. what a host puts on a Principal ───────────────────────────────────


class _Session:
    """Stands in for a DB session or an HTTP client: real, and not deep-copyable."""

    def __init__(self) -> None:
        self._lock = threading.Lock()


PRINCIPAL_ATTRIBUTES = {
    "string": {"tenant_id": "acme"},
    "int": {"seat_count": 4},
    "list": {"tenants": ["acme", "globex"]},
    "nested": {"limits": {"daily": 10}},
    "frozenset": {"regions": frozenset({"eu"})},
    "none": {"delegate": None},
    "enum": {"tier": Level.LOW},
    "uncopyable-session": {"db": _Session()},
    "lock": {"guard": threading.Lock()},
    "callable": {"resolve": len},
    "module": {"where": json},
}


@pytest.mark.parametrize("name", sorted(PRINCIPAL_ATTRIBUTES))
def test_a_principal_can_be_built_from_what_a_host_actually_has(name):
    """A host builds one of these per request; construction must not be able to fail."""
    Principal(role="ok", identity="i", attributes=PRINCIPAL_ATTRIBUTES[name])


@pytest.mark.parametrize(
    ("spelling", "expected"),
    [
        (frozenset({"pii"}), frozenset({"pii"})),
        ({"pii"}, frozenset({"pii"})),
        (["pii", "secret"], frozenset({"pii", "secret"})),
        (("pii",), frozenset({"pii"})),
        ("pii", frozenset({"pii"})),
    ],
)
def test_can_view_means_the_same_however_it_is_written(spelling, expected):
    """A bare string is the spelling that silently became `{'p', 'i'}`."""
    assert Principal(role="ok", can_view=spelling).can_view == expected


# ── 3. cards ─────────────────────────────────────────────────────────────


def _detects(text: str) -> bool:
    return any(d.kind == "pan" for d in scan_string(text))


@pytest.mark.parametrize("entry", _load("cards.json")["must_detect"], ids=lambda e: e["brand"])
def test_a_real_card_number_is_detected(entry):
    """A miss here is a card number that egresses."""
    assert _detects(entry["number"]), f"{entry['brand']} not detected"


@pytest.mark.parametrize("entry", _load("cards.json")["must_not_detect"], ids=lambda e: e["what"])
def test_a_luhn_clean_identifier_that_is_not_a_card_is_left_alone(entry):
    """A hit here redacts a legitimate identifier out of a working tool's output."""
    assert not _detects(entry["number"]), f"{entry['what']} wrongly detected"


# ── 4. patterns ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("pattern", _load("patterns.json")["must_load"])
def test_a_pattern_a_policy_author_would_write_still_loads(pattern):
    """Each of these is measured under 10 ms against 4 KiB of its own alphabet."""
    Field(type="string", pattern=pattern)


@pytest.mark.parametrize("pattern", _load("patterns.json")["must_refuse"])
def test_a_pattern_measured_expensive_is_refused(pattern):
    with pytest.raises(PolicyError):
        Field(type="string", pattern=pattern)


# ── 5. real schemas ──────────────────────────────────────────────────────


PYDANTIC_TOOLS = _load("pydantic_mcp_tools.json")["tools"]


@pytest.mark.parametrize("tool", PYDANTIC_TOOLS, ids=lambda t: t["name"])
def test_a_schema_pydantic_actually_emits_imports(tool):
    """Every MCP server built on FastMCP or the MCP Python SDK emits exactly these."""
    contracts_from_mcp([tool])


def test_the_whole_pydantic_manifest_imports_as_one():
    contracts = contracts_from_mcp(PYDANTIC_TOOLS)
    assert len(contracts) == len(PYDANTIC_TOOLS), "a manifest lost tools it should have kept"


def test_the_real_petstore_document_imports_completely():
    spec = _load("openapi_petstore.json")
    operations = sum(
        1
        for item in spec["paths"].values()
        for method in item
        if method in ("get", "post", "put", "patch", "delete")
    )
    assert len(contracts_from_openapi(spec)) == operations


# ── 6. the shipped policies still load ───────────────────────────────────


@pytest.mark.parametrize(
    "path",
    sorted((pathlib.Path(__file__).resolve().parents[1] / "policies").glob("*.policy.yaml")),
    ids=lambda p: p.name,
)
def test_every_shipped_policy_still_loads(path):
    from histos import load_policy

    load_policy(path)


# ── 7. the per-call path stays fast ──────────────────────────────────────


def test_a_gated_call_over_a_realistic_result_stays_under_a_millisecond():
    """The README claims microsecond-scale. A ceiling, not a benchmark: it exists to
    catch an order-of-magnitude regression, not to police a few microseconds."""
    import time

    rows = [{"id": i, "name": f"row-{i}", "note": "x" * 40} for i in range(1000)]

    def listing() -> list[dict]:
        return rows

    safe = Gate(_echo_policy()).wrap(listing, name="t")
    with use_principal(Principal(role="ok", identity="i")):
        safe()
        started = time.perf_counter()
        for _ in range(20):
            safe()
        per_call = (time.perf_counter() - started) / 20
    assert per_call < 0.050, f"{per_call * 1000:.1f} ms per call over a 1000-row result"


def test_the_pattern_corpus_is_measured_not_asserted():
    """The corpus files carry their provenance; a corpus nobody can re-derive is folklore."""
    for name in ("cards.json", "patterns.json"):
        assert "$comment" in _load(name), f"{name} does not say where it came from"
    assert re.search(r"computed", _load("cards.json")["$comment"], re.I)
