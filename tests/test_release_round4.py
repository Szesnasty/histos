"""The fourth adversarial pass, pinned.

The third pass rewrote about 1300 lines of `src/`. This pass attacked those lines
specifically, on the theory that a fix written against one reported attack is blind to
the sibling nobody reported — which is what most of these turned out to be. One test
per finding, named by the finding, because the assertion alone does not say why it
matters.
"""

from __future__ import annotations

import subprocess
import sys
import warnings

import pytest

from histos import (
    Field,
    Gate,
    JSONLAuditSink,
    Policy,
    Principal,
    Schema,
    ToolContract,
    use_principal,
)

# ── the audit sink is not allowed to decide a call, and `strict` is ──────


def _one_write_tool() -> Policy:
    return Policy(
        tools={"charge": ToolContract(name="charge", args=Schema({}), access="write")},
        permissions={"teller": frozenset({"charge"})},
    )


def _dead_sink(tmp_path) -> JSONLAuditSink:
    """A sink whose path is a directory: every write raises IsADirectoryError."""
    (tmp_path / "log.jsonl").mkdir()
    return JSONLAuditSink(tmp_path / "log.jsonl")


def test_strict_sink_reaches_the_caller_through_the_gate(tmp_path):
    """`strict=True` was inert through every entry point the README teaches.

    The sink re-raises when strict. `Gate._emit` was the library's only caller of
    `record()`, and its blanket `except Exception` caught that re-raise and turned it
    back into a RuntimeWarning — so the flag changed nothing through `protect()`,
    `gate()` or `Gate`, while the sink's own warning text recommended it as the remedy.
    """
    sink = _dead_sink(tmp_path)
    sink.strict = True
    safe = Gate(_one_write_tool(), audit=sink).wrap(lambda: "receipt", name="charge")  # noqa: E731
    with use_principal(Principal(role="teller", identity="t")), pytest.raises(IsADirectoryError):
        safe()


def test_a_lenient_sink_still_never_decides_a_call(tmp_path):
    """The default is unchanged: a collector outage does not stop an agent.

    And the loss is countable. The shipped sink absorbs its own write errors, so the
    gate saw a clean return and a host had nothing to alarm on but a RuntimeWarning —
    which is not something a monitor reads. `Gate.audit_failures` covers both the sink
    that raises and the sink that swallows.
    """
    sink = _dead_sink(tmp_path)
    gate_ = Gate(_one_write_tool(), audit=sink)
    safe = gate_.wrap(lambda: "receipt", name="charge")  # noqa: E731
    with use_principal(Principal(role="teller", identity="t")), warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert safe() == "receipt"
    assert gate_.audit_failures == 2, "pre and post were both lost and both have to be counted"
    assert sink.failed == 2
    assert any("could not be written" in str(w.message) for w in caught)


def test_the_pre_phase_loss_says_it_is_the_pre_phase():
    """The guard's justification — "the side effect already happened, so raising
    prevents nothing" — is true on POST and false on PRE, and the message claimed the
    harmless case on both."""

    class Collector:
        def record(self, entry: dict) -> None:
            raise ConnectionError("collector unreachable")

    safe = Gate(_one_write_tool(), audit=Collector()).wrap(lambda: "receipt", name="charge")  # noqa: E731
    with use_principal(Principal(role="teller", identity="t")), warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        safe()
    said = [str(w.message) for w in caught]
    assert any("(pre phase)" in m and "no record of the decision" in m for m in said), said
    assert any("(post phase)" in m and "side effect stands" in m for m in said), said


def test_a_denied_call_is_still_denied_when_the_sink_is_dead(tmp_path):
    """Enforcement never depended on the trail, and must not start to."""
    from histos.errors import GateDenied

    safe = Gate(_one_write_tool(), audit=_dead_sink(tmp_path)).wrap(lambda: "receipt", name="charge")  # noqa: E731
    with use_principal(Principal(role="viewer", identity="v")), pytest.raises(GateDenied):
        safe()


_WARN_AS_ERROR = """
import sys, pathlib, warnings
sys.path.insert(0, {src!r})
from histos import Gate, Policy, Principal, Schema, ToolContract, use_principal, JSONLAuditSink

log = pathlib.Path({log!r})
log.mkdir()
sink = JSONLAuditSink(log)
policy = Policy(
    tools={{"charge": ToolContract(name="charge", args=Schema({{}}), access="write")}},
    permissions={{"teller": frozenset({{"charge"}})}},
)
effects = []
def charge():
    effects.append(1)
    return "receipt"

safe = Gate(policy, audit=sink).wrap(charge, name="charge")
with use_principal(Principal(role="teller", identity="t")):
    got = safe()
print("RESULT", got, "EFFECTS", len(effects))

# and the sink's own documented totality, called directly
sink.record({{"effect": "allow"}})
print("DIRECT ok, failed =", sink.failed)
"""


def test_warnings_as_errors_does_not_turn_a_lost_record_into_a_lost_call(tmp_path):
    """`-W error` is an ordinary CI setting, and it reached inside the one code path
    documented as total: on POST the side effect stood, the record was lost *and* the
    caller got a RuntimeWarning instead of the value. A warning filter is a reporting
    choice, not a security one.

    Run in a fresh interpreter with the real flag rather than `simplefilter("error")`,
    because the bug is about the process-wide filter a host actually sets.
    """
    src = str(pytest.importorskip("histos").__file__).rsplit("/histos/", 1)[0]
    script = tmp_path / "run.py"
    script.write_text(_WARN_AS_ERROR.format(src=src, log=str(tmp_path / "log.jsonl")))
    proc = subprocess.run([sys.executable, "-W", "error", str(script)], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert "RESULT receipt EFFECTS 1" in proc.stdout, proc.stdout
    assert "DIRECT ok, failed = 3" in proc.stdout, proc.stdout
    assert "histos: an audit record could not be written" in proc.stderr, "the loss became invisible instead"


def test_a_host_sink_opts_into_strict_the_same_way(tmp_path):
    """`AuditSink` is a Protocol, so the contract has to be a plain attribute."""

    class Collector:
        strict = True

        def record(self, entry: dict) -> None:
            raise ConnectionError("collector unreachable")

    safe = Gate(_one_write_tool(), audit=Collector()).wrap(lambda: "receipt", name="charge")  # noqa: E731
    with use_principal(Principal(role="teller", identity="t")), pytest.raises(ConnectionError):
        safe()


# ── the projector reads the names a record publishes ─────────────────────


def _projecting(returns: dict) -> Policy:
    return Policy(
        tools={
            "t": ToolContract(
                name="t",
                args=Schema({}),
                returns=Schema(returns),
                project_output=True,
            )
        },
        permissions={"ok": frozenset({"t"})},
    )


def test_an_ordinary_value_in_a_declared_field_is_not_a_projection_failure():
    """The P0 the previous fix opened. Routing every value outside
    `str/bytes/int/float/bool/None` through `on_output_violation` (default redact_all)
    was written for the record that hides a field, and applied to the set that also
    holds `datetime`, `Decimal`, `UUID` and `Path` — so a declared field holding a
    timestamp replaced the whole tool output with a redaction string."""
    import datetime
    import decimal
    import pathlib
    import uuid

    policy = _projecting({"when": Field(type="string")})
    for value in (
        datetime.datetime(2026, 1, 1, 12, 0),
        decimal.Decimal("12.30"),
        uuid.UUID("12345678-1234-5678-1234-567812345678"),
        pathlib.PurePosixPath("/tmp/x"),
    ):
        safe = Gate(policy).wrap(lambda _v=value: {"when": _v}, name="t")
        with use_principal(Principal(role="ok", identity="i")):
            assert safe() == {"when": value}, f"a declared {type(value).__name__} was redacted away"


def test_the_record_shapes_are_entered_rather_than_refused():
    """Which is what closes the leak the refusal was reaching for, without the cost."""
    import dataclasses
    import typing

    @dataclasses.dataclass
    class AsDataclass:
        public: str
        secret: str

    class AsNamedTuple(typing.NamedTuple):
        public: str
        secret: str

    class AsPlainObject:
        def __init__(self) -> None:
            self.public = "fine"
            self.secret = "leak"

    policy = _projecting({"public": Field(type="string")})
    for make in (lambda: AsDataclass("fine", "leak"), lambda: AsNamedTuple("fine", "leak"), AsPlainObject):
        safe = Gate(policy).wrap(lambda _m=make: {"public": _m()}, name="t")
        with use_principal(Principal(role="ok", identity="i")):
            out = safe()
        assert "leak" not in repr(out), f"{make} leaked the undeclared field"
        assert "REDACTED" not in repr(out), f"{make} was refused rather than projected"


def test_an_enum_member_is_a_value_and_not_a_record():
    """It carries a `__dict__` (`_name_`, `_value_`, `_sort_order_`) that belongs to the
    enum machinery, not to the author, so reading it as fields would drop the member."""
    import enum

    class Colour(enum.Enum):
        RED = "red"

    safe = Gate(_projecting({"c": Field(type="string")})).wrap(lambda: {"c": Colour.RED}, name="t")  # noqa: E731
    with use_principal(Principal(role="ok", identity="i")):
        assert safe() == {"c": Colour.RED}


def test_a_correctly_declared_record_keeps_its_type():
    """Projection rebuilds a record as a mapping only when something had to be dropped —
    the same bargain a dict gets. A caller's attribute access survives the common case.
    """
    import dataclasses

    @dataclasses.dataclass
    class Row:
        public: str

    safe = Gate(_projecting({"public": Field(type="string")})).wrap(lambda: Row("fine"), name="t")  # noqa: E731
    with use_principal(Principal(role="ok", identity="i")):
        out = safe()
    assert isinstance(out, Row) and out.public == "fine"


def test_a_slots_only_object_is_still_named_in_the_trail():
    """The honest residual: slots cannot separate a user's record from a stdlib value
    type, and reading them would project a `UUID` into `{"int": ...}`. Named, not
    entered, and covered by `strict_returns` instead — SECURITY.md says so."""
    from histos import InMemoryAuditSink

    class Opaque:
        __slots__ = ("secret",)

        def __init__(self) -> None:
            self.secret = "leak"

    sink = InMemoryAuditSink()
    safe = Gate(_projecting({"public": Field(type="string")}), audit=sink).wrap(lambda: {"public": Opaque()}, name="t")
    with use_principal(Principal(role="ok", identity="i")):
        safe()
    assert "output:uninspectable:Opaque" in sink.entries[-1]["redactions"]


def test_the_residual_is_written_down_where_the_projector_is_described():
    """A residual that only lives in a commit message is not a residual, it is a bug."""
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent / "SECURITY.md").read_text()
    assert "__slots__" in text, "SECURITY.md does not name the shape the projector cannot enter"


# ── the audit trail must not cry wolf, and must not merge two tenants ─────


def test_a_log_this_library_wrote_verifies():
    """`verify_chain` reported an honest file as forged.

    The respelling check searched the raw line for a `\\uXXXX` escape of a printable
    character. A tool argument holding the *literal text* of one — a regex, a code
    snippet, a Windows path — is serialised by `json.dumps` as a doubled backslash and
    five ordinary characters, which the search found too. A verifier that fails on a log
    written one line earlier is worse than no verifier: it is what teaches an operator
    to stop reading it.
    """
    import tempfile
    from pathlib import Path

    from histos import JSONLAuditSink, verify_chain

    backslash = chr(92)
    for value in (
        backslash + "u0041",
        "regex " + backslash + "d+ then " + backslash + "u0041",
        "C:" + backslash + "Users" + backslash + "bob",
    ):
        log = Path(tempfile.mkdtemp()) / "a.jsonl"
        JSONLAuditSink(log).record({"effect": "allow", "rule": "allow", "note": value})
        ok, why = verify_chain(log)
        assert ok, f"{value!r} was reported as forged: {why}"


def test_the_respelling_attack_is_still_caught():
    import tempfile
    from pathlib import Path

    from histos import JSONLAuditSink, verify_chain

    log = Path(tempfile.mkdtemp()) / "a.jsonl"
    JSONLAuditSink(log).record({"effect": "deny", "rule": "rbac"})
    backslash = chr(92)
    forged = log.read_text(encoding="utf-8").strip().replace('"deny"', f'"{backslash}u0064eny"')
    log.write_text(forged + "\n", encoding="utf-8")
    ok, why = verify_chain(log)
    assert not ok and "spells a printable character" in why


def test_only_an_odd_backslash_run_makes_an_escape():
    from histos.audit import _respelt_ascii

    backslash = chr(92)
    for count, is_escape in ((1, True), (2, False), (3, True), (4, False)):
        line = '{"effect": "' + backslash * count + 'u0064eny"}'
        assert (_respelt_ascii(line) is not None) is is_escape, f"{count} backslashes"


def test_the_erasure_memory_is_keyed_on_a_location_that_survives_the_file(tmp_path):
    """Keying on `st_ino` was the first answer and forgets at the one moment it is for."""
    from histos.audit import _path_key

    log = tmp_path / "x.jsonl"
    log.write_text("{}", encoding="utf-8")
    before = _path_key(log)
    log.unlink()
    assert _path_key(log) == before


def test_two_tenants_in_differently_cased_directories_do_not_share_a_key(tmp_path):
    """Case folding was applied on darwin and win32 unconditionally, which guesses.

    On a case-*sensitive* volume — APFS can be formatted that way, and any mounted image
    may be — that merged two tenants: the second tenant's first-ever record was written
    with the first tenant's `prev`, and one tenant calling the published `rotated()`
    remedy cleared the other's erasure memory, after which erasing that other log and
    appending verified clean. The fold is measured per directory now, so this holds on
    either kind of volume: distinct directories are never one key.
    """
    from histos.audit import _path_key

    (tmp_path / "Acme").mkdir()
    (tmp_path / "Zeta").mkdir()
    assert _path_key(tmp_path / "Acme" / "l.jsonl") != _path_key(tmp_path / "Zeta" / "l.jsonl")


def test_two_spellings_of_one_file_still_share_a_key(tmp_path):
    """The property the fold existed for, kept: on a case-insensitive volume one capital
    letter must not hand two sinks two locks and two erasure memories."""
    from histos.audit import _folds_case, _path_key

    if not _folds_case(str(tmp_path)):
        import pytest as _pytest

        _pytest.skip("this volume is case-sensitive; the two spellings are two files")
    assert _path_key(tmp_path / "Trail.jsonl") == _path_key(tmp_path / "trail.jsonl")


# ── a keyword that enforces something must reach the hash ────────────────


def test_every_field_keyword_reaches_the_contract_structure():
    """The durable half of the `unique_items` fix.

    A `Field` keyword that enforces something and is missing from
    `_schema_structure` produces two policies that decide differently and hash the
    same. `unique_items` did all four of the things that follow from that: the gate
    gave opposite verdicts on one call under one `policy_hash`, two committed bundle
    files collided on `content_hash`, the lock's `contract_sha256` collided, and
    `histos drift` printed "0 reaching enforcement" and exited 0 across the flip.

    Walking the dataclass is the check, so the next keyword cannot be added without
    either reaching the hash or being named here as deliberately outside it.
    """
    import dataclasses

    from histos.contracts import _schema_structure
    from histos.schema import Field, Schema

    structure = _schema_structure(Schema({"f": Field(type="string")}))
    covered = set(structure["fields"]["f"])
    declared = {f.name for f in dataclasses.fields(Field)}
    assert declared <= covered, f"these Field keywords never reach the contract hash: {sorted(declared - covered)}"


def test_unique_items_moves_every_hash_it_has_to():
    from histos.contracts import Policy, ToolContract
    from histos.lockfile import contract_hash
    from histos.schema import Field, Schema

    def build(unique: bool) -> ToolContract:
        return ToolContract(
            name="t",
            args=Schema({"ids": Field(type="array", item_type="string", unique_items=unique)}),
            access="write",
        )

    loose, strict = build(False), build(True)
    assert contract_hash(loose) != contract_hash(strict)
    policies = [Policy(tools={"t": c}, permissions={"r": frozenset({"t"})}) for c in (loose, strict)]
    assert policies[0].content_hash() != policies[1].content_hash()


def test_unique_items_is_linear_in_the_element_count():
    """It ran at pre-gate step 3, before the output size budget at step 5, as an
    equality scan against a growing list: 8 000 distinct integers cost 461 ms of held
    CPU per call for a payload that builds in under a millisecond. The duplicate case
    short-circuits, so only the *valid* payload was expensive — the one an attacker
    sends."""
    import time

    from histos.schema import Field, Schema, validate

    schema = Schema({"ids": Field(type="array", unique_items=True)})
    payload = {"ids": list(range(8000))}
    start = time.perf_counter()
    assert validate(schema, payload) == []
    elapsed = time.perf_counter() - start
    # Two orders of magnitude of headroom under the measured 461 ms, so this fails on a
    # return to quadratic and not on a slow machine.
    assert elapsed < 0.05, f"8 000 unique elements took {elapsed * 1000:.0f} ms"


def test_unique_items_still_catches_a_duplicate_of_either_kind():
    from histos.schema import Field, Schema, validate

    schema = Schema({"ids": Field(type="array", unique_items=True)})
    assert validate(schema, {"ids": [1, 2, 2]}), "a hashable duplicate went unnoticed"
    assert validate(schema, {"ids": [{"a": 1}, {"a": 1}]}), "an unhashable duplicate went unnoticed"
    assert validate(schema, {"ids": [{"a": 1}, {"a": 2}]}) == []


def test_too_many_unhashable_elements_is_refused_rather_than_scanned():
    """ "This costs too much to check" and "this is fine" are not the same answer."""
    from histos.schema import Field, Schema, validate

    schema = Schema({"ids": Field(type="array", unique_items=True)})
    errors = validate(schema, {"ids": [{"i": i} for i in range(600)]})
    assert errors and "cannot be hashed" in errors[0]
