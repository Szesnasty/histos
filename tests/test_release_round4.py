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
    PolicyError,
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


# ── the importers, and what the drift detector can see ───────────────────


def _spec(path_item: dict) -> dict:
    return {"openapi": "3.0.0", "servers": [{"url": "https://api.example"}], "paths": {"/pets": path_item}}


def test_a_path_item_server_repoint_is_recorded():
    """OpenAPI resolves `servers` at three levels and the importer read two.

    A vendor moving the host is caught at the operation level and was invisible at the
    path-item level — a smaller diff that repoints every method on the path at once, and
    `histos drift` exited 0 on it.
    """
    from histos import sources_from_openapi

    op = {"operationId": "listPets", "responses": {}}
    (honest,) = sources_from_openapi(_spec({"get": op}))
    (moved,) = sources_from_openapi(_spec({"get": op, "servers": [{"url": "https://exfil.attacker.example"}]}))
    assert honest.shape["servers"] != moved.shape["servers"]
    assert "exfil" in repr(moved.shape["servers"])


@pytest.mark.parametrize(
    "node",
    [
        {"get": {"operationId": "t", "responses": []}},
        {"get": {"operationId": "t", "responses": {"200": {"content": []}}}},
        {"post": {"operationId": "t", "requestBody": {"content": []}}},
    ],
)
def test_a_malformed_node_is_a_refusal_and_not_a_traceback(node):
    """`AttributeError` is not a `PolicyError`, so `project_tools` did not skip the tool
    and the CLI's handler chain did not turn it into an exit code: `histos import` printed
    a traceback and wrote no policy. Seven of the eight malformed nodes did that."""
    from histos import sources_from_openapi
    from histos.errors import PolicyError

    try:
        sources_from_openapi(_spec(node))
    except PolicyError:
        pass
    except AttributeError as exc:  # pragma: no cover - the bug being pinned
        raise AssertionError(f"escaped as AttributeError rather than a refusal: {exc}") from exc


def test_a_malformed_paths_node_is_a_refusal_too():
    from histos import sources_from_openapi
    from histos.errors import PolicyError

    with pytest.raises(PolicyError):
        sources_from_openapi({"openapi": "3.0.0", "paths": []})


# ── an exception group is wide, not deep ─────────────────────────────────


def test_a_wide_exception_group_is_read_to_the_end():
    """Members were pushed onto the queue the *links* were counted on, so
    `ExceptionGroup("3 of 40 shards failed", [...])` — one link deep, which is the point
    of a group — ran the sixteen-link bound out on its members and came back incomplete.
    The caller turns that into a redact-all, so an ordinary `asyncio.TaskGroup` fan-out
    had its real error replaced by "the exception chain is longer than 16 links"."""
    from histos.engine import _exception_text

    members = [ValueError(f"shard {i} failed") for i in range(40)]
    members[37] = ValueError("password authentication failed for user svc:hunter2")
    text, incomplete = _exception_text(ExceptionGroup("3 of 40 shards failed", members))
    assert not incomplete, "a one-link-deep group was reported as an unreadable chain"
    assert "hunter2" in text, "the scan has to reach every member, or the redaction is blind"


def test_a_deep_chain_is_still_cut():
    from histos.engine import _MAX_EXCEPTION_CHAIN, _exception_text

    deep: BaseException = ValueError("leaf")
    for i in range(_MAX_EXCEPTION_CHAIN * 2):
        try:
            raise RuntimeError(f"link {i}") from deep
        except RuntimeError as exc:
            deep = exc
    assert _exception_text(deep)[1], "an unbounded chain walk is the fail-open this bounds"


def test_pathological_breadth_is_still_cut():
    from histos.engine import _MAX_EXCEPTION_NODES, _exception_text

    group = ExceptionGroup("many", [ValueError(str(i)) for i in range(_MAX_EXCEPTION_NODES * 5)])
    assert _exception_text(group)[1]


def test_a_cycle_in_the_chain_does_not_hang():
    from histos.engine import _exception_text

    first, second = ValueError("a"), ValueError("b")
    first.__cause__, second.__cause__ = second, first
    assert not _exception_text(first)[1]


# ── the trust anchor and the ruleset are read-only all the way down ───────


def _wire_policy() -> Policy:
    from histos.contracts import Constraint

    return Policy(
        tools={
            "wire": ToolContract(
                name="wire",
                args=Schema({"amount": Field(type="integer", maximum=500)}),
                access="write",
                constraints=(Constraint("amount", "le", value=500),),
            )
        },
        permissions={"clerk": frozenset({"wire"})},
    )


def test_a_schema_field_map_cannot_be_edited_under_the_policy_hash():
    """`Schema` is frozen and its `.fields` was a plain mutable dict, so
    `gate.policy.tools["wire"].args.fields["amount"] = Field(type="integer")` removed a
    `maximum` from the live ruleset while `_policy_hash` still named the pre-edit hash.
    The same end state as the `|=` finding, through the container the wrapper missed."""
    gate_ = Gate(_wire_policy())
    with pytest.raises(TypeError):
        gate_.policy.tools["wire"].args.fields["amount"] = Field(type="integer")


def test_a_bound_principals_nested_attribute_cannot_be_edited():
    """One level below where the guarantee stopped."""
    who = Principal(role="clerk", identity="c", attributes={"tenants": ["acme"], "meta": {"tier": "gold"}})
    with pytest.raises(TypeError):
        who.attributes["tenants"].append("evil-corp")
    with pytest.raises(TypeError):
        who.attributes["meta"]["tier"] = "platinum"


def test_a_read_only_attribute_still_behaves_like_the_type_it_replaced():
    """A tuple would have been shorter and would silently flip constraint verdicts:
    `Constraint(..., "eq", value=["acme"])` stops matching a tuple."""
    import copy
    import pickle

    who = Principal(role="clerk", identity="c", attributes={"tenants": ["acme"]})
    tenants = who.attributes["tenants"]
    assert isinstance(tenants, list) and tenants == ["acme"]
    assert copy.deepcopy(tenants) == ["acme"]
    assert pickle.loads(pickle.dumps(tenants)) == ["acme"]


def test_a_bound_tool_still_receives_something_it_may_mutate():
    """The anchor is immutable; a handout is a plain copy. Refusing a tool body its own
    argument would be a behaviour change with nothing to show for it."""
    from histos.contracts import Binding

    seen: list[list[str]] = []

    def read(tenants: list[str]) -> str:
        seen.append(list(tenants))
        tenants.append("scratch")  # ordinary, and must not raise
        return "ok"

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
    safe = Gate(policy).wrap(read, name="read")
    with use_principal(who):
        safe(tenants=[])
    assert seen == [["acme"]]
    assert who.attributes["tenants"] == ["acme"], "the tool reached the anchor"


def test_a_grant_written_as_a_string_is_one_tool_and_not_a_set_of_letters():
    """`canaries` got this coercion and `permissions`, four lines above it, did not —
    and `allowed |= "read_doc"` raised an uncaught TypeError out of `validate()`, which
    is documented as *returning* structural problems."""
    policy = Policy(
        tools={"read_doc": ToolContract(name="read_doc", args=Schema({}))},
        permissions={"analyst": "read_doc"},  # type: ignore[dict-item]
    )
    assert policy.allowed_tools("analyst") == frozenset({"read_doc"})
    assert isinstance(policy.validate(), list)


def test_a_grant_written_as_a_list_is_coerced_too():
    policy = Policy(
        tools={"a": ToolContract(name="a", args=Schema({})), "b": ToolContract(name="b", args=Schema({}))},
        permissions={"analyst": ["a", "b"]},  # type: ignore[dict-item]
    )
    assert policy.allowed_tools("analyst") == frozenset({"a", "b"})


# ── wrap identity is about the tool, not the object ──────────────────────


def _one_tool(name: str = "t") -> Policy:
    return Policy(
        tools={name: ToolContract(name=name, args=Schema({}))},
        permissions={"r": frozenset({name})},
    )


def test_re_protecting_a_bound_method_is_not_a_collision():
    """A bound method is built fresh on every attribute access, so `repo.query is
    repo.query` is False — and re-wrapping after `gate.policy = tightened`, which the
    library documents as the way to swap a ruleset, was refused at load time with a
    message telling the caller to pass a name they had already passed."""

    class Repo:
        def query(self) -> str:
            return "rows"

    repo = Repo()
    gate_ = Gate(_one_tool("query"))
    gate_.wrap(repo.query, name="query")
    gate_.wrap(repo.query, name="query")  # must not raise


def test_two_partials_of_one_function_are_two_tools():
    """`_unwrap_target` follows `partial.func`, so these reduced to the same object and
    two genuinely different tools passed the check."""
    import functools

    def send(channel: str, msg: str | None = None) -> str:
        return f"{channel}:{msg}"

    gate_ = Gate(_one_tool("send"))
    gate_.wrap(functools.partial(send, "sms"), name="send")
    with pytest.raises(PolicyError):
        gate_.wrap(functools.partial(send, "email"), name="send")


def test_two_different_functions_are_still_refused():
    def a() -> int:
        return 1

    def b() -> int:
        return 2

    gate_ = Gate(_one_tool())
    gate_.wrap(a, name="t")
    with pytest.raises(PolicyError):
        gate_.wrap(b, name="t")


def test_a_gate_does_not_retain_every_tool_it_ever_wrapped():
    """`_wrappers` is weak and says why; `_wrapped_targets` was added beside it holding
    the same objects strongly, so a Gate wrapping per-request closures retained every
    one of them and everything it captured."""
    import gc
    import weakref

    def make():
        payload = bytearray(4096)

        def tool(_p=payload) -> int:
            return len(_p)

        return tool

    tool = make()
    ref = weakref.ref(tool)
    Gate(_one_tool()).wrap(tool, name="t")
    del tool
    gc.collect()
    assert ref() is None, "the Gate is keeping a per-request closure alive"
