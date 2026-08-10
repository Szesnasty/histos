"""Hostile and malformed input: imported schemas, policy bundles, the CLI.

An imported tool schema is UNTRUSTED — it is whatever server the user pointed at.
Everything here is a regression test for a way that input used to hang the process,
leak an argument value, or produce a policy that reads as constrained and enforces
nothing.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

from histos import (
    Field,
    Gate,
    GateDenied,
    InMemoryAuditSink,
    LimitStore,
    Policy,
    PolicyError,
    Principal,
    Schema,
    ToolContract,
    ToolSource,
    contracts_from_mcp,
    dump_bundle,
    load_bundle,
    parse_json_bundle,
    parse_yaml_bundle,
    review_policy,
    use_principal,
)
from histos.bundle import _MAX_EXPANDED_NODES, _expanded_size, load_bundle_yaml
from histos.cli import main
from histos.contracts import Constraint
from histos.importers import KINDS, field_from_json_schema, reader_for, register_source_kind
from histos.infer import infer_schema
from histos.lockfile import build_lock, parse_lock, unverifiable_tools
from histos.schema import _MAX_PATTERN_INPUT, sensitive_fields, validate

GALLERY = Path(__file__).resolve().parent.parent / "policies"

# ── ReDoS from an imported pattern ───────────────────────────────────────

# The classic catastrophic families. Every one of these used to import cleanly and
# then hang on a crafted argument well inside the 4 KiB cap.
CATASTROPHIC = [
    r"(a+)+$",
    r"([a-z]+)*$",
    r"(a|a)+",
    r"(a|ab)*",
    r"(?:a{1,3})+",
    r"(x+x+)+y",
    r"\d+\d+",
    r"^(\w+\s?)*$",
    r"(?=(a+)+)x",
]

# Patterns a real policy actually contains, including every one in `policies/`.
BENIGN = [
    r"ORD-[0-9]+",
    r"[A-Za-z0-9._%+-]+@acme-corp\.com",
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    r"(v[0-9]+\.[0-9]+\.[0-9]+|[0-9a-f]{40})",
    r"^\d{4}-\d{2}-\d{2}$",
    r"^(GET|POST|PUT)$",
    r"\w+\s+\w+",
    r"(?>a+)+",
    r"a*+b",
]


@pytest.mark.parametrize("pattern", CATASTROPHIC)
def test_a_pattern_that_backtracks_exponentially_is_refused_at_load(pattern):
    with pytest.raises(PolicyError, match="backtrack exponentially"):
        Field(type="string", pattern=pattern)


@pytest.mark.parametrize("pattern", BENIGN)
def test_the_screen_does_not_reject_the_patterns_real_policies_use(pattern):
    assert Field(type="string", pattern=pattern).pattern == pattern


def test_an_untrusted_mcp_server_cannot_hand_us_a_pattern_that_hangs_the_process():
    """The whole point: the refusal happens at import, in microseconds.

    `re` has no step budget and holds the GIL, so once a catastrophic match starts
    there is nothing to interrupt it. The old code accepted this schema and the first
    call carrying `"a" * 40 + "!"` never returned; the 4096-char cap the module
    advertised as the bound was never a bound at all.
    """
    hostile = {
        "tools": [
            {
                "name": "lookup",
                "inputSchema": {
                    "type": "object",
                    "properties": {"q": {"type": "string", "pattern": r"(a+)+$"}},
                    "required": ["q"],
                },
            }
        ]
    }
    started = time.perf_counter()
    with pytest.raises(PolicyError, match="backtrack exponentially"):
        contracts_from_mcp(hostile)
    assert time.perf_counter() - started < 1.0


def test_a_permitted_pattern_matches_a_full_length_worst_case_input_quickly():
    """What survives the screen must stay bounded at the cap the module advertises."""
    schema = Schema({"q": Field(type="string", pattern=r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")})
    worst_case = "a" * (_MAX_PATTERN_INPUT - 1) + "!"

    started = time.perf_counter()
    errors = validate(schema, {"q": worst_case})
    elapsed = time.perf_counter() - started

    assert errors == ["q: does not match required pattern"]
    assert elapsed < 0.5, f"a 4 KiB non-match took {elapsed:.3f}s"


# ── numeric bounds that never fire ───────────────────────────────────────


@pytest.mark.parametrize(
    "kwargs",
    [
        {"maximum": float("nan")},
        {"minimum": float("nan")},
        {"maximum": float("inf")},
        {"exclusive_minimum": float("-inf")},
        {"multiple_of": float("nan")},
    ],
)
def test_a_non_finite_bound_is_refused_rather_than_silently_never_enforcing(kwargs):
    """Every IEEE comparison against NaN is False, so the bound reads as a cap and is not one."""
    with pytest.raises(PolicyError, match="non-finite"):
        Field(type="number", **kwargs)


def test_a_bound_past_the_float_range_is_refused_instead_of_raising_inside_the_gate():
    with pytest.raises(PolicyError, match="past the range a float can compare"):
        Field(type="number", multiple_of=10**400)


@pytest.mark.parametrize("value", [True, "5", None])
def test_a_length_bound_must_be_a_non_negative_whole_number(value):
    if value is None:
        assert Field(type="string", max_length=None).max_length is None
        return
    with pytest.raises(PolicyError, match="non-negative integer"):
        Field(type="string", max_length=value)


def test_an_imported_infinite_bound_is_refused_at_the_importer():
    """`1e999` is valid JSON that json.loads overflows to inf — no exotic literal needed."""
    with pytest.raises(PolicyError, match="finite number"):
        field_from_json_schema({"type": "number", "maximum": 1e999}, required=True)


def test_the_json_parser_refuses_pythons_nan_and_infinity_literals():
    with pytest.raises(PolicyError, match="non-standard JSON literal"):
        parse_json_bundle('{"tools": {"t": {"args": {"a": {"type": "number", "maximum": NaN}}}}}')
    with pytest.raises(PolicyError, match="non-standard JSON literal"):
        parse_json_bundle('{"tools": {"t": {"args": {"a": {"type": "number", "maximum": Infinity}}}}}')


# ── validation errors never carry an argument value ──────────────────────

CANARY = "CANARY-7f3a-DO-NOT-LEAK"
PII = "Jane Doe, DOB 1971-03-02, HIV+, card 4111111111111111"


def _enum_policy() -> Policy:
    return Policy(
        tools={"note": ToolContract(name="note", args=Schema({"body": Field(type="string", enum=("a", "b"))}))},
        permissions={"agent": frozenset({"note"})},
        canaries=frozenset({CANARY}),
    )


@pytest.mark.parametrize("value", [PII, f"leaking {CANARY} here"])
def test_a_pre_phase_schema_denial_never_writes_the_argument_to_the_audit_record(value):
    """The PRE path had no equivalent of the POST-path redaction test, and needed one.

    `arg_schema` is evaluated before the canary check, so an enum-typed argument put
    the rejected value — PII, or the canary token itself — verbatim into the audit
    `reason` the docs promise holds only an HMAC digest.
    """
    sink = InMemoryAuditSink()
    safe = Gate(_enum_policy(), audit=sink).wrap(lambda body: body, name="note")

    with use_principal(Principal(role="agent")), pytest.raises(GateDenied) as exc:
        safe(body=value)

    records = sink.entries
    assert records, "the denial must be recorded"
    for record in records:
        assert value not in json.dumps(record)
        assert CANARY not in json.dumps(record)
    assert value not in str(exc.value)
    assert CANARY not in str(exc.value)


@pytest.mark.parametrize(
    ("spec", "call_args"),
    [
        (Field(type="integer", minimum=0, maximum=10), {"body": 4_111_111_111_111_111}),
        (Field(type="integer", multiple_of=5), {"body": 4_111_111_111_111_111}),
        (Field(type="number", exclusive_maximum=1.0), {"body": 4111.1111111111}),
    ],
)
def test_a_bound_violation_names_the_bound_and_not_the_value(spec, call_args):
    errors = validate(Schema({"body": spec}), call_args)
    assert errors, "the bound must still fire"
    assert str(call_args["body"]) not in errors[0]


# ── can_view gates sensitivity classes, as documented ────────────────────


def _returns() -> Schema:
    return Schema(
        {
            "email": Field(type="string", sensitive="pii"),
            "token": Field(type="string", sensitive="secret"),
            "total": Field(type="number"),
        }
    )


def test_a_principal_without_can_view_sees_every_sensitive_field_redacted():
    assert sensitive_fields(_returns()) == ["email", "token"]


def test_can_view_names_a_sensitivity_class_as_the_docs_document_it():
    """`can_view=frozenset({"pii"})` is the exact spelling in docs/identity.md."""
    assert sensitive_fields(_returns(), allowed=frozenset({"pii"})) == ["token"]
    assert sensitive_fields(_returns(), allowed=frozenset({"pii", "secret"})) == []


def test_a_field_name_in_can_view_does_not_unredact_anything():
    """The undocumented escape hatch is closed: a name the policy never published
    must not disclose the field it happens to match."""
    assert sensitive_fields(_returns(), allowed=frozenset({"email"})) == ["email", "token"]


def test_can_view_is_per_principal_and_does_not_leak_between_callers():
    privileged = Principal(role="support", can_view=frozenset({"pii"}))
    ordinary = Principal(role="support")
    assert sensitive_fields(_returns(), allowed=privileged.can_view) == ["token"]
    assert sensitive_fields(_returns(), allowed=ordinary.can_view) == ["email", "token"]


# ── every bundle failure is a PolicyError ────────────────────────────────

MALFORMED = {
    "unknown field type": {"tools": {"t": {"args": {"x": {"type": "strng"}}}}},
    "multiple_of zero": {"tools": {"t": {"args": {"x": {"type": "integer", "multiple_of": 0}}}}},
    "bad sensitive": {"tools": {"t": {"args": {"x": {"sensitive": "nope"}}}}},
    "uncompilable regex": {"tools": {"t": {"args": {"x": {"pattern": "("}}}}},
    "unknown sensitivity": {"tools": {"t": {"sensitivity": "nope"}}},
    "args is a list": {"tools": {"t": {"args": []}}},
    "field is null": {"tools": {"t": {"args": {"f": None}}}},
    "pattern is a number": {"tools": {"t": {"args": {"f": {"pattern": 7}}}}},
    "where is missing field": {"tools": {"t": {"resource": {"where": [{"op": "eq"}]}}}},
    "where is a string": {"tools": {"t": {"resource": {"where": "tenant_id"}}}},
    "resource is a number": {"tools": {"t": {"resource": 5}}},
    "owns is missing principal_attr": {"tools": {"t": {"resource": {"owns": {"field": "a"}}}}},
    "roles is a number": {"tools": {}, "roles": {"r": 5}},
    "bind is a number": {"tools": {"t": {"bind": 5}}},
    "confirmation is a number": {"tools": {"t": {"confirmation": 5}}},
    "output is a number": {"tools": {"t": {"output": 5}}},
    "tool spec is a list": {"tools": {"t": ["access"]}},
    "json_schema is a number": {"tools": {"t": {"args": {"json_schema": 5}}}},
    "enum is a number": {"tools": {"t": {"args": {"x": {"enum": 5}}}}},
    "bound past float range": {"tools": {"t": {"args": {"x": {"type": "integer", "maximum": 10**400}}}}},
    "min_length is a string": {"tools": {"t": {"args": {"x": {"min_length": "5"}}}}},
    "top level is a list": [],
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_every_malformed_bundle_raises_policy_error_not_a_raw_builtin(name):
    """A host doing the documented `except PolicyError: fail_closed()` must catch it.

    These used to escape as AttributeError / TypeError / KeyError / ValueError, past
    the documented contract and past the CLI's error handler, which printed a
    traceback at whoever typed the command.
    """
    with pytest.raises(PolicyError):
        load_bundle(MALFORMED[name])


# ── list-valued fields are type-checked, not just key-checked ────────────


def test_canaries_as_a_bare_string_is_refused_instead_of_becoming_one_per_character():
    """One missing bracket used to turn a policy into a total-denial policy.

    `frozenset("SECRET-TOKEN")` is nine one-character canaries, every argument
    containing any of those letters is denied as exfiltration, and `histos validate`
    reported the policy as fine.
    """
    with pytest.raises(PolicyError, match="`canaries` must be a list"):
        load_bundle({"tools": {}, "canaries": "SECRET-TOKEN"})


def test_a_one_character_canary_is_refused_even_when_the_list_is_well_formed():
    with pytest.raises(PolicyError, match="shorter than"):
        load_bundle({"tools": {}, "canaries": ["S"]})


def test_a_non_string_canary_is_refused():
    with pytest.raises(PolicyError, match="canaries are string tokens"):
        load_bundle({"tools": {}, "canaries": [42]})


def test_a_real_canary_still_loads():
    policy = load_bundle({"tools": {}, "canaries": [CANARY]})
    assert policy.canaries == frozenset({CANARY})


def test_allow_as_a_bare_string_is_refused_instead_of_granting_one_tool_per_character():
    with pytest.raises(PolicyError, match="`allow` on role 'agent' must be a list"):
        load_bundle({"tools": {"refund": {}}, "roles": {"agent": {"allow": "refund"}}})


# ── the YAML alias-expansion bomb ────────────────────────────────────────

BOMB = """
tools:
  a: &a ["x","x","x","x","x","x","x","x","x"]
  b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
  c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
  d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
  e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
  f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
  g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
"""


def test_a_yaml_alias_bomb_is_refused_at_parse_rather_than_expanded_by_content_hash():
    """A YAML alias is a reference, so this parses instantly and holds nothing.

    It costs everything to *walk*, and `content_hash` walks: 276 bytes became 59 MB of
    canonical JSON and 700 MB of RSS before any decision was made.
    """
    assert len(BOMB.encode()) < 400
    started = time.perf_counter()
    with pytest.raises(PolicyError, match="expands to more than"):
        parse_yaml_bundle(BOMB)
    assert time.perf_counter() - started < 1.0


def test_load_bundle_refuses_the_same_bomb_handed_over_as_an_already_parsed_dict():
    """The ImportError message tells a user without PyYAML to parse it themselves and
    call `load_bundle(dict)`, so that door has to be guarded too."""
    shared = ["x"] * 9
    for _ in range(7):
        shared = [shared] * 9
    with pytest.raises(PolicyError, match="expands to more than"):
        load_bundle({"tools": {"t": shared}})


def test_an_ordinary_policy_is_nowhere_near_the_expansion_budget():
    """The budget has to be unreachable by anything a human would write."""
    biggest = max(GALLERY.glob("*.policy.yaml"), key=lambda p: p.stat().st_size)
    data = parse_yaml_bundle(biggest.read_text(encoding="utf-8"))
    assert _expanded_size(data, {}) < _MAX_EXPANDED_NODES / 50


# ── dump → load round-trips to the same content_hash ─────────────────────


@pytest.mark.parametrize(
    "constraints",
    [
        (Constraint("status", "ne", value="cancelled"), Constraint.owns("tenant_id")),
        (Constraint.owns("tenant_id"), Constraint("status", "ne", value="cancelled")),
        (Constraint.owns("tenant_id"), Constraint.owns("region", "home_region")),
        (Constraint.owns("owner_id", "user_id"),),
    ],
)
def test_a_dumped_bundle_reloads_to_the_same_content_hash(constraints):
    """`histos import --update` dumps, reviews and reloads. Hoisting an ownership rule
    out of the middle of the list reordered the constraints, and `Policy.fingerprint`
    hashes them in order — so a policy whose meaning did not change came back with a
    different hash and silently invalidated every approval pinned to the old one."""
    policy = Policy(tools={"t": ToolContract(name="t", args=Schema({}), constraints=constraints)})
    reloaded = load_bundle(dump_bundle(policy))
    assert [(c.field, c.op, c.principal_attr) for c in reloaded.tools["t"].constraints] == [
        (c.field, c.op, c.principal_attr) for c in constraints
    ]
    assert reloaded.content_hash() == policy.content_hash()


def test_every_policy_in_the_gallery_round_trips_to_the_same_hash():
    for path in sorted(GALLERY.glob("*.policy.yaml")):
        policy = load_bundle_yaml(path.read_text(encoding="utf-8"))
        assert load_bundle(dump_bundle(policy)).content_hash() == policy.content_hash(), path.name


# ── the curated PyYAML message is reachable ──────────────────────────────


def test_the_pip_install_message_is_what_a_user_without_pyyaml_actually_sees(monkeypatch):
    """`parse_yaml_bundle` had its own bare `import yaml`, which raised first and made
    the curated message in `_strict_yaml_loader` dead code."""
    import histos.bundle as bundle_module

    monkeypatch.setattr(bundle_module, "_yaml_loader_cache", None)
    monkeypatch.setitem(sys.modules, "yaml", None)  # a None entry makes `import yaml` raise

    with pytest.raises(ImportError, match=r"pip install histos\[yaml\]"):
        parse_yaml_bundle("tools: {}")


# ── inference degrades loudly, not silently ──────────────────────────────


def _module_with_unresolvable_annotation():
    import types

    source = (
        "from __future__ import annotations\n"
        "import typing\n"
        "if typing.TYPE_CHECKING:\n"
        "    from nowhere import Thing\n"
        "def tool(a: int, b: Thing) -> None: ...\n"
    )
    module = types.ModuleType("unresolvable")
    exec(compile(source, "unresolvable", "exec"), module.__dict__)  # noqa: S102 — fixture, not input
    return module


def test_an_unresolvable_annotation_degrades_to_any_without_crashing():
    schema = infer_schema(_module_with_unresolvable_annotation().tool)
    assert {name: f.type for name, f in schema.fields.items()} == {"a": "any", "b": "any"}


def test_review_names_a_schema_in_which_no_field_declares_a_type():
    """`_schema_constrains` keeps `protect()` fail-closed, but the degradation used to be
    invisible in every report — `histos review` counted it as coverage."""
    degraded = Policy(
        tools={"t": ToolContract(name="t", args=Schema({"a": Field(type="any"), "b": Field(type="any")}))},
        permissions={"r": frozenset({"t"})},
    )
    review = review_policy(degraded)
    assert any("no field declares a type" in w for w in review.warnings)
    assert review.needs_review == ["t"]

    typed = Policy(
        tools={"t": ToolContract(name="t", args=Schema({"a": Field(type="string")}))},
        permissions={"r": frozenset({"t"})},
    )
    assert not any("no field declares a type" in w for w in review_policy(typed).warnings)


# ── limit state does not grow on the read path ───────────────────────────


def test_a_read_only_limit_check_allocates_no_per_identity_state():
    """`Engine.pre` calls `check`, and `check` used to create a deque per identity.

    An attacker-chosen identity string was therefore unbounded memory, and evaluating
    a policy for analysis perturbed the store it was measuring.
    """
    store = LimitStore()
    for i in range(1_000):
        assert store.check(f"user-{i}", "t", rate_limit=5, budget=3) is None
    assert len(store._calls) == 0
    assert len(store._budget_used) == 0


def test_prune_evicts_expired_rate_state_and_never_a_budget():
    clock_time = [1_000.0]
    store = LimitStore(window_seconds=60.0, time_fn=lambda: clock_time[0])
    for i in range(10):
        store.consume(f"user-{i}", "t")
    assert len(store._calls) == 10

    assert store.prune() == 0, "nothing has expired yet"
    clock_time[0] += 61.0
    assert store.prune() == 10
    assert len(store._calls) == 0
    # A budget is for the life of the store; forgetting one hands the allowance back.
    assert store.check("user-0", "t", rate_limit=None, budget=1) == "budget"


# ── importers are an extension point ─────────────────────────────────────


def _anthropic_reader(doc):
    return [
        ToolSource(
            name=tool["name"],
            kind="anthropic",
            description=tool.get("description"),
            shape={"input": tool.get("input_schema")},
            contract=ToolContract(name=tool["name"], args=Schema({})),
        )
        for tool in doc["tools"]
    ]


def test_a_third_party_importer_can_register_a_kind_and_reach_the_lock():
    """A host could always build a ToolContract but never a ToolSource, so its tools
    could not enter a lock file and `histos drift` reported them as unverifiable
    forever, with no way to close the gap short of forking."""
    register_source_kind("anthropic", _anthropic_reader)
    try:
        assert "anthropic" in KINDS
        assert reader_for("anthropic") is _anthropic_reader

        sources = _anthropic_reader({"tools": [{"name": "search"}]})
        lock = parse_lock(json.loads(build_lock(sources, policy="p.json", locator="anthropic://x").dumps()))
        assert lock.tools["search"].kind == "anthropic"
        assert unverifiable_tools(["search"], lock) == ()
    finally:
        del KINDS._readers["anthropic"]


def test_registering_over_a_built_in_kind_is_refused():
    """A lock entry names its kind, so rebinding one changes what recorded provenance means."""
    with pytest.raises(ValueError, match="already registered"):
        register_source_kind("mcp", _anthropic_reader)


def test_an_unregistered_kind_still_cannot_construct_a_tool_source():
    with pytest.raises(ValueError, match="unknown source kind"):
        ToolSource(name="x", kind="pydantic", description=None, shape={}, contract=ToolContract(name="x"))


# ── imported bounds that would enforce nothing ───────────────────────────


@pytest.mark.parametrize(
    "prop",
    [
        {"type": "string", "maxLength": True},
        {"type": "string", "maxLength": "50"},
        {"type": "string", "minLength": -1},
        {"type": "string", "minLength": 1.5},
    ],
)
def test_a_malformed_length_bound_fails_the_import(prop):
    """`maxLength: true` became a one-character cap; `maxLength: "50"` raised TypeError
    from inside the gate, where a decision was owed."""
    with pytest.raises(PolicyError, match="malformed"):
        field_from_json_schema(prop, required=True)


def test_an_enum_that_contradicts_its_declared_type_fails_the_import_loudly():
    """The type check runs first, so a string enum on an integer field denies every
    call — fail-closed and therefore silent. Name it where it can be fixed."""
    with pytest.raises(PolicyError, match="no value can satisfy both"):
        field_from_json_schema({"type": "integer", "enum": ["a", "b"]}, required=True)
    with pytest.raises(PolicyError, match="no value can satisfy both"):
        field_from_json_schema({"type": "integer", "enum": [1, True]}, required=True)


def test_a_well_formed_import_is_untouched():
    field = field_from_json_schema(
        {"type": "integer", "minimum": 1, "maximum": 500, "enum": [1, 5, 500]}, required=True
    )
    assert (field.minimum, field.maximum, field.enum) == (1, 500, (1, 5, 500))
    # draft-4's boolean modifier form is still dropped rather than read as the number 1.
    draft4 = field_from_json_schema({"type": "number", "minimum": 0, "exclusiveMinimum": True}, required=True)
    assert (draft4.minimum, draft4.exclusive_minimum) == (0, None)
    # A nullable field may enumerate null.
    nullable = field_from_json_schema({"type": ["string", "null"], "enum": ["a", None]}, required=True)
    assert nullable.enum == ("a", None)


# ── the CLI and the runtime agree about what is loadable ─────────────────


def _mcp_source(tmp_path: Path) -> str:
    doc = {
        "tools": [
            {
                "name": "read_file",
                "description": "read a file",
                "inputSchema": {"type": "object", "properties": {"p": {"type": "string"}}, "required": ["p"]},
            }
        ]
    }
    path = tmp_path / "tools.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def test_the_cli_refuses_an_unknown_extension_exactly_as_the_gate_does(tmp_path, capsys):
    """`histos validate policy.yaml.bak` used to be parsed as JSON and could validate
    clean, while `Gate(policy='policy.yaml.bak')` refused it outright — a CI gate
    passing on an artifact the runtime will not load."""
    path = tmp_path / "security.policy.yaml.bak"
    path.write_text(json.dumps({"tools": {}}), encoding="utf-8")

    assert main(["validate", str(path)]) == 2
    assert "must be .yaml, .yml or .json" in capsys.readouterr().err


def test_a_malformed_policy_reaches_the_cli_handler_instead_of_printing_a_traceback(tmp_path, capsys):
    path = tmp_path / "security.policy.json"
    path.write_text(json.dumps({"tools": {"t": {"args": []}}}), encoding="utf-8")

    assert main(["review", str(path)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: ")
    assert "Traceback" not in err


def test_drift_states_its_coverage_and_can_be_made_to_fail_on_it(tmp_path, capsys):
    """cli.py advertises drift as the CI gate, and CI reads the exit code, not the prose."""
    source = _mcp_source(tmp_path)
    policy = str(tmp_path / "security.policy.json")
    assert main(["import", source, "--kind", "mcp", "--out", policy]) == 0
    capsys.readouterr()

    data = json.loads(Path(policy).read_text(encoding="utf-8"))
    data["tools"]["hand_written"] = {"args": {"x": {"type": "string"}}}
    Path(policy).write_text(json.dumps(data), encoding="utf-8")

    # Fail-closed by default: a CI gate that passes having checked only half the policy
    # is worse than no gate, so the tool it could not verify is what decides the exit
    # code. `--allow-unverifiable` is the deliberate opt-out.
    assert main(["drift", policy, "--source", source, "--kind", "mcp"]) == 1
    captured = capsys.readouterr()
    assert "unverifiable from here (1): hand_written" in captured.out
    assert "were not checked at all" in captured.err

    assert main(["drift", policy, "--source", source, "--kind", "mcp", "--allow-unverifiable"]) == 0
    out = capsys.readouterr().out
    assert "OK — 1 of 2 policy tool(s) match the lock" in out


def test_drift_still_passes_cleanly_when_the_lock_covers_everything(tmp_path, capsys):
    source = _mcp_source(tmp_path)
    policy = str(tmp_path / "security.policy.json")
    assert main(["import", source, "--kind", "mcp", "--out", policy]) == 0
    capsys.readouterr()

    assert main(["drift", policy, "--source", source, "--kind", "mcp", "--fail-on-unverifiable"]) == 0
    assert "OK — 1 of 1 policy tool(s) match the lock" in capsys.readouterr().out
