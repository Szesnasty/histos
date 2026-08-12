"""Release review, importers track: a bound in the source document must not vanish.

P0-5 and T-19 are the same defect seen twice. A malformed *value* already failed the
import loudly; an unrecognised *keyword* was dropped in silence, so
``{"$ref": "#/$defs/Mode"}`` imported as ``type: any`` — weaker than not importing the
argument at all — and every element bound under ``items`` beyond ``items.type`` went
the same way. These tests pin both halves: what is now resolved, what is now refused,
and what stays ignored because it constrains nothing.

The second half of the file pins the *other* failure mode, found by attacking the
first round of that fix: refusing by name was applied to shapes that project
perfectly well (``const``, ``anyOf: [T, null]``, an element ``enum``), and one
refusal took a whole manifest down without naming the tool it came from. An importer
that refuses honest input is the same release blocker as one that drops a bound —
the deployment breaks at load time and the user turns the importer off. So there are
tests here for what must still import, not only for what must not.
"""

from __future__ import annotations

import pytest

from histos import (
    Gate,
    GateDenied,
    GateRequest,
    Policy,
    PolicyError,
    Principal,
    Schema,
    contracts_from_mcp,
    contracts_from_openapi,
    schema_from_json_schema,
    sources_from_mcp,
    sources_from_openapi,
    use_principal,
)
from histos.importers import field_from_json_schema
from histos.importers.sources import ToolImportSkipped
from histos.schema import validate

# A pydantic-shaped document: the argument's whole contract lives behind a `$ref`,
# which is what FastMCP and the MCP Python SDK emit for any Enum or nested model.
PYDANTIC_SHAPED = {
    "type": "object",
    "properties": {"mode": {"$ref": "#/$defs/Mode"}},
    "required": ["mode"],
    "$defs": {"Mode": {"type": "string", "enum": ["read", "write"], "maxLength": 5}},
}


def _one(prop: dict, *, required: bool = True):
    """Project a single property the way an importer does — through the document."""
    doc = {"type": "object", "properties": {"a": prop}, "required": ["a"] if required else []}
    return schema_from_json_schema(doc).fields["a"]


# ── a local $ref carries its bounds instead of degrading to `any` ────────


def test_a_local_ref_is_resolved_and_every_bound_behind_it_survives():
    field = schema_from_json_schema(PYDANTIC_SHAPED).fields["mode"]
    assert field.type == "string"  # used to be "any": no type, no enum, no length
    assert field.enum == ("read", "write")
    assert field.max_length == 5
    assert field.required is True


def test_keywords_written_next_to_a_ref_win_over_the_target():
    """2020-12 allows both, and that is how a schema narrows a shared definition."""
    doc = {
        "type": "object",
        "properties": {"mode": {"$ref": "#/$defs/Mode", "maxLength": 4}},
        "$defs": {"Mode": {"type": "string", "maxLength": 5}},
    }
    field = schema_from_json_schema(doc).fields["mode"]
    assert (field.type, field.max_length) == ("string", 4)


@pytest.mark.parametrize(
    "ref",
    ["https://example.com/schema.json#/Mode", "other.json#/$defs/Mode", "#Mode", 7],
)
def test_a_ref_this_bridge_cannot_follow_is_refused(ref):
    """No network, so a remote reference is a bound that provably cannot be imported."""
    with pytest.raises(PolicyError, match="not a pointer into this document"):
        schema_from_json_schema({"type": "object", "properties": {"m": {"$ref": ref}}})


def test_a_dangling_local_ref_is_refused():
    with pytest.raises(PolicyError, match="names nothing in this document"):
        schema_from_json_schema({"type": "object", "properties": {"m": {"$ref": "#/$defs/Missing"}}})


def test_a_recursive_ref_is_refused():
    doc = {
        "type": "object",
        "properties": {"node": {"$ref": "#/$defs/Node"}},
        "$defs": {"Node": {"$ref": "#/$defs/Node"}},
    }
    with pytest.raises(PolicyError, match="recursive or over-deep"):
        schema_from_json_schema(doc)


def test_a_ref_chain_deeper_than_the_bound_is_refused():
    defs = {f"L{i}": {"$ref": f"#/$defs/L{i + 1}"} for i in range(12)}
    defs["L12"] = {"type": "string"}
    with pytest.raises(PolicyError, match="recursive or over-deep"):
        schema_from_json_schema({"type": "object", "properties": {"a": {"$ref": "#/$defs/L0"}}, "$defs": defs})


def test_a_ref_with_no_document_to_resolve_against_is_refused_not_widened():
    """A caller that hands over a property with no root has given the bridge nothing
    to resolve against, and the refusal says exactly that rather than blaming the
    document. Every importer in the package now passes a root."""
    with pytest.raises(PolicyError, match="no document was supplied"):
        field_from_json_schema({"$ref": "#/components/schemas/Mode"}, required=True)


# ── OpenAPI: the root document reaches the bridge ────────────────────────
#
# openapi.py was never given the `root=` argument, so the three places a `$ref`
# actually appears in an OpenAPI document all refused: two of them with "no document
# was supplied", and a requestBody property `$ref` with "names nothing in this
# document" — about a target sitting in `components/schemas`, which is a false
# statement about the user's file.

OPENAPI_WITH_REFS = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1"},
    "components": {
        "schemas": {
            "Mode": {"type": "string", "enum": ["read", "write"], "maxLength": 5},
            "Body": {"type": "object", "properties": {"mode": {"$ref": "#/components/schemas/Mode"}}},
        },
        "parameters": {"ModeParam": {"name": "mode", "in": "query", "schema": {"$ref": "#/components/schemas/Mode"}}},
    },
    "paths": {
        "/x": {
            "get": {
                "operationId": "getX",
                "parameters": [{"name": "mode", "in": "query", "schema": {"$ref": "#/components/schemas/Mode"}}],
            }
        },
        "/y": {"get": {"operationId": "getY", "parameters": [{"$ref": "#/components/parameters/ModeParam"}]}},
        "/z": {
            "post": {
                "operationId": "postZ",
                "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Body"}}}},
                "responses": {
                    "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Body"}}}}
                },
            }
        },
    },
}


@pytest.mark.parametrize("tool", ["getX", "getY", "postZ"])
def test_every_place_a_ref_appears_in_an_openapi_document_carries_its_bounds(tool):
    """A parameter's schema, a $ref'd parameter *object*, and a requestBody property."""
    contracts = {c.name: c for c in contracts_from_openapi(OPENAPI_WITH_REFS)}
    field = contracts[tool].args.fields["mode"]
    assert (field.type, field.enum, field.max_length) == ("string", ("read", "write"), 5)


def test_an_openapi_response_ref_is_resolved_too():
    contracts = {c.name: c for c in contracts_from_openapi(OPENAPI_WITH_REFS)}
    assert contracts["postZ"].returns.fields["mode"].enum == ("read", "write")


def test_no_openapi_refusal_can_claim_a_target_is_absent_when_it_is_present():
    """The regression that made the fix look like a document bug: the bridge was
    called with no root, so it reported `components/schemas/Mode` as naming nothing.

    Asserting only that `args` is populated was not enough to catch it — before the
    fix the `$ref` degraded to `type: any` and `args` was a populated Schema all the
    same. What separates the two states is whether the bound behind the reference
    survived, so that is what is checked."""
    for source in sources_from_openapi(OPENAPI_WITH_REFS):
        assert source.contract.args is not None
        mode = source.contract.args.fields["mode"]
        assert mode.type == "string", "the $ref degraded to `any` instead of resolving"
        assert mode.enum == ("read", "write")


def test_a_dangling_openapi_parameter_ref_is_refused_rather_than_dropping_the_argument():
    """`_deref` used to answer a miss with `{}`, so the parameter simply vanished."""
    spec = {
        "openapi": "3.0.0",
        "paths": {"/x": {"get": {"operationId": "getX", "parameters": [{"$ref": "#/components/parameters/Gone"}]}}},
    }
    with pytest.raises(PolicyError, match="names nothing in this document"):
        contracts_from_openapi(spec)


# ── an assertion the projection cannot carry is refused, not dropped ─────


@pytest.mark.parametrize(
    "prop",
    [
        {"anyOf": [{"type": "string"}, {"type": "integer"}]},  # a real union has no single type
        {"anyOf": [{"type": "string", "maxLength": 3}, {"const": "x"}]},
        {"oneOf": [{"type": "string"}]},
        {"allOf": [{"type": "string", "maxLength": 3}]},
        {"not": {"type": "string"}},
        {"if": {"type": "string"}, "then": {"maxLength": 3}},
        {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
        {"type": "array", "items": {"type": "string"}, "contains": {"const": "x"}},
        {"type": "array", "prefixItems": [{"type": "string"}]},
        {"type": "object", "additionalProperties": False},
        {"type": "object", "patternProperties": {"^a": {"type": "string"}}},
        {"type": "object", "propertyNames": {"maxLength": 3}},
        {"type": "object", "minProperties": 1},
        {"type": "object", "dependentRequired": {"a": ["b"]}},
    ],
)
def test_an_assertion_keyword_the_bridge_cannot_project_is_refused(prop):
    """Refuse rather than drop: a dropped assertion is a policy that reads as
    constrained and enforces nothing, which is the whole point of the module."""
    with pytest.raises(PolicyError, match="does not carry"):
        _one(prop)


def test_the_refusal_names_the_argument_and_the_keyword():
    with pytest.raises(PolicyError) as excinfo:
        schema_from_json_schema(
            {"type": "object", "properties": {"ids": {"anyOf": [{"type": "string"}, {"type": "integer"}]}}}
        )
    assert "'ids'" in str(excinfo.value)
    assert "anyOf" in str(excinfo.value)
    assert excinfo.value.code == "invalid_import"


def test_an_object_level_assertion_is_refused_but_the_three_projected_ones_are_not():
    with pytest.raises(PolicyError, match="does not carry"):
        schema_from_json_schema({"type": "object", "anyOf": [{"required": ["a"]}], "properties": {}})
    schema = schema_from_json_schema(
        {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"], "additionalProperties": True}
    )
    assert schema.allow_extra is True and schema.fields["a"].required is True


def test_a_boolean_schema_is_refused_rather_than_crashing_the_import():
    with pytest.raises(PolicyError, match="not a schema object"):
        schema_from_json_schema({"type": "object", "properties": {"a": True}})


def test_annotations_still_import_in_silence():
    """They constrain no value, so ignoring one cannot make the field weaker — and the
    conformance corpus pins `format`/`default`/`title`/`examples` as unprojected."""
    annotated = _one(
        {
            "type": "string",
            "title": "Mode",
            "description": "how",
            "default": "read",
            "examples": ["read"],
            "format": "email",
            "$comment": "note",
            "readOnly": True,
            "deprecated": True,
            "x-vendor-hint": {"anything": True},
        }
    )
    assert annotated == _one({"type": "string"})


# ── T-19: element bounds under `items` ───────────────────────────────────


def test_items_scalar_bounds_project_onto_the_array_field():
    """The engine already applies them per element; only `items.type` was read."""
    field = _one(
        {
            "type": "array",
            "items": {"type": "string", "pattern": "^[a-z]+$", "minLength": 2, "maxLength": 5},
        }
    )
    assert (field.type, field.item_type) == ("array", "string")
    assert (field.pattern, field.min_length, field.max_length) == ("^[a-z]+$", 2, 5)

    numeric = _one({"type": "array", "items": {"type": "integer", "minimum": 1, "maximum": 9, "multipleOf": 3}})
    assert (numeric.minimum, numeric.maximum, numeric.multiple_of) == (1, 9, 3)


def test_the_arrays_own_bound_wins_over_the_one_written_inside_items():
    field = _one({"type": "array", "maxLength": 3, "items": {"type": "string", "maxLength": 50}})
    assert field.max_length == 3


def test_a_malformed_bound_inside_items_names_where_it_was_written():
    with pytest.raises(PolicyError, match="items.maxLength"):
        _one({"type": "array", "items": {"type": "string", "maxLength": "5"}})


def test_draft4s_boolean_exclusive_minimum_is_still_ignored_inside_items():
    field = _one({"type": "array", "items": {"type": "integer", "minimum": 3, "exclusiveMinimum": True}})
    assert (field.minimum, field.exclusive_minimum) == (3, None)


def test_an_element_enum_is_carried_as_a_value_set_per_element():
    """Carried as `Field.item_enum` and checked per element. It spent one release as an
    escaped alternation in `pattern`, which worked only because the per-element screen
    happened to be a string screen — and therefore left an integer element enum
    unimportable for a reason about the implementation rather than about the source."""
    field = _one({"type": "array", "items": {"type": "string", "enum": ["read", "write"]}})
    assert field.item_enum == ("read", "write")
    assert validate(Schema({"a": field}), {"a": ["read"]}) == []
    assert validate(Schema({"a": field}), {"a": ["read", "delete"]}) != []


def test_a_non_string_element_enum_is_carried_too():
    field = _one({"type": "array", "items": {"type": "integer", "enum": [1, 2]}})
    assert field.item_enum == (1, 2)
    assert validate(Schema({"a": field}), {"a": [1, 2]}) == []
    assert validate(Schema({"a": field}), {"a": [3]}) != []


def test_an_element_enum_that_contradicts_the_element_type_is_refused():
    with pytest.raises(PolicyError):
        _one({"type": "array", "items": {"type": "integer", "enum": ["read"]}})


def test_an_element_enum_and_an_element_pattern_are_both_enforced():
    """They live in separate fields now, so the source can write both and the engine
    applies the intersection — which is what the document says."""
    field = _one({"type": "array", "items": {"type": "string", "enum": ["read"], "pattern": "^r.*$"}})
    assert field.item_enum == ("read",) and field.pattern == "^r.*$"


def test_an_element_enum_member_with_regex_metacharacters_is_matched_literally():
    field = _one({"type": "array", "items": {"type": "string", "enum": ["a.b", "c*"]}})
    schema = Schema({"a": field})
    assert validate(schema, {"a": ["a.b", "c*"]}) == []
    assert validate(schema, {"a": ["axb"]})  # `.` must not have matched any character


def test_pydantic_optional_is_an_optional_field_not_a_union():
    """`Optional[str]` is `{"anyOf": [{"type": "string"}, {"type": "null"}]}` —
    the single commonest argument shape an MCP server emits."""
    field = _one({"anyOf": [{"type": "string"}, {"type": "null"}]}, required=True)
    assert (field.type, field.required) == ("string", False)


def test_an_optional_ref_carries_the_bounds_behind_the_ref():
    doc = {
        "type": "object",
        "properties": {"mode": {"anyOf": [{"$ref": "#/$defs/Mode"}, {"type": "null"}]}},
        "$defs": {"Mode": {"type": "string", "enum": ["read", "write"], "maxLength": 5}},
    }
    field = schema_from_json_schema(doc).fields["mode"]
    assert (field.type, field.enum, field.max_length, field.required) == ("string", ("read", "write"), 5, False)


def test_a_keyword_written_next_to_the_union_wins_over_the_branch():
    field = _one({"anyOf": [{"type": "string", "maxLength": 9}, {"type": "null"}], "maxLength": 4})
    assert field.max_length == 4


def test_const_is_a_one_member_enum_and_carries_the_type_it_implies():
    field = _one({"const": "invoice"})
    assert (field.type, field.enum) == ("string", ("invoice",))
    assert _one({"const": 7}).type == "integer"
    assert _one({"const": True}).type == "boolean"  # bool before int: `true` is not 1


def test_const_beside_an_enum_is_refused_rather_than_intersected():
    with pytest.raises(PolicyError, match="both const and enum"):
        _one({"type": "string", "const": "a", "enum": ["a", "b"]})


def test_a_union_of_literals_collapses_into_one_enum():
    """`Literal["a", "b"]` and `Literal["a"] | Literal["b"]` are the same field."""
    assert _one({"oneOf": [{"const": "a"}, {"const": "b"}]}).enum == ("a", "b")
    assert _one({"anyOf": [{"enum": ["a", "b"]}, {"const": "c"}]}).enum == ("a", "b", "c")


def test_an_optional_union_of_literals_is_both_collapsed_and_optional():
    field = _one({"anyOf": [{"const": "a"}, {"const": "b"}, {"type": "null"}]}, required=True)
    assert (field.type, field.enum, field.required) == ("string", ("a", "b"), False)


def test_a_union_of_literals_that_disagree_on_type_is_refused():
    with pytest.raises(PolicyError, match="does not carry"):
        _one({"oneOf": [{"const": "a"}, {"const": 2}]})


def test_the_honest_limit_of_the_projection_is_still_refused():
    """Where the projection stops, pinned so it stays a decision rather than a drift.

    Two things moved out of this list deliberately. A nested object now projects to
    `type: object` — which is exactly what the engine checks, and what
    docs/policy-reference.md has always said it checks — because refusing it cost every
    pydantic model with a model inside it and 4 of the 19 Petstore operations. And a
    recursive model follows: the bridge stops at `type: object` and never descends, so
    there is no cycle left to hit.
    """
    for unprojectable in (
        {"type": "object", "additionalProperties": {"type": "string"}},
        {"type": "object", "patternProperties": {"^a": {"type": "string"}}},
        {"type": "object", "propertyNames": {"maxLength": 3}},
        {"anyOf": [{"type": "string"}, {"type": "integer"}]},
    ):
        with pytest.raises(PolicyError, match="does not carry"):
            _one(unprojectable)


def test_a_recursive_model_projects_as_an_object_and_does_not_hang():
    """ "Does not hang" is the property that mattered when this used to refuse."""
    recursive = schema_from_json_schema(
        {
            "type": "object",
            "properties": {"node": {"$ref": "#/$defs/N"}},
            "$defs": {"N": {"type": "object", "properties": {"child": {"$ref": "#/$defs/N"}}}},
        }
    )
    assert recursive.fields["node"].type == "object"


# ── one bad tool must not take the manifest with it ──────────────────────


def _manifest(*schemas):
    return {"tools": [{"name": f"t{i}", "inputSchema": s} for i, s in enumerate(schemas)]}


GOOD = {"type": "object", "properties": {"q": {"type": "string"}}}
# A real value-type union: no single `type` can stand for it and `any` would accept
# everything. `maxItems` used to play this role and is now carried, so it no longer can.
UNPROJECTABLE = {
    "type": "object",
    "properties": {"amount": {"anyOf": [{"type": "string"}, {"type": "integer"}]}},
}


def test_one_unprojectable_tool_no_longer_refuses_the_whole_manifest():
    """It used to. Eight healthy tools stopped importing because of the ninth, and the
    user's next move is to stop importing rather than to fix anything."""
    with pytest.warns(ToolImportSkipped):
        sources = sources_from_mcp(_manifest(GOOD, UNPROJECTABLE, GOOD))
    assert [s.name for s in sources] == ["t0", "t2"]


def test_the_skipped_tool_is_reported_by_name_alongside_the_argument_and_keyword():
    with pytest.warns(ToolImportSkipped) as warnings_seen:
        sources = sources_from_mcp(_manifest(GOOD, UNPROJECTABLE))
    (skipped,) = sources.skipped
    assert skipped.name == "t1"
    for text in (skipped.reason, str(warnings_seen[0].message)):
        assert "'t1'" in text and "'amount'" in text and "anyOf" in text


def test_a_skipped_tool_has_no_contract_so_the_gate_denies_it():
    """Skipping is only survivable because it is fail-closed downstream: a tool with
    no contract has no policy entry, and an unknown tool is denied by default."""
    with pytest.warns(ToolImportSkipped):
        contracts = contracts_from_mcp(_manifest(GOOD, UNPROJECTABLE))
    policy = Policy(tools={c.name: c for c in contracts}, permissions={"agent": frozenset({"t0", "t1"})})
    decision = Gate(policy).engine.pre(GateRequest("t1", {}, Principal(role="agent", identity="svc-1"), phase="pre"))
    assert not decision.allowed and decision.rule == "unknown_tool"


def test_a_hostile_pattern_on_one_tool_does_not_deny_the_import_of_every_other():
    """The ReDoS screen raises `unsafe_pattern`, not `invalid_import`, so scoping only
    the latter left a server able to take the whole manifest down with one regex it
    chose itself — the same denial of service one layer up."""
    redos = {"type": "object", "properties": {"q": {"type": "string", "pattern": "(a+)+$"}}}
    with pytest.warns(ToolImportSkipped, match="t1"):
        sources = sources_from_mcp(_manifest(GOOD, redos, GOOD))
    assert [s.name for s in sources] == ["t0", "t2"]


def test_a_source_where_nothing_imported_still_raises():
    """An empty policy written without a word about why is the silent failure the
    whole module exists to avoid."""
    with pytest.raises(PolicyError, match="no tool in this mcp source could be imported"):
        sources_from_mcp(_manifest(UNPROJECTABLE, UNPROJECTABLE))


def test_one_unprojectable_openapi_operation_does_not_refuse_the_others():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/a": {"get": {"operationId": "getA", "parameters": [{"name": "q", "in": "query"}]}},
            "/b": {
                "get": {
                    "operationId": "getB",
                    "parameters": [
                        {"name": "ids", "in": "query", "schema": {"anyOf": [{"type": "string"}, {"type": "integer"}]}}
                    ],
                }
            },
        },
    }
    with pytest.warns(ToolImportSkipped, match="getB"):
        assert [c.name for c in contracts_from_openapi(spec)] == ["getA"]


def test_items_on_a_field_that_is_not_an_array_is_refused():
    with pytest.raises(PolicyError, match="not declared as an array"):
        _one({"items": {"type": "string", "maxLength": 3}})


def test_an_array_of_bare_strings_still_imports_unchanged():
    """The corpus case: `items: {type: string}` alone must not move the contract."""
    field = _one({"type": "array", "items": {"type": "string"}})
    assert (field.type, field.item_type, field.max_length, field.pattern) == ("array", "string", None, None)


# ── end to end, through a real gate ──────────────────────────────────────


def _gate_for(input_schema: dict, tool_name: str = "t"):
    contracts = contracts_from_mcp({"tools": [{"name": tool_name, "inputSchema": input_schema}]})
    policy = Policy(tools={c.name: c for c in contracts}, permissions={"agent": frozenset({tool_name})})
    return Gate(policy)


def test_the_bound_behind_a_ref_refuses_a_real_call():
    gate = _gate_for(PYDANTIC_SHAPED)
    run = gate.wrap(lambda mode: {"ok": mode}, name="t")
    with use_principal(Principal(role="agent", identity="svc-1")):
        assert run(mode="read") == {"ok": "read"}
        with pytest.raises(GateDenied) as excinfo:
            run(mode="admin_write; DROP TABLE users")
    assert excinfo.value.decision.rule == "arg_schema"


def test_the_scopes_shape_imports_and_refuses_a_scope_outside_the_element_enum():
    """T-19's headline shape, end to end: `{type: array, items: {type: string, enum:
    [...]}}` is how a real MCP tool declares scopes, and it must both import and bite."""
    gate = _gate_for(
        {
            "type": "object",
            "properties": {"scopes": {"type": "array", "items": {"type": "string", "enum": ["read", "write"]}}},
            "required": ["scopes"],
        }
    )
    run = gate.wrap(lambda scopes: {"ok": scopes}, name="t")
    with use_principal(Principal(role="agent", identity="svc-1")):
        assert run(scopes=["read", "write"]) == {"ok": ["read", "write"]}
        with pytest.raises(GateDenied) as excinfo:
            run(scopes=["read", "admin"])
    assert excinfo.value.decision.rule == "arg_schema"


def test_an_element_bound_from_items_refuses_a_real_call():
    gate = _gate_for(
        {
            "type": "object",
            "properties": {"scopes": {"type": "array", "items": {"type": "string", "pattern": "^[a-z]+$"}}},
            "required": ["scopes"],
        }
    )
    run = gate.wrap(lambda scopes: {"ok": scopes}, name="t")
    with use_principal(Principal(role="agent", identity="svc-1")):
        assert run(scopes=["read"]) == {"ok": ["read"]}
        with pytest.raises(GateDenied) as excinfo:
            run(scopes=["read", "admin:*"])
    assert excinfo.value.decision.rule == "arg_schema"


# ── shapes that used to be refused and are now carried ───────────────────
#
# Refusing them was the first cut of "do not drop a bound", and it took the stance too
# far: `maxItems` is a bound this field model can hold, and a nested object degrades to
# `type: object`, which is precisely what the engine checks and what
# docs/policy-reference.md has always said it checks. Refusing instead cost every
# pydantic model with a nested model in it, and 4 of the 19 operations in the standard
# Swagger Petstore document — and a bridge people stop pointing at protects nothing.


@pytest.mark.parametrize(
    ("keyword", "attribute", "expected"),
    [("maxItems", "max_items", 3), ("minItems", "min_items", 1)],
)
def test_an_array_length_bound_is_carried_now_that_the_field_can_hold_one(keyword, attribute, expected):
    field = _one({"type": "array", "items": {"type": "string"}, keyword: expected})
    assert getattr(field, attribute) == expected


def test_a_nested_object_projects_as_an_object_rather_than_taking_the_tool_down():
    field = _one({"type": "object", "properties": {"inner": {"type": "string", "maxLength": 2}}})
    assert field.type == "object", "the engine checks it is a mapping; the inner shape is not carried"


def test_a_value_type_union_is_still_refused():
    """`any` would accept everything, which is the widening this bridge exists to refuse."""
    with pytest.raises(PolicyError):
        _one({"anyOf": [{"type": "string"}, {"type": "integer"}]})


def test_an_optional_is_still_not_a_union():
    field = _one({"anyOf": [{"type": "string", "maxLength": 4}, {"type": "null"}]})
    assert (field.type, field.nullable, field.max_length) == ("string", True, 4)
