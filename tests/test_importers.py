"""Importers: JSON Schema bridge, MCP, OpenAPI → ToolContract."""

from __future__ import annotations

import pytest

from histos import (
    Gate,
    GateDenied,
    Policy,
    Principal,
    contracts_from_mcp,
    contracts_from_openapi,
    schema_from_json_schema,
    use_principal,
)
from histos.importers.sources import UNREVIEWED_ACCESS, UNREVIEWED_SENSITIVITY


def test_json_schema_bridge_maps_types_required_enum_and_constraints():
    schema = schema_from_json_schema(
        {
            "type": "object",
            "properties": {
                "invoice_id": {"type": "string", "maxLength": 20, "pattern": r"inv-\d+"},
                "count": {"type": "integer"},
                "status": {"type": "string", "enum": ["open", "paid"]},
                "tags": {"type": "array", "items": {"type": "string"}},
                "email": {"type": "string", "x-sensitive": "pii"},
            },
            "required": ["invoice_id"],
        }
    )
    assert schema.fields["invoice_id"].type == "string"
    assert schema.fields["invoice_id"].required is True
    assert schema.fields["invoice_id"].max_length == 20
    assert schema.fields["invoice_id"].pattern == r"inv-\d+"
    assert schema.fields["count"].required is False  # not in required[]
    assert schema.fields["status"].enum == ("open", "paid")
    assert schema.fields["tags"].type == "array"
    assert schema.fields["tags"].item_type == "string"
    assert schema.fields["email"].sensitive == "pii"


def test_json_schema_bridge_carries_numeric_and_length_bounds():
    """A bound the tool author already wrote must survive the import.

    Dropping one is worse than never having it: the generated policy looks like it
    carries the constraint and nobody re-derives it by hand.
    """
    schema = schema_from_json_schema(
        {
            "type": "object",
            "properties": {
                "amount": {"type": "integer", "minimum": 1, "maximum": 10000},
                "ratio": {"type": "number", "exclusiveMinimum": 0, "exclusiveMaximum": 1},
                "quantity": {"type": "integer", "multipleOf": 5},
                "note": {"type": "string", "minLength": 2, "maxLength": 40},
                # Draft-4 wrote this as a boolean modifier of `minimum`. Reading it as
                # the number 1 would invent a bound nobody asked for.
                "legacy": {"type": "integer", "minimum": 3, "exclusiveMinimum": True},
            },
        }
    )
    assert (schema.fields["amount"].minimum, schema.fields["amount"].maximum) == (1, 10000)
    assert (schema.fields["ratio"].exclusive_minimum, schema.fields["ratio"].exclusive_maximum) == (0, 1)
    assert schema.fields["quantity"].multiple_of == 5
    assert (schema.fields["note"].min_length, schema.fields["note"].max_length) == (2, 40)
    assert schema.fields["legacy"].minimum == 3
    assert schema.fields["legacy"].exclusive_minimum is None


def test_imported_bound_actually_denies():
    """End to end: a bound that came from `tools/list` refuses a call at runtime."""
    contracts = contracts_from_mcp(
        {
            "tools": [
                {
                    "name": "make_refund",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"amount": {"type": "integer", "minimum": 1, "maximum": 500}},
                        "required": ["amount"],
                    },
                }
            ]
        }
    )
    policy = Policy(tools={c.name: c for c in contracts}, permissions={"agent": frozenset({"make_refund"})})
    gate = Gate(policy)
    refund = gate.wrap(lambda amount: {"ok": amount}, name="make_refund")

    with use_principal(Principal(role="agent", identity="svc-1")):
        assert refund(amount=400) == {"ok": 400}
        with pytest.raises(GateDenied) as excinfo:
            refund(amount=5000)
    assert excinfo.value.decision.rule == "arg_schema"


def test_json_schema_closed_by_default():
    schema = schema_from_json_schema({"type": "object", "properties": {"a": {"type": "integer"}}})
    assert schema.allow_extra is False
    schema_open = schema_from_json_schema(
        {"type": "object", "properties": {"a": {"type": "integer"}}, "additionalProperties": True}
    )
    assert schema_open.allow_extra is True


def test_nullable_type_list_is_optional():
    schema = schema_from_json_schema(
        {"type": "object", "properties": {"note": {"type": ["string", "null"]}}, "required": ["note"]}
    )
    assert schema.fields["note"].type == "string"
    assert schema.fields["note"].required is False  # nullable → not required


def test_mcp_import_maps_input_and_output():
    tools = contracts_from_mcp(
        [
            {
                "name": "get_invoice",
                "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]},
                "outputSchema": {"type": "object", "properties": {"total": {"type": "number"}}},
            }
        ]
    )
    assert tools[0].name == "get_invoice"
    assert tools[0].args.fields["id"].required is True
    assert tools[0].returns.fields["total"].type == "number"
    # MCP declares neither access nor sensitivity, so the import records the most
    # damaging reading rather than the most convenient one: a vendor's `export_contacts`
    # used to land in a generated skeleton labelled `read` / `low`, which is a review
    # safety net that reads as one and is not one. `histos review` holds the policy
    # until a human decides.
    assert tools[0].access == UNREVIEWED_ACCESS == "write"
    assert tools[0].sensitivity == UNREVIEWED_SENSITIVITY


def test_openapi_import_method_maps_to_access():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/invoices/{id}": {
                "get": {
                    "operationId": "get_invoice",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object", "properties": {"total": {"type": "number"}}}
                                }
                            }
                        }
                    },
                },
                "delete": {
                    "operationId": "delete_invoice",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                },
            },
            "/invoices": {
                "post": {
                    "operationId": "create_invoice",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"amount": {"type": "number"}},
                                    "required": ["amount"],
                                }
                            }
                        }
                    },
                }
            },
        },
    }
    by_name = {c.name: c for c in contracts_from_openapi(spec)}
    assert by_name["get_invoice"].access == "read"
    assert by_name["get_invoice"].args.fields["id"].required is True
    assert by_name["get_invoice"].returns.fields["total"].type == "number"
    assert by_name["delete_invoice"].access == "write"
    assert by_name["create_invoice"].access == "write"
    assert by_name["create_invoice"].args.fields["amount"].required is True
