"""Contract inference from signature + type hints."""

from __future__ import annotations

import enum

from histos import infer_contract, infer_schema


class Color(enum.Enum):
    RED = "red"
    BLUE = "blue"


def test_basic_types_and_requiredness():
    def f(a: int, b: str = "x", flag: bool = False):
        return None

    schema = infer_schema(f)
    assert schema.fields["a"].type == "integer"
    assert schema.fields["a"].required is True
    assert schema.fields["b"].type == "string"
    assert schema.fields["b"].required is False  # has a default
    assert schema.fields["flag"].type == "boolean"


def test_optional_becomes_not_required():
    def f(c: int | None = None):
        return None

    schema = infer_schema(f)
    assert schema.fields["c"].type == "integer"
    assert schema.fields["c"].required is False


def test_list_item_type_is_inferred():
    def f(tags: list[str]):
        return None

    schema = infer_schema(f)
    assert schema.fields["tags"].type == "array"
    assert schema.fields["tags"].item_type == "string"


def test_enum_becomes_string_with_allowed_values():
    def f(color: Color):
        return None

    schema = infer_schema(f)
    assert schema.fields["color"].type == "string"
    assert set(schema.fields["color"].enum) == {"red", "blue"}


def test_var_keyword_allows_extra():
    def f(a: int, **rest):
        return None

    schema = infer_schema(f)
    assert schema.allow_extra is True
    assert "rest" not in schema.fields


def test_untyped_param_is_any():
    def f(whatever):
        return None

    schema = infer_schema(f)
    assert schema.fields["whatever"].type == "any"


def test_infer_contract_uses_function_name():
    def delete_thing(thing_id: int):
        return None

    contract = infer_contract(delete_thing, access="write")
    assert contract.name == "delete_thing"
    assert contract.access == "write"
    assert contract.args.fields["thing_id"].type == "integer"
