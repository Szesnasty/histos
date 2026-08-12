"""Every field in the policy format has to explain itself.

The schema is not only a validator: it is the *documentation surface*. A policy
carrying `# yaml-language-server: $schema=...` gets completion and hover text
straight out of this file, and `docs/policy-reference.md` is generated from it.
A property with no `description` therefore produces an editor tooltip that says
nothing and a reference row that is blank - which is how somebody ends up
guessing what `on_violation` does.

So this is a test rather than a convention: adding a field to the format without
saying what it does fails the suite.
"""

from __future__ import annotations

import json
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "spec" / "policy-0.1.schema.json"

# A minimum that rules out placeholder text like "the tool name" while staying
# well under the shortest real description in the file.
MINIMUM_DESCRIPTION_LENGTH = 24


def _properties(node: dict, path: str) -> list[tuple[str, dict]]:
    """Every `properties` entry reachable from `node`, with a dotted path."""
    found: list[tuple[str, dict]] = []
    for key, value in (node.get("properties") or {}).items():
        found.append((f"{path}.{key}", value))
        if isinstance(value, dict):
            found += _properties(value, f"{path}.{key}")
    for nested_key in ("additionalProperties", "items"):
        nested = node.get(nested_key)
        if isinstance(nested, dict):
            found += _properties(nested, f"{path}[*]")
    return found


def _every_property() -> list[tuple[str, dict]]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    found = _properties(schema, "root")
    for name, definition in (schema.get("$defs") or {}).items():
        found += _properties(definition, f"$defs.{name}")
    return found


def test_the_schema_has_properties_at_all():
    assert len(_every_property()) > 30, "the walker found almost nothing - it is probably broken"


def test_every_property_is_described():
    undocumented = [path for path, prop in _every_property() if not (prop or {}).get("description")]
    assert not undocumented, (
        "these fields would show an empty tooltip in an editor and an empty row in the "
        f"reference: {', '.join(undocumented)}"
    )


def test_no_description_is_a_placeholder():
    too_short = [
        f"{path} ({len(prop['description'])} chars)"
        for path, prop in _every_property()
        if len((prop or {}).get("description") or "") < MINIMUM_DESCRIPTION_LENGTH
    ]
    assert not too_short, f"descriptions that say nothing useful: {', '.join(too_short)}"


def test_enums_are_documented_where_the_values_are_not_obvious():
    """A closed set of values is exactly where a reader needs to be told the default."""
    for path, prop in _every_property():
        if isinstance(prop, dict) and prop.get("enum"):
            assert prop.get("description"), f"{path} has a fixed set of values and no explanation"


def test_the_published_field_keys_are_exactly_the_ones_the_loader_accepts():
    """The two drifted, and nothing said so. `_FIELD_KEYS` learned `nullable`,
    `item_enum`, `max_items` and `min_items`; `spec/policy-0.1.schema.json` did not,
    and it declares `additionalProperties: false` — so `histos import --out` wrote a
    bundle that is invalid against the library's own published format, under an
    unchanged `histos.policy/0.1` version string. A second implementation reading the
    spec would have refused a file this one writes."""
    from histos.bundle import _FIELD_KEYS

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    published = set(schema["$defs"]["field"]["properties"])
    assert published == set(_FIELD_KEYS), (
        f"in the loader but not the spec: {sorted(set(_FIELD_KEYS) - published)}; "
        f"in the spec but not the loader: {sorted(published - set(_FIELD_KEYS))}"
    )


def test_a_dumped_policy_validates_against_the_published_format():
    """The round trip the spec exists for, run rather than assumed."""
    from histos import Field, Policy, Schema, ToolContract, dump_bundle

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    field_props = set(schema["$defs"]["field"]["properties"])
    schema_props = set(schema["$defs"]["schema"].get("properties", {}))

    policy = Policy(
        tools={
            "t": ToolContract(
                name="t",
                args=Schema(
                    {
                        "tags": Field(
                            type="array",
                            item_type="string",
                            item_enum=("read", "write"),
                            max_items=4,
                            min_items=1,
                            nullable=True,
                        )
                    },
                    allow_extra=True,
                ),
            )
        },
        permissions={"ok": frozenset({"t"})},
    )
    node = dump_bundle(policy)["tools"]["t"]["args"]
    for key, value in node.items():
        if key.startswith("$"):
            assert key in schema_props, f"{key} is emitted but undocumented"
            continue
        assert set(value) <= field_props, f"field {key} emits undocumented keys: {sorted(set(value) - field_props)}"
