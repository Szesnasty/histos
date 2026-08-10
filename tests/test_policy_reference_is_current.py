"""The generated reference must match the schema it claims to describe.

A reference document that drifts is worse than none: it is a confident answer to
"what does this key do" that stopped being true two releases ago. So the
committed file is compared against a fresh render, and the suite fails if
somebody edits the schema without regenerating.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
GENERATOR_PATH = REPOSITORY_ROOT / "scripts" / "generate_policy_reference.py"
REFERENCE_PATH = REPOSITORY_ROOT / "docs" / "policy-reference.md"


def _load_generator():
    spec = importlib.util.spec_from_file_location("generate_policy_reference", GENERATOR_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["generate_policy_reference"] = module
    spec.loader.exec_module(module)
    return module


def test_the_reference_is_regenerated_from_the_current_schema():
    expected = _load_generator().build()
    assert REFERENCE_PATH.read_text(encoding="utf-8") == expected, (
        "docs/policy-reference.md is out of date - run: python scripts/generate_policy_reference.py"
    )


def test_the_reference_documents_every_tool_key():
    """A key the engine accepts but the reference omits is a key nobody can look up."""
    import json

    schema = json.loads((REPOSITORY_ROOT / "spec" / "policy-0.1.schema.json").read_text(encoding="utf-8"))
    reference = REFERENCE_PATH.read_text(encoding="utf-8")

    for key in schema["$defs"]["tool"]["properties"]:
        assert f"| `{key}` |" in reference, f"tool key {key!r} is missing from the reference"
    for key in schema["$defs"]["field"]["properties"]:
        assert f"| `{key}` |" in reference, f"field key {key!r} is missing from the reference"
