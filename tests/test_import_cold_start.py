"""The first command a new user runs must not hand them a traceback.

`histos import` is the front door: the documented flow is `tools/list` → infer
contracts → generate policy. A real `tools/list` response is
`{"tools": [...]}`, so accepting only a bare list meant the very first command
failed on the very file the protocol tells you to expect - and failed with a
Python stack trace rather than a sentence.
"""

from __future__ import annotations

import json

import pytest

from histos import contracts_from_mcp
from histos.cli import main

TOOLS_LIST_RESPONSE = {
    "tools": [
        {
            "name": "get_ticket",
            "description": "Read a ticket",
            "inputSchema": {"type": "object", "properties": {"ticket_id": {"type": "string"}}},
        },
        {
            "name": "delete_ticket",
            "description": "Delete a ticket",
            "inputSchema": {"type": "object", "properties": {"ticket_id": {"type": "string"}}},
        },
    ]
}


def test_accepts_a_tools_list_response():
    contracts = contracts_from_mcp(TOOLS_LIST_RESPONSE)
    assert [c.name for c in contracts] == ["get_ticket", "delete_ticket"]


def test_accepts_a_bare_list_of_tools():
    contracts = contracts_from_mcp(TOOLS_LIST_RESPONSE["tools"])
    assert [c.name for c in contracts] == ["get_ticket", "delete_ticket"]


def test_both_shapes_produce_the_same_contracts():
    wrapped = contracts_from_mcp(TOOLS_LIST_RESPONSE)
    bare = contracts_from_mcp(TOOLS_LIST_RESPONSE["tools"])
    assert [c.name for c in wrapped] == [c.name for c in bare]
    assert [sorted(c.args.fields) if c.args else None for c in wrapped] == [
        sorted(c.args.fields) if c.args else None for c in bare
    ]


def test_an_object_without_tools_says_what_it_expected():
    with pytest.raises(ValueError) as exc:
        contracts_from_mcp({"result": {"tools": []}})
    message = str(exc.value)
    assert "'tools' key" in message
    assert "result" in message, "the error should name the keys actually present"


def test_a_non_object_tool_is_refused_with_its_position():
    with pytest.raises(ValueError) as exc:
        contracts_from_mcp({"tools": ["get_ticket"]})
    assert "position 0" in str(exc.value)


# ── the CLI ──────────────────────────────────────────────────────────────


def test_cli_imports_a_tools_list_response(tmp_path, capsys):
    source = tmp_path / "tools.json"
    source.write_text(json.dumps(TOOLS_LIST_RESPONSE), encoding="utf-8")

    assert main(["import", str(source), "--kind", "mcp"]) == 0
    assert "get_ticket" in capsys.readouterr().out


def test_cli_reports_a_bad_shape_as_a_sentence(tmp_path, capsys):
    source = tmp_path / "tools.json"
    source.write_text(json.dumps({"result": []}), encoding="utf-8")

    assert main(["import", str(source), "--kind", "mcp"]) == 2
    assert "error:" in capsys.readouterr().err


def test_cli_reports_a_missing_file_as_a_sentence(capsys):
    assert main(["import", "no-such-file.json", "--kind", "mcp"]) == 2
    assert "no such file" in capsys.readouterr().err


def test_cli_reports_invalid_json_as_a_sentence(tmp_path, capsys):
    source = tmp_path / "tools.json"
    source.write_text("{not json", encoding="utf-8")

    assert main(["import", str(source), "--kind", "mcp"]) == 2
    assert "not valid JSON" in capsys.readouterr().err
