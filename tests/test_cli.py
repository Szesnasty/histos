"""The ``histos`` CLI (Phase 0.1) — validate / review / coverage / explain / audit verify."""

from __future__ import annotations

import json

from histos.cli import main

_BUNDLE = {
    "version": "1",
    "tools": {
        "make_refund": {
            "access": "write",
            "args": {"order_id": {"type": "string"}, "amount": {"type": "integer", "maximum": 500}},
        }
    },
    "roles": {"support": {"allow": ["make_refund"]}},
}


def _policy_file(tmp_path):
    p = tmp_path / "security.policy.json"
    p.write_text(json.dumps(_BUNDLE), encoding="utf-8")
    return str(p)


def test_validate_ok(tmp_path, capsys):
    assert main(["validate", _policy_file(tmp_path)]) == 0
    assert "valid" in capsys.readouterr().out


def test_review_runs(tmp_path, capsys):
    assert main(["review", _policy_file(tmp_path)]) == 0
    assert "discovered" in capsys.readouterr().out


def test_coverage_fails_on_undeclared(tmp_path, capsys):
    rc = main(["coverage", _policy_file(tmp_path), "--tools", "make_refund,delete_everything"])
    assert rc == 1
    assert "delete_everything" in capsys.readouterr().out


def test_explain_denies_over_limit(tmp_path, capsys):
    rc = main(
        [
            "explain",
            _policy_file(tmp_path),
            "make_refund",
            "--role",
            "support",
            "--args",
            '{"order_id":"O1","amount":9999}',
        ]
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "ACTION_NOT_AUTHORIZED" in out  # agent view
    assert "arg_schema" in out  # developer view


def test_explain_allows_within_policy(tmp_path, capsys):
    rc = main(
        [
            "explain",
            _policy_file(tmp_path),
            "make_refund",
            "--role",
            "support",
            "--args",
            '{"order_id":"O1","amount":100}',
        ]
    )
    assert rc == 0
    assert "ALLOW" in capsys.readouterr().out


def test_audit_verify(tmp_path, capsys):
    from histos import JSONLAuditSink

    log = tmp_path / "a.jsonl"
    sink = JSONLAuditSink(log, hash_chain=True)
    sink.record({"decision_id": 1, "effect": "allow", "rule": "allow"})
    assert main(["audit", "verify", str(log)]) == 0
    assert "OK" in capsys.readouterr().out
