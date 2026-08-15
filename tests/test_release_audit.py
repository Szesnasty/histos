"""P0-4 — a model-chosen argument *name* must not make the evidence file unreadable.

The record is still never dropped and the digest still refuses no input; what changed is
that the JSONL line is ASCII by construction, so a lone surrogate in an argument name is
escaped rather than written as raw ED A0 80.
"""

from __future__ import annotations

import json

import pytest

from histos import (
    AuditRecord,
    Field,
    Gate,
    GateDenied,
    JSONLAuditSink,
    Policy,
    Principal,
    Schema,
    ToolContract,
    use_principal,
    verify_chain,
)

STABLE_KEY = b"release-audit-key"


def _read_records(log):
    """Read the log the ordinary way — strict UTF-8, line by line."""
    with open(log, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


# ── the file stays readable ───────────────────────────────────────────────


def test_a_lone_surrogate_argument_key_leaves_the_file_utf8_readable(tmp_path):
    log = tmp_path / "a.jsonl"
    sink = JSONLAuditSink(log, hash_chain=True, key=STABLE_KEY)
    sink.record({"decision_id": 1, "effect": "deny", "arg_keys": ["\ud800evil"]})

    assert log.read_bytes().isascii()
    records = _read_records(log)
    assert [r["decision_id"] for r in records] == [1]
    assert records[0]["arg_keys"] == ["\ud800evil"]
    assert verify_chain(log, key=STABLE_KEY)[0] is True


def test_one_poisoned_record_does_not_hide_the_records_around_it(tmp_path):
    log = tmp_path / "a.jsonl"
    sink = JSONLAuditSink(log, hash_chain=True, key=STABLE_KEY)
    for i in range(5):
        keys = ["\udccc\ud800"] if i == 2 else ["q"]
        sink.record({"decision_id": i, "effect": "allow", "arg_keys": keys})

    # the io layer decodes a whole buffer at a time, so before the fix a single
    # un-encodable line yielded zero of five, not four of five.
    assert [r["decision_id"] for r in _read_records(log)] == [0, 1, 2, 3, 4]
    assert verify_chain(log, key=STABLE_KEY)[0] is True


def test_ordinary_non_ascii_text_round_trips_through_the_escape(tmp_path):
    log = tmp_path / "a.jsonl"
    sink = JSONLAuditSink(log, hash_chain=True)
    sink.record({"tool": "wysyłka", "identity": "józef@example.pl", "effect": "allow"})

    assert log.read_bytes().isascii()
    record = _read_records(log)[0]
    assert record["tool"] == "wysyłka"
    assert record["identity"] == "józef@example.pl"
    assert verify_chain(log)[0] is True


def test_the_whole_gate_path_writes_a_readable_line(tmp_path):
    log = tmp_path / "a.jsonl"
    policy = Policy(
        tools={"search": ToolContract(name="search", args=Schema({"q": Field(type="any")}))},
        permissions={"clerk": frozenset({"search"})},
    )
    sink = JSONLAuditSink(log, hash_chain=True, key=STABLE_KEY)
    safe = Gate(policy, audit=sink).wrap(lambda **k: "res", name="search")
    # the denial is the point: the one call an attacker gets is the one that used to
    # poison the file, and a denied attempt is what the trail exists to hold.
    with use_principal(Principal(identity="c@example.com", role="clerk")), pytest.raises(GateDenied):
        safe(**{"\ud800evil": 1, "q": "x"})

    records = _read_records(log)
    assert [r["phase"] for r in records] == ["pre"]
    assert "\ud800evil" in records[0]["arg_keys"]
    assert verify_chain(log, key=STABLE_KEY)[0] is True


# ── a log written by the old code still verifies ──────────────────────────


def test_verify_chain_still_accepts_a_log_hashed_with_ensure_ascii_false(tmp_path):
    """Written the way `record` used to write it, byte for byte."""
    from histos.trail.logpath import tip_path_for
    from histos.trail.verify import _chain_digest, _tip_body

    log = tmp_path / "legacy.jsonl"
    payload: dict[str, object] = {"decision_id": 1, "effect": "deny", "tool": "wysyłka", "seq": 1, "prev": ""}
    payload["hash"] = _chain_digest(json.dumps(payload, sort_keys=True, ensure_ascii=False), STABLE_KEY)
    log.write_bytes((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8", "surrogatepass"))
    tip = {
        "records": 1,
        "hash": payload["hash"],
        "mac": _chain_digest(_tip_body(1, str(payload["hash"])), STABLE_KEY),
    }
    tip_path_for(log).write_text(json.dumps(tip) + "\n", encoding="utf-8")

    ok, detail = verify_chain(log, key=STABLE_KEY)
    assert ok is True, detail


def test_a_legacy_line_that_was_actually_edited_is_still_caught(tmp_path):
    from histos.trail.logpath import tip_path_for
    from histos.trail.verify import _chain_digest, _tip_body

    log = tmp_path / "legacy.jsonl"
    payload: dict[str, object] = {"decision_id": 1, "effect": "deny", "tool": "wysyłka", "seq": 1, "prev": ""}
    payload["hash"] = _chain_digest(json.dumps(payload, sort_keys=True, ensure_ascii=False), STABLE_KEY)
    payload["effect"] = "allow"
    log.write_bytes((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8", "surrogatepass"))
    tip = {
        "records": 1,
        "hash": payload["hash"],
        "mac": _chain_digest(_tip_body(1, str(payload["hash"])), STABLE_KEY),
    }
    tip_path_for(log).write_text(json.dumps(tip) + "\n", encoding="utf-8")

    ok, detail = verify_chain(log, key=STABLE_KEY)
    assert ok is False
    assert "hash mismatch" in detail


# ── arg_keys is bounded attacker text ─────────────────────────────────────


def _record(**kw):
    base = dict(
        ts=0.0,
        decision_id=1,
        phase="pre",
        tool="t",
        role="clerk",
        identity=None,
        effect="deny",
        rule="rbac",
        reason="no",
        args_digest="hmac-sha256:x",
    )
    base.update(kw)
    return AuditRecord(**base)  # type: ignore[arg-type]


def test_arg_keys_are_capped_in_number_and_the_clipping_is_visible():
    rec = _record(arg_keys=[f"k{i:04d}" for i in range(500)])
    assert len(rec.arg_keys) <= 64
    assert rec.arg_keys[0] == "k0000"
    assert rec.arg_keys_truncated is True


def test_a_single_enormous_arg_key_is_clipped():
    rec = _record(arg_keys=["a" * 100_000])
    assert rec.arg_keys == ["a" * 128]
    assert rec.arg_keys_truncated is True


def test_arg_keys_have_a_total_length_budget():
    rec = _record(arg_keys=["b" * 128] * 64)
    assert sum(len(k) for k in rec.arg_keys) <= 1024
    assert rec.arg_keys_truncated is True


def test_an_ordinary_call_is_not_marked_truncated():
    rec = _record(arg_keys=["phone", "q"])
    assert rec.arg_keys == ["phone", "q"]
    assert rec.arg_keys_truncated is False


# ── and so is every other free-text field ─────────────────────────────────
#
# Capping `arg_keys` alone bounded one field of a record whose other fields carry the
# same text: an auditor wrote a single 801,429-byte line out of a 200,000-character
# tool name and a 200,000-character identity, and a 200,000-character *argument* name
# comes back in `field_name` and again inside the interpolated `reason`.


def test_an_enormous_tool_name_is_clipped_with_the_clipping_visible():
    rec = _record(tool="t" * 200_000)
    assert len(rec.tool) < 400
    assert rec.tool.startswith("tttt")
    assert rec.tool.endswith("...[truncated]")


def test_an_enormous_identity_is_clipped_with_the_clipping_visible():
    rec = _record(identity="i" * 200_000)
    assert len(rec.identity) < 400
    assert rec.identity.endswith("...[truncated]")


def test_an_absent_identity_survives_the_cap():
    assert _record(identity=None).identity is None


def test_an_ordinary_tool_name_and_identity_are_untouched():
    rec = _record(tool="wire_transfer", identity="jane.doe@example.com", role="support")
    assert (rec.tool, rec.identity, rec.role) == ("wire_transfer", "jane.doe@example.com", "support")


def test_the_reason_and_the_field_name_are_bounded_too():
    """The reason interpolates the same attacker text the other caps just removed."""
    rec = _record(rule="arg_schema", reason="undeclared argument " + "x" * 200_000, field_name="x" * 200_000)
    assert len(rec.reason) < 600
    assert len(rec.field_name) < 400
    assert rec.reason.endswith("...[truncated]")


def test_a_whole_gate_decision_stays_a_readable_line(tmp_path):
    """End to end: the one call an attacker gets must not cost a megabyte of evidence."""
    log = tmp_path / "a.jsonl"
    sink = JSONLAuditSink(log, hash_chain=True, key=STABLE_KEY)
    safe = Gate(Policy(tools={}, permissions={}), audit=sink).wrap(lambda **k: 1, name="T" * 200_000)
    with use_principal(Principal(identity="I" * 200_000, role="R" * 200_000)), pytest.raises(GateDenied):
        safe(**{"X" * 200_000: 1})

    assert log.stat().st_size < 8192
    record = _read_records(log)[0]
    assert record["tool"].endswith("...[truncated]")
    assert record["identity"].endswith("...[truncated]")
    assert verify_chain(log, key=STABLE_KEY)[0] is True


def test_a_capped_record_is_still_written_and_still_verifies(tmp_path):
    log = tmp_path / "a.jsonl"
    sink = JSONLAuditSink(log, hash_chain=True, key=STABLE_KEY)
    sink.record(_record(arg_keys=["\ud800" * 200] * 500).to_dict())

    assert log.read_bytes().isascii()
    record = _read_records(log)[0]
    assert record["arg_keys_truncated"] is True
    assert len(record["arg_keys"]) <= 64
    assert verify_chain(log, key=STABLE_KEY)[0] is True
