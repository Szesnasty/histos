"""Audit integrity: keyed digest (no raw values), hash-chain, tamper detection."""

from __future__ import annotations

import json

from conftest import STABLE_KEY

from histos import (
    Field,
    Gate,
    GateDenied,
    JSONLAuditSink,
    Policy,
    Principal,
    Schema,
    ToolContract,
    digest_args,
    use_principal,
)


def _policy() -> Policy:
    return Policy(
        tools={"t": ToolContract(name="t", args=Schema({"secret": Field(type="string")}))},
        permissions={"r": frozenset({"t"})},
        policy_version="9",
    )


def test_digest_is_keyed_and_hides_raw_values():
    args = {"secret": "hunter2"}
    d1 = digest_args(args, STABLE_KEY)
    assert d1.startswith("hmac-sha256:")
    assert "hunter2" not in d1
    # same key + same args → same digest; different key → different digest
    assert digest_args(args, STABLE_KEY) == d1
    assert digest_args(args, b"another-key-000000000000000000000") != d1


def test_record_carries_no_raw_argument_values():
    def t(secret):
        return "ok"

    sink_entries = []

    class Capture:
        def record(self, entry):
            sink_entries.append(entry)

    g = Gate(_policy(), audit=Capture(), audit_key=STABLE_KEY)
    safe = g.wrap(t)
    with use_principal(Principal(role="r", identity="u1")):
        safe(secret="hunter2")
    blob = json.dumps(sink_entries)
    assert "hunter2" not in blob
    assert sink_entries[0]["arg_keys"] == ["secret"]
    assert sink_entries[0]["policy_version"] == "9"
    assert sink_entries[0]["policy_hash"].startswith("sha256:")
    assert sink_entries[0]["gate_version"]


def test_jsonl_hash_chain_verifies_and_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    sink = JSONLAuditSink(path, hash_chain=True)

    def t(secret):
        return "ok"

    g = Gate(_policy(), audit=sink, audit_key=STABLE_KEY)
    safe = g.wrap(t)
    with use_principal(Principal(role="r", identity="u1")):
        safe(secret="a")
        try:
            with use_principal(Principal(role="nobody")):
                safe(secret="b")
        except GateDenied:
            pass

    assert sink.verify() is True
    # denied attempt is on the record
    lines = [json.loads(x) for x in path.read_text().splitlines()]
    assert any(rec["effect"] == "deny" for rec in lines)

    # tamper: flip a field in the first record and rewrite
    lines[0]["effect"] = "allow" if lines[0]["effect"] != "allow" else "deny"
    path.write_text("\n".join(json.dumps(rec) for rec in lines) + "\n")
    assert JSONLAuditSink(path, hash_chain=True).verify() is False
