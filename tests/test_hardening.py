"""Regression tests for the adversarial code-review findings (F1, F2, F4, F6, F7, F8)."""

from __future__ import annotations

import hashlib
import json
import threading

from histos import (
    Field,
    Gate,
    InMemoryAuditSink,
    JSONLAuditSink,
    LimitStore,
    Policy,
    Principal,
    Schema,
    ToolContract,
    load_bundle,
    review_policy,
    use_principal,
)

# ── F1: sensitive-field redaction must recurse into lists of records ─────


def test_sensitive_field_redacted_in_list_of_records():
    policy = Policy(
        tools={
            "list_users": ToolContract(
                name="list_users",
                args=Schema({}),
                returns=Schema({"name": Field(type="string"), "ssn": Field(type="string", sensitive="secret")}),
            )
        },
        permissions={"agent": frozenset({"list_users"})},
    )

    def list_users():
        return [{"name": "a", "ssn": "111-11-1111"}, {"name": "b", "ssn": "222-22-2222"}]

    safe = Gate(policy).wrap(list_users)
    with use_principal(Principal(role="agent")):
        out = safe()
    assert "111-11-1111" not in json.dumps(out)
    assert "222-22-2222" not in json.dumps(out)
    assert out[0]["ssn"] == "[REDACTED]" and out[1]["ssn"] == "[REDACTED]"
    assert out[0]["name"] == "a"  # non-sensitive kept


# ── F2: canary redaction reaches sets, bytes and dict keys ───────────────

CANARY = "CANARY-Z9"


def _canary_gate():
    policy = Policy(
        tools={"fetch": ToolContract(name="fetch", args=Schema({}))},
        permissions={"agent": frozenset({"fetch"})},
        canaries=frozenset({CANARY}),
    )
    return policy


def test_canary_redacted_in_nested_set_bytes_and_key():
    def fetch():
        return {
            f"key-{CANARY}": "v",  # canary in a dict KEY
            "blob": f"x {CANARY} y".encode(),  # canary in bytes
            "tags": {f"t-{CANARY}", "clean"},  # canary in a set
        }

    safe = Gate(_canary_gate()).wrap(fetch)
    with use_principal(Principal(role="agent")):
        out = safe()
    flat = repr(out)
    assert CANARY not in flat


# ── F4: check→consume is atomic under concurrency ────────────────────────


def test_try_consume_is_atomic_under_threads():
    store = LimitStore()
    successes = []
    barrier = threading.Barrier(20)

    def worker():
        barrier.wait()  # maximise contention
        rule = store.try_consume("u1", "t", rate_limit=None, budget=1)
        if rule is None:
            successes.append(1)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(successes) == 1  # exactly one caller consumed the budget of 1


# ── F7: observe mode emits the pre record exactly once ───────────────────


def test_observe_confirmation_emits_pre_once():
    policy = Policy(
        tools={"danger": ToolContract(name="danger", args=Schema({}), requires_confirmation=True)},
        permissions={"agent": frozenset({"danger"})},
    )
    ran = []

    def danger():
        ran.append(1)
        return "done"

    sink = InMemoryAuditSink()
    safe = Gate(policy, audit=sink, enforcement="observe").wrap(danger)  # no confirm callback
    with use_principal(Principal(role="agent")):
        safe()

    pre = [e for e in sink.entries if e["phase"] == "pre"]
    assert len(pre) == 1  # exactly one, not two
    assert pre[0]["rule"] == "requires_confirmation"
    assert pre[0]["enforced"] is False
    assert ran == [1]  # observe still ran it


# ── F8: keyed hash-chain resists content rewrite ─────────────────────────


def test_keyed_chain_detects_recompute_without_key(tmp_path):
    path = tmp_path / "audit.jsonl"
    sink = JSONLAuditSink(path, hash_chain=True, key=b"top-secret")

    policy = Policy(
        tools={"t": ToolContract(name="t", args=Schema({}))},
        permissions={"r": frozenset({"t"})},
    )

    def t():
        return "ok"

    safe = Gate(policy, audit=sink).wrap(t)
    with use_principal(Principal(role="r", identity="u1")):
        safe()
        safe()
    assert sink.verify() is True

    # Attacker (no key) rewrites the first record and recomputes the whole chain
    # with plain sha256 — a keyed verify must still reject it.
    records = [json.loads(x) for x in path.read_text().splitlines()]
    records[0]["effect"] = "tampered"
    prev = ""
    for rec in records:
        rec.pop("hash", None)
        rec["prev"] = prev
        body = json.dumps(rec, sort_keys=True, ensure_ascii=False)
        rec["hash"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
        prev = rec["hash"]
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")

    assert JSONLAuditSink(path, hash_chain=True, key=b"top-secret").verify() is False


# ── F6: review flags permissive schema + unconstrained write tool ────────


def test_review_flags_permissive_and_unconstrained_write():
    policy = load_bundle(
        {
            "version": "1",
            "tools": {
                "delete_row": {"access": "write", "args": {"id": {"type": "string"}}},  # no constraint
                "wild": {"access": "read"},  # no args at all
            },
            "roles": {"admin": {"allow": ["delete_row", "wild"]}},
        }
    )
    # give 'wild' a permissive (allow_extra) schema to exercise F6
    from dataclasses import replace

    policy.tools["wild"] = replace(policy.tools["wild"], args=Schema({}, allow_extra=True))

    warnings = review_policy(policy).warnings
    assert any("no resource constraint" in w for w in warnings)
    assert any("permissive" in w for w in warnings)
