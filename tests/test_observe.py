"""Observe (dry-run) mode: record what would happen, never block or modify."""

from __future__ import annotations

from histos import Gate, InMemoryAuditSink, Principal, use_principal


def test_observe_never_blocks_but_records_the_would_be_denial(sample_policy):
    sink = InMemoryAuditSink()
    calls = []

    def delete_invoice(invoice_id):
        calls.append(invoice_id)
        return {"ok": True}

    safe = Gate(sample_policy, audit=sink, enforcement="observe").wrap(delete_invoice)
    # viewer has no grant → would be denied under enforce, but observe lets it run.
    with use_principal(Principal(role="viewer", attributes={"tenant_id": "acme"})):
        result = safe(invoice_id=1)

    assert result == {"ok": True}
    assert calls == [1]  # the tool actually ran
    pre = [e for e in sink.entries if e["phase"] == "pre"][0]
    assert pre["effect"] == "deny"
    assert pre["rule"] == "rbac"
    assert pre["enforced"] is False  # marked as not enforced


def test_observe_does_not_redact_output(sample_policy):
    sink = InMemoryAuditSink()

    def get_order(order_id):
        return {"total": 1.0, "email": "real@person.com"}

    safe = Gate(sample_policy, audit=sink, enforcement="observe").wrap(get_order)
    with use_principal(Principal(role="viewer")):
        result = safe(order_id=1)
    # would redact email under enforce; observe returns it raw
    assert result["email"] == "real@person.com"
    post = [e for e in sink.entries if e["phase"] == "post"][0]
    assert post["effect"] == "redact"
    assert post["enforced"] is False


def test_enforce_is_the_default(sample_policy):
    assert Gate(sample_policy).enforcement == "enforce"
