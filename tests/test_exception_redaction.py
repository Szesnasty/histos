"""A raising tool is the *other* way content reaches the model.

Before this, `result = tool(**args)` sat outside any `try`, so an exception skipped
`_finish` and with it the whole POST chain: a canary or a recognised secret in the
error text went to the caller verbatim, and the audit trail recorded only the
pre-decision. These tests pin the closed version — including the parts that are easy
to get subtly wrong, like not re-attaching the original exception through `__cause__`.
"""

from __future__ import annotations

import asyncio

import pytest

from histos import (
    Field,
    Gate,
    InMemoryAuditSink,
    Policy,
    Principal,
    Schema,
    ToolContract,
    ToolErrorRedacted,
    use_principal,
)

CANARY = "CANARY-7f3a-DO-NOT-LEAK"
PAN = "4111111111111111"  # Luhn-valid test card


def _policy(**tool_kwargs) -> Policy:
    return Policy(
        tools={
            "fetch_invoice": ToolContract(
                name="fetch_invoice",
                args=Schema({"invoice_id": Field(type="string")}),
                **tool_kwargs,
            )
        },
        permissions={"agent": frozenset({"fetch_invoice"})},
        canaries=frozenset({CANARY}),
    )


def _raising(message: str):
    def fetch_invoice(invoice_id):
        raise RuntimeError(message)

    return fetch_invoice


# ── the leak itself ──────────────────────────────────────────────────


def test_canary_in_an_exception_is_redacted():
    safe = Gate(_policy()).wrap(_raising(f"invoice {CANARY} not found"))

    with use_principal(Principal(role="agent")), pytest.raises(ToolErrorRedacted) as exc:
        safe(invoice_id="INV-1")

    assert CANARY not in str(exc.value)
    assert "[REDACTED-CANARY]" in str(exc.value)
    assert exc.value.decision.rule == "exception_redaction"
    assert exc.value.decision.redactions == (f"canary:{CANARY}",)


def test_recognised_secret_in_an_exception_is_redacted():
    safe = Gate(_policy()).wrap(_raising(f"declined for card {PAN}"))

    with use_principal(Principal(role="agent")), pytest.raises(ToolErrorRedacted) as exc:
        safe(invoice_id="INV-1")

    assert PAN not in str(exc.value)
    assert any(r.startswith("secret:") for r in exc.value.decision.redactions)


def test_the_original_exception_type_is_still_identifiable():
    safe = Gate(_policy()).wrap(_raising(f"timeout after leaking {CANARY}"))

    with use_principal(Principal(role="agent")), pytest.raises(ToolErrorRedacted) as exc:
        safe(invoice_id="INV-1")

    assert exc.value.original_type == "RuntimeError"
    assert "RuntimeError" in str(exc.value)


def test_the_unredacted_original_is_not_reachable_through_the_exception_chain():
    """`raise ... from None` is load-bearing: the original still holds the secret.

    A traceback printer walks `__cause__` and `__context__`, so leaving either one
    attached would put the canary back on screen — and into any log that formats the
    exception chain.
    """
    safe = Gate(_policy()).wrap(_raising(f"invoice {CANARY} not found"))

    with use_principal(Principal(role="agent")), pytest.raises(ToolErrorRedacted) as exc:
        safe(invoice_id="INV-1")

    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None
    assert not any(CANARY in str(a) for a in exc.value.args)


# ── the common case must be unchanged ────────────────────────────────


def test_a_clean_exception_passes_through_untouched():
    original = ValueError("no such invoice")

    def fetch_invoice(invoice_id):
        raise original

    safe = Gate(_policy()).wrap(fetch_invoice)

    with use_principal(Principal(role="agent")), pytest.raises(ValueError) as exc:
        safe(invoice_id="INV-1")

    # The very same object, so the traceback the developer needs survives intact.
    assert exc.value is original
    assert not isinstance(exc.value, ToolErrorRedacted)


def test_redaction_respects_the_tools_output_settings():
    """The same knobs that govern the return value govern the exception."""
    policy = _policy(scan_output_for_canary=False, redact_secret_output=False)
    safe = Gate(policy).wrap(_raising(f"invoice {CANARY} not found"))

    with use_principal(Principal(role="agent")), pytest.raises(RuntimeError) as exc:
        safe(invoice_id="INV-1")

    assert not isinstance(exc.value, ToolErrorRedacted)
    assert CANARY in str(exc.value)


# ── the audit trail ──────────────────────────────────────────────────


def test_the_raising_call_is_recorded_as_having_executed():
    sink = InMemoryAuditSink()
    safe = Gate(_policy(), audit=sink).wrap(_raising(f"invoice {CANARY} not found"))

    with use_principal(Principal(role="agent")), pytest.raises(ToolErrorRedacted):
        safe(invoice_id="INV-1")

    post = [e for e in sink.entries if e["phase"] == "post"]
    assert len(post) == 1, "the post phase must be recorded even when the tool raised"
    assert post[0]["rule"] == "exception_redaction"
    assert post[0]["executed"] is True
    # Which token fired is named in `redactions`, exactly as on the return-value path:
    # the audit trail is the operator's artifact and the canary is a value they planted.
    # The model-facing `reason` must not carry it.
    assert post[0]["redactions"] == [f"canary:{CANARY}"]
    assert CANARY not in post[0]["reason"]


def test_observe_mode_records_but_changes_nothing():
    sink = InMemoryAuditSink()
    safe = Gate(_policy(), mode="observe", audit=sink).wrap(_raising(f"invoice {CANARY} not found"))

    with use_principal(Principal(role="agent")), pytest.raises(RuntimeError) as exc:
        safe(invoice_id="INV-1")

    assert not isinstance(exc.value, ToolErrorRedacted)
    assert CANARY in str(exc.value), "observe never modifies what the caller sees"
    assert [e["rule"] for e in sink.entries if e["phase"] == "post"] == ["exception_redaction"]


# ── both paths share the chain ───────────────────────────────────────


def test_async_tools_go_through_the_same_chain():
    async def fetch_invoice(invoice_id):
        raise RuntimeError(f"invoice {CANARY} not found")

    safe = Gate(_policy()).wrap(fetch_invoice)

    async def run():
        with use_principal(Principal(role="agent")):
            await safe(invoice_id="INV-1")

    with pytest.raises(ToolErrorRedacted) as exc:
        asyncio.run(run())

    assert CANARY not in str(exc.value)
    assert exc.value.decision.rule == "exception_redaction"


# ── fail-closed ──────────────────────────────────────────────────────


def test_a_failure_inside_redaction_drops_the_text_entirely(monkeypatch):
    """If the redaction machinery breaks, nothing about the text can be trusted."""
    import histos.decide.engine as engine_mod

    def boom(*_a, **_k):
        raise MemoryError("redactor exploded")

    monkeypatch.setattr(engine_mod.canary, "redact", boom)
    safe = Gate(_policy()).wrap(_raising(f"invoice {CANARY} not found"))

    with use_principal(Principal(role="agent")), pytest.raises(ToolErrorRedacted) as exc:
        safe(invoice_id="INV-1")

    assert CANARY not in str(exc.value)
    assert "could not be safely redacted" in str(exc.value)
    assert exc.value.decision.rule == "internal_error"
