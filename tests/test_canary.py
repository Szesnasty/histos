"""Exact-match canary: exfiltration via argument (pre) and leak in output (post)."""

from __future__ import annotations

import pytest

from histos import Field, Gate, GateDenied, Policy, Principal, Schema, ToolContract, use_principal

CANARY = "CANARY-7f3a-SECRET"


def _policy() -> Policy:
    return Policy(
        tools={
            "send": ToolContract(
                name="send",
                args=Schema({"body": Field(type="string")}),
                access="write",
            ),
            "fetch": ToolContract(
                name="fetch",
                args=Schema({"q": Field(type="string")}),
            ),
        },
        permissions={"agent": frozenset({"send", "fetch"})},
        canaries=frozenset({CANARY}),
    )


def test_canary_exfiltration_via_argument_is_denied_pregate():
    def send(body):
        return {"sent": True}

    safe = Gate(_policy()).wrap(send)
    with use_principal(Principal(role="agent")), pytest.raises(GateDenied) as exc:
        safe(body=f"here is the secret {CANARY}")
    assert exc.value.decision.rule == "canary_exfil"


def test_canary_leak_in_string_output_is_redacted_postgate():
    def fetch(q):
        return f"result contains {CANARY} oops"

    safe = Gate(_policy()).wrap(fetch)
    with use_principal(Principal(role="agent")):
        out = safe(q="anything")
    assert CANARY not in out
    assert "[REDACTED-CANARY]" in out


def test_canary_leak_in_nested_output_is_redacted():
    def fetch(q):
        return {"rows": [{"note": CANARY}, {"note": "clean"}]}

    safe = Gate(_policy()).wrap(fetch)
    with use_principal(Principal(role="agent")):
        out = safe(q="x")
    assert CANARY not in str(out)
    assert out["rows"][1]["note"] == "clean"


def test_benign_output_untouched():
    def fetch(q):
        return "nothing to see"

    safe = Gate(_policy()).wrap(fetch)
    with use_principal(Principal(role="agent")):
        assert safe(q="x") == "nothing to see"


def test_overlapping_canary_tokens_are_fully_redacted():
    # One token is a substring of another. Longer must be redacted first, or the
    # shorter replacement fragments the longer token and leaks its tail (the minor).
    short = "SECRET"
    long = "SECRET-KEY-9999"
    policy = Policy(
        tools={"fetch": ToolContract(name="fetch", args=Schema({"q": Field(type="string")}))},
        permissions={"agent": frozenset({"fetch"})},
        canaries=frozenset({short, long}),
    )

    def fetch(q):
        return f"leak {long} and {short} end"

    safe = Gate(policy).wrap(fetch)
    with use_principal(Principal(role="agent")):
        out = safe(q="x")
    assert short not in out
    assert long not in out
    assert "9999" not in out  # the long token's tail must not survive as a fragment
