"""Audit regressions for the pre/post chains and canary matching.

Every test here pins a behaviour that was reachable-and-wrong before the audit fixes:
an evasion the canary tier missed, a leak the output traversers walked past, a call the
post-gate denied *after* it had run, a resolver the async path touched too early, a
schema-valid argument that stalled the gate, and the fail-closed handlers that a single
edited word could turn into fail-open with the rest of the suite still green.
"""

from __future__ import annotations

import asyncio
import time
from typing import NamedTuple

import pytest

import histos.engine as engine_mod
from histos import (
    Constraint,
    Field,
    Gate,
    GateDenied,
    Policy,
    Principal,
    Schema,
    ToolContract,
    use_principal,
)
from histos.contracts import Effect, GateRequest
from histos.engine import Engine
from histos.errors import ToolErrorRedacted
from histos.limits import LimitStore

CANARY = "CANARY-7f3a-SECRET"
ZERO_WIDTH = "​"
AKIA = "AKIAIOSFODNN7EXAMPLE"
AKIA_OTHER = "AKIAJ7SFODNN7EXAMPLE"


def _policy(**tool_kwargs) -> Policy:
    return Policy(
        tools={
            "fetch": ToolContract(name="fetch", args=Schema({"q": Field(type="string")}), **tool_kwargs),
        },
        permissions={"agent": frozenset({"fetch"})},
        canaries=frozenset({CANARY}),
    )


def _engine(policy: Policy | None = None) -> Engine:
    return Engine(policy or _policy(), LimitStore())


def _pre(engine: Engine, args: dict) -> object:
    return engine.pre(GateRequest("fetch", args, Principal(role="agent")))


def _post(engine: Engine, result: object) -> tuple:
    return engine.post(GateRequest("fetch", {"q": "x"}, Principal(role="agent"), phase="post"), result)


# ── the canary normalization tier, which had no coverage at all ──────────


@pytest.mark.parametrize(
    ("evasion", "label"),
    [
        ("C A N A R Y-7f3a-SECRET", "spaced out"),
        ("CANARY_7f3a_SECRET", "underscores for hyphens"),
        ("CANARY.7f3a.SECRET", "dots for hyphens"),
        (f"CANARY{ZERO_WIDTH}-7f3a-SECRET", "zero-width space wedged in"),
        ("canary-7f3a-secret", "case shifted"),
        ("C-A-N-A-R-Y-7f3a-S.E.C.R.E.T", "separators throughout"),
    ],
)
def test_a_mechanically_evaded_canary_is_still_denied_pregate(evasion, label):
    """`find_normalized` exists for exactly these; deleting it left the suite green."""
    from histos import canary

    assert canary.find(evasion, {CANARY}) == [], f"{label} should not match verbatim"
    assert canary.find_normalized(evasion, {CANARY}) == [CANARY], label

    safe = Gate(_policy()).wrap(lambda q: {"ok": True}, name="fetch")
    with use_principal(Principal(role="agent")), pytest.raises(GateDenied) as exc:
        safe(q=f"exfiltrating {evasion}")
    assert exc.value.decision.rule == "canary_exfil"


def test_normalization_does_not_deny_text_that_merely_shares_a_prefix():
    """The transform strips separators and casefolds — aggressive enough to need a floor."""
    from histos import canary

    for benign in ("the canary sang", "CANARY-7f3a", "canary secret", "7f3a-SECRET"):
        assert canary.find_normalized(benign, {CANARY}) == [], benign

    safe = Gate(_policy()).wrap(lambda q: {"ok": True}, name="fetch")
    with use_principal(Principal(role="agent")):
        assert safe(q="the canary in the coal mine sang a secret") == {"ok": True}


# ── post must match at least as hard as pre ──────────────────────────────


def test_a_zero_width_space_does_not_carry_a_canary_out_in_a_string():
    leaked = f"row: CANARY{ZERO_WIDTH}-7f3a-SECRET"
    decision, out = _post(_engine(), leaked)
    assert decision.effect is Effect.REDACT
    assert "7f3a" not in out
    assert decision.redactions == (f"canary:{CANARY}",)


def test_a_zero_width_space_does_not_carry_a_canary_out_in_bytes_or_a_dict_key():
    payload = {f"CANARY{ZERO_WIDTH}-7f3a-SECRET": "v", "b": b"C A N A R Y-7f3a-SECRET"}
    decision, out = _post(_engine(), payload)
    assert decision.effect is Effect.REDACT
    assert "7f3a" not in str(out)
    assert b"7f3a" not in b" ".join(v for v in out.values() if isinstance(v, bytes))


def test_a_canary_split_across_two_output_fields_drops_the_whole_value():
    """The pre-gate denies the same split because it scans one joined blob."""
    split = {"head": "CAN", "tail": "ARY-7f3a-SECRET"}

    two_fields = Schema({"head": Field(type="string"), "tail": Field(type="string")})
    two_args = Policy(
        tools={"fetch": ToolContract(name="fetch", args=two_fields)},
        permissions={"agent": frozenset({"fetch"})},
        canaries=frozenset({CANARY}),
    )
    engine = Engine(two_args, LimitStore())
    assert engine.pre(GateRequest("fetch", split, Principal(role="agent"))).rule == "canary_exfil"

    decision, out = _post(_engine(), split)
    assert decision.effect is Effect.REDACT
    assert "output:redacted_all" in decision.redactions
    assert "7f3a" not in str(out)


def test_an_output_with_no_canary_is_untouched_by_the_cross_field_sweep():
    payload = {"rows": [{"note": "all clear"}, {"note": "nothing here"}], "n": 2}
    decision, out = _post(_engine(), payload)
    assert decision.effect is Effect.ALLOW
    assert out == payload


def test_a_raised_exception_cannot_smuggle_a_normalized_canary():
    """The exception message was matched verbatim only — the cheapest exit in the library."""

    def fetch(q):
        raise ValueError(f"no such row: CANARY{ZERO_WIDTH}-7f3a-SECRET")

    safe = Gate(_policy()).wrap(fetch)
    with use_principal(Principal(role="agent")), pytest.raises(ToolErrorRedacted) as exc:
        safe(q="x")
    assert "7f3a" not in str(exc.value)
    assert exc.value.decision.rule == "exception_redaction"
    assert f"canary:{CANARY}" in exc.value.decision.redactions


def test_a_raised_exception_cannot_smuggle_a_spaced_out_canary():
    def fetch(q):
        raise ValueError("no such row: C A N A R Y-7f3a-SECRET")

    safe = Gate(_policy()).wrap(fetch)
    with use_principal(Principal(role="agent")), pytest.raises(ToolErrorRedacted) as exc:
        safe(q="x")
    assert "7f3a" not in str(exc.value)


# ── output secret redaction: dict keys and bytes ─────────────────────────


def test_a_credential_used_as_a_dict_key_is_redacted():
    decision, out = _post(_engine(), {AKIA: "prod"})
    assert decision.effect is Effect.REDACT
    assert AKIA not in str(out)
    assert "secret:aws_key" in decision.redactions


def test_a_credential_inside_a_bytes_result_is_redacted():
    decision, out = _post(_engine(), {"body": f"token={AKIA}".encode()})
    assert decision.effect is Effect.REDACT
    assert AKIA.encode() not in out["body"]
    assert isinstance(out["body"], bytes)


def test_two_credentials_used_as_keys_do_not_collapse_into_one_record():
    """Both redact to the same mark; a plain assignment silently dropped a record."""
    _decision, out = _post(_engine(), {AKIA: "prod", AKIA_OTHER: "staging"})
    assert sorted(out.values()) == ["prod", "staging"]


def test_a_key_that_literally_spells_the_mark_does_not_overwrite_a_redacted_record():
    _decision, out = _post(_engine(), {AKIA: "prod", "[REDACTED-SECRET]": "keep-me"})
    assert sorted(out.values()) == ["keep-me", "prod"]


# ── a tuple subclass must not be denied after the tool ran ───────────────


class Receipt(NamedTuple):
    id: str
    amount: int


def test_a_namedtuple_return_survives_the_post_gate():
    """Rebuilding with `type(obj)(items)` raised, so the gate denied a call that ran."""
    side_effects: list[int] = []

    def fetch(q):
        side_effects.append(10)
        return Receipt(id="r1", amount=10)

    safe = Gate(_policy()).wrap(fetch)
    with use_principal(Principal(role="agent")):
        out = safe(q="x")
    assert out == Receipt(id="r1", amount=10)
    assert isinstance(out, Receipt)
    assert side_effects == [10]


def test_a_namedtuple_return_is_still_redacted():
    decision, out = _post(_engine(), Receipt(id=AKIA, amount=1))
    assert decision.effect is Effect.REDACT
    assert isinstance(out, Receipt)
    assert out.id == "[REDACTED-SECRET]"


def test_a_tuple_subclass_that_cannot_be_rebuilt_degrades_instead_of_denying():
    class Pair(tuple):
        def __new__(cls, first, second):
            return super().__new__(cls, (first, second))

    decision, out = _post(_engine(), Pair(AKIA, "b"))
    assert decision.effect is Effect.REDACT
    assert tuple(out) == ("[REDACTED-SECRET]", "b")


# ── the async path must touch what the sync path touches ─────────────────


def _resolver_policy() -> Policy:
    return Policy(
        tools={
            "pay": ToolContract(
                name="pay",
                args=Schema({"invoice_id": Field(type="string", pattern=r"^INV-\d+$")}),
                constraints=(Constraint.owns("tenant_id"),),
            )
        },
        permissions={"billing": frozenset({"pay"})},
    )


def _spying_resolvers() -> tuple[list, object, object]:
    seen: list[dict] = []

    def sync_resolve(tool, args):
        seen.append(dict(args))
        return {"tenant_id": "acme"}

    async def async_resolve(tool, args):
        seen.append(dict(args))
        return {"tenant_id": "acme"}

    return seen, sync_resolve, async_resolve


_INTRUDER = Principal(role="intruder", attributes={"tenant_id": "acme"})
_BILLING = Principal(role="billing", attributes={"tenant_id": "acme"})


@pytest.mark.parametrize(
    ("args", "principal", "rule"),
    [
        ({"invoice_id": "INV-1"}, _INTRUDER, "rbac"),
        ({"invoice_id": "'; DROP TABLE invoices;--"}, _BILLING, "arg_schema"),
    ],
)
def test_a_call_the_cheap_checks_reject_never_reaches_the_resolver(args, principal, rule):
    """`apre` resolved first, so an unauthorized caller drove a real datastore lookup."""
    seen, sync_resolve, async_resolve = _spying_resolvers()
    req = GateRequest("pay", args, principal)

    sync_engine = Engine(_resolver_policy(), LimitStore(), resource_resolver=sync_resolve)
    assert sync_engine.pre(req).rule == rule
    sync_seen = list(seen)

    seen.clear()
    async_engine = Engine(_resolver_policy(), LimitStore(), resource_resolver=async_resolve)
    assert asyncio.run(async_engine.apre(req)).rule == rule
    assert seen == sync_seen == []


def test_a_call_that_passes_the_cheap_checks_still_reaches_the_resolver():
    seen, _sync_resolve, async_resolve = _spying_resolvers()
    engine = Engine(_resolver_policy(), LimitStore(), resource_resolver=async_resolve)
    req = GateRequest("pay", {"invoice_id": "INV-9"}, _BILLING)
    assert asyncio.run(engine.apre(req)).effect is Effect.ALLOW
    assert seen == [{"invoice_id": "INV-9"}]


# ── an unbounded array must not stall the gate ───────────────────────────


def test_an_oversized_argument_is_denied_rather_than_scanned_in_part():
    """20k max-length elements is schema-valid and took 6.7 s of CPU inside the gate."""
    policy = Policy(
        tools={"bulk": ToolContract(name="bulk", args=Schema({"labels": Field(type="array", item_type="string")}))},
        permissions={"agent": frozenset({"bulk"})},
        canaries=frozenset({CANARY}),
    )
    engine = Engine(policy, LimitStore())
    req = GateRequest("bulk", {"labels": ["x" * 4096] * 300}, Principal(role="agent"))

    started = time.perf_counter()
    decision = engine.pre(req)
    elapsed = time.perf_counter() - started

    assert decision.effect is Effect.DENY
    assert decision.rule == "arg_schema"
    assert "budget" in decision.reason
    assert elapsed < 2.0, f"the size check itself stalled the gate ({elapsed:.2f}s)"


def test_the_size_budget_stops_the_walk_before_the_rest_is_materialised():
    """`str()` on the whole argument costs the very megabytes the bound exists to avoid."""

    class Explodes:
        def __str__(self):
            raise AssertionError("the walk materialised past the budget")

        __repr__ = __str__

    args = {"labels": ["x" * 4096] * 300 + [Explodes()] * 50}
    assert engine_mod._stringify_args(args) == ("", True)


def test_an_ordinary_call_is_not_caught_by_the_size_budget():
    policy = Policy(
        tools={"bulk": ToolContract(name="bulk", args=Schema({"labels": Field(type="array", item_type="string")}))},
        permissions={"agent": frozenset({"bulk"})},
        canaries=frozenset({CANARY}),
    )
    engine = Engine(policy, LimitStore())
    req = GateRequest("bulk", {"labels": ["label"] * 500}, Principal(role="agent"))
    assert engine.pre(req).effect is Effect.ALLOW


# ── fail-closed: the handlers a one-word edit turns into fail-open ───────


def test_a_crash_inside_the_sync_pre_chain_denies(monkeypatch):
    monkeypatch.setattr(engine_mod, "validate", _boom)
    decision = _pre(_engine(), {"q": "x"})
    assert decision.effect is Effect.DENY
    assert decision.rule == "internal_error"
    assert not decision.allowed


def test_a_crash_inside_the_async_pre_chain_denies(monkeypatch):
    monkeypatch.setattr(engine_mod, "validate", _boom)
    req = GateRequest("fetch", {"q": "x"}, Principal(role="agent"))
    decision = asyncio.run(_engine().apre(req))
    assert decision.effect is Effect.DENY
    assert decision.rule == "internal_error"
    assert not decision.allowed


def test_a_crash_inside_the_post_chain_denies_and_withholds_the_raw_result(monkeypatch):
    """The worst of the four: fail-open here returns the output with no redaction at all."""
    monkeypatch.setattr(engine_mod.detectors, "redact_string", _boom)
    decision, out = _post(_engine(), {"card": "4111111111111111", "note": "hi"})
    assert decision.effect is Effect.DENY
    assert decision.rule == "internal_error"
    assert out is None


def test_a_crash_in_the_pre_chain_reaches_the_caller_as_a_denial(monkeypatch):
    monkeypatch.setattr(engine_mod, "validate", _boom)
    safe = Gate(_policy()).wrap(lambda q: {"ok": True}, name="fetch")
    with use_principal(Principal(role="agent")), pytest.raises(GateDenied) as exc:
        safe(q="x")
    assert exc.value.decision.rule == "internal_error"


def _boom(*_args, **_kwargs):
    raise RuntimeError("a check exploded")


# ── confirmation.expires_in ──────────────────────────────────────────────


def _confirm_policy(**kwargs) -> Policy:
    return Policy(
        tools={
            "refund": ToolContract(
                name="refund",
                args=Schema({"amount": Field(type="integer")}),
                requires_confirmation=True,
                **kwargs,
            )
        },
        permissions={"agent": frozenset({"refund"})},
    )


def _confirm_decision(**kwargs):
    engine = Engine(_confirm_policy(**kwargs), LimitStore())
    return engine.pre(GateRequest("refund", {"amount": 1}, Principal(role="agent")))


def test_a_declared_confirmation_window_is_published_on_the_decision():
    decision = _confirm_decision(confirmation_expires_in=900)
    assert decision.effect is Effect.REQUIRE_CONFIRMATION
    assert "900" in decision.expected


def test_a_contract_with_no_confirmation_window_still_requires_confirmation():
    decision = _confirm_decision()
    assert decision.effect is Effect.REQUIRE_CONFIRMATION
    assert decision.rule == "requires_confirmation"


@pytest.mark.parametrize("window", [0, -1, -900, "900", 900.5, True])
def test_a_confirmation_window_no_approval_could_satisfy_is_refused(window):
    """Downgrading an unusable window to 'no expiry' turns a stricter policy into a looser one."""
    decision = _confirm_decision(confirmation_expires_in=window)
    assert decision.effect is Effect.DENY
    assert decision.rule == "confirm_error"
    assert decision.field == "confirmation.expires_in"
