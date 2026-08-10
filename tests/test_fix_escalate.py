"""Two audit findings: the `escalate` seam, and a coverage report that could not see
the mistake it was cited for catching.

**`escalate`** was promised in writing and existed only as an unread boolean on
`GateDecision` — no policy key produced it, no engine read it, no host could wire a
tier. The security claim attached to it ("adding meaning never weakens the gate, and
not having it never opens one") had nothing enforcing it. What is tested here is mostly
the *negative* half: the tier cannot allow what the deterministic chain refused, cannot
be skipped by declaring confirmation as well, and cannot be configured into an allow by
its own absence.

**`coverage()`** compared names. `protect_tools(tools, gate=g)` with the return value
dropped hands the agent the ungated originals, and a name-based report called that
clean — the exact scenario `demo/00-mediation` section F runs. The fix asks the objects.
"""

from __future__ import annotations

import asyncio
import gc
import json
from pathlib import Path

import pytest

from histos import (
    Effect,
    Field,
    Gate,
    GateDecision,
    GateDenied,
    GateRequest,
    Policy,
    PolicyError,
    Principal,
    Schema,
    ToolContract,
    dump_bundle,
    load_bundle,
    protect,
)

SPEC = Path(__file__).resolve().parent.parent / "spec" / "decision-codes.json"
CORPUS = Path(__file__).resolve().parent.parent / "conformance" / "decisions"

CLERK = Principal(role="clerk")

ESCALATE_CODES = ("escalated", "escalation_denied", "escalation_error", "no_escalation_tier")


def bundle(**tool_extra: object) -> dict:
    return {
        "version": "1",
        "tools": {"wire": {"access": "write", "args": {"to": {"type": "string"}}, **tool_extra}},
        "roles": {"clerk": {"allow": ["wire"]}},
    }


ESCALATED = bundle(escalate={"required": True})


def wire_request(to: str = "acct-1") -> GateRequest:
    return GateRequest("wire", {"to": to}, CLERK)


# ── A. the policy can say it ─────────────────────────────────────────────


def test_a_tool_contract_can_require_escalation():
    """Before: `escalate` was an unknown key, so the seam was unreachable from a policy."""
    policy = load_bundle(ESCALATED)
    assert policy.tools["wire"].requires_escalation is True
    assert load_bundle(bundle()).tools["wire"].requires_escalation is False


def test_escalation_round_trips_through_dump_and_load():
    policy = load_bundle(ESCALATED)
    dumped = dump_bundle(policy)
    assert dumped["tools"]["wire"]["escalate"] == {"required": True}
    assert load_bundle(dumped).content_hash() == policy.content_hash()


def test_escalation_is_part_of_the_policys_identity():
    """An approval pinned to a policy hash must not survive `escalate` being removed."""
    assert load_bundle(ESCALATED).content_hash() != load_bundle(bundle()).content_hash()


def test_a_typo_inside_the_escalate_block_is_refused():
    """The compatibility gate reaches into the new block too — `requred: true` would
    otherwise load as "escalation off" while reading as "escalation on"."""
    with pytest.raises(PolicyError) as exc:
        load_bundle(bundle(escalate={"requred": True}))
    assert exc.value.code == "unknown_key"


def test_escalation_is_a_declarable_engine_capability():
    from histos import ENGINE_FEATURES

    assert "escalation" in ENGINE_FEATURES
    load_bundle({**ESCALATED, "requires": {"features": ["escalation"]}})


# ── B. the collapse ──────────────────────────────────────────────────────


def test_with_no_tier_wired_an_escalated_call_is_denied():
    """The whole security property. Before: the policy could not say it at all; the
    hazard the seam has to avoid is saying it and having it mean nothing."""
    decision = Gate(load_bundle(ESCALATED)).engine.pre(wire_request())
    assert decision.effect is Effect.DENY
    assert decision.rule == "no_escalation_tier"
    assert decision.escalate is True
    assert decision.allowed is False
    assert decision.public_reason == "ACTION_NOT_AUTHORIZED"  # nothing coaching reaches the model
    assert "Gate(escalate=" in decision.remedy  # the developer channel says how to fix it


def test_the_collapse_stops_the_tool_body_running():
    ran: list[str] = []

    def wire(to: str) -> str:
        ran.append(to)  # pragma: no cover - reached only if the collapse fails
        return "sent"

    guarded = Gate(load_bundle(ESCALATED)).wrap(wire, fixed_principal=CLERK)
    with pytest.raises(GateDenied) as exc:
        guarded(to="acct-1")
    assert exc.value.decision.rule == "no_escalation_tier"
    assert ran == []


def test_there_is_no_kwarg_that_turns_a_missing_tier_into_an_allow():
    """`escalate=None` is the default and the *only* thing "no tier" can mean. A gate
    built with an explicit None must not read as a host that opted out of the check."""
    assert Gate(load_bundle(ESCALATED), escalate=None).engine.pre(wire_request()).rule == "no_escalation_tier"


# ── C. a wired tier can release, never grant ─────────────────────────────


def test_a_wired_tier_lets_the_call_continue():
    decision = Gate(load_bundle(ESCALATED), escalate=lambda req: True).engine.pre(wire_request())
    assert decision.effect is Effect.ALLOW
    assert decision.rule == "escalated"
    assert decision.escalate is True


def test_a_refusing_tier_denies():
    decision = Gate(load_bundle(ESCALATED), escalate=lambda req: False).engine.pre(wire_request())
    assert (decision.effect, decision.rule, decision.escalate) == (Effect.DENY, "escalation_denied", True)


def test_a_raising_tier_fails_closed():
    def tier(req: GateRequest) -> bool:
        raise RuntimeError("the judge is down")

    decision = Gate(load_bundle(ESCALATED), escalate=tier).engine.pre(wire_request())
    assert (decision.effect, decision.rule) == (Effect.DENY, "escalation_error")
    assert "the judge is down" in decision.reason


def test_an_async_tier_on_a_sync_tool_fails_closed():
    """A coroutine object is truthy. Read as a verdict it would release every escalated
    call un-judged, which is the one mistake this seam exists to make impossible."""

    async def tier(req: GateRequest) -> bool:
        return True  # pragma: no cover - never awaited on the sync path

    decision = Gate(load_bundle(ESCALATED), escalate=tier).engine.pre(wire_request())
    assert (decision.effect, decision.rule) == (Effect.DENY, "escalation_error")
    assert "async" in decision.reason


def test_the_async_path_awaits_the_tier():
    async def tier(req: GateRequest) -> bool:
        await asyncio.sleep(0)
        return True

    gate = Gate(load_bundle(ESCALATED), escalate=tier)
    assert asyncio.run(gate.engine.apre(wire_request())).rule == "escalated"
    assert asyncio.run(Gate(load_bundle(ESCALATED)).engine.apre(wire_request())).rule == "no_escalation_tier"


def test_the_tier_is_never_asked_about_a_call_the_chain_already_refuses():
    """Reaching a tier is a model call. An unauthorized caller, or one whose arguments
    the schema rejects, must not be able to spend one — and a tier that answered "yes"
    must not be able to overturn the refusal."""
    asked: list[str] = []

    def tier(req: GateRequest) -> bool:
        asked.append(req.tool_name)
        return True

    gate = Gate(load_bundle(ESCALATED), escalate=tier)
    assert gate.engine.pre(GateRequest("wire", {"to": 42}, CLERK)).rule == "arg_schema"
    assert gate.engine.pre(GateRequest("wire", {"to": "a"}, Principal(role="stranger"))).rule == "rbac"
    assert gate.engine.pre(GateRequest("nope", {}, CLERK)).rule == "unknown_tool"
    assert asked == []


def test_the_tier_cannot_rewrite_the_arguments_the_tool_receives():
    """The seam gets a detached copy, like `confirm`. A tier is a far likelier place for
    a callback to normalise what it was shown, and the call has already been checked."""

    def tier(req: GateRequest) -> bool:
        req.args["to"] = "attacker"
        return True

    live = {"to": "acct-1"}
    Gate(load_bundle(ESCALATED), escalate=tier).engine.pre(GateRequest("wire", live, CLERK))
    assert live == {"to": "acct-1"}


# ── D. escalation and confirmation compose, in that order ────────────────

BOTH = bundle(escalate={"required": True}, confirmation={"required": True})


def test_a_missing_tier_is_answered_before_a_human_is_asked():
    """Otherwise an engine with no tier hands the call to an approver as though every
    machine check had passed, and the granted approval executes something nothing judged."""
    assert Gate(load_bundle(BOTH)).engine.pre(wire_request()).rule == "no_escalation_tier"


def test_the_tiers_approval_does_not_stand_in_for_the_humans():
    decision = Gate(load_bundle(BOTH), escalate=lambda req: True).engine.pre(wire_request())
    assert decision.effect is Effect.REQUIRE_CONFIRMATION
    assert decision.escalate is True  # the tier ran, and the record says so


def test_confirmation_does_not_skip_the_tier():
    """The reverse ordering bug: a confirmed call must not bypass escalation."""
    ran: list[str] = []

    def wire(to: str) -> str:
        ran.append(to)  # pragma: no cover - reached only if the ordering breaks
        return "sent"

    guarded = Gate(load_bundle(BOTH), confirm=lambda req: True).wrap(wire, fixed_principal=CLERK)
    with pytest.raises(GateDenied) as exc:
        guarded(to="acct-1")
    assert exc.value.decision.rule == "no_escalation_tier"
    assert ran == []


# ── E. the marker is not an effect ───────────────────────────────────────


def test_the_escalate_marker_can_never_read_as_permission():
    """It records that meaning was consulted; it decides nothing. A decision carrying it
    is exactly as allowed as the same decision without it."""
    denied = GateDecision(Effect.DENY, "escalation_denied", escalate=True)
    assert denied.allowed is False
    assert denied.public_reason == "ACTION_NOT_AUTHORIZED"
    assert GateDecision(Effect.ALLOW, "escalated", escalate=True).allowed is True


def test_an_effect_the_wrapper_does_not_know_blocks_rather_than_executes():
    """Why `Effect.ESCALATE` was not added. The enforce branch used to list the effects
    that block, so any effect it had not been taught fell through to the tool body — a
    fail-open reached by adding a member to an enum. ALLOW is the only word for yes."""
    policy = Policy(
        tools={"wire": ToolContract(name="wire", args=Schema({"to": Field(type="string")}))},
        permissions={"clerk": frozenset({"wire"})},
    )
    ran: list[str] = []

    def wire(to: str) -> str:
        ran.append(to)  # pragma: no cover - reached only if an unknown effect fails open
        return "sent"

    gate = Gate(policy)
    guarded = gate.wrap(wire, fixed_principal=CLERK)
    # REDACT is a post-phase effect and has no meaning on a pre-decision — it stands in
    # here for any effect this branch has not been taught.
    gate.engine.pre = lambda req: GateDecision(Effect.REDACT, "from-the-future")  # type: ignore[method-assign]
    with pytest.raises(GateDenied):
        guarded(to="acct-1")
    assert ran == []


def test_public_reason_falls_through_to_the_refusal():
    assert GateDecision(Effect.REDACT, "post_redaction").public_reason == "OUTPUT_REDACTED"
    assert GateDecision(Effect.ALLOW, "allow").public_reason == "OK"


# ── F. the published vocabulary and the corpus stay in step ──────────────


def test_every_escalation_code_the_engine_emits_is_published():
    vocabulary = json.loads(SPEC.read_text(encoding="utf-8"))
    published = {code["code"]: code for code in vocabulary["codes"]}
    for code in ESCALATE_CODES:
        assert code in published, f"{code!r} is emitted by the engine and absent from the spec"
    assert published["escalated"]["effect"] == "allow"
    assert all(published[code]["effect"] == "deny" for code in ESCALATE_CODES[1:])
    assert set(vocabulary["escalation"]["codes"]) == set(ESCALATE_CODES)


def test_every_escalation_denial_carries_a_remedy():
    """The developer channel has to say what to do; the agent channel never does."""
    from histos.contracts import _REMEDY

    for code in ESCALATE_CODES[1:]:
        assert _REMEDY.get(code), f"{code!r} denies with no remedy for the developer"
    assert set(_REMEDY) <= {code["code"] for code in json.loads(SPEC.read_text(encoding="utf-8"))["codes"]}


def test_the_conformance_corpus_pins_the_collapse():
    """A second implementation must reproduce it, not take our word for it."""
    fixtures = [json.loads(p.read_text(encoding="utf-8")) for p in CORPUS.glob("escalate-*.json")]
    assert fixtures, "the corpus no longer pins the escalate collapse"
    collapses = [f for f in fixtures if f["expect"]["rule"] == "no_escalation_tier"]
    assert collapses, "no fixture asserts the DENY an engine with no tier must reach"
    for fixture in collapses:
        assert fixture["expect"]["effect"] == "deny"


# ── G. coverage against the objects the agent is handed ──────────────────


class FrameworkTool:
    """The shape a framework hands an agent: a name, plus the callable it will invoke.

    LangChain's `StructuredTool` in miniature — enough to show that the check reads the
    object the framework will actually call, not the one the developer meant to pass.
    """

    def __init__(self, name, func):
        self.name = name
        self.func = func


def _policy() -> Policy:
    return Policy(
        tools={"wire": ToolContract(name="wire", args=Schema({"to": Field(type="string")}))},
        permissions={"clerk": frozenset({"wire"})},
    )


def wire(to: str) -> str:
    return f"sent {to}"


def test_coverage_catches_a_discarded_protect_result():
    """The audit finding. `protect()` returns NEW objects; dropping the return value
    hands the agent the ungated originals, and every name-based key still reads clean."""
    gate = Gate(_policy())
    tools = [wire]
    gate.protect(tools)  # ← the return value is dropped, exactly as the demo does it

    report = gate.coverage(tools)
    assert report["ungated"] == ["wire"]
    # The three original keys are unchanged, and unchanged means: still clean. That is
    # the point — they were never able to answer this, and now something else does.
    assert report["covered"] == ["wire"]
    assert report["undeclared"] == []
    assert report["unwrapped"] == []
    assert gate.ungated_tools(tools) == ["wire"]


def test_coverage_is_clean_when_the_wrapped_tools_are_the_ones_exposed():
    gate = Gate(_policy())
    result = gate.protect([wire])
    exposed = list(result.tools.values())
    assert gate.ungated_tools(exposed) == []
    assert gate.coverage(exposed)["ungated"] == []


def test_the_check_reads_the_callable_a_framework_tool_will_invoke():
    gate = Gate(_policy())
    guarded = FrameworkTool("wire", gate.wrap(wire))
    raw = FrameworkTool("wire", wire)
    assert gate.ungated_tools([guarded]) == []
    assert gate.ungated_tools([raw]) == ["wire"]


def test_a_tool_gated_under_a_different_name_is_ungated():
    """Enforcement installed against the wrong contract is not enforcement. A callable
    gated as `read_balance` and published as `wire` is checked against `read_balance`."""
    gate = Gate(_policy())
    mislabelled = FrameworkTool("wire", gate.wrap(wire, name="read_balance"))
    assert gate.ungated_tools([mislabelled]) == ["wire"]


def test_names_still_work_and_say_they_were_not_checked():
    """The old signature is a CI gate somewhere; breaking it silently is its own hazard.
    It answers the question it always answered — and now says which one it did not."""
    gate = Gate(_policy())
    gate.wrap(wire)
    report = gate.coverage(["wire", "forgotten"])
    assert report["covered"] == ["wire"]
    assert report["undeclared"] == ["forgotten"]
    assert report["unwrapped"] == []
    assert report["ungated"] == []
    assert report["unchecked"] == ["forgotten", "wire"]


def test_a_mixed_report_checks_what_it_can():
    gate = Gate(_policy())
    gate.wrap(wire)
    report = gate.coverage([wire, "other"])
    assert report["ungated"] == ["wire"]
    assert report["unchecked"] == ["other"]


def test_ungated_tools_refuses_a_name_rather_than_answering_clean():
    gate = Gate(_policy())
    with pytest.raises(PolicyError, match="live tool objects"):
        gate.ungated_tools(["wire"])


def test_a_tool_with_no_usable_name_is_refused_rather_than_skipped():
    """Skipping is how an ungated tool ends up absent from the report that exists to
    find ungated tools."""
    gate = Gate(_policy())
    with pytest.raises(PolicyError, match="exposed name"):
        gate.ungated_tools([object()])


def test_the_gate_does_not_pin_every_wrapper_it_ever_made_in_memory():
    """The registry is identity-based, so it has to be weak — and a dead entry must not
    be able to answer "yes, I produced that" for whatever the interpreter puts at that
    address next."""
    gate = Gate(_policy())
    for _ in range(3):
        gate.wrap(wire)
    gate.wrap(wire)  # the prune runs on the way in
    gc.collect()
    gate.wrap(wire)
    assert len([ref for ref in gate._wrappers if ref() is not None]) <= 2  # noqa: SLF001 - the registry is the fix


def test_protect_returns_wrappers_that_answer_for_themselves():
    """The library-level `protect()` path, without a Gate in hand."""
    result = protect([wire], policy=_policy())
    (wrapped,) = result.tools.values()
    assert wrapped.__gate_name__ == "wire"
    assert not hasattr(wire, "__gate_name__")
