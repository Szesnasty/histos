"""Injecting the arguments the model is not allowed to choose.

Split out of `gate.py`. A `Binding` is the third of the three mechanisms the policy
format offers and the only one that *writes*: the argument schema asks whether a value is
admissible, a `Constraint` asks whether this principal may act on this resource, and a
binding removes the question by overwriting the field with a trusted attribute before
anything else reads it. Different job, different failure mode, its own file.

Takes a Gate rather than being part of one, for the reason `protection.py` gives.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from histos.mediate import callctx
from histos.policy.contracts import Effect, GateDecision, Principal
from histos.policy.frozen import _snapshot_value

if TYPE_CHECKING:
    from histos.mediate.gate import Gate


def apply_bindings(
    gate: Gate,
    tool_name: str,
    active: Principal,
    call_args: dict[str, Any],
    rebound: list[str] | None = None,
    overrides: dict[str, Any] | None = None,
) -> GateDecision | None:
    """Overwrite bound args with trusted principal attributes (Phase 0.1).

    The bound value is what the tool and every check see, so a hijacked model
    passing ``tenant_id="attacker"`` simply has it replaced. Fail closed if the
    principal lacks the attribute — never inject a missing/None trusted value.

    ``rebound`` collects the fields that were actually *changed*, and it exists
    because a rewrite is an authorization decision that used to leave no trace.
    A run where the gate silently redirected an SMS from the attacker's number to
    the caller's own recorded `effect=allow` and nothing else, so an auditor —
    and a measurement — could not tell it apart from a call the policy simply had
    no opinion about. Fields whose value already matched are not listed: nothing
    was overridden, and reporting one would inflate the count of interventions.

    The value itself never reaches the record. Only the field name does.
    """
    # The ruleset this call started under, not whatever the Gate holds now: bindings
    # otherwise ran under a policy swapped in after PRE had decided under another.
    contract = callctx.engine_for(gate).policy.contract_for(tool_name)
    if contract is None or not contract.bindings:
        return None
    # A caller that supplies `overrides` is asking for the rewrites rather than for
    # them to be applied — the gate does that so observe can evaluate the bound
    # arguments while executing the unbound ones. Everyone else, including the
    # conformance corpus, gets the straightforward thing: `call_args` comes back
    # bound.
    apply_in_place = overrides is None
    if overrides is None:
        overrides = {}
    for b in contract.bindings:
        if b.principal_attr not in active.attributes:
            return GateDecision(
                Effect.DENY,
                "arg_binding_unresolved",
                f"principal is missing trusted attribute {b.principal_attr!r} for arg {b.field!r}",
                field=b.field,
            )
        # Copied on the way out. `Principal` deep-copies on construction, which
        # stops the *caller* rewriting a bound identity; it does not stop the tool,
        # and a bind hands the tool the stored object it gates. So an ordinary
        # `tenants.append(...)` inside a tool body edited the trust anchor that the
        # next call in the same request would be authorized against — the one value
        # in the library that must not be reachable from anything the model can
        # influence.
        # The same walk `Principal` snapshots with, and for the same reason twice
        # over. A bare `copy.deepcopy` here raised on any attribute holding an
        # uncopyable descendant — a lock, a session, an open file — so teaching the
        # *constructor* to tolerate one only moved the outage from construction to
        # call time, where it arrived as an uncaught TypeError out of the wrapper
        # with no audit record for a call the policy had already allowed.
        # `readonly=False`: the *anchor* is immutable, a *handout* is a plain copy.
        # The stored attribute is a ReadOnlyDict/ReadOnlyList so nobody holding the
        # Principal can edit a bound identity, but a tool mutating the argument it
        # was given harms nothing and refusing it would break ordinary tool bodies.
        trusted = _snapshot_value(active.attributes[b.principal_attr], readonly=False)
        if rebound is not None and (b.field not in call_args or call_args[b.field] != trusted):
            rebound.append(b.field)
        overrides[b.field] = trusted
    if apply_in_place:
        call_args.update(overrides)
    return None
