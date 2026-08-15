"""Wrapping a whole tool set at once, and saying what the policy still owes.

Split out of `gate.py`, which was 725 lines. `Gate` is one tool, one contract, one
decision; this is the bulk path — infer what can be inferred, wrap everything, and hand
back a coverage report beside a review of the policy as a human *authored* it.

The dependency runs one way on purpose. This module does not import `Gate`: it takes one.
The convenience that builds a Gate and drives it belongs above the Gate, not inside it,
and expressing that as a parameter rather than an import is what keeps the two layers
from becoming a cycle — three of which turned up during the last repackaging, each one
naming a symbol that was living in the wrong module.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from histos.errors import PolicyError
from histos.mediate.callsig import _schema_constrains
from histos.mediate.policyref import _resolve_fixed_principal
from histos.policy.contracts import Principal, ToolContract
from histos.provenance.infer import infer_contract, infer_schema
from histos.review import PolicyReview, review_policy

if TYPE_CHECKING:  # the annotation only — see the module docstring
    from histos.mediate.gate import Gate


@dataclass
class ProtectResult:
    """What :func:`protect` / :meth:`Gate.protect` return.

    A small object, never a tuple — a tuple return ages badly. ``.tools`` maps
    each tool's name to its wrapped form, ``.coverage`` says which tools had a
    contract and a grant, and ``.review`` is the full tri-state
    :class:`~histos.review.PolicyReview` for the resulting policy.

    Iterating the result yields the wrapped tools, so
    ``agent.tools = list(protect(tools, policy=p))`` reads naturally — and reads
    naturally is the point. These are **new** objects; the originals stay alive and
    ungated, so a result that is computed and dropped protects nothing while every
    name-based report stays green. :meth:`Gate.ungated_tools` is the assertion that
    catches it, and it has to be asked of the objects the agent is handed.
    """

    tools: dict[str, Callable[..., Any]] = field(default_factory=dict)
    coverage: list[dict[str, Any]] = field(default_factory=list)
    review: PolicyReview | None = None

    @property
    def report(self) -> list[dict[str, Any]]:
        """Deprecated alias for :attr:`coverage`."""
        return self.coverage

    def __iter__(self) -> Iterator[Callable[..., Any]]:
        return iter(self.tools.values())

    def summary(self) -> str:
        ready = sum(1 for r in self.coverage if r["status"] == "ready")
        needs = [r["tool"] for r in self.coverage if r["status"] != "ready"]
        line = f"{ready}/{len(self.coverage)} tools fully covered"
        if needs:
            line += f"; needs a decision: {', '.join(needs)}"
        return line


def protect_tools(
    gate: Gate,
    tool_objects: list[Callable[..., Any]],
    *,
    fixed_principal: Principal | None = None,
    principal: Principal | None = None,
    infer_missing: bool = True,
) -> ProtectResult:
    """Wrap every tool, inferring missing arg schemas, and report coverage.

    ``infer_missing`` fills in an argument schema from each tool's signature
    so args are still validated — but a tool with no RBAC grant
    or no contract stays denied-by-default until a human adds the policy.
    The report says exactly which tools "need a decision".

    The honest limit on inference: it never writes a *contract* for a tool a role
    already grants. Such a tool keeps denying with ``unknown_tool``, because the one
    thing inference must not do is supply the declaration the grant is waiting for.

    ``review`` describes the policy as **authored**, not as inferred, so it can name
    a gap ``coverage`` reports as filled — a tool whose arg schema was guessed from a
    signature is still a tool nobody wrote a schema for. The two halves answer
    different questions: ``coverage`` says what is enforced now, ``review`` says what
    a human still owes the policy.
    """
    bound = _resolve_fixed_principal(fixed_principal, principal)
    result = ProtectResult()
    # The review describes the policy the HUMAN wrote, so it is read off a snapshot
    # taken before any inference. Reviewing the live policy afterwards made the
    # report erase its own worst finding: `role 'admin' grants unknown tool
    # 'delete_user'` came back clean, because protect() had just declared the tool
    # the warning was about. A report that answers for its own edits is worse than
    # no report.
    authored = replace(gate.policy, tools=dict(gate.policy.tools))
    # Inference accumulates here and is installed once, through the property setter,
    # rather than written into the live ruleset item by item. The Gate's policy is
    # read-only precisely so an in-place edit cannot take effect against a
    # `policy_hash` computed before it, and `protect()` must not be the one caller
    # that goes around that.
    tools: dict[str, ToolContract] = dict(gate.policy.tools)
    for tool in tool_objects:
        tool_name = getattr(tool, "__name__", None)
        if not tool_name:
            raise PolicyError("cannot determine a tool name in protect(); wrap it individually with name=")
        # The name is the policy key, so two tools answering to one name is not a
        # collision to resolve — it is two different callables enforcing one
        # contract. `result.tools` kept the last, `coverage` listed the name twice
        # as ready, and the agent was handed a tool gated against somebody else's
        # rules. Two modules each defining `def delete(...)` is all it takes.
        if tool_name in result.tools:
            raise PolicyError(
                f"protect() was handed two tools named {tool_name!r} "
                f"({getattr(tool, '__qualname__', tool_name)!r} and one before it). The name is the "
                "policy key, so one of them would be enforced against the other's contract. Wrap them "
                "separately with Gate.wrap(tool, name=...) and give each its own name.",
            )
        if tool_name == "<lambda>":
            raise PolicyError(
                "protect() was handed a lambda, which has no stable name to key a policy on. "
                "Wrap it with Gate.wrap(tool, name=...)."
            )

        contract = gate.policy.contract_for(tool_name)
        has_policy = contract is not None
        granted = any(tool_name in gate.policy.allowed_tools(role) for role in gate.policy.permissions)
        # An inferred schema is a convenience, never a grant, and never a stand-in
        # for one that can reject something. A signature with unannotated
        # parameters or `**kwargs` infers to a schema that accepts every argument
        # of every type; installing that where the policy had none replaced the
        # documented `unknown_tool` / `no_arg_schema` denial with a check that
        # cannot fail — a fail-open reached by the DEFAULT argument, while the
        # coverage report still said "needs-policy" about a tool that just ran.
        # So it is only installed when it actually constrains.
        #
        # And never for a tool that is already GRANTED but undeclared. Inferring a
        # schema fills a hole in a contract a human wrote; inferring the contract
        # itself writes the declaration the grant was waiting for, and `unknown_tool`
        # — the denial that makes "nothing is silently left ungated" true — became an
        # allow for a tool whose `tools:` entry someone had deleted or renamed. That
        # combination keeps denying until a human declares it.
        if contract is None and infer_missing and not granted:
            inferred = infer_contract(tool)
            if inferred.args is not None and _schema_constrains(inferred.args):
                tools[tool_name] = inferred
        elif contract is not None and contract.args is None and infer_missing:
            schema = infer_schema(tool)
            if _schema_constrains(schema):
                tools[tool_name] = replace(contract, args=schema)

        if has_policy and granted:
            status = "ready"
        elif not has_policy:
            status = "needs-policy"  # inferred schema only; no RBAC → denies by default
        else:
            status = "needs-grant"  # contract exists but no role may call it yet

        result.tools[tool_name] = gate.wrap(tool, name=tool_name, fixed_principal=bound)
        result.coverage.append({"tool": tool_name, "status": status, "granted": granted, "had_contract": has_policy})

    if tools != dict(gate.policy.tools):
        gate.policy = replace(gate.policy, tools=tools)  # type: ignore[assignment]
    # The names go in explicitly because the snapshot is, correctly, blind to them:
    # a tool the policy never declared is not in `authored.tools`, so without this
    # the review would answer for three tools while the agent holds four.
    result.review = review_policy(authored, discovered=result.tools)
    return result
