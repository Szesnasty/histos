"""One decision, as the row that goes in the trail — and what may not be in it.

Split out of `audit.py`. The claim this module has to keep is that a record never
stores a raw argument value, and that claim covers the *whole* row rather than the
digest field: a decision `reason` that quotes the value it refused is the same leak by a
different column, so an unrecognised rule redacts by default.

Every free-text field is bounded here rather than at a sink, so every sink gets the
bound. They are all model-chosen text — the tool name a host wrapped, an identity from
a token claim, the argument names themselves — and one call once wrote an 800 KB line
with `arg_keys` dutifully capped at 1 KB inside it.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import asdict, dataclass, field
from typing import Any


def digest_args(args: dict[str, Any], key: bytes) -> str:
    """Keyed HMAC-SHA256 hex of the arguments — never the raw values.

    Uses the one canonical serializer (Phase 0.1), so two calls with the same arguments
    digest the same *under the same key*. It does not equal the approval fingerprint,
    which this used to claim: that one is an unkeyed SHA-256 over the tool, the args and
    the whole principal, and it exists to be reproducible by a host that never sees this
    key. Two different questions, two different values.

    The key matters more than it looks. `Gate` generates a random one per instance
    unless given `audit_key=`, which is right for the default — a bare SHA of a
    low-entropy argument is brute-forceable — but it means the column cannot be
    correlated across processes, across a restart, or between two Gates in one process
    unless the operator passes a stable key. Pass one from your secret store if
    "the same call, again" is a question you need the trail to answer.

    Audit must never crash the gate, so an un-canonicalizable value falls back to a
    stable repr rather than raising.
    """
    from histos.canonical import canonical_json

    try:
        canonical = canonical_json(args)
    except (TypeError, ValueError):
        canonical = repr(sorted(args.items(), key=lambda kv: kv[0]))
    # `surrogatepass`, because a plain `.encode("utf-8")` here is a way to make a
    # decision disappear. The serializer rejects a lone surrogate, but the repr
    # fallback does not: an argument object whose `__repr__` returns one produced a
    # `UnicodeEncodeError` out of `Gate._emit` *before* the sink was reached, so the
    # call that provoked it was the one call with no record at all. There is no input
    # this digest is allowed to refuse.
    return "hmac-sha256:" + hmac.new(key, canonical.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()


# Decision rules whose `reason` this module composes itself, out of things the record
# already publishes or the operator already has: tool names, the caller's role, policy
# literals the developer wrote, field names, limit names. Safe to keep verbatim.
#
# Absent from the list, and therefore redacted: every rule whose reason is built by
# interpolating a *foreign* string — an exception raised by a host resolver, a confirm
# callback, or a check that fell over. `KeyError('jane.doe@x.com')` is the ordinary
# shape of such an exception, and it is a raw argument value on its way into an
# append-only file. An unrecognised rule redacts too, so a rule added later is assumed
# to quote data until someone says otherwise.
_REASON_IS_POLICY_TEXT: frozenset[str] = frozenset(
    {
        "allow",
        "confirmed",
        "unknown_tool",
        "no_arg_schema",
        "no_principal",
        "rbac",
        "arg_schema",
        "arg_binding_unresolved",
        "resource_constraint",
        "no_resource_resolver",
        "canary_exfil",
        "secret_detected",
        "injection_pattern",
        "exfiltration_pattern",
        "rate_limit",
        "budget",
        "requires_confirmation",
        "post_redaction",
        "exception_redaction",
        "output_schema",
        # composed from the tool name and the *kind* of lazy value that came back
        # ("generator", "structure containing a memoryview …") — never from the value,
        # which is the one thing the gate could not read in the first place.
        "uninspectable_output",
        # tool name and a count of positional arguments; no value is quoted.
        "confirm_suspended",
        "unnameable_args",
    }
)

_REDACTED = "[redacted — this rule's reason quotes foreign text; it stays in the developer channel]"

# `arg_keys` is the one field made entirely of model-chosen text, and it used to be
# copied in whole: a call with ten thousand one-kilobyte argument names wrote a ten-
# megabyte line into an append-only file, once per decision, for free. Caps here rather
# than at the sink so every sink gets them, and truncation is announced in the record
# instead of leaving a short list that reads like a short call.
_MAX_ARG_KEYS = 64
_MAX_ARG_KEY_LEN = 128
_MAX_ARG_KEYS_TOTAL = 1024

# Capping only `arg_keys` turned out to be the shape of the bug rather than the fix.
# The other text fields are copied in whole from the same places: `tool` is whatever
# name the host wrapped (a 200,000-character tool name is a 200,000-character field),
# `identity` and `role` come from a Principal a host may build out of a token claim,
# `field_name` is frequently the model's own argument name, and `reason` INTERPOLATES
# those — so a single call still wrote an 800 KB line with `arg_keys` dutifully capped
# at 1 KB inside it. Every free-text field is bounded here, and a clipped string keeps
# a marker so a truncated value is never read as the whole one. Chosen over a
# `<field>_truncated` flag per field: the marker travels with the text through every
# sink, dashboard and grep, none of which know about a new column.
_MAX_NAME_LEN = 256
_MAX_TEXT_LEN = 512
_TRUNCATED = "...[truncated]"


def _cap_arg_keys(keys: list[str]) -> tuple[list[str], bool]:
    """Bound an attacker-sized ``arg_keys`` list; returns (kept, truncated)."""
    kept: list[str] = []
    budget = _MAX_ARG_KEYS_TOTAL
    for key in keys[:_MAX_ARG_KEYS]:
        clipped = key[:_MAX_ARG_KEY_LEN]
        if len(clipped) > budget:
            break
        budget -= len(clipped)
        kept.append(clipped)
    return kept, kept != keys


def _cap_text(value: str, limit: int) -> str:
    """Bound one free-text field, leaving the clipping visible in the value itself."""
    return value if len(value) <= limit else value[:limit] + _TRUNCATED


@dataclass
class AuditRecord:
    """One gate decision, ready to serialise.

    The record is the **durable** channel, and it is held to the module's headline
    claim: no raw argument value reaches it, in any field. The engine's own denial
    text names rules and fields without quoting values, but a reason that carries a
    *foreign* exception (`resource_resolver raised: KeyError('jane.doe@x.com')`) does
    quote one, and copying that into an append-only file on disk is the outcome the
    argument digest exists to prevent. Those reasons are dropped here; the decision
    keeps its `rule`, `field` and `expected`, and the full text stays on the
    in-process `GateDenied.decision` where a developer debugging the denial reads it.
    """

    ts: float
    decision_id: int
    phase: str  # "pre" | "post"
    tool: str
    role: str
    identity: str | None
    effect: str
    rule: str
    reason: str
    args_digest: str
    arg_keys: list[str] = field(default_factory=list)
    #: Whether `arg_keys` was clipped on the way in — see :data:`_MAX_ARG_KEYS`. A record
    #: listing 64 keys is otherwise indistinguishable from a call that had exactly 64.
    arg_keys_truncated: bool = False
    #: Arguments the policy *overwrote* with a trusted principal attribute before the
    #: tool saw them — field names only, never values.
    #:
    #: A binding is an authorization decision, and it used to leave no trace. A run in
    #: which the gate silently redirected a message from an attacker's number to the
    #: caller's own recorded `effect=allow` and nothing else, which is
    #: indistinguishable in the trail from a call the policy had no opinion about. An
    #: auditor asking "why did this not go where the model asked" had nothing to read,
    #: and a measurement could not attribute the absence of harm to the policy.
    #:
    #: Only fields whose value actually changed are listed. A bound field the caller
    #: already had right was not overridden, and counting it would inflate the number
    #: of interventions the gate appears to have made.
    rebound_args: list[str] = field(default_factory=list)
    field_name: str = ""
    expected: str = ""
    received: str = ""
    redactions: list[str] = field(default_factory=list)
    enforced: bool = True
    # Whether the tool body actually ran for this call. In observe mode a DENY
    # still executes, so `effect=deny enforced=false executed=true` is the record
    # that must never be mistaken for a block.
    executed: bool = True
    latency_us: int | None = None
    policy_hash: str = ""
    policy_version: str = ""
    gate_version: str = ""

    def __post_init__(self) -> None:
        self.arg_keys, self.arg_keys_truncated = _cap_arg_keys(self.arg_keys)
        if self.rule not in _REASON_IS_POLICY_TEXT:
            self.reason = _REDACTED
            # `received` is shape-only everywhere the engine sets it (`resource.<field>`,
            # a detector kind, the caller's role), but it is held to the same rule as
            # the reason rather than trusted to stay that way.
            self.received = _REDACTED if self.received else ""
        # after the redaction, so a dropped reason is never clipped into something that
        # looks like half of a real one.
        self.tool = _cap_text(self.tool, _MAX_NAME_LEN)
        self.role = _cap_text(self.role, _MAX_NAME_LEN)
        if self.identity is not None:
            self.identity = _cap_text(self.identity, _MAX_NAME_LEN)
        self.field_name = _cap_text(self.field_name, _MAX_NAME_LEN)
        self.reason = _cap_text(self.reason, _MAX_TEXT_LEN)
        self.expected = _cap_text(self.expected, _MAX_TEXT_LEN)
        self.received = _cap_text(self.received, _MAX_TEXT_LEN)
        # `redactions` was missed by the cap pass that bounded every other free-text
        # field, and it is the one built from the *output*: `drop:<key>` carries a raw
        # return-value key, `output:uninspectable:<type>` a type name, and a projected
        # dict with ten thousand undeclared keys writes ten thousand of them into an
        # append-only file. Same budget, same visible marker.
        self.redactions, clipped = _cap_arg_keys(list(self.redactions))
        if clipped:
            self.redactions.append("...[truncated]")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
