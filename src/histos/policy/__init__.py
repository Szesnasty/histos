"""What a ruleset *is*, before anything decides anything with it.

Everything here is a plain, serialisable dataclass — no ORM, no DB, no network — because
a policy is a portable artifact that another tool may generate and this engine loads with
nothing else present. Two properties hold the whole thing up.

**It cannot change under a decision.** A frozen dataclass whose contents are ordinary
mutable dicts is not frozen; that gap was found three times at three depths, which is why
`frozen` exists as a module and why `Principal` lives in it.

**It hashes injectively and deterministically.** `content_hash` is what approvals bind
to, what pinning rests on, and what every audit record names — so a keyword that enforces
something and is missing from the fingerprint is two policies that decide differently and
hash the same.
"""

from histos.policy.authz import Binding, Constraint, ConstraintResult
from histos.policy.canonical import canonical_json, normalize_numbers
from histos.policy.contracts import (
    SCHEMA_VERSION,
    Effect,
    GateDecision,
    GateRequest,
    Policy,
    Sensitivity,
    ToolContract,
)
from histos.policy.frozen import Principal, ReadOnlyDict, ReadOnlyList
from histos.policy.schema import Field, Schema
from histos.policy.validation import sensitive_fields, validate

__all__ = [
    "SCHEMA_VERSION",
    "Binding",
    "Constraint",
    "ConstraintResult",
    "Effect",
    "Field",
    "GateDecision",
    "GateRequest",
    "Policy",
    "Principal",
    "ReadOnlyDict",
    "ReadOnlyList",
    "Schema",
    "Sensitivity",
    "ToolContract",
    "canonical_json",
    "normalize_numbers",
    "sensitive_fields",
    "validate",
]
