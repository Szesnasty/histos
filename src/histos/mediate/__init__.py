"""Putting the decision in the way of the call.

The engine decides; this is what makes a decision unavoidable. Three things live here and
each of them is a guarantee that fails silently if it is got wrong.

**The identity is bound out-of-band.** It comes from the host, never from a tool argument
or model output, and the gate is only as strong as that. Its two ContextVars are
process-wide singletons for the same reason.

**Every path goes through the gate.** A gate around nine of ten tools protects nine, and
the tenth is where the call goes — so `coverage` is a report a host runs in CI against
the exact list it is about to register.

**Both halves are recorded, whichever way the call went.** Including the ones that raise,
which was for a long time the one path out of the process that skipped redaction.
"""

from histos.mediate.approvals import ApprovalStore
from histos.mediate.gate import Gate, ProtectResult, gate, protect
from histos.mediate.identity import reset_principal, set_principal, use_principal

__all__ = [
    "ApprovalStore",
    "Gate",
    "ProtectResult",
    "gate",
    "protect",
    "reset_principal",
    "set_principal",
    "use_principal",
]
