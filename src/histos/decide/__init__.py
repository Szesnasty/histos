"""Making the decision, and deciding what may come back.

The engine reads only the request and the static policy — never conversation, documents,
or prior tool outputs — which is the property that keeps a manipulated model from
arguing its way past a rule.

The two halves have opposite economics and that shapes everything in here. A pre-gate
DENY costs a call. A post-gate DENY costs a call whose side effect has *already*
happened, so the post path errs toward returning something usable with the removed part
named in the trail. Both are fail-closed: any exception inside a check becomes a DENY,
never a silent allow.

Both are also budgeted, because every pass is linear in what it is given and the size of
that is chosen by whoever is talking to the model. Over budget is a refusal rather than a
partial scan — truncating would mean silently not looking past the cut.
"""

from histos.decide.canary import find, find_normalized, redact
from histos.decide.content_rules import ContentRules
from histos.decide.engine import Engine, EscalationTier, ResourceResolver, for_callback
from histos.decide.limits import LimitStore

__all__ = [
    "ContentRules",
    "Engine",
    "EscalationTier",
    "LimitStore",
    "ResourceResolver",
    "find",
    "find_normalized",
    "for_callback",
    "redact",
]
