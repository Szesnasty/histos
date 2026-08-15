"""Trusted, out-of-band confirmation — approvals bound to an exact request.

Confirmation must come from **outside the model** (a human approver, a trusted
console, a secure channel), never a boolean the agent can influence — the same
rule as identity. A naive ``confirm=lambda req: True`` (or one that reads a field
the agent controls) lets an injected agent self-approve a destructive action.

:class:`ApprovalStore` is the safe primitive:

* the gate raises ``GateConfirmationRequired`` on an unconfirmed high-risk call;
* a **trusted host** — never the agent — calls :meth:`grant` out-of-band with
  ``exc.fingerprint``, e.g. after a human clicks approve;
* the agent retries the **same** call and the gate consumes the approval.

Take the fingerprint off the exception, not from the arguments you sent. A ``bind``
overwrites its fields with the principal's trusted attribute *before* the request is
fingerprinted, so for any tool that has one, the arguments the host passed and the
arguments the approval covers are different — and a fingerprint built from the former
matches nothing, which shows up as a call that pauses forever with a grant sitting in
the store. ``exc.request.args`` is the spelling that ran.

Approvals are **single-use** and **bound to the exact (tool, args, principal)** —
role, identity, trusted attributes and ``can_view``, all of it — so one cannot be
replayed to a different action or to the same action under different trusted
context, and the agent — which cannot write to the store — cannot approve itself.

They are bound to the **ruleset** as well. Three places said so and nothing did it:
the fingerprint above covers the action and says nothing about the rules in force, so
an approval granted at 10:00 under a strict policy was still spendable at 10:06 after
a deploy loosened it. That is not a remote bypass — spending it needs the ability to
change the Gate's policy, and anyone with that can drop ``requires_confirmation``
outright — but it is the evidence failing quietly, which is what confirmation is for:
the record would say "approved by the officer" about a decision made under rules the
officer never saw. The hash in force at grant is recorded and compared at consume.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable

from histos.policy.canonical import canonical_json
from histos.policy.contracts import GateRequest, Policy, Principal


def request_fingerprint(tool_name: str, args: dict, principal: Principal) -> str:
    """Stable fingerprint of a specific action: (tool, args, **whole** principal).

    Uses the one canonical serializer (Phase 0.1) so `1` and `"1"` do not collide
    and an approval binds to the exact action. Un-canonicalizable args raise — an
    action the gate cannot fingerprint stably cannot be safely approved (fail-closed).

    ``attributes`` and ``can_view`` are part of the binding, not decoration. They are
    what a ``Constraint`` compares against, so leaving them out let one identity carry
    an approval across the boundary they exist to draw: a support console acting for
    tenant "acme" got an approval granted, switched to tenant "evil-corp", and the
    same fingerprint consumed it against a resource the first tenant never owned.
    ``can_view`` changes which sensitive return fields come back in the clear, which
    is the same question asked about the output.
    """
    body = canonical_json(
        {
            "tool": tool_name,
            "args": args,
            "role": principal.role,
            "identity": principal.identity,
            # `attributes` is a read-only view, which the canonicalizer does not accept
            # as a mapping — copy it rather than let a fingerprint fail on its type.
            "attributes": dict(principal.attributes),
            "can_view": principal.can_view,
        }
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def fingerprint_of(request: GateRequest) -> str:
    return request_fingerprint(request.tool_name, request.args, request.principal)


class ApprovalStore:
    """Out-of-band, single-use approvals keyed by request fingerprint (thread-safe).

    Approvals also **expire**, when the policy says they do. ``confirmation.expires_in``
    is part of the policy format and the engine publishes the declared window on the
    decision, but the engine has no clock and never consumes an approval — the store
    does both, so the window is enforced here. Hand this the same ``Policy`` the gate
    runs on and a grant for a tool declaring ``expires_in: 900`` stops being usable 900
    seconds after it was granted, which is what an operator writing a 15-minute window
    on a production deploy has always been told they were getting.

    The policy is required, and the default that made it optional is gone. A store
    built without one cannot see ``confirmation.expires_in`` at all, so a fifteen-minute
    window written on a production deploy simply did not exist — the grant stayed usable
    until something consumed it — and nothing said so at any point: not at construction,
    not at grant, not at consume. ``ApprovalStore(None)`` still works for the case where
    there genuinely is no window to enforce, but it has to be written down.
    """

    def __init__(self, policy: Policy | None, *, clock: Callable[[], float] = time.monotonic) -> None:
        # Monotonic, not wall-clock: an NTP step backwards must not extend a window.
        self._clock = clock
        self._policy = policy
        self._approved: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()

    def grant(self, fingerprint: str) -> None:
        """Record an out-of-band approval for one exact action. Host-only.

        The ruleset in force is recorded beside the clock. `README.md` and this
        module's own callers said an approval binds to the policy hash and nothing
        did it: the fingerprint covers the tool, the arguments and the whole
        principal, and says nothing about the rules. So an approval granted at 10:00
        under a strict ruleset was still spendable at 10:06 after a deploy loosened
        it, and the audit line then read "approved by the officer" about a decision
        made under rules that officer never saw.
        """
        with self._lock:
            self._approved[fingerprint] = (self._clock(), self._policy_hash())

    def _policy_hash(self) -> str:
        """The ruleset this store was handed, or "" when it was handed none.

        Hashing is not free and a grant is rare, so it happens here rather than per
        call. A store built with `ApprovalStore(None)` — the documented case where
        there is genuinely no window and no ruleset to bind to — records "" and the
        check below is skipped, which is the same fail-open the constructor already
        makes the host write down.
        """
        return "" if self._policy is None else self._policy.content_hash()

    def revoke(self, fingerprint: str) -> None:
        with self._lock:
            self._approved.pop(fingerprint, None)

    def _window(self, tool_name: str) -> float | None:
        if self._policy is None:
            return None
        contract = self._policy.contract_for(tool_name)
        return None if contract is None else contract.confirmation_expires_in

    def consume(self, request: GateRequest) -> bool:
        """Single-use check used as the gate's ``confirm`` callback."""
        fingerprint = fingerprint_of(request)
        with self._lock:
            entry = self._approved.pop(fingerprint, None)
            if entry is None:
                return False
            granted_at, granted_under = entry
            # The ruleset has to be the one the approval was issued against. Dropped
            # either way, like an expiry: an approval whose rules moved is spent, not
            # retryable, or "the policy changed" would mean "wait for the agent to ask
            # again". Both hashes must be present to compare — a request built by hand
            # carries none, and a store built without a policy recorded none.
            if granted_under and request.policy_hash and request.policy_hash != granted_under:
                return False
            window = self._window(request.tool_name)
            # Dropped either way: an approval that timed out is spent, not retryable.
            # Leaving it in the store would make "expired" mean "expired until the
            # agent asks again", which is not an expiry.
            return window is None or self._clock() - granted_at <= window

    def as_confirm(self):
        """Return the callback to pass as ``Gate(confirm=...)``."""
        return self.consume
