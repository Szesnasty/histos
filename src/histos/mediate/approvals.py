"""Trusted, out-of-band confirmation — approvals bound to an exact request.

Confirmation must come from **outside the model** (a human approver, a trusted
console, a secure channel), never a boolean the agent can influence — the same
rule as identity. A naive ``confirm=lambda req: True`` (or one that reads a field
the agent controls) lets an injected agent self-approve a destructive action.

:class:`ApprovalStore` is the safe primitive:

* the gate raises ``GateConfirmationRequired`` on an unconfirmed high-risk call;
* a **trusted host** — never the agent — calls :meth:`grant` out-of-band with
  ``exc.request``, e.g. after a human clicks approve;
* the agent retries the **same** call and the gate consumes the approval.

Take the request off the exception, not a fingerprint rebuilt from the arguments you
sent. A ``bind`` overwrites its fields with the principal's trusted attribute *before* the request is
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
import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from histos.errors import PolicyError
from histos.policy.canonical import canonical_json
from histos.policy.contracts import GateRequest, Policy, Principal


@dataclass(frozen=True)
class _Grant:
    """One approval: when it was made, under which ruleset, and for how long."""

    at: float
    policy_hash: str
    window: float | None
    # ``None`` is a real, pinned "no expiry" for a GateRequest. Only the legacy
    # fingerprint form has no window information and may consult the store's policy.
    window_pinned: bool


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
    on a production deploy has always been told they were getting. Prefer granting the
    paused request: it carries that window from the exact Gate snapshot that produced
    it, even if the store itself predates a policy hot reload.

    The policy is required, and the default that made it optional is gone. A store
    built without one cannot see ``confirmation.expires_in`` at all, so a fifteen-minute
    window written on a production deploy simply did not exist — the grant stayed usable
    until something consumed it — and nothing said so at any point: not at construction,
    not at grant, not at consume. ``ApprovalStore(None)`` still works for the case where
    there genuinely is no window to enforce, but it has to be written down.
    """

    def __init__(self, policy: Policy | None, *, clock: Callable[[], float] = time.monotonic) -> None:
        # Monotonic, not wall-clock: an NTP step backwards must not extend a window.
        if policy is not None and not isinstance(policy, Policy):
            raise PolicyError(f"approval policy must be a Policy or None, got {type(policy).__name__}")
        if not callable(clock):
            raise PolicyError(f"approval clock must be callable, got {type(clock).__name__}")
        self._clock = clock
        self._last_clock: float | None = None
        self._policy = policy
        self._approved: dict[str, _Grant] = {}
        self._lock = threading.Lock()

    def grant(self, approved: GateRequest | str) -> None:
        """Record an out-of-band approval for one exact action. Host-only.

        **Pass the request the gate paused** — `exc.request` off
        `GateConfirmationRequired`. It carries the ruleset the gate actually decided
        under, and that is the only place that information exists at the moment an
        operator clicks approve.

        A fingerprint string still works and is the weaker spelling. It cannot say which
        ruleset it belongs to, so the store falls back to the policy it was *built* with
        — and `Gate.policy = ...` replaces the Gate's policy and engine and cannot reach
        in here. After one hot reload the store signed every grant with the outgoing
        hash, `consume` correctly refused each one, and every tool requiring
        confirmation was dead for the life of the process: fail-closed, and a permanent
        outage reached through the documented way to change rules in flight. That is the
        defect this overload exists to remove, and the string form is kept only because
        it is published.

        The window is recorded here too, never read back at consume, for the same
        reason: `_window()` reads `self._policy`, so a store that has outlived its
        ruleset would apply the *old* `confirmation.expires_in` to a grant made under
        the new one. The window an operator was shown is the window that binds.
        """
        if isinstance(approved, str):
            with self._lock:
                self._approved[approved] = _Grant(self._time(), self._policy_hash(), None, False)
            return
        if not isinstance(approved, GateRequest):
            raise PolicyError(f"approved must be a GateRequest or fingerprint string, got {type(approved).__name__}")
        with self._lock:
            self._approved[fingerprint_of(approved)] = _Grant(
                self._time(),
                approved.policy_hash or self._policy_hash(),
                approved.confirmation_expires_in,
                True,
            )

    def grant_for(self, fingerprint: str, tool_name: str) -> None:
        """:meth:`grant` with the tool named, for a host that holds no request.

        Pins `confirmation.expires_in` as it stands now. Superseded by passing the
        request itself, which pins the ruleset as well and is the spelling to reach for.
        """
        if not isinstance(fingerprint, str) or not fingerprint:
            raise PolicyError("approval fingerprint must be a non-empty string")
        if not isinstance(tool_name, str) or not tool_name:
            raise PolicyError("approval tool_name must be a non-empty string")
        with self._lock:
            self._approved[fingerprint] = _Grant(self._time(), self._policy_hash(), self._window(tool_name), True)

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
            # The ruleset has to be the one the approval was issued against. Dropped
            # either way, like an expiry: an approval whose rules moved is spent, not
            # retryable, or "the policy changed" would mean "wait for the agent to ask
            # again". Both hashes must be present to compare — a request built by hand
            # carries none, and a store built without a policy recorded none.
            if entry.policy_hash and request.policy_hash and request.policy_hash != entry.policy_hash:
                return False
            # The window pinned at grant, or — for a plain `grant()`, which cannot know
            # which contract to read — whatever the store's policy says now.
            window = entry.window if entry.window_pinned else self._window(request.tool_name)
            # Dropped either way: an approval that timed out is spent, not retryable.
            # Leaving it in the store would make "expired" mean "expired until the
            # agent asks again", which is not an expiry.
            return window is None or self._time() - entry.at <= window

    def _time(self) -> float:
        """Read the monotonic clock without allowing expiry to move backwards."""
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
            raise PolicyError(f"approval clock must return a finite number, got {value!r}")
        now = float(value)
        if self._last_clock is not None and now < self._last_clock:
            raise PolicyError(
                f"approval clock moved backwards from {self._last_clock!r} to {now!r}; "
                "a non-monotonic clock can extend an approval past its expiry"
            )
        self._last_clock = now
        return now

    def as_confirm(self):
        """Return the callback to pass as ``Gate(confirm=...)``."""
        return self.consume
