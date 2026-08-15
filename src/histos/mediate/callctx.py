"""The ruleset one call decides under, from its first byte to its last.

A `Gate` is mutable by design: `gate.policy = ...` is how a deploy tightens the rules
without rebuilding the agent. Every read of `gate.engine` during a call is therefore a
separate chance to get a *different* ruleset, and a call makes many — bindings, PRE, the
callbacks, the limit, the record, POST, and the exception path.

Three defects came out of that, all of them the same defect:

* PRE ran under the policy the call started with and POST re-read `gate.engine`, so a
  swap while the tool was running applied the *new* rules to the result. Measured: a
  policy that redacts secrets in, one that does not by the time the tool returned, and
  an AWS key back in the clear — recorded against the hash of the policy that forbade
  it.
* `policy_hash` came from the call and `policy_version` from the Gate's live field, so a
  record could pair one ruleset's hash with another's version: an identifier for a
  policy that never existed.
* A gated tool calling a *second* gated tool — an adapter, a client, an agent-shaped
  tool — left the inner Gate's value behind, and the outer POST recorded it.

So the snapshot is taken once, holds everything a decision or a record needs, and is
scoped with a token like any other `ContextVar`. It is a context variable rather than a
parameter for the reason `_current_principal` is: it has to reach a dozen sites across
two call paths and four modules, and threading it by hand is how the previous attempt
missed four of them while its own comment claimed otherwise.

`reset` in a `finally` is the part that makes nesting work, and its absence is what the
third defect was.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - types only, and importing Engine here would cycle
    from histos.decide.engine import Engine


@dataclass(frozen=True)
class CallContext:
    """Everything about the ruleset that must not change under one call."""

    engine: Engine
    policy_hash: str
    policy_version: str
    enforce: bool


_call_context: ContextVar[CallContext | None] = ContextVar("histos_call_context", default=None)


def current() -> CallContext | None:
    """The snapshot this call is running under, or None outside a gated call."""
    return _call_context.get()


def open_context(gate: Any) -> Token[CallContext | None]:
    """Take the snapshot. One read of `gate.engine`, and everything else off it.

    The engine carries the hash and the policy of the ruleset it was built for, so
    reading it once yields a consistent set — where reading `gate.engine` and
    `gate._recorder.policy_hash` separately is two reads with a swap possible between
    them.
    """
    engine = gate.engine
    return _call_context.set(
        CallContext(
            engine=engine,
            policy_hash=engine.policy_hash,
            policy_version=engine.policy.policy_version,
            enforce=gate._enforce,
        )
    )


def close_context(token: Token[CallContext | None]) -> None:
    """Restore whatever was in force before this call — an outer Gate, or nothing."""
    _call_context.reset(token)


def engine_for(gate: Any) -> Any:
    """The engine this call decides under, falling back to the Gate's current one.

    The fallback is for a caller reaching the engine outside a gated call — `histos
    explain`, a test driving `Engine.pre` directly. Inside a call the snapshot always
    wins, which is the whole point.
    """
    context = _call_context.get()
    return context.engine if context is not None else gate.engine


def policy_hash_for(gate: Any) -> str:
    """The hash of the ruleset this call decides under, for the POST record."""
    context = _call_context.get()
    return context.policy_hash if context is not None else gate._recorder.policy_hash


def enforce_for(gate: Any) -> bool:
    """Whether this call enforces, decided once at entry.

    Read live, `gate.enforcement = "observe"` landing between PRE and the raise turned a
    denial into an execution: the decision said no and the branch that acts on it asked a
    Gate that had since been told to watch rather than block. Mode is part of the ruleset
    a call runs under, so it is part of the snapshot.
    """
    context = _call_context.get()
    return context.enforce if context is not None else bool(gate._enforce)
