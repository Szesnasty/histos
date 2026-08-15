"""The two call paths, and what happens at each end of them.

Split out of `gate.py`. These are the only places in the library where a decision turns
into an *action*, and the order inside them is the whole guarantee: nothing reaches the
tool before the pre-gate has answered, nothing reaches the caller before the post-gate
has, and both halves are recorded whichever way the call went.

The sync and async paths are near-duplicates and are deliberately left that way. Merging
them means one body with `await` sprinkled through a branch, and the two differ in
places that matter — a coroutine can be cancelled, an async tool can return an async
generator, and `_close_quietly` has a different job on each. A shared implementation
would have to be right about all of that at once; two readable ones only have to be
right separately. The cost is that a fix has to be applied twice, which is what the
tests beside them are for.

`_finish_exception` is here rather than beside the post-gate for the same reason the
comment at the raise site gives: the substitute has to be raised *outside* the handler
that caught the original, because the original still carries the content the post-gate
took out of the message.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Callable
from typing import Any

from histos.decide.engine import UndetachableArgument, for_callback
from histos.errors import (
    GateConfirmationRequired,
    GateDenied,
    ToolErrorRedacted,
)
from histos.mediate import callctx as _callctx
from histos.mediate.callsig import _invoke, _positional_binder, _Unnameable
from histos.mediate.identity import _current_principal
from histos.mediate.inspection import _close_quietly, _uninspectable_kind
from histos.mediate.toolref import _adopt_metadata
from histos.policy.contracts import Effect, GateDecision, GateRequest, Principal


def _record_pre_cancelled(gate, tool_name, call_args, active, started, rebound) -> None:
    """Record a host cancellation before PRE produced its first decision."""
    gate._recorder.record(
        tool_name,
        call_args,
        GateDecision(
            Effect.DENY,
            "pre_cancelled",
            f"{tool_name!r} was cancelled while awaiting a pre-gate host callback",
        ),
        "pre",
        started,
        active,
        False,
        rebound,
    )


def _wrap_sync(gate, tool: Callable[..., Any], tool_name: str, bound: Principal | None) -> Callable[..., Any]:
    binder = _positional_binder(tool)

    def _gated_call(*args: Any, **kwargs: Any) -> Any:
        started = time.perf_counter()
        engine = _callctx.engine_for(gate)
        active = bound or _current_principal.get()
        if args:
            if binder is None:
                return _refuse_unnameable(gate, tool_name, kwargs, active, started, tool, args)
            try:
                call_args = binder(*args, **kwargs)
            except _Unnameable as exc:
                return _refuse_unnameable(gate, tool_name, kwargs, active, started, tool, args, str(exc))
        else:
            call_args = dict(kwargs)

        # No trusted identity → fail closed. Identity is never inferred.
        if active is None:
            decision = gate._no_principal()
            gate._recorder.record(tool_name, call_args, decision, "pre", started, None, gate._will_execute(decision))
            if _callctx.enforce_for(gate):
                raise GateDenied(decision)
            return _invoke(tool, binder, call_args)

        rebound: list[str] = []
        overrides: dict[str, Any] = {}
        exec_source = dict(call_args)
        binding_denial = gate._apply_bindings(tool_name, active, call_args, rebound, overrides)
        if binding_denial is not None:
            gate._recorder.record(
                tool_name,
                call_args,
                binding_denial,
                "pre",
                started,
                active,
                gate._will_execute(binding_denial),
                rebound,
            )
            if _callctx.enforce_for(gate):
                raise GateDenied(binding_denial)
            return _invoke(tool, binder, call_args)

        # Two dicts, because observe has to predict enforce and the two questions are
        # different. `checked_args` is what the policy is evaluated against and what
        # the trail records — always post-binding, so a dry run reports the decision
        # the real thing would make. `exec_args` is what the tool actually receives,
        # and only enforce rewrites that: observe is documented as changing nothing,
        # and a dry run whose side effects differ from the ungated app measures the
        # wrong thing. Deferring both was the first attempt, and it made observe
        # evaluate the model's unbound arguments — so it stopped predicting enforce
        # in both directions, which is the one thing observe is for.
        checked_args = {**call_args, **overrides}
        # Observe does not rewrite an argument the caller sent — that is the whole
        # point of it — but it does have to supply one the caller never sent at all.
        # A `bind` on a parameter the model is not expected to pass is the ordinary
        # shape (`def read(tenants): ...` with `tenants` bound from the principal),
        # and leaving it out meant observe invoked the tool with a missing argument
        # and raised a `TypeError` on a call enforce serves without complaint. A dry
        # run that breaks the app teaches the team to skip the dry run.
        supplied = (
            {k: v for k, v in overrides.items() if k not in exec_source} if not _callctx.enforce_for(gate) else {}
        )
        exec_args = checked_args if _callctx.enforce_for(gate) else {**exec_source, **supplied}
        call_args = checked_args

        contract = engine.policy.contract_for(tool_name)
        req = GateRequest(
            tool_name,
            call_args,
            active,
            phase="pre",
            policy_hash=engine.policy_hash,
            confirmation_expires_in=None if contract is None else contract.confirmation_expires_in,
        )
        try:
            pre = engine.pre(req)
        except asyncio.CancelledError:
            _record_pre_cancelled(gate, tool_name, call_args, active, started, rebound)
            raise

        # Human/operator confirmation resolved via a host callback (never a tool
        # the agent can call) — an injected agent cannot self-approve.
        if pre.effect is Effect.REQUIRE_CONFIRMATION and gate._confirm is not None:
            # Guarded exactly like the async path. An approvals UI that raises —
            # its queue is down, the operator's session expired — used to escape
            # the gate as its own exception, with no audit record for a call the
            # policy had already decided needed a human. Fail closed and record it.
            try:
                outcome = gate._confirm(for_callback(req))
            except asyncio.CancelledError:
                # A synchronous host may use the same cancellation signal as its
                # async runner. It is a BaseException on supported Python versions,
                # so the generic callback guard does not catch it. Record the parked
                # call, preserve shutdown semantics, and never run the tool.
                gate._recorder.record(
                    tool_name,
                    call_args,
                    GateDecision(
                        Effect.REQUIRE_CONFIRMATION,
                        "confirm_cancelled",
                        f"{tool_name!r} was cancelled while awaiting an out-of-band approval",
                    ),
                    "pre",
                    started,
                    active,
                    False,
                    rebound,
                )
                raise
            except UndetachableArgument as exc:
                pre = exc.as_decision()
                outcome = None
            except gate._confirm_suspends:
                # Recorded before it leaves. The comment above says a raising
                # confirm "used to escape the gate as its own exception, with no
                # audit record for a call the policy had already decided needed a
                # human" — and this branch reintroduced exactly that half: a call
                # that reached the approval stage and parked produced no record at
                # all, so the trail could not show that a human had been asked.
                # `executed=False`, because a suspension is "no decision yet".
                gate._recorder.record(
                    tool_name,
                    call_args,
                    GateDecision(
                        Effect.REQUIRE_CONFIRMATION,
                        "confirm_suspended",
                        f"{tool_name!r} parked awaiting an out-of-band approval",
                    ),
                    "pre",
                    started,
                    active,
                    False,
                    rebound,
                )
                # The host is suspending the run, not failing. A checkpointing
                # approval (LangGraph's `interrupt()`, a queue that parks the
                # request) signals by raising, and turning that into a denial made
                # the gate refuse the legitimate work it had just approved — the
                # false positive this library names as its own worst outcome.
                # Propagating is safe precisely because the tool has NOT run: a
                # suspension is "no decision yet", never "allow".
                raise
            except Exception as exc:  # noqa: BLE001 — a raising confirm fails closed
                pre = GateDecision(Effect.DENY, "confirm_error", f"confirm callback raised: {exc!r}")
            else:
                if inspect.isawaitable(outcome):
                    closer = getattr(outcome, "close", None)
                    if callable(closer):
                        closer()
                    pre = GateDecision(
                        Effect.DENY,
                        "confirm_error",
                        f"confirm callback for {tool_name!r} is async but the tool is sync — "
                        "an async confirm can only be awaited on the async path",
                    )
                else:
                    pre = gate._confirmed(pre, req, outcome)

        if pre.effect is Effect.ALLOW:
            raced = gate._consume_limit(tool_name, active)
            if raced is not None:
                pre = raced

        gate._recorder.record(tool_name, call_args, pre, "pre", started, active, gate._will_execute(pre), rebound)
        if _callctx.enforce_for(gate) and pre.effect is not Effect.ALLOW:
            # Deny-by-default over the *effect space*, not a list of the effects
            # that block. Written the other way round, an effect this branch has
            # not been taught — a member added to `Effect` later, or one a host
            # constructs itself — falls through to the tool body: a fail-open
            # reached by adding a value to an enum. ALLOW is the only word for yes.
            if pre.effect is Effect.REQUIRE_CONFIRMATION:
                # The request travels with the pause. `req.args` is post-binding, and
                # that is the only spelling an approval will match — see
                # GateConfirmationRequired.
                try:
                    paused = for_callback(req)
                except UndetachableArgument as exc:
                    # Not parked. The fingerprint an approval is granted against is
                    # taken from the request that travels with this pause, so a call
                    # whose arguments cannot be detached cannot be safely approved
                    # either — the host would be fingerprinting a live dict.
                    raise GateDenied(exc.as_decision()) from None
                raise GateConfirmationRequired(pre, paused)
            raise GateDenied(pre)

        redacted: BaseException | None = None
        try:
            result = _invoke(tool, binder, exec_args)
        except Exception as exc:
            outcome = _finish_exception(gate, tool_name, call_args, active, started, exc)
            if outcome is exc:
                raise
            redacted = outcome
        # Raised *outside* the handler on purpose: inside it, the interpreter
        # would attach the original — which still holds the unredacted text — as
        # __context__, and anything walking the exception chain would print it
        # straight back out. `from None` alone only suppresses the display.
        if redacted is not None:
            raise redacted from None
        return _finish(gate, tool_name, call_args, active, started, result)

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        # The snapshot is opened here and closed in `finally`, which is what makes a
        # *nested* gate work: a gated tool calling a second gated tool is ordinary, and
        # without the reset the inner Gate's ruleset stayed behind and stamped the outer
        # POST record. Everything inside reads the snapshot rather than the Gate.
        token = _callctx.open_context(gate)
        try:
            return _gated_call(*args, **kwargs)
        finally:
            _callctx.close_context(token)

    _adopt_metadata(wrapped, tool, tool_name, gate._mediation_token)
    return wrapped


def _wrap_async(gate, tool: Callable[..., Any], tool_name: str, bound: Principal | None) -> Callable[..., Any]:
    binder = _positional_binder(tool)

    async def _gated_call(*args: Any, **kwargs: Any) -> Any:
        started = time.perf_counter()
        engine = _callctx.engine_for(gate)
        active = bound or _current_principal.get()
        if args:
            if binder is None:
                outcome = _refuse_unnameable(gate, tool_name, kwargs, active, started, tool, args)
                return await outcome if inspect.isawaitable(outcome) else outcome
            try:
                call_args = binder(*args, **kwargs)
            except _Unnameable as exc:
                outcome = _refuse_unnameable(gate, tool_name, kwargs, active, started, tool, args, str(exc))
                return await outcome if inspect.isawaitable(outcome) else outcome
        else:
            call_args = dict(kwargs)

        if active is None:
            decision = gate._no_principal()
            gate._recorder.record(tool_name, call_args, decision, "pre", started, None, gate._will_execute(decision))
            if _callctx.enforce_for(gate):
                raise GateDenied(decision)
            return await _invoke(tool, binder, call_args)

        rebound: list[str] = []
        overrides: dict[str, Any] = {}
        exec_source = dict(call_args)
        binding_denial = gate._apply_bindings(tool_name, active, call_args, rebound, overrides)
        if binding_denial is not None:
            gate._recorder.record(
                tool_name,
                call_args,
                binding_denial,
                "pre",
                started,
                active,
                gate._will_execute(binding_denial),
                rebound,
            )
            if _callctx.enforce_for(gate):
                raise GateDenied(binding_denial)
            return await _invoke(tool, binder, call_args)

        # See the sync path: the policy is evaluated against the bound arguments in
        # both modes, and only enforce rewrites the ones the tool receives.
        checked_args = {**call_args, **overrides}
        # Observe does not rewrite an argument the caller sent — that is the whole
        # point of it — but it does have to supply one the caller never sent at all.
        # A `bind` on a parameter the model is not expected to pass is the ordinary
        # shape (`def read(tenants): ...` with `tenants` bound from the principal),
        # and leaving it out meant observe invoked the tool with a missing argument
        # and raised a `TypeError` on a call enforce serves without complaint. A dry
        # run that breaks the app teaches the team to skip the dry run.
        supplied = (
            {k: v for k, v in overrides.items() if k not in exec_source} if not _callctx.enforce_for(gate) else {}
        )
        exec_args = checked_args if _callctx.enforce_for(gate) else {**exec_source, **supplied}
        call_args = checked_args

        contract = engine.policy.contract_for(tool_name)
        req = GateRequest(
            tool_name,
            call_args,
            active,
            phase="pre",
            policy_hash=engine.policy_hash,
            confirmation_expires_in=None if contract is None else contract.confirmation_expires_in,
        )
        try:
            pre = await engine.apre(req)
        except asyncio.CancelledError:
            _record_pre_cancelled(gate, tool_name, call_args, active, started, rebound)
            raise

        if pre.effect is Effect.REQUIRE_CONFIRMATION and gate._confirm is not None:
            try:
                outcome = gate._confirm(for_callback(req))
                if inspect.isawaitable(outcome):
                    outcome = await outcome
            except asyncio.CancelledError:
                # Recorded, then re-raised untouched. The engine had already decided
                # REQUIRE_CONFIRMATION and the wrapper was waiting on a human; a
                # cancelled task raises this, which is not in `_confirm_suspends` unless
                # a host thought to name it — so the call unwound with the sink empty. A
                # high-risk call that reached the approval stage and left no trace is the
                # "every decision is recorded" promise failing on the one call shape that
                # most needs the record.
                #
                # Nothing ran, so `executed=False`. And the cancellation is re-raised as
                # itself: swallowing a `CancelledError` breaks the shutdown that sent it.
                gate._recorder.record(
                    tool_name,
                    call_args,
                    GateDecision(
                        Effect.REQUIRE_CONFIRMATION,
                        "confirm_cancelled",
                        f"{tool_name!r} was cancelled while awaiting an out-of-band approval",
                    ),
                    "pre",
                    started,
                    active,
                    False,
                    rebound,
                )
                raise
            except UndetachableArgument as exc:
                pre = exc.as_decision()
                outcome = None
            except gate._confirm_suspends:
                # Recorded before it leaves. The comment above says a raising
                # confirm "used to escape the gate as its own exception, with no
                # audit record for a call the policy had already decided needed a
                # human" — and this branch reintroduced exactly that half: a call
                # that reached the approval stage and parked produced no record at
                # all, so the trail could not show that a human had been asked.
                # `executed=False`, because a suspension is "no decision yet".
                gate._recorder.record(
                    tool_name,
                    call_args,
                    GateDecision(
                        Effect.REQUIRE_CONFIRMATION,
                        "confirm_suspended",
                        f"{tool_name!r} parked awaiting an out-of-band approval",
                    ),
                    "pre",
                    started,
                    active,
                    False,
                    rebound,
                )
                # The host is suspending the run, not failing. A checkpointing
                # approval (LangGraph's `interrupt()`, a queue that parks the
                # request) signals by raising, and turning that into a denial made
                # the gate refuse the legitimate work it had just approved — the
                # false positive this library names as its own worst outcome.
                # Propagating is safe precisely because the tool has NOT run: a
                # suspension is "no decision yet", never "allow".
                raise
            except Exception as exc:  # noqa: BLE001 — a raising confirm fails closed
                pre = GateDecision(Effect.DENY, "confirm_error", f"confirm callback raised: {exc!r}")
            else:
                pre = gate._confirmed(pre, req, outcome)

        # Consumed after the last await so no lock is held across a suspension.
        if pre.effect is Effect.ALLOW:
            raced = gate._consume_limit(tool_name, active)
            if raced is not None:
                pre = raced

        gate._recorder.record(tool_name, call_args, pre, "pre", started, active, gate._will_execute(pre), rebound)
        if _callctx.enforce_for(gate) and pre.effect is not Effect.ALLOW:
            # Deny-by-default over the *effect space*, not a list of the effects
            # that block. Written the other way round, an effect this branch has
            # not been taught — a member added to `Effect` later, or one a host
            # constructs itself — falls through to the tool body: a fail-open
            # reached by adding a value to an enum. ALLOW is the only word for yes.
            if pre.effect is Effect.REQUIRE_CONFIRMATION:
                # The request travels with the pause. `req.args` is post-binding, and
                # that is the only spelling an approval will match — see
                # GateConfirmationRequired.
                try:
                    paused = for_callback(req)
                except UndetachableArgument as exc:
                    # Not parked. The fingerprint an approval is granted against is
                    # taken from the request that travels with this pause, so a call
                    # whose arguments cannot be detached cannot be safely approved
                    # either — the host would be fingerprinting a live dict.
                    raise GateDenied(exc.as_decision()) from None
                raise GateConfirmationRequired(pre, paused)
            raise GateDenied(pre)

        redacted: BaseException | None = None
        try:
            result = await _invoke(tool, binder, exec_args)
        except Exception as exc:
            outcome = _finish_exception(gate, tool_name, call_args, active, started, exc)
            if outcome is exc:
                raise
            redacted = outcome
        # See the sync path: raised outside the handler so the original is not
        # attached as __context__.
        if redacted is not None:
            raise redacted from None
        return _finish(gate, tool_name, call_args, active, started, result)

    async def wrapped(*args: Any, **kwargs: Any) -> Any:
        # The snapshot is opened here and closed in `finally`, which is what makes a
        # *nested* gate work: a gated tool calling a second gated tool is ordinary, and
        # without the reset the inner Gate's ruleset stayed behind and stamped the outer
        # POST record. Everything inside reads the snapshot rather than the Gate.
        token = _callctx.open_context(gate)
        try:
            return await _gated_call(*args, **kwargs)
        finally:
            _callctx.close_context(token)

    _adopt_metadata(wrapped, tool, tool_name, gate._mediation_token)
    return wrapped


def _finish(
    gate,
    tool_name: str,
    call_args: dict[str, Any],
    active: Principal,
    started: float,
    result: Any,
) -> Any:
    """The POST chain — pure and synchronous, so both paths share it verbatim."""
    lazy = _uninspectable_kind(result)
    if lazy is not None:
        return _refuse_uninspectable(gate, tool_name, call_args, active, started, result, lazy)
    post_req = GateRequest(tool_name, call_args, active, phase="post", policy_hash=_callctx.policy_hash_for(gate))
    post, final = _callctx.engine_for(gate).post(post_req, result)
    # The tool has already run by definition on the post phase.
    gate._recorder.record(tool_name, call_args, post, "post", started, active, True)
    if post.effect is Effect.DENY and _callctx.enforce_for(gate):
        raise GateDenied(post)
    # observe mode never modifies the result.
    return final if _callctx.enforce_for(gate) else result


def _refuse_unnameable(
    gate,
    tool_name: str,
    kwargs: dict[str, Any],
    active: Principal | None,
    started: float,
    tool: Callable[..., Any],
    args: tuple[Any, ...],
    reason: str | None = None,
) -> Any:
    """Refuse a positional call the gate cannot turn into named arguments.

    Only reached for the two shapes where no honest mapping exists — ``*args``, and
    a callable with no introspectable signature — because for everything else
    :func:`_positional_binder` asks Python for the names. The gate cannot validate
    what it cannot name: a schema, a ``bind`` and the trail are all written against
    names, so allowing the call would skip all three.

    This used to be a bare ``PolicyError`` raised before anything was recorded,
    which made it the one refusal in the library that left no trace, and made it
    fire in ``observe`` mode, which is documented as blocking nothing. It is a
    decision now, so it is audited like one, and observe watches it rather than
    blocking on it — a dry run that breaks the app teaches the team to skip the dry
    run.
    """
    decision = GateDecision(
        Effect.DENY,
        "unnameable_args",
        reason
        or (
            f"{tool_name!r} was called with {len(args)} positional argument(s) and its parameters "
            "cannot be named (it takes *args, or exposes no signature), so the schema, the bindings "
            "and the audit trail have nothing to attach to. Call it with keyword arguments."
        ),
    )
    gate._recorder.record(tool_name, dict(kwargs), decision, "pre", started, active, gate._will_execute(decision))
    if _callctx.enforce_for(gate):
        raise GateDenied(decision)
    return tool(*args, **kwargs)


def _refuse_uninspectable(
    gate,
    tool_name: str,
    call_args: dict[str, Any],
    active: Principal,
    started: float,
    result: Any,
    kind: str,
) -> Any:
    """Refuse a returned value whose payload is behind an iteration nothing performs.

    ``wrap`` refuses a generator *function*, but that asks the wrong object: a plain
    ``def search(q): return (row for row in rows)`` — or an async tool forced onto
    the sync path with ``is_async=False`` — looks ordinary at wrap time and only
    shows what it is here. The post chain then scanned the *iterator object* and
    reported ``allow`` with ``redactions: []``, so the canary, the secret and the
    projected-away field flowed to the model with a clean line in the log saying
    nothing was there.

    The honest limit, and the reason this reads as a denial of a value rather than
    of an action: the tool has already run, so nothing here can undo what it did.
    Refusing only stops the unscanned payload reaching the model.
    """
    decision = GateDecision(
        Effect.DENY,
        # its own published code, not `output_schema`: that one means the output was
        # read and did not match the declared return shape, and borrowing it here
        # said the opposite of what happened — nothing read this output at all — to
        # every dashboard and second implementation that groups by rule.
        "uninspectable_output",
        f"{tool_name!r} returned a {kind}: the output half of the gate can only inspect a "
        "materialised value, so nothing scanned it. Collect it first — `list(...)`, `dict(...)`, "
        "`bytes(...)` — and return that.",
    )
    # executed=True without argument: the tool body ran to completion.
    gate._recorder.record(tool_name, call_args, decision, "post", started, active, True)
    if not _callctx.enforce_for(gate):
        # observe mode never modifies the result, and closing it would modify it
        # more thoroughly than any redaction — the caller would get an exhausted
        # object where its data used to be.
        return result
    _close_quietly(result)
    raise GateDenied(decision)


def _finish_exception(
    gate,
    tool_name: str,
    call_args: dict[str, Any],
    active: Principal,
    started: float,
    exc: Exception,
) -> BaseException:
    """The POST chain for a raising tool. Returns the exception to raise.

    A tool that raises used to be the one way out of the process that skipped the
    post-gate entirely, so a canary or a secret in the error text reached the model
    unredacted while the audit trail recorded only the pre-decision. Both paths
    share this, and it is pure and synchronous for the same reason ``_finish`` is.

    Returns ``exc`` itself when nothing had to be removed — the caller re-raises it
    with its original traceback intact, so the common case is unchanged.
    """
    post_req = GateRequest(tool_name, call_args, active, phase="post", policy_hash=_callctx.policy_hash_for(gate))
    post, text = _callctx.engine_for(gate).post_exception(post_req, exc, mutate=_callctx.enforce_for(gate))
    # `post_exception` reads the exception's *text*, so an exception carrying its
    # payload as a lazy object — `raise ToolError(rows_iterator)` — is the raising
    # half of the same hole `_refuse_uninspectable` closes: `str(exc)` shows
    # `<generator object ...>`, nothing scans what the host will iterate out of
    # `exc.args`, and the record says allow. Each arg is asked the recursive
    # question, because `raise ToolError([rows])` hides the same object one level
    # down and a host draining `exc.args` finds it just as easily.
    lazy = next((kind for kind in map(_uninspectable_kind, exc.args) if kind is not None), None)
    if lazy is not None:
        post = GateDecision(
            Effect.DENY,
            "uninspectable_output",  # see `_refuse_uninspectable` on the code
            f"{tool_name!r} raised an error carrying a {lazy}: the output half of the gate can only "
            "inspect materialised text, so nothing scanned it.",
        )
    # The tool ran — it just ended by raising.
    gate._recorder.record(tool_name, call_args, post, "post", started, active, True)
    # observe mode records what it *would* have removed and changes nothing.
    if post.effect is Effect.ALLOW or not _callctx.enforce_for(gate):
        return exc
    if lazy is not None:
        # substituting the redacted exception is what drops the unscanned payload —
        # the original, and the object it holds, never reach the caller.
        for arg in exc.args:
            if _uninspectable_kind(arg) is not None:
                _close_quietly(arg)
    return ToolErrorRedacted(post, type(exc).__name__, text)


# ── protect the whole tool set ────────────────────
