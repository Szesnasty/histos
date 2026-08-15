"""The half of the gate that runs after the tool has already done something.

Split out of `engine.py`, and the split is the module\'s own structure: the pre-gate
decides whether a call may happen, this decides what may come back, and the two have
opposite economics. A pre-gate DENY costs a call. A post-gate DENY costs a call whose
side effect has *already* landed — the charge is made, the money is gone — and the
caller gets a refusal instead of the receipt. So everything here errs toward returning
something the caller can use, with the removed part named in the trail.

The passes, in order, and each one is here because it was once the way round the others:
the size budget (asked first, and only where something is actually going to read the
value), output projection, the canary scan in both tiers, the secret detectors, and
declared-sensitive fields. A *raised* exception goes through the same machinery, because
it is the other way a tool hands content back and was for a long time the one path out
of the process that skipped redaction entirely.
"""

from __future__ import annotations

from typing import Any

from histos.decide import canary, detectors
from histos.decide.budget import _over_output_budget, _text_blob
from histos.decide.excchain import _MAX_EXCEPTION_CHAIN, _exception_text, _hidden_branches
from histos.decide.redaction import (
    _project_output,
    _projectable,
    _redact_secrets_structure,
    _redact_sensitive,
    _redact_structure,
    _validate_output,
)
from histos.policy.contracts import Effect, GateDecision, GateRequest, ToolContract
from histos.policy.schema import sensitive_fields


def post(engine, req: GateRequest, result: Any) -> tuple[GateDecision, Any]:
    try:
        return _post(engine, req, result)
    except Exception as exc:  # noqa: BLE001 — fail-closed
        return GateDecision(Effect.DENY, "internal_error", f"fail-closed on exception: {exc!r}"), None


def post_exception(engine, req: GateRequest, exc: BaseException, *, mutate: bool = True) -> tuple[GateDecision, str]:
    """The POST chain for a *raising* tool.

    A raised exception is the other way a tool hands content back to the model,
    so it must not be the one path out of the process that skips redaction. Only
    the controls that apply to unstructured text run here — canary tokens and
    recognised secrets. Output projection, strict returns and sensitive-field
    redaction are all keyed on a declared return *shape*, which an exception does
    not have, so applying them would be inventing semantics.

    Canaries are matched in both tiers, as everywhere else. Matching verbatim only
    made a raised message the cheapest exit in the library: one zero-width space in
    ``ValueError(f"not found: {canary}")`` and the token reached the model inside an
    ordinary, un-redacted exception, with nothing in the audit trail.
    """
    try:
        return _post_exception(engine, req, exc, mutate=mutate)
    except Exception as inner:  # noqa: BLE001 — fail-closed
        # The redaction machinery itself failed, so nothing about the original
        # text can be trusted to be safe. Drop it entirely rather than pass it on.
        return (
            GateDecision(
                Effect.DENY,
                "internal_error",
                f"fail-closed redacting a raised exception: {inner!r}",
            ),
            "[REDACTED: the tool raised, and the error text could not be safely redacted]",
        )


def _post_exception(engine, req: GateRequest, exc: BaseException, *, mutate: bool = True) -> tuple[GateDecision, str]:
    contract = engine.policy.contract_for(req.tool_name)
    text, incomplete = _exception_text(exc, engine._output_budget)
    redactions: list[str] = []
    # Only where a pass was going to read it. The check used to run before any
    # contract field was consulted, so a contract with the canary scan and the
    # secret detectors both off — nothing that touches the text at all — still had a
    # sixteen-link exception replaced by a redaction string. A recursive-descent
    # parser annotating each frame reaches sixteen links honestly.
    will_read = contract is not None and (
        (contract.scan_output_for_canary and engine.policy.canaries) or contract.redact_secret_output
    )
    if incomplete and will_read:
        return (
            GateDecision(
                Effect.REDACT,
                "exception_redaction",
                f"the exception chain is longer than {_MAX_EXCEPTION_CHAIN} links, or larger than the "
                f"{engine._output_budget} character scan budget, so it could not be read to the end",
                redactions=("output:redacted_all",),
            ),
            "[REDACTED: the tool raised through a chain too long to inspect]",
        )

    if contract is not None and contract.scan_output_for_canary and engine.policy.canaries:
        text, found = _redact_structure(text, engine.policy.canaries)
        redactions.extend(f"canary:{tok}" for tok in found)

    if contract is not None and contract.redact_secret_output:
        text, kinds = detectors.redact_string(text)
        redactions.extend(f"secret:{k}" for k in dict.fromkeys(kinds))

    # `_next_link` stops at `__suppress_context__` because what Python will not
    # display is not something the caller can read — true of the *text*, and not of
    # the object. `raise X from None` leaves the suppressed exception attached to
    # `X.__context__`, and a caller that logs `exc.__context__` or hands the
    # exception to an error reporter reads exactly the secret the scan agreed not to
    # look at. So the hidden branch is scanned separately, and a hit detaches it
    # rather than redacting text nobody sees.
    #
    # `__context__ is not __cause__` because CPython sets `__suppress_context__`
    # whenever a cause is set, so the textbook `except Driver as e: raise Repo() from e`
    # satisfied this condition with the two attributes holding the same object.
    # Nothing is hidden there — Python displays the cause and the walk above has
    # already read and redacted it — yet the branch nulled `__context__` while
    # `__cause__` kept the identical object, so no exposure was removed, and it
    # recorded `suppressed_context_detached` about a suppressed branch that did not
    # exist, plus every canary and secret kind a second time.
    #
    # Every hidden branch in the chain, not only the one on `exc`. The scan was
    # applied at depth zero while `_exception_text` stops at each suppression it
    # meets, so the ordinary two-level shape — a repository hiding the driver with
    # `from None`, a service wrapping the repository — was inspected by neither.
    detached: list[str] = []
    scan_canaries = bool(contract is not None and contract.scan_output_for_canary and engine.policy.canaries)
    # One budget across every branch, not one budget each. `_MAX_EXCEPTION_NODES`'
    # comment says the real limiter on work is the character budget the walk carries,
    # which was true while exactly one branch was scanned. Handing each holder the full
    # budget again multiplies it by the number of suppressions a tool chooses to write,
    # and a tool chooses that freely.
    remaining = engine._output_budget
    for holder in _hidden_branches(exc) if will_read else []:
        branch = holder.__context__
        if branch is None:  # pragma: no cover - `_hidden_branches` only yields holders
            continue
        hidden, hidden_incomplete = _exception_text(branch, max(remaining, 0))
        remaining -= len(hidden)
        # Both tiers, like every other canary site in this library. Verbatim-only
        # matching is what this module's own docstring calls the cheapest exit in
        # the library, and the hidden branch had exactly that. Gated on the
        # contract's switch too: the visible pass asks `scan_output_for_canary` and
        # this one asked only whether tokens were planted, so a tool with the
        # per-tool opt-out had its cause detached on the strength of a scan the
        # contract had turned off.
        hidden_tokens: list[str] = []
        if scan_canaries:
            hidden_tokens = list(canary.find(hidden, engine.policy.canaries))
            hidden_tokens += [
                t for t in canary.find_normalized(hidden, engine.policy.canaries) if t not in hidden_tokens
            ]
        kinds = [d.kind for d in detectors.scan_string(hidden)] if contract and contract.redact_secret_output else []
        # `hidden_incomplete` used to be discarded. `take()` refuses the crossing
        # piece rather than truncating it, so a suppressed context over the budget
        # came back as the *empty string*: nothing found, nothing detached, nothing
        # recorded, ALLOW — reporting clean about text it never read. The main path
        # does the opposite for exactly this case.
        if not (hidden_tokens or kinds or hidden_incomplete):
            continue
        # `mutate` is false in observe mode, which is documented as recording what
        # it would have done and changing nothing. Detaching here ran inside the
        # engine, before `Gate._finish_exception` consults `_enforce`, so observe
        # was the one control in the library that reached into the caller's object.
        if mutate:
            holder.__context__ = None
        detached += [
            *(f"canary:{tok}" for tok in dict.fromkeys(hidden_tokens)),
            *(f"secret:{k}" for k in dict.fromkeys(kinds)),
            *(["exception:suppressed_context_unread"] if hidden_incomplete else []),
        ]
    if detached:
        detached.append("exception:suppressed_context_detached")
        if not redactions:
            # Nothing the caller can *read* changed: the message is untouched and so
            # is the exception type, which `raise X from None` deliberately chose.
            # What changed is that the hidden branch no longer hangs off the object
            # for an error reporter to pick up. An ALLOW with a note, not a
            # redaction — swapping the type would punish a leak that never reached
            # the text.
            return GateDecision(Effect.ALLOW, "allow", redactions=tuple(dict.fromkeys(detached))), text
        redactions.extend(dict.fromkeys(detached))

    if redactions:
        return (
            GateDecision(
                Effect.REDACT,
                "exception_redaction",
                "redacted sensitive/canary content from a raised exception",
                redactions=tuple(redactions),
            ),
            text,
        )
    return GateDecision(Effect.ALLOW, "allow"), text


def _will_read_output(engine, contract: ToolContract, req: GateRequest) -> bool:
    """Whether any post-gate pass is going to walk the returned value.

    The passes that do, and the only ones the budget is bounding: the canary scan
    (which needs canaries planted to do anything), the secret detectors, and
    anything keyed on a declared return shape.

    "Keyed on a declared return shape" is not the same as "has one", which is what
    this asked first. All three of those passes are themselves conditional — strict
    returns on `strict_returns`, projection on `project_output`, the sensitive walk
    on there being a sensitive field the caller may not see — so a contract that
    merely *declares* its return shape, which is exactly what the lockfile and drift
    detection want it to do, read nothing and still had a 6 MB return replaced by a
    68-character redaction string. That is the same sentence as the fix above, one
    step to the side: where no work is about to happen it is not a bound, it is a
    size limit nobody asked for.
    """
    return bool(
        contract.redact_secret_output
        or (contract.scan_output_for_canary and engine.policy.canaries)
        or (
            contract.returns is not None
            and (
                contract.strict_returns
                or contract.project_output
                or (
                    sensitive_fields(contract.returns, allowed=req.principal.can_view if req.principal else frozenset())
                )
            )
        )
    )


def _post(engine, req: GateRequest, result: Any) -> tuple[GateDecision, Any]:
    contract = engine.policy.contract_for(req.tool_name)
    redactions: list[str] = []
    out = result

    # The size question is asked once, before anything walks the payload. It used to
    # sit inside the canary branch, which left the two expensive passes outside it:
    # the secret detectors, which are the slowest thing here by an order of
    # magnitude, and the sensitive-field walk. A 63 MB return with canaries switched
    # off was still fully scanned. Asking first also means the answer costs one
    # traversal rather than being paid after the payload has already been walked.
    #
    # Asked only where an answer changes something. Moving it out of the canary
    # branch also moved it out of every *condition*, so it ran for a plain
    # `ToolContract(name=…, args=Schema({}))` with no canaries, no secret scan and no
    # declared return — a contract under which nothing reads the value at all. A
    # 4.4 MB CSV that came back in 186 ms before now came back as a 70-character
    # redaction string. A budget exists to bound work that is about to happen; where
    # no work is about to happen it is not a bound, it is a size limit nobody asked
    # for.
    if (
        contract is not None
        and _will_read_output(engine, contract, req)
        and _over_output_budget(out, engine._output_budget)
    ):
        if contract.on_output_violation == "deny":
            return GateDecision(
                Effect.DENY,
                "output_schema",
                f"tool output exceeds the {engine._output_budget} character scan budget, so no output "
                "control could read it",
            ), None
        # Everything that is not `deny` redacts, including `allow`, and that arm is
        # deliberately gone. `on_output_violation` is *malformed-output* policy —
        # "the return did not match the declared schema" — and hosts set `allow`
        # because a vendor's response shape drifts. Reusing it for the size question
        # meant those hosts had also, silently, switched off canary and secret
        # redaction for every oversized return: a planted canary and an AWS key both
        # egressed under an ALLOW record. A host that legitimately returns more than
        # the budget raises `Engine(output_budget=...)`, which enlarges what gets
        # scanned; it does not get a switch that stops the scanning.
        #
        # Scanning a prefix and reporting on the rest is the fail-open the pre-gate's
        # budget refuses an input to avoid. The tool has already run, so the honest
        # answer keeps the decision and drops the value.
        return (
            GateDecision(
                Effect.REDACT,
                "post_redaction",
                "tool output exceeded the scan budget and was not inspected",
                redactions=("output:redacted_all",),
            ),
            "[REDACTED: tool output exceeded the scan budget and was not inspected]",
        )

    # 0. Malformed-output policy (strict returns). Name-based redaction cannot
    #    save a secret that lands in an *undeclared* field, so an output that
    #    does not conform to the declared return schema is handled up front:
    #    known schema + conforming → deterministic field redaction (below);
    #    schema violation / unknown shape → deny or redact-all (conservative).
    if contract is not None and contract.strict_returns and contract.returns is not None:
        errors = _validate_output(contract.returns, out)
        if errors and contract.on_output_violation != "allow":
            if contract.on_output_violation == "deny":
                return GateDecision(
                    Effect.DENY, "output_schema", f"output did not match declared return schema: {errors[0]}"
                ), None
            return (
                GateDecision(
                    Effect.REDACT,
                    "output_schema",
                    "output did not match declared return schema — redacted",
                    redactions=("output:redacted_all",),
                ),
                "[REDACTED: tool output did not match its declared return schema]",
            )

    # 0b. Output field projection — deny-by-default on the return surface: drop
    #     any key not declared in `returns` (undeclared fields, where a secret can
    #     hide out of reach of name-based redaction, never egress).
    if contract is not None and contract.project_output and contract.returns is not None:
        # An object return cannot be projected — the projector walks dicts and
        # lists, and everything else it returns untouched. So `project_output=True`
        # on a tool returning a dataclass or a Pydantic model dropped nothing,
        # recorded nothing, and produced an audit line indistinguishable from one
        # where there was nothing to drop. A knob that silently does not apply is
        # worse than one that is off, because the policy says it is on. Treated as
        # a projection failure and handled by `on_output_violation`, exactly like a
        # return that fails its declared schema.
        # `None` is excluded deliberately: a tool that returns nothing has no
        # fields to project and nothing to leak, and treating it as a projection
        # failure replaced every `Optional[...]` return with a truthy redaction
        # string — so `if result is None:` in the caller stopped being true and the
        # tool silently changed meaning.
        if out is not None and not _projectable(out):
            if contract.on_output_violation == "deny":
                return GateDecision(
                    Effect.DENY,
                    "output_schema",
                    f"project_output is set but a {type(out).__name__} return has no fields to project; "
                    "return a mapping, or turn projection off for this tool",
                ), None
            if contract.on_output_violation != "allow":
                return (
                    GateDecision(
                        Effect.REDACT,
                        "output_schema",
                        f"project_output is set but a {type(out).__name__} return has no fields to project",
                        redactions=("output:redacted_all",),
                    ),
                    "[REDACTED: tool output could not be projected]",
                )
        out, dropped, opaque = _project_output(out, frozenset(contract.returns.fields))
        redactions.extend(f"drop:{k}" for k in dict.fromkeys(dropped))
        redactions.extend(f"output:uninspectable:{name}" for name in dict.fromkeys(opaque))
        # Nothing more than naming it. This used to route every `opaque` entry
        # through `on_output_violation`, whose default is redact_all, on the
        # reasoning that an object the projector cannot enter is exactly the
        # undeclared field one level down. The reasoning was right about records and
        # wrong about the set it was applied to: `opaque` holds everything outside
        # `_INSPECTABLE_LEAF`, so a declared field holding a `datetime`, `Decimal`,
        # `UUID` or `Path` — ordinary values, no undeclared field anywhere near them
        # — replaced the entire tool output with a redaction string. `_record_fields`
        # now enters the shapes that really can hide a field, which is what that
        # block was reaching for; what is left here is a *value* the projector
        # cannot read, and a value sitting under a declared key is not an
        # undeclared field. `strict_returns` is the knob for refusing those.

    # 1. Canary leak in the output → redact verbatim *and* normalized tokens
    #    anywhere in the structure, then ask the pre-gate's question of the whole
    #    thing: the pre-gate scans one blob joined from every argument, so it denies
    #    a token split across two of them, while per-leaf redaction cannot see a
    #    token split across two fields of the return. Post has to match at least as
    #    hard as pre or the output channel is the cheap way round the control — and
    #    a split token cannot be located leaf by leaf, so the value is dropped whole
    #    rather than returned with a leak the redactor could see but not reach.
    if contract is not None and contract.scan_output_for_canary and engine.policy.canaries:
        out, found = _redact_structure(out, engine.policy.canaries)
        redactions.extend(f"canary:{tok}" for tok in found)
        # The blob is rebuilt *after* redaction, and redaction grows text: an
        # 8-character token becomes the 17-character `[REDACTED-CANARY]`. So an
        # output that fitted the budget on the way in can exceed it here, and this
        # call site threw the truncation flag away — leaving `find_normalized`, the
        # only thing in the library that can see a token split across two fields,
        # reading a prefix and reporting clean about the rest.
        blob, blob_cut = _text_blob(out, engine._output_budget)
        if blob_cut:
            redactions.append("output:redacted_all")
            why = "redaction grew the output past the scan budget, so it could not be checked for a canary"
            return (
                GateDecision(Effect.REDACT, "post_redaction", f"{why} — output dropped", redactions=tuple(redactions)),
                f"[REDACTED: {why}]",
            )
        crossing = canary.find_normalized(blob, engine.policy.canaries)
        if crossing:
            redactions.extend(f"canary:{tok}" for tok in crossing)
            redactions.append("output:redacted_all")
            why = "a canary token spans several output fields and cannot be redacted in place"
            return (
                GateDecision(Effect.REDACT, "post_redaction", f"{why} — output dropped", redactions=tuple(redactions)),
                f"[REDACTED: {why}]",
            )

    # 2. Sensitive return fields the caller's role may not see → redact by name,
    #    recursively (covers lists of records + nested structures, not just a
    #    top-level dict).
    if contract is not None and contract.returns is not None:
        sensitive = frozenset(sensitive_fields(contract.returns, allowed=req.principal.can_view))
        if sensitive:
            out, hidden = _redact_sensitive(out, sensitive)
            redactions.extend(f"field:{f}" for f in dict.fromkeys(hidden))

    # 3. Recognised secrets anywhere in the output (checksum + structural) → redact.
    if contract is not None and contract.redact_secret_output:
        out, secret_kinds = _redact_secrets_structure(out)
        redactions.extend(f"secret:{k}" for k in dict.fromkeys(secret_kinds))

    if redactions:
        return (
            GateDecision(
                Effect.REDACT, "post_redaction", "redacted sensitive/canary content", redactions=tuple(redactions)
            ),
            out,
        )
    return GateDecision(Effect.ALLOW, "allow"), out
